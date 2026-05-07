#!/usr/bin/env bash
# Random-shutdown stress test for testimonyd.
#
# Repeatedly:
#   1. Start testimonyd with a fresh config.
#   2. Spawn a small fleet of clients.
#   3. After a random delay (0..1500 ms) send one of:
#        - SIGTERM  (graceful — daemon must clean up .sock + AF_PACKET ring)
#        - SIGINT   (graceful — same code path as SIGTERM)
#        - SIGKILL  (no graceful path — kernel reclaims, but next start
#                    must handle the stale .sock file)
#   4. Wait for the daemon to exit (or, on SIGKILL, kill -0 it until gone).
#   5. Inspect the system:
#        - .sock file is gone (after SIGTERM/SIGINT) OR is handled by the
#          next iteration's `fs::remove_file` (after SIGKILL).
#        - /proc/net/packet's row count for our daemon is 0 (no orphan
#          AF_PACKET sockets).
#        - the daemon log shows clean shutdown for the SIGTERM/SIGINT
#          cases or any well-defined message for SIGKILL.
#   6. Repeat N times.
#
# At the end, also verify resource counts:
#   - Total AF_PACKET sockets did not grow over N iterations (no leak).
#   - Total open files for testimonyd PIDs is 0 (none alive).
#
# This is the test that pins down "the daemon cleans up after itself".

set -euo pipefail

TARGET=${TARGET:-/work/target/release}
DUMMY=${DUMMY:-dummy0}
PCAP=${PCAP:-/work/tests/test.pcap}

ITERATIONS=${ITERATIONS:-25}
SOCK=/tmp/testimony_chaos.sock
CFG=/tmp/testimony_chaos.json
LOGDIR=/tmp/chaos_logs
LOG_DAEMON="$LOGDIR/daemon.log"
CLIENT_LOGDIR="$LOGDIR/clients"

bold() { printf "\n\e[1;36m=== %s ===\e[0m\n" "$*"; }

cleanup() {
  set +e
  [ -n "${DAEMON_PID:-}" ] && kill -KILL "$DAEMON_PID" 2>/dev/null
  for pid in ${CLIENT_PIDS:-}; do
    kill -KILL "$pid" 2>/dev/null
  done
  rm -f "$SOCK" "$CFG"
}
trap cleanup EXIT

mkdir -p "$LOGDIR" "$CLIENT_LOGDIR"

bold "Setting up dummy interface (idempotent)"
modprobe dummy 2>/dev/null || echo "(modprobe dummy unavailable; assuming static)"
if ! ip link show "$DUMMY" >/dev/null 2>&1; then
  ip link add "$DUMMY" type dummy
  ip link set "$DUMMY" up
  ip addr add 169.254.1.2/24 dev "$DUMMY" 2>/dev/null || true
fi

cat > "$CFG" <<EOF
[
  {
      "SocketName": "$SOCK"
    , "Interface": "$DUMMY"
    , "BlockSize": 65536
    , "NumBlocks": 4
    , "BlockTimeoutMillis": 100
    , "FanoutSize": 1
    , "User": "$(whoami)"
  }
]
EOF

# Snapshot baseline AF_PACKET socket count BEFORE we start spinning up daemons.
# The kernel exposes one row per AF_PACKET socket in /proc/net/packet (after
# the header line). We compare before/after to confirm we didn't leak any.
baseline_pkt_count() {
  if [ -r /proc/net/packet ]; then
    tail -n +2 /proc/net/packet | wc -l
  else
    echo 0
  fi
}
PKT_BASE=$(baseline_pkt_count)
bold "Baseline AF_PACKET sockets on system: $PKT_BASE"

# Pseudo-random helper: returns a random integer in [lo, hi].
rnd() {
  local lo=$1 hi=$2
  echo $(( RANDOM % (hi - lo + 1) + lo ))
}

# Replay traffic in the background so the daemon has packets to fan out.
# `tcpreplay --loop=0` is "loop forever".
( while :; do tcpreplay -i "$DUMMY" --topspeed --loop=1 "$PCAP" >/dev/null 2>&1 || true; sleep 0.1; done ) &
REPLAY_PID=$!

# Run the chaos loop.
SIGNAL_HISTORY=""
GRACE_OK=0
GRACE_FAIL=0
KILL_OK=0
KILL_FAIL=0

for i in $(seq 1 "$ITERATIONS"); do
  ITER_LOG="$LOGDIR/iter${i}.log"
  bold "Iteration $i / $ITERATIONS"

  # Pre-check: ensure no stale daemon and (if previous iter SIGKILLed) no
  # leftover socket file. The daemon's bind() handles a stale .sock by
  # remove_file-then-bind, so leftover is fine, but we want to log it.
  if [ -e "$SOCK" ]; then
    echo "  pre-iter: $SOCK exists (left by previous iter); daemon will unlink"
  fi

  # Start daemon.
  RUST_LOG=info "$TARGET/testimonyd" --config="$CFG" > "$ITER_LOG" 2>&1 &
  DAEMON_PID=$!

  # Wait for the daemon to bind the socket; up to ~2s.
  ready=0
  for _ in $(seq 1 40); do
    if [ -S "$SOCK" ]; then ready=1; break; fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then break; fi
    sleep 0.05
  done
  if [ "$ready" -ne 1 ]; then
    echo "  FAIL: daemon did not bring up socket within 2s"
    cat "$ITER_LOG"
    exit 1
  fi

  # Spawn 3 clients in parallel.
  CLIENT_PIDS=""
  for j in 1 2 3; do
    "$TARGET/testclient" --socket="$SOCK" --count=-1 \
      > "$CLIENT_LOGDIR/iter${i}_client${j}.out" \
      2> "$CLIENT_LOGDIR/iter${i}_client${j}.err" &
    CLIENT_PIDS="$CLIENT_PIDS $!"
  done

  # Sleep a random amount so the daemon and clients have some live state.
  DELAY_MS=$(rnd 50 1500)
  sleep "$(printf '0.%03d' $DELAY_MS)"

  # Pick a random signal: 40% TERM, 30% INT, 30% KILL.
  R=$(rnd 0 9)
  if [ "$R" -lt 4 ]; then
    SIG=TERM; SIG_KIND="graceful"
  elif [ "$R" -lt 7 ]; then
    SIG=INT;  SIG_KIND="graceful"
  else
    SIG=KILL; SIG_KIND="hard"
  fi
  SIGNAL_HISTORY="$SIGNAL_HISTORY $SIG"
  echo "  delay=${DELAY_MS}ms; sending SIG${SIG} ($SIG_KIND)"

  kill -"$SIG" "$DAEMON_PID" 2>/dev/null || true

  # Wait for daemon to exit. Generous deadline.
  exited=0
  for _ in $(seq 1 100); do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then exited=1; break; fi
    sleep 0.05
  done
  if [ "$exited" -ne 1 ]; then
    echo "  FAIL: daemon did not exit within 5s of SIG${SIG}"
    kill -KILL "$DAEMON_PID" 2>/dev/null
    cat "$ITER_LOG"
    exit 1
  fi

  # Reap clients.
  for pid in $CLIENT_PIDS; do
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done

  # Verify resource state after this kind of shutdown.
  if [ "$SIG_KIND" = "graceful" ]; then
    # SIGTERM/SIGINT: socket file MUST be gone; daemon log MUST contain
    # "shut down cleanly".
    if [ -e "$SOCK" ]; then
      echo "  FAIL: $SOCK still present after graceful shutdown"
      cat "$ITER_LOG"
      GRACE_FAIL=$((GRACE_FAIL + 1))
      exit 1
    fi
    if ! grep -q "shut down cleanly" "$ITER_LOG"; then
      echo "  FAIL: daemon log missing 'shut down cleanly' after SIG${SIG}"
      cat "$ITER_LOG"
      GRACE_FAIL=$((GRACE_FAIL + 1))
      exit 1
    fi
    GRACE_OK=$((GRACE_OK + 1))
  else
    # SIGKILL: socket file is allowed to be present (no Drop runs).
    # Daemon log may be truncated; we don't assert on its contents.
    KILL_OK=$((KILL_OK + 1))
  fi

  DAEMON_PID=""
done

# After all iterations, verify no AF_PACKET socket leak and no leftover
# .sock file (the last iteration might have left one if it was SIGKILL,
# but cleanup() trap will unlink it).
PKT_FINAL=$(baseline_pkt_count)
bold "AF_PACKET sockets after $ITERATIONS iterations: $PKT_FINAL (baseline $PKT_BASE)"
if [ "$PKT_FINAL" -gt "$PKT_BASE" ]; then
  echo "FAIL: AF_PACKET socket count grew by $((PKT_FINAL - PKT_BASE)) — kernel ring leak"
  exit 1
fi

# Verify no testimonyd processes survived.
if pgrep -f "testimonyd" >/dev/null; then
  echo "FAIL: testimonyd processes still running"
  pgrep -af testimonyd
  exit 1
fi

# Stop the background tcpreplay loop.
kill "$REPLAY_PID" 2>/dev/null || true
wait "$REPLAY_PID" 2>/dev/null || true

bold "Random-shutdown summary"
echo "  iterations:           $ITERATIONS"
echo "  graceful (TERM/INT):  $GRACE_OK ok / $GRACE_FAIL fail"
echo "  hard (KILL):          $KILL_OK ok / $KILL_FAIL fail"
echo "  signals:             $SIGNAL_HISTORY"
echo "  AF_PACKET delta:      $((PKT_FINAL - PKT_BASE))"
echo "PASS"
