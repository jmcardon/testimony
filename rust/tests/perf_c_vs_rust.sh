#!/usr/bin/env bash
# C client vs. Rust client end-to-end perf comparison.
#
# Each pass:
#   1. Boots a fresh testimonyd against a dummy interface.
#   2. Starts ONE client.
#   3. Replays test.pcap forever (tcpreplay --loop=0) for $DURATION
#      seconds, then kills the replay.
#   4. Reads each client's reported per-block packet counts and sums.
#   5. Prints packets/sec to stdout AND writes a summary file to LOGDIR.
#
# Run from inside the docker image:
#   docker build --platform=linux/amd64 -f rust/Dockerfile.test -t testimony-perf rust/
#   docker run --rm --platform=linux/amd64 \
#       --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=IPC_LOCK \
#       -v "$PWD/perf-logs:/perf-logs" \
#       -e LOGDIR=/perf-logs \
#       --entrypoint /work/tests/perf_c_vs_rust.sh testimony-perf
#
# Or use the wrapper which sets the volume mount for you:
#   ./rust/tests/run_perf_compare.sh
#
# Knobs (env vars):
#   DURATION   (default 15) — seconds of replay per pass
#   BLOCK_SIZE (default 1048576) — testimonyd ring block size
#   NUM_BLOCKS (default 16)      — testimonyd ring block count
#   LOGDIR     (default /tmp/perf_logs) — where per-pass logs land
#                                          (mount this from the host to
#                                           inspect after `docker run --rm`)

set -euo pipefail

TARGET=${TARGET:-/work/target/release}
DUMMY=${DUMMY:-dummy0}
# Prefer the synthesised perf pcap (~150 MB, 1.5M packets); fall back to
# the tiny golden-test pcap so this script still works on a host that
# hasn't built the perf pcap yet (it will just be lower-throughput).
if [ -z "${PCAP:-}" ]; then
  if [ -f /work/tests/perf.pcap ]; then
    PCAP=/work/tests/perf.pcap
  else
    PCAP=/work/tests/test.pcap
  fi
fi
DURATION=${DURATION:-15}
BLOCK_SIZE=${BLOCK_SIZE:-1048576}
NUM_BLOCKS=${NUM_BLOCKS:-16}

# Default to a host-mountable path so users see the logs after the
# container is reaped. The wrapper script `run_perf_compare.sh` mounts
# /perf-logs by default; if you run docker by hand, do the same.
LOGDIR=${LOGDIR:-/tmp/perf_logs}
SUMMARY="$LOGDIR/summary.txt"
SOCK=/tmp/testimony_perf.sock
CFG=/tmp/testimony_perf.json
mkdir -p "$LOGDIR"
: > "$SUMMARY"

bold() { printf "\n\e[1;36m=== %s ===\e[0m\n" "$*"; }

cleanup() {
  set +e
  [ -n "${DAEMON_PID:-}" ] && kill -KILL "$DAEMON_PID" 2>/dev/null
  [ -n "${REPLAY_PID:-}" ] && kill -KILL "$REPLAY_PID" 2>/dev/null
  [ -n "${CLIENT_PID:-}" ] && kill -KILL "$CLIENT_PID" 2>/dev/null
  rm -f "$SOCK" "$CFG"
}
trap cleanup EXIT

bold "Setting up dummy interface"
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
    , "BlockSize": $BLOCK_SIZE
    , "NumBlocks": $NUM_BLOCKS
    , "BlockTimeoutMillis": 100
    , "FanoutSize": 1
    , "User": "$(whoami)"
  }
]
EOF

# C-built testclient against libtestimony.so. The Dockerfile pre-compiles
# this at /tmp/testimony_c_client; if you're running outside the image
# (e.g. on a Linux host) the script falls back to compiling on demand.
C_CLIENT=/tmp/testimony_c_client
if [ ! -x "$C_CLIENT" ]; then
  bold "Compiling C testclient (links against libtestimony.so)"
  CSRC=/work/c/testimony_client.c
  if [ ! -f "$CSRC" ]; then
    # Fallback for host runs (outside Docker): use the canonical c/ at
    # the repo root.
    CSRC="$(dirname "$0")/../../c/testimony_client.c"
  fi
  cc -O2 "$CSRC" \
     -I "$(dirname "$CSRC")" \
     -L "$TARGET" -ltestimony \
     -Wl,-rpath,"$TARGET" \
     -o "$C_CLIENT"
fi

run_one_pass() {
  local kind="$1"  # "rust" or "c"
  local out_log="$LOGDIR/${kind}.out"
  local err_log="$LOGDIR/${kind}.err"
  : > "$out_log"; : > "$err_log"

  bold "Starting daemon for $kind pass"
  RUST_LOG=warn "$TARGET/testimonyd" --config="$CFG" > "$LOGDIR/daemon_${kind}.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 40); do
    [ -S "$SOCK" ] && break
    sleep 0.05
  done
  if ! [ -S "$SOCK" ]; then
    echo "FAIL: daemon didn't bring up socket"; exit 1
  fi

  # Spawn the client (run forever; we kill it after $DURATION).
  case "$kind" in
    rust)
      "$TARGET/testclient" --socket="$SOCK" --count=-1 \
        > "$out_log" 2> "$err_log" &
      ;;
    c)
      # The C client takes --socket and --count; --count=0 means "exit
      # on first pre-decrement to 0" which is "process forever" because
      # post-decrement underflows below 0 only after billions of packets
      # — fine for our 10-second window.
      "$C_CLIENT" --socket "$SOCK" --count 0 \
        > "$out_log" 2> "$err_log" &
      ;;
    *) echo "unknown kind"; exit 2;;
  esac
  CLIENT_PID=$!

  # Wait for client to be in steady state.
  sleep 0.5

  # Replay packets in a tight loop forever (`--loop=0`); we kill it
  # after the timed window. This ensures the receiver never starves on
  # the input even if the pcap is small. With the 1.5M-packet
  # synthesised pcap a single loop already takes ~1s at line rate; we
  # loop anyway in case the host CPU is fast enough to drain a loop in
  # < $DURATION seconds.
  ( tcpreplay -i "$DUMMY" --topspeed --loop=0 "$PCAP" > "$LOGDIR/tcpreplay_${kind}.log" 2>&1 || true ) &
  REPLAY_PID=$!

  # Timed window.
  sleep "$DURATION"

  # Stop replay first, then client (so client drains tail).
  kill "$REPLAY_PID" 2>/dev/null || true
  wait "$REPLAY_PID" 2>/dev/null || true
  REPLAY_PID=""
  sleep 0.2

  # Kill the client and capture its stats from stderr.
  kill -INT "$CLIENT_PID" 2>/dev/null || true
  sleep 0.2
  kill -KILL "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""

  # Tear down the daemon (graceful so the next pass starts clean).
  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  for _ in $(seq 1 50); do
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""

  # Pull "block N had K packets, T total" lines from stderr (Rust) or
  # "got block ... with K packets" (C). Sum the per-block counts.
  local pkts=0
  local blocks=0
  case "$kind" in
    rust)
      # Format: "block 12 had 1024 packets, 30000 total in 9.5s"
      blocks=$(grep -c "^block " "$err_log" || true)
      pkts=$(awk '/^block .* had / { sum += $4 } END { print sum+0 }' "$err_log")
      ;;
    c)
      # Format: "got block 0x... with 1024 packets"
      blocks=$(grep -c "^got block " "$err_log" || true)
      pkts=$(awk '/^got block .* with / { sum += $5 } END { print sum+0 }' "$err_log")
      ;;
  esac

  local pps_int=0
  if [ "$DURATION" -gt 0 ]; then
    pps_int=$(awk -v p="$pkts" -v d="$DURATION" 'BEGIN { printf "%d", (p/d)+0.5 }')
  fi
  local line
  line=$(printf "%-9s %10d blocks  %14d pkts  %12d pkt/s  (%ds)" \
    "$kind" "$blocks" "$pkts" "$pps_int" "$DURATION")
  echo "  $line"
  printf "%s\n" "$line" >> "$SUMMARY"

  # Sanity: zero packets means setup broke (BPF filter, daemon, dummy
  # interface, …). Surface it loudly instead of silently shipping a 0.
  if [ "$pkts" -eq 0 ]; then
    echo "FAIL: $kind pass measured 0 packets — see $LOGDIR/${kind}.err and $LOGDIR/daemon_${kind}.log"
    return 1
  fi
}

bold "PERF: Rust testclient vs C testclient_c"
echo "  pcap=$PCAP  duration=${DURATION}s  block_size=$BLOCK_SIZE  num_blocks=$NUM_BLOCKS"
echo "  pcap size: $(du -h "$PCAP" 2>/dev/null | cut -f1) ($(stat -c %s "$PCAP" 2>/dev/null || stat -f %z "$PCAP") bytes)"
{
  printf "PERF SUMMARY  pcap=%s  duration=%ds  block_size=%d  num_blocks=%d\n" \
    "$PCAP" "$DURATION" "$BLOCK_SIZE" "$NUM_BLOCKS"
  printf "%-9s %10s  %14s  %12s\n" "kind" "blocks" "pkts" "pkt/s"
  printf '%s\n' "------------------------------------------------------------------"
} > "$SUMMARY"

run_one_pass rust
run_one_pass c
bold "Re-running Rust pass to confirm reproducibility"
run_one_pass rust

bold "FINAL SUMMARY"
echo "  log directory inside container: $LOGDIR"
echo "  (mount it from the host with -v \$PWD/perf-logs:$LOGDIR to inspect)"
echo
cat "$SUMMARY"
