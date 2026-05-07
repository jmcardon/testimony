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

# `run_one_pass kind tag` runs ONE measured pass and appends a result
# line tagged `tag` to the summary. tag distinguishes warmup vs measure.
run_one_pass() {
  local kind="$1"  # "rust" or "c"
  local tag="$2"   # "warmup" or "measure-N"
  local err_log="$LOGDIR/${kind}-${tag}.err"
  local replay_log="$LOGDIR/tcpreplay_${kind}-${tag}.log"
  local daemon_log="$LOGDIR/daemon_${kind}-${tag}.log"
  : > "$err_log"; : > "$replay_log"; : > "$daemon_log"

  RUST_LOG=warn "$TARGET/testimonyd" --config="$CFG" > "$daemon_log" 2>&1 &
  DAEMON_PID=$!
  local up=0
  for _ in $(seq 1 40); do
    [ -S "$SOCK" ] && { up=1; break; }
    sleep 0.05
  done
  if [ "$up" -ne 1 ]; then
    echo "FAIL: daemon didn't bring up socket for $kind/$tag"
    cat "$daemon_log"
    exit 1
  fi

  # Spawn the client. Both clients run forever; we send SIGTERM at the
  # end of the timed window so the Rust client can print its
  # TESTCLIENT_RESULT summary line before exiting. The C legacy client
  # has no such graceful path; we parse its existing per-block stderr.
  case "$kind" in
    rust)
      "$TARGET/testclient" --socket="$SOCK" --count=-1 --quiet \
        > /dev/null 2> "$err_log" &
      ;;
    c)
      "$C_CLIENT" --socket "$SOCK" --count 0 \
        > /dev/null 2> "$err_log" &
      ;;
    *) echo "unknown kind"; exit 2;;
  esac
  CLIENT_PID=$!

  # Let the client reach steady state before we start the timer.
  sleep 0.3

  # Background replay loop. tcpreplay reports its own pps at exit; we
  # capture that to detect when tcpreplay (not the client) is the
  # bottleneck.
  ( tcpreplay -i "$DUMMY" --topspeed --loop=0 "$PCAP" > "$replay_log" 2>&1 || true ) &
  REPLAY_PID=$!

  sleep "$DURATION"

  # Stop the replay first so tcpreplay's stats are flushed, then signal
  # the client (graceful — Rust client prints summary; C client just dies).
  kill "$REPLAY_PID" 2>/dev/null || true
  wait "$REPLAY_PID" 2>/dev/null || true
  REPLAY_PID=""
  sleep 0.1
  # Graceful TERM gives the Rust client time to print its summary line.
  kill -TERM "$CLIENT_PID" 2>/dev/null || true
  # Wait up to 2s for graceful exit, then force-kill.
  local i
  for i in $(seq 1 40); do
    kill -0 "$CLIENT_PID" 2>/dev/null || break
    sleep 0.05
  done
  kill -KILL "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  CLIENT_PID=""

  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  for i in $(seq 1 50); do
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""

  # Extract the client's measured packet rate.
  # Disable pipefail / -e locally so a no-match grep doesn't tear the
  # whole script down — `pkts=0` is a valid (if alarming) result that
  # the post-pass FAIL check handles separately.
  set +eo pipefail
  local pkts=0
  local blocks=0
  local pps=0
  case "$kind" in
    rust)
      # The Rust client prints a single TESTCLIENT_RESULT line on graceful exit.
      local result_line
      result_line=$(grep '^TESTCLIENT_RESULT' "$err_log" 2>/dev/null | tail -n 1)
      if [ -n "$result_line" ]; then
        blocks=$(printf '%s\n' "$result_line" | sed -n 's/.*blocks=\([0-9]*\).*/\1/p')
        pkts=$(printf '%s\n' "$result_line" | sed -n 's/.*packets=\([0-9]*\).*/\1/p')
        # Use the client's own elapsed-ns clock for pps so we don't
        # confound with our shell-side sleep slop.
        local ns
        ns=$(printf '%s\n' "$result_line" | sed -n 's/.*elapsed_ns=\([0-9]*\).*/\1/p')
        if [ -n "$ns" ] && [ "$ns" -gt 0 ]; then
          pps=$(awk -v p="$pkts" -v n="$ns" 'BEGIN { printf "%d", (p*1e9/n)+0.5 }')
        fi
      fi
      ;;
    c)
      blocks=$(grep -c "^got block " "$err_log" 2>/dev/null)
      pkts=$(awk '/^got block .* with / { sum += $5 } END { print sum+0 }' "$err_log")
      pps=$(awk -v p="$pkts" -v d="$DURATION" 'BEGIN { printf "%d", (p/d)+0.5 }')
      ;;
  esac
  # Default to 0 if any of the parses bailed out empty.
  blocks=${blocks:-0}
  pkts=${pkts:-0}
  pps=${pps:-0}

  # Pull tcpreplay's measured rate so we can detect generator-side
  # bottlenecking. Format from tcpreplay 4.x:
  #   "Actual: 1234567 packets ... (567890 pps)"
  local replay_pps
  replay_pps=$(grep -oE '[0-9]+\.?[0-9]* pps' "$replay_log" 2>/dev/null | tail -n 1 | awk '{print $1}')
  replay_pps=${replay_pps:-0}
  # Re-enable strict mode for the rest of the function.
  set -eo pipefail

  local line
  line=$(printf "%-7s %-12s %10s blocks  %14s pkts  %12s pkt/s  (replay=%s pps)" \
    "$kind" "$tag" "$blocks" "$pkts" "$pps" "$replay_pps")
  echo "  $line"
  printf "%s\n" "$line" >> "$SUMMARY"
  # Machine-readable line for the median extractor. One field per
  # column, space-separated. Stored alongside the human summary so we
  # don't have to re-parse the formatted version.
  printf 'RESULT %s %s %s %s %s %s\n' \
    "$kind" "$tag" "$blocks" "$pkts" "$pps" "$replay_pps" >> "$SUMMARY"

  if [ "${tag#warmup}" = "$tag" ] && [ "$pkts" -eq 0 ]; then
    # Only fail on measure passes; warmups are allowed to be 0 if the
    # very first kernel-level setup eats the whole window.
    echo "FAIL: $kind/$tag measured 0 packets — see $err_log and $daemon_log"
    return 1
  fi
}

bold "PERF: Rust testclient vs C testclient_c"
echo "  pcap=$PCAP"
echo "  pcap size: $(du -h "$PCAP" 2>/dev/null | cut -f1) ($(stat -c %s "$PCAP" 2>/dev/null || stat -f %z "$PCAP") bytes)"
echo "  duration=${DURATION}s  block_size=$BLOCK_SIZE  num_blocks=$NUM_BLOCKS"
{
  printf "PERF SUMMARY  pcap=%s  duration=%ds  block_size=%d  num_blocks=%d\n" \
    "$PCAP" "$DURATION" "$BLOCK_SIZE" "$NUM_BLOCKS"
  printf "%-7s %-12s %10s  %14s  %12s  %s\n" "kind" "tag" "blocks" "pkts" "pkt/s" "replay"
  printf '%s\n' "----------------------------------------------------------------------------------------"
} > "$SUMMARY"

# Warm everything up FIRST: pcap into page cache, AF_PACKET slabs, BPF
# JIT, tcpreplay binary, libtestimony in dyld cache. Without this the
# first measured pass sees 30-50% lower numbers than the rest. We do
# both kinds because each binary takes its own warmup. Warmup failures
# are tolerated (`|| true`) — only the measure passes are load-bearing.
bold "Warmup pass (untimed for measurement, but takes ~${DURATION}s of wall clock)"
run_one_pass rust warmup || echo "  (warmup rust failed — continuing to measured passes anyway)"
run_one_pass c warmup    || echo "  (warmup c failed — continuing to measured passes anyway)"

# Three measured passes per client, alternating, so any drift between
# kinds shows up as a per-pass difference rather than a systematic
# advantage. Median is the headline number.
bold "Measured passes (3 each, alternating)"
for n in 1 2 3; do
  run_one_pass rust "measure-$n" || echo "  (measure-$n rust failed — see logs)"
  run_one_pass c    "measure-$n" || echo "  (measure-$n c failed — see logs)"
done

bold "FINAL SUMMARY"
echo "  log directory inside container: $LOGDIR"
echo "  (mount it from the host with -v \$PWD/perf-logs:$LOGDIR to inspect)"
echo
cat "$SUMMARY"
echo
# Compute median pkt/s per kind for the headline. Reads the
# `RESULT kind tag blocks pkts pps replay` machine-readable lines so
# the parsing is robust against printf alignment changes.
for kind in rust c; do
  awk -v k="$kind" '
    $1 == "RESULT" && $2 == k && $3 ~ /^measure-/ { print $6 }
  ' "$SUMMARY" | sort -n | awk -v k="$kind" '
    { a[NR] = $1 }
    END {
      if (NR == 0) { exit }
      if (NR % 2) { med = a[int((NR+1)/2)] }
      else        { med = (a[NR/2] + a[NR/2+1]) / 2 }
      printf "  median pkt/s [%s] = %d (n=%d)\n", k, med, NR
    }'
done
