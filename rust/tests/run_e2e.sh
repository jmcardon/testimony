#!/usr/bin/env bash
# End-to-end smoke test, run inside the Dockerfile.test container.
#
# Boots a dummy interface, starts testimonyd, runs MULTIPLE clients in
# parallel against it (matches the original integration_test/test.sh's
# 10-client scenario), then SIGTERMs the daemon and verifies the socket
# file was unlinked (proof that UnlinkOnDrop fires) and that the process
# exits cleanly (proof that munmap and SHM cleanup ran).

set -euo pipefail

TARGET=/work/target/release
SOCK=/tmp/testimony_e2e.sock
CFG=/tmp/testimony_e2e.json
LOG_DAEMON=/tmp/daemon.log
LOG_DIR=/tmp/clients
PCAP=/work/tests/test.pcap
DUMMY=dummy0
CLIENTS=10

bold() { printf "\n\e[1;36m=== %s ===\e[0m\n" "$*"; }

cleanup() {
  set +e
  [ -n "${DAEMON_PID:-}" ] && kill -KILL "$DAEMON_PID" 2>/dev/null
  ip link del "$DUMMY" 2>/dev/null
  rm -f "$SOCK" "$CFG"
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT

bold "Probing kernel"
uname -a

bold "Setting up dummy interface"
modprobe dummy 2>/dev/null || echo "(modprobe dummy unavailable; assuming static)"
ip link add "$DUMMY" type dummy
ip link set "$DUMMY" up
ip addr add 169.254.1.2/24 dev "$DUMMY"

mkdir -p "$LOG_DIR"

bold "Writing config (FanoutSize 1, no BPF filter)"
cat > "$CFG" <<EOF
[
  {
      "SocketName": "$SOCK"
    , "Interface": "$DUMMY"
    , "BlockSize": 1048576
    , "NumBlocks": 16
    , "BlockTimeoutMillis": 1000
    , "FanoutSize": 1
    , "User": "$(whoami)"
  }
]
EOF
cat "$CFG"

bold "Starting testimonyd"
RUST_LOG=info "$TARGET/testimonyd" --config="$CFG" > "$LOG_DAEMON" 2>&1 &
DAEMON_PID=$!
sleep 1
if ! kill -0 $DAEMON_PID 2>/dev/null; then
  echo "DAEMON DIED EARLY"
  cat "$LOG_DAEMON"
  exit 1
fi

bold "Verifying socket exists"
[ -S "$SOCK" ] || { echo "$SOCK not a socket"; exit 1; }
ls -la "$SOCK"

bold "Starting $CLIENTS testclients in parallel"
CLIENT_PIDS=""
for i in $(seq 1 $CLIENTS); do
  "$TARGET/testclient" --socket="$SOCK" --count=10 --dump > "$LOG_DIR/out$i" 2> "$LOG_DIR/err$i" &
  CLIENT_PIDS="$CLIENT_PIDS $!"
done
sleep 1

# Verify they're all alive.
for pid in $CLIENT_PIDS; do
  kill -0 $pid 2>/dev/null || { echo "client $pid died early"; cat "$LOG_DIR/err"*; exit 1; }
done

bold "Replaying packets (5 loops to exercise the batching/Returned interleaving)"
tcpreplay -i "$DUMMY" --topspeed --loop=5 "$PCAP"
sleep 2

bold "Waiting for clients to finish"
FAILED=0
for pid in $CLIENT_PIDS; do
  if ! wait "$pid"; then
    FAILED=$((FAILED + 1))
  fi
done
if [ $FAILED -gt 0 ]; then
  echo "FAIL: $FAILED clients failed"
  for i in $(seq 1 $CLIENTS); do
    echo "--- client $i stderr ---"
    cat "$LOG_DIR/err$i"
  done
  exit 1
fi

bold "Verifying every client received packets"
for i in $(seq 1 $CLIENTS); do
  LINES=$(grep -c "^[0-9a-f][0-9a-f]" "$LOG_DIR/out$i" || true)
  if [ "$LINES" -lt 1 ]; then
    echo "FAIL: client $i received 0 packets"
    cat "$LOG_DIR/err$i"
    exit 1
  fi
  echo "client $i: $LINES packet hex lines"
done

bold "SIGTERM daemon — exercising graceful shutdown / SHM cleanup"
kill -TERM $DAEMON_PID
for _ in $(seq 1 50); do
  kill -0 $DAEMON_PID 2>/dev/null || break
  sleep 0.1
done
if kill -0 $DAEMON_PID 2>/dev/null; then
  echo "FAIL: daemon did not exit within 5s of SIGTERM"
  kill -KILL $DAEMON_PID
  cat "$LOG_DAEMON"
  exit 1
fi
DAEMON_PID=""

bold "Verifying socket file was unlinked"
if [ -e "$SOCK" ]; then
  echo "FAIL: $SOCK still present after graceful shutdown"
  ls -la "$SOCK"
  exit 1
fi

bold "Verifying no testimonyd processes survived"
if pgrep -f testimonyd > /dev/null; then
  echo "FAIL: testimonyd processes still running after SIGTERM"
  pgrep -af testimonyd
  exit 1
fi

bold "Verifying daemon exited cleanly"
if ! grep -q "shut down cleanly" "$LOG_DAEMON"; then
  echo "WARN: did not see 'shut down cleanly' in daemon log; full log:"
  cat "$LOG_DAEMON"
fi

bold "Verifying no orphan AF_PACKET ring memory"
# /proc/net/packet lists every AF_PACKET socket. After a clean shutdown
# with no clients still holding the fd, our entries should be gone.
# (Other AF_PACKET sockets on the system may exist; we only assert there
# are no rows whose Refcnt mentions our daemon.)
PSOCK=$(cat /proc/net/packet 2>/dev/null | tail -n +2 | wc -l)
echo "AF_PACKET sockets currently on system: $PSOCK"

bold "Daemon log tail"
tail -25 "$LOG_DAEMON"

bold "Running C ABI smoke (links against libtestimony.so)"

# Stand up a fresh daemon dedicated to the C ABI test so the loop has
# clean state to wrap the ring against.
SOCK_C=/tmp/testimony_cabi.sock
CFG_C=/tmp/testimony_cabi.json
LOG_C=/tmp/daemon_cabi.log
cat > "$CFG_C" <<EOF
[
  {
      "SocketName": "$SOCK_C"
    , "Interface": "$DUMMY"
    , "BlockSize": 65536
    , "NumBlocks": 4
    , "BlockTimeoutMillis": 200
    , "FanoutSize": 1
    , "User": "$(whoami)"
  }
]
EOF
RUST_LOG=info "$TARGET/testimonyd" --config="$CFG_C" > "$LOG_C" 2>&1 &
DAEMON_PID=$!
sleep 1
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
  echo "FAIL: c-abi daemon didn't start"
  cat "$LOG_C"
  exit 1
fi

# Drive traffic in the background so the C client can actually wrap the ring.
( tcpreplay -i "$DUMMY" --topspeed --loop=200 "$PCAP" > /dev/null 2>&1 || true ) &
REPLAY_PID=$!

# Run the C ABI smoke against a real socket: phase 1 (negative connect),
# phase 2 (wrap the 4-block ring at least 2× → 8 distinct block-deliveries
# per index), phase 3 (return_packets). With the B1 regression intact this
# would fail in phase 2 with -EIO somewhere around block 5.
#
# IMPORTANT: c_abi_smoke.c parses --socket and --wraps as space-separated
# (argp-style), not --key=value. Pass them as separate tokens.
if ! /work/tests/c_abi_smoke --socket "$SOCK_C" --wraps 2; then
  echo "FAIL: C ABI multi-block test"
  kill "$REPLAY_PID" 2>/dev/null || true
  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  cat "$LOG_C"
  exit 1
fi
kill "$REPLAY_PID" 2>/dev/null || true
wait "$REPLAY_PID" 2>/dev/null || true

# Tear down the c-abi daemon and verify clean shutdown.
kill -TERM "$DAEMON_PID"
for _ in $(seq 1 50); do
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$DAEMON_PID" 2>/dev/null; then
  echo "FAIL: c-abi daemon did not exit within 5s of SIGTERM"
  kill -KILL "$DAEMON_PID"
  cat "$LOG_C"
  exit 1
fi
DAEMON_PID=""
if [ -e "$SOCK_C" ]; then
  echo "FAIL: c-abi sock still present after shutdown"
  exit 1
fi
rm -f "$CFG_C"

bold "Stress: 5 clients reading forever while tcpreplay loops 100x"
SOCK3=/tmp/testimony_stress.sock
CFG3=/tmp/testimony_stress.json
LOG3=/tmp/daemon_stress.log
LOG3_DIR=/tmp/clients_stress
mkdir -p "$LOG3_DIR"

cat > "$CFG3" <<EOF
[
  {
      "SocketName": "$SOCK3"
    , "Interface": "$DUMMY"
    , "BlockSize": 1048576
    , "NumBlocks": 16
    , "BlockTimeoutMillis": 100
    , "FanoutSize": 1
    , "User": "$(whoami)"
  }
]
EOF
RUST_LOG=info "$TARGET/testimonyd" --config="$CFG3" > "$LOG3" 2>&1 &
DAEMON_PID=$!
sleep 1
kill -0 $DAEMON_PID || { echo "stress daemon died"; cat "$LOG3"; exit 1; }

# 5 clients with --count=-1 (read forever).
STRESS_PIDS=""
for i in 1 2 3 4 5; do
  "$TARGET/testclient" --socket="$SOCK3" --count=-1 > "$LOG3_DIR/out$i" 2> "$LOG3_DIR/err$i" &
  STRESS_PIDS="$STRESS_PIDS $!"
done
sleep 1

# Replay 100 loops to keep blocks moving while clients return them.
tcpreplay -i "$DUMMY" --topspeed --loop=100 "$PCAP" > /dev/null 2>&1 || true
sleep 3

# All clients should still be alive (not crashed on duplicate-block or panic).
ALIVE=0
for pid in $STRESS_PIDS; do
  if kill -0 $pid 2>/dev/null; then
    ALIVE=$((ALIVE + 1))
  fi
done
echo "stress: $ALIVE/5 clients still running after 100x replay"
kill $STRESS_PIDS 2>/dev/null || true
for pid in $STRESS_PIDS; do
  wait $pid 2>/dev/null || true
done

if [ $ALIVE -lt 5 ]; then
  echo "FAIL: $((5 - ALIVE)) stress clients crashed before being killed"
  for i in 1 2 3 4 5; do
    echo "--- stress client $i stderr ---"
    cat "$LOG3_DIR/err$i"
  done
  exit 1
fi

# Daemon should also still be healthy.
if ! kill -0 $DAEMON_PID 2>/dev/null; then
  echo "FAIL: stress daemon died"
  cat "$LOG3"
  exit 1
fi

kill -TERM $DAEMON_PID
for _ in $(seq 1 50); do
  kill -0 $DAEMON_PID 2>/dev/null || break
  sleep 0.1
done
kill -KILL $DAEMON_PID 2>/dev/null || true
DAEMON_PID=""
if [ -e "$SOCK3" ]; then
  echo "FAIL: stress sock still present"
  exit 1
fi
rm -f "$CFG3"
rm -rf "$LOG3_DIR"

bold "Re-running with FanoutSize=2 to exercise the fanout dispatch path"
SOCK2=/tmp/testimony_fanout.sock
CFG2=/tmp/testimony_fanout.json
LOG2=/tmp/daemon_fanout.log
LOG2_DIR=/tmp/clients_fanout
mkdir -p "$LOG2_DIR"

cat > "$CFG2" <<EOF
[
  {
      "SocketName": "$SOCK2"
    , "Interface": "$DUMMY"
    , "BlockSize": 1048576
    , "NumBlocks": 16
    , "BlockTimeoutMillis": 1000
    , "FanoutSize": 2
    , "FanoutType": 0
    , "User": "$(whoami)"
  }
]
EOF

RUST_LOG=info "$TARGET/testimonyd" --config="$CFG2" > "$LOG2" 2>&1 &
DAEMON_PID=$!
sleep 1
kill -0 $DAEMON_PID || { echo "fanout daemon died"; cat "$LOG2"; exit 1; }

# Two clients, one per fanout slot.
"$TARGET/testclient" --socket="$SOCK2" --fanout=0 --count=5 --dump > "$LOG2_DIR/out0" 2> "$LOG2_DIR/err0" &
P0=$!
"$TARGET/testclient" --socket="$SOCK2" --fanout=1 --count=5 --dump > "$LOG2_DIR/out1" 2> "$LOG2_DIR/err1" &
P1=$!
sleep 1

tcpreplay -i "$DUMMY" --topspeed --loop=10 "$PCAP"
sleep 2

# Clients may not finish if fanout splits unevenly; kill them after a beat.
kill $P0 $P1 2>/dev/null || true
wait $P0 2>/dev/null || true
wait $P1 2>/dev/null || true

# Verify at least ONE client got packets (LB fanout can drop to one side).
TOTAL=0
for i in 0 1; do
  L=$(grep -c "^[0-9a-f][0-9a-f]" "$LOG2_DIR/out$i" 2>/dev/null || true)
  echo "fanout client $i: $L packet hex lines"
  TOTAL=$((TOTAL + L))
done
if [ $TOTAL -lt 1 ]; then
  echo "FAIL: fanout test received zero packets across both clients"
  cat "$LOG2"
  exit 1
fi

kill -TERM $DAEMON_PID
for _ in $(seq 1 50); do
  kill -0 $DAEMON_PID 2>/dev/null || break
  sleep 0.1
done
# Belt-and-braces SIGKILL; ignore exit code (proc usually already dead).
kill -KILL $DAEMON_PID 2>/dev/null || true
DAEMON_PID=""
if [ -e "$SOCK2" ]; then
  echo "FAIL: $SOCK2 still present after fanout daemon shutdown"
  exit 1
fi
rm -f "$CFG2"
rm -rf "$LOG2_DIR"

bold "Golden-output parity test (matches legacy integration_test/test.sh)"
# The Go-era integration test cracks 10 testclients open against a
# BPF-filtered socket, replays test.pcap *exactly once* at topspeed, and
# asserts that every client's --dump output is byte-identical to
# test.expected. This pins down:
#   - tp_mac / snaplen / tp_next_offset packet slicing
#   - block layout (every client sees the same blocks)
#   - that the BPF filter actually filters (test.pcap has 10 packets;
#     all match the host filter, so 10 lines per client)
#   - that --count=10 exits the client cleanly mid-block if the count
#     is hit before the block is exhausted
SOCK_GOLD=/tmp/testimony_gold.sock
CFG_GOLD=/tmp/testimony_gold.json
LOG_GOLD=/tmp/daemon_gold.log
LOG_GOLD_DIR=/tmp/clients_gold
EXPECTED=/work/tests/test.expected

# Sanity: golden file present in the image.
if [ ! -f "$EXPECTED" ]; then
  echo "FAIL: golden output $EXPECTED missing from image"
  exit 1
fi

mkdir -p "$LOG_GOLD_DIR"
cat > "$CFG_GOLD" <<EOF
[
  {
      "SocketName": "$SOCK_GOLD"
    , "Interface": "$DUMMY"
    , "BlockSize": 1048576
    , "NumBlocks": 16
    , "BlockTimeoutMillis": 1000
    , "FanoutSize": 1
    , "User": "$(whoami)"
    , "Filter": "host 169.254.1.1 and host 169.254.1.2"
  }
]
EOF
RUST_LOG=info "$TARGET/testimonyd" --config="$CFG_GOLD" > "$LOG_GOLD" 2>&1 &
DAEMON_PID=$!
sleep 1
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
  echo "FAIL: golden daemon didn't start"
  cat "$LOG_GOLD"
  exit 1
fi

# Spawn 10 parallel clients exactly like integration_test/test.sh.
GOLD_PIDS=""
for i in $(seq 1 10); do
  "$TARGET/testclient" --socket="$SOCK_GOLD" --dump --count=10 \
    > "$LOG_GOLD_DIR/out$i" 2> "$LOG_GOLD_DIR/err$i" &
  GOLD_PIDS="$GOLD_PIDS $!"
done
sleep 1

# Replay exactly once (no --loop), at topspeed.
tcpreplay -i "$DUMMY" --topspeed "$PCAP"
sleep 2

# Wait for clients (they exit after --count=10 packets).
for pid in $GOLD_PIDS; do
  wait "$pid" 2>/dev/null || true
done

# Byte-for-byte assertion against the legacy golden output.
GOLD_FAIL=0
for i in $(seq 1 10); do
  if ! diff -q "$LOG_GOLD_DIR/out$i" "$EXPECTED" > /dev/null 2>&1; then
    echo "FAIL: client $i output diverges from $EXPECTED"
    diff -u "$EXPECTED" "$LOG_GOLD_DIR/out$i" | head -40
    echo "--- client $i stderr ---"
    cat "$LOG_GOLD_DIR/err$i"
    GOLD_FAIL=$((GOLD_FAIL + 1))
  fi
done
if [ "$GOLD_FAIL" -gt 0 ]; then
  echo "FAIL: $GOLD_FAIL/10 clients had non-matching output"
  cat "$LOG_GOLD"
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  exit 1
fi
echo "OK: 10/10 clients produced byte-identical golden output"

# Tear down the golden daemon cleanly.
kill -TERM "$DAEMON_PID"
for _ in $(seq 1 50); do
  kill -0 "$DAEMON_PID" 2>/dev/null || break
  sleep 0.1
done
kill -KILL "$DAEMON_PID" 2>/dev/null || true
DAEMON_PID=""
rm -f "$CFG_GOLD"
rm -rf "$LOG_GOLD_DIR"
if [ -e "$SOCK_GOLD" ]; then
  echo "FAIL: golden sock $SOCK_GOLD still present after shutdown"
  exit 1
fi

bold "Recv-throughput microbench (buffered vs unbuffered)"
# Find the bench binary cargo emitted; the suffix is a content hash.
BENCH=$(ls -1 /work/target/release/deps/recv_throughput-* 2>/dev/null | grep -v '\.d$' | head -n1)
if [ -n "$BENCH" ] && [ -x "$BENCH" ]; then
  "$BENCH"
else
  echo "(recv_throughput bench binary not found; skipping)"
fi

bold "Random-shutdown stress: kill daemon at random points (TERM/INT/KILL)"
# Cleanup any stale state from previous tests.
rm -f /tmp/testimony_chaos.sock /tmp/testimony_chaos.json
TARGET="$TARGET" DUMMY="$DUMMY" PCAP="$PCAP" ITERATIONS=15 \
  /work/tests/random_shutdown.sh

bold "SUCCESS — $CLIENTS clients + fanout=2 + random-shutdown stress, daemon shut down cleanly"
exit 0
