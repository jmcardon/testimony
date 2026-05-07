#!/usr/bin/env bash
# One-shot wrapper to build the test image and run the C-vs-Rust perf
# comparison. Run from anywhere; this script `cd`s to the rust/
# directory itself before invoking docker.
#
#   ./rust/tests/run_perf_compare.sh
#
# Env knobs (forwarded to perf_c_vs_rust.sh inside the container):
#   DURATION   — seconds of replay per pass (default 10)
#   LOOPS      — tcpreplay --loop count per pass (default 200)
#   BLOCK_SIZE — testimonyd ring block size in bytes (default 1048576)
#   NUM_BLOCKS — testimonyd ring block count (default 16)
#   IMAGE      — docker tag to use (default testimony-perf)
#   SKIP_BUILD — if set, skip `docker build` (use existing image)

set -euo pipefail

IMAGE="${IMAGE:-testimony-perf}"
DURATION="${DURATION:-10}"
LOOPS="${LOOPS:-200}"
BLOCK_SIZE="${BLOCK_SIZE:-1048576}"
NUM_BLOCKS="${NUM_BLOCKS:-16}"

# Resolve the rust/ dir relative to this script so the user can run
# the script from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

bold() { printf "\n\e[1;36m=== %s ===\e[0m\n" "$*"; }

# Pre-flight checks.
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not in PATH"; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERROR: docker daemon not reachable"; exit 1; }

if [ -z "${SKIP_BUILD:-}" ]; then
  bold "Building test image '$IMAGE' from $RUST_DIR"
  docker build \
    --platform=linux/amd64 \
    -f "$RUST_DIR/Dockerfile.test" \
    -t "$IMAGE" \
    "$RUST_DIR"
else
  bold "SKIP_BUILD set — using existing image '$IMAGE'"
fi

bold "Running C-vs-Rust perf comparison (DURATION=${DURATION}s, LOOPS=${LOOPS})"
docker run --rm --platform=linux/amd64 \
  --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=IPC_LOCK \
  -e DURATION="$DURATION" \
  -e LOOPS="$LOOPS" \
  -e BLOCK_SIZE="$BLOCK_SIZE" \
  -e NUM_BLOCKS="$NUM_BLOCKS" \
  --entrypoint /work/tests/perf_c_vs_rust.sh \
  "$IMAGE"
