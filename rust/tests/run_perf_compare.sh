#!/usr/bin/env bash
# One-shot wrapper to build the test image and run the C-vs-Rust perf
# comparison. Run from anywhere; this script `cd`s to the rust/
# directory itself before invoking docker.
#
#   ./rust/tests/run_perf_compare.sh
#
# Env knobs (forwarded to perf_c_vs_rust.sh inside the container):
#   DURATION   — seconds of replay per pass (default 15)
#   BLOCK_SIZE — testimonyd ring block size in bytes (default 1048576)
#   NUM_BLOCKS — testimonyd ring block count (default 16)
#   IMAGE      — docker tag to use (default testimony-perf)
#   SKIP_BUILD — if set, skip `docker build` (use existing image)
#   LOG_HOST   — host-side log directory (default ./perf-logs next to
#                this script's parent); the script `mkdir -p`s it and
#                bind-mounts it so the per-pass logs survive `--rm`

set -euo pipefail

IMAGE="${IMAGE:-testimony-perf}"
DURATION="${DURATION:-15}"
BLOCK_SIZE="${BLOCK_SIZE:-1048576}"
NUM_BLOCKS="${NUM_BLOCKS:-16}"

# Resolve the rust/ dir relative to this script so the user can run
# the script from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_HOST="${LOG_HOST:-$RUST_DIR/perf-logs}"

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

# Make sure the host-side log dir exists BEFORE bind-mounting; docker
# creates missing mounts as root-owned dirs which the script can't write
# to without sudo. Pre-creating with the user's umask keeps perms sane.
mkdir -p "$LOG_HOST"
bold "Running C-vs-Rust perf comparison"
echo "  DURATION=${DURATION}s  BLOCK_SIZE=$BLOCK_SIZE  NUM_BLOCKS=$NUM_BLOCKS"
echo "  log dir (host): $LOG_HOST"
echo "  log dir (container): /perf-logs"

docker run --rm --platform=linux/amd64 \
  --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=IPC_LOCK \
  -v "$LOG_HOST:/perf-logs" \
  -e LOGDIR=/perf-logs \
  -e DURATION="$DURATION" \
  -e BLOCK_SIZE="$BLOCK_SIZE" \
  -e NUM_BLOCKS="$NUM_BLOCKS" \
  --entrypoint /work/tests/perf_c_vs_rust.sh \
  "$IMAGE"

bold "Logs preserved at: $LOG_HOST"
echo "  cat $LOG_HOST/summary.txt"
ls -la "$LOG_HOST" 2>/dev/null | sed 's/^/  /' || true
