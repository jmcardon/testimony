# Rust rewrite

Workspace that replaces the legacy Go daemon (`go/`) and C client library (`c/`)
with a single Rust stack. Wire protocol is unchanged (version 2), so legacy
clients continue to interoperate during the transition.

## Crates

| Crate                    | Output                          | Purpose                                                                |
| ------------------------ | ------------------------------- | ---------------------------------------------------------------------- |
| `testimony-protocol`     | rlib                            | TLV / type constants. Mirrors `go/protocol/protocol.go`.               |
| `testimony-afpacket`     | rlib (Linux-only impl)          | AF_PACKET TPACKET_V3 ring + RAII `MmapRing`. Replaces `c/socket.c`.    |
| `testimony-client`       | rlib + `cdylib` `libtestimony.so` + staticlib | Rust API and ABI-compatible C exports for legacy consumers. Replaces `c/testimony.c`. |
| `testimonyd`             | bin `testimonyd`                | Daemon. Replaces `go/testimonyd/`.                                     |
| `testclient`             | bin `testclient`                | Test consumer. Replaces `go/testclient/` and `c/testimony_client.c`.   |

## Why

* The original C client and the cgo half of `testimonyd` shared all the
  interesting AF_PACKET logic; consolidating into one language eliminates the
  duplicated wire-format constants and the cgo overhead on every
  `WaitForBlocks`.
* RAII gives us an actual fix for the SHM-leak-on-bad-shutdown bug:
  `MmapRing::Drop` calls `munmap`, the daemon's `UnlinkOnDrop` removes the
  AF_UNIX socket file, and SIGTERM/SIGINT triggers an orderly drop of every
  owned resource.

## Build

```sh
make build          # cargo build --release on the workspace
make test           # workspace tests
sudo ./install.sh   # install /usr/sbin/testimonyd, /usr/local/lib/libtestimony.so, etc.
```

Cross-target check during development on a non-Linux host:

```sh
cargo check --workspace --target x86_64-unknown-linux-gnu
```

## Compatibility

* Wire protocol byte-identical to v2 (see `testimony-protocol`).
* C ABI: `libtestimony.so` exports the same `testimony_*` functions in
  `c/testimony.h`. Existing C consumers re-link without source changes.
* Config file: same JSON schema at `/etc/testimony.conf`.
* CLI: `testimonyd --config <path>` matches the Go flag surface.
