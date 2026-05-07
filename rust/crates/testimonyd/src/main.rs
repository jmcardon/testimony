//! testimonyd: shares AF_PACKET TPACKET_V3 ring sockets across local clients.
//!
//! Replaces the cgo-based daemon in `go/testimonyd`. Notable improvements:
//!
//! * RAII shutdown — `CaptureSocket` munmaps + closes its fd in `Drop`,
//!   `UnlinkOnDrop` removes AF_UNIX socket files. SIGTERM/SIGINT trigger
//!   an orderly drop of every owned resource. `panic = "unwind"` plus a
//!   panic hook means even a worker panic results in a full cleanup —
//!   only SIGKILL or kernel-level OOM can leak the kernel ring.
//! * Per-socket worker threads, per-client reader/writer threads. No async
//!   runtime, no cgo, no goroutine-pinning overhead.
//! * Structured errors: every libc / nix call surfaces a typed
//!   `DaemonError` with the syscall name and the relevant arguments, so
//!   logs identify the failure precisely instead of just "EINVAL".

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("testimonyd only runs on Linux");
    std::process::exit(1);
}

// `config`, `conn`, `shutdown`, `error` compile cross-platform so we can
// unit test them on macOS. `server` uses libc/nix Linux APIs and is
// Linux-only. On non-Linux several items go unused; suppress dead-code
// warnings rather than peppering each item.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod config;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod conn;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod error;
#[cfg(target_os = "linux")]
mod server;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod shutdown;

#[cfg(target_os = "linux")]
fn main() {
    use std::path::PathBuf;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let mut config_path = PathBuf::from("/etc/testimony.conf");
    let mut iter = args.iter().skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" | "-config" => match iter.next() {
                Some(v) => config_path = PathBuf::from(v),
                None => {
                    eprintln!("{arg}: missing argument");
                    std::process::exit(2);
                }
            },
            s if s.starts_with("--config=") => {
                config_path = PathBuf::from(&s["--config=".len()..]);
            }
            s if s.starts_with("-config=") => {
                config_path = PathBuf::from(&s["-config=".len()..]);
            }
            // Bool-style flag: bare `-syslog` is `true`. We do NOT consume
            // the next argv token (Go's flag package doesn't either), so
            // `testimonyd -syslog -config foo` correctly parses as two
            // separate flags. `-syslog=false` and friends fall through to
            // the `=value` arm below. (Audit B2.)
            "--syslog" | "-syslog" => {
                // Routing to syslog is wired via systemd's `StandardOutput=`
                // in the unit file; nothing for us to do here.
            }
            s if s.starts_with("--syslog=") || s.starts_with("-syslog=") => {
                // Silently accept an explicit value for Go-flag compat.
            }
            "--help" | "-h" => {
                eprintln!("Usage: testimonyd [--config /etc/testimony.conf]");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    match server::run(&config_path) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            // Use {:#} via Display chain on Source manually since std doesn't
            // give us the chain by default.
            log::error!("testimonyd exiting with error: {e}");
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                log::error!("  caused by: {s}");
                src = s.source();
            }
            std::process::exit(1);
        }
    }
}
