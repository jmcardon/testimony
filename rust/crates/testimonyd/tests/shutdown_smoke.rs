//! Smoke test for the daemon's early-exit cleanup paths.
//!
//! Spawns the testimonyd binary with various pathological configs and
//! verifies the process exits cleanly within a timeout — i.e. that
//! validation failures don't hang the daemon.
//!
//! Linux-only: on non-Linux hosts the binary's main() prints "only runs
//! on Linux" and exits 1 immediately, which would make these tests pass
//! for the wrong reason. Skip there.
//!
//! The "real" cleanup test (random SIGTERM/SIGINT/SIGKILL while clients
//! are mid-request) lives in `rust/tests/random_shutdown.sh` because it
//! requires AF_PACKET (root + Linux). What we can test here is: bad
//! config → fast clean exit, no temp files left behind.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cargo_bin(name: &str) -> std::path::PathBuf {
    // Prefer CARGO_BIN_EXE_<name> when cargo provides it; cargo only sets
    // this for some [[bin]]/test combinations, so we also fall back to
    // walking up from the test binary's path. The test binary lives at
    // `target/<profile>/deps/<test>-<hash>` so the bin we want is at
    // `target/<profile>/<name>`.
    let key = format!("CARGO_BIN_EXE_{name}");
    if let Some(p) = std::env::var_os(&key) {
        return std::path::PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("deps dir");
    let profile_dir = deps.parent().expect("profile dir");
    let candidate = profile_dir.join(name);
    if candidate.exists() {
        return candidate;
    }
    panic!(
        "{key} not set and could not locate {name} via current_exe walk \
         (looked at {})",
        candidate.display()
    );
}

fn write_tmp_config(content: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "testimony_shutdown_smoke_{}_{}.json",
        std::process::id(),
        Instant::now().elapsed().as_nanos(),
    ));
    let mut f = std::fs::File::create(&path).expect("create tmp");
    f.write_all(content.as_bytes()).expect("write tmp");
    path
}

/// Run testimonyd against a given config, with a deadline. Returns the
/// process exit status and a captured stderr tail. Kills the process if
/// it doesn't exit on its own.
fn run_with_deadline(
    config_path: &std::path::Path,
    deadline: Duration,
) -> (Option<std::process::ExitStatus>, String) {
    let mut child = Command::new(cargo_bin("testimonyd"))
        .arg(format!("--config={}", config_path.display()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn testimonyd");

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut err = String::new();
                if let Some(s) = child.stderr.take() {
                    let _ = std::io::Read::read_to_string(&mut std::io::BufReader::new(s), &mut err);
                }
                return (Some(status), err);
            }
            Ok(None) => {
                if start.elapsed() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (None, "(deadline exceeded)".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
}

/// Bad config (zero block size) → daemon exits non-zero quickly.
#[test]
fn invalid_block_size_exits_fast() {
    let cfg = write_tmp_config(
        r#"[{
            "SocketName": "/tmp/_testimony_smoke_bs.sock",
            "Interface": "_dummy_",
            "BlockSize": 0,
            "NumBlocks": 16,
            "BlockTimeoutMillis": 1000,
            "FanoutSize": 1
        }]"#,
    );
    let (status, _err) = run_with_deadline(&cfg, Duration::from_secs(5));
    let _ = std::fs::remove_file(&cfg);
    let s = status.expect("daemon should exit on bad config; deadline hit");
    assert!(!s.success(), "expected non-zero exit; got {s}");
}

/// Empty config array → daemon exits non-zero quickly.
#[test]
fn empty_config_exits_fast() {
    let cfg = write_tmp_config("[]");
    let (status, _err) = run_with_deadline(&cfg, Duration::from_secs(5));
    let _ = std::fs::remove_file(&cfg);
    let s = status.expect("daemon should exit on empty config");
    assert!(!s.success());
}

/// Missing config file → daemon exits non-zero quickly.
#[test]
fn missing_config_exits_fast() {
    let nope = std::path::PathBuf::from("/tmp/_testimony_smoke_does_not_exist.json");
    let _ = std::fs::remove_file(&nope);
    let (status, _err) = run_with_deadline(&nope, Duration::from_secs(5));
    let s = status.expect("daemon should exit when config is missing");
    assert!(!s.success());
}

/// Malformed JSON → daemon exits non-zero quickly.
#[test]
fn malformed_json_exits_fast() {
    let cfg = write_tmp_config("{ this is not json");
    let (status, _err) = run_with_deadline(&cfg, Duration::from_secs(5));
    let _ = std::fs::remove_file(&cfg);
    let s = status.expect("daemon should exit on malformed json");
    assert!(!s.success());
}

/// Duplicate SocketName → daemon exits non-zero with a duplicate-name error.
/// (We can't observe the error message reliably from a piped stderr in all
/// CI environments, so just check exit status.)
#[test]
fn duplicate_socket_name_exits_fast() {
    let cfg = write_tmp_config(
        r#"[
            {
                "SocketName": "/tmp/_testimony_dup.sock",
                "Interface": "_dummy_",
                "BlockSize": 1024,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1
            },
            {
                "SocketName": "/tmp/_testimony_dup.sock",
                "Interface": "_dummy_",
                "BlockSize": 1024,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1
            }
        ]"#,
    );
    let (status, _err) = run_with_deadline(&cfg, Duration::from_secs(5));
    let _ = std::fs::remove_file(&cfg);
    let s = status.expect("daemon should exit on duplicate socket name");
    assert!(!s.success());
}

/// Duplicate explicit FanoutID → daemon exits non-zero.
#[test]
fn duplicate_fanout_id_exits_fast() {
    let cfg = write_tmp_config(
        r#"[
            {
                "SocketName": "/tmp/_testimony_fid_a.sock",
                "Interface": "_dummy_",
                "BlockSize": 1024,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1,
                "FanoutID": 7
            },
            {
                "SocketName": "/tmp/_testimony_fid_b.sock",
                "Interface": "_dummy_",
                "BlockSize": 1024,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1,
                "FanoutID": 7
            }
        ]"#,
    );
    let (status, _err) = run_with_deadline(&cfg, Duration::from_secs(5));
    let _ = std::fs::remove_file(&cfg);
    let s = status.expect("daemon should exit on duplicate fanout id");
    assert!(!s.success());
}
