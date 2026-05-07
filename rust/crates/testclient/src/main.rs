//! testclient: a small consumer of testimonyd for integration testing.
//! Replaces both `go/testclient/testclient.go` and `c/testimony_client.c`.
//! Same flag surface so `integration_test/test.sh` can call it interchangeably.

use std::process::ExitCode;

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("testclient only runs on Linux");
    ExitCode::from(1)
}

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("testclient: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use std::time::Instant;
    use testimony::Conn;

    let mut socket: Option<String> = None;
    let mut fanout: u32 = 0;
    let mut count: i64 = -1;
    let mut dump = false;
    // Perf-friendly mode: suppress per-block stderr lines that would
    // otherwise dominate observable cost at multi-100k blocks/sec, and
    // have the program print one summary line on graceful exit. Used
    // by `rust/tests/perf_c_vs_rust.sh`.
    let mut quiet = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--socket" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err("--socket needs an argument".into());
                };
                socket = Some(v.clone());
            }
            "--fanout" | "--index" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err(format!("{a} needs an argument"));
                };
                fanout = v.parse().map_err(|e| format!("invalid {a}: {e}"))?;
            }
            "--count" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err("--count needs an argument".into());
                };
                count = v.parse().map_err(|e| format!("invalid --count: {e}"))?;
            }
            "--dump" => dump = true,
            "--quiet" => quiet = true,
            "--help" | "-h" => {
                eprintln!(
                    "Usage: testclient --socket PATH [--fanout N] [--count N] [--dump] [--quiet]"
                );
                return Ok(());
            }
            s if s.starts_with("--socket=") => socket = Some(s["--socket=".len()..].into()),
            s if s.starts_with("--fanout=") => {
                fanout = s["--fanout=".len()..]
                    .parse()
                    .map_err(|e| format!("invalid --fanout: {e}"))?;
            }
            s if s.starts_with("--index=") => {
                fanout = s["--index=".len()..]
                    .parse()
                    .map_err(|e| format!("invalid --index: {e}"))?;
            }
            s if s.starts_with("--count=") => {
                count = s["--count=".len()..]
                    .parse()
                    .map_err(|e| format!("invalid --count: {e}"))?;
            }
            other => {
                return Err(format!("unknown arg: {other}"));
            }
        }
        i += 1;
    }

    let Some(socket) = socket else {
        return Err("--socket is required".into());
    };

    // Install a SIGINT/SIGTERM watcher that flips a flag the main loop
    // polls between blocks. On graceful exit (or after `--count` is
    // hit), we print one machine-readable summary line. The perf script
    // uses this instead of stderr-scraping per-block log lines.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = stop.clone();
        // SAFETY: signal-hook installs a safe wrapper; we just flip the flag.
        let mut signals = signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
        ])
        .map_err(|e| format!("signal-hook init: {e}"))?;
        std::thread::spawn(move || {
            if signals.forever().next().is_some() {
                s.store(true, Ordering::SeqCst);
            }
        });
    }

    if !quiet {
        eprintln!("connecting to {socket:?}");
    }
    let mut conn = Conn::connect(&socket).map_err(|e| format!("connect: {e}"))?;
    if !quiet {
        eprintln!("setting fanout to {fanout}");
    }
    conn.init(fanout).map_err(|e| format!("init: {e}"))?;

    if !quiet {
        eprintln!("reading blocks");
    }
    let mut total = 0i64;
    let mut block_num: u64 = 0;
    let start = Instant::now();
    'outer: loop {
        if stop.load(Ordering::Relaxed) {
            break 'outer;
        }
        // Use a short timeout so we observe the stop flag between blocks
        // even when the daemon is idle. 100 ms keeps shutdown latency low
        // without spinning on poll.
        let block = match conn
            .next_block(Some(std::time::Duration::from_millis(100)))
            .map_err(|e| format!("get block: {e}"))?
        {
            Some(b) => b,
            None => continue, // timeout — recheck stop flag
        };
        block_num += 1;
        let mut block_count: i64 = 0;
        let mut hit_zero = false;
        for pkt in block.iter_packets() {
            if count == 0 {
                hit_zero = true;
                break;
            }
            count -= 1;
            if dump {
                let data = pkt.data();
                let mut s = String::with_capacity(data.len() * 2);
                for b in data {
                    use std::fmt::Write as _;
                    let _ = write!(s, "{b:02x}");
                }
                println!("{s}");
            }
            block_count += 1;
            if count == 0 {
                hit_zero = true;
                break;
            }
        }
        block
            .return_block()
            .map_err(|e| format!("return block: {e}"))?;
        total = total.saturating_add(block_count);
        if !quiet {
            eprintln!(
                "block {block_num} had {block_count} packets, {total} total in {:?}",
                start.elapsed()
            );
        }
        if hit_zero {
            break 'outer;
        }
    }

    let elapsed = start.elapsed();
    // Final summary line. Always printed (quiet or not) so the perf
    // harness has a single, easy-to-parse anchor: prefix "TESTCLIENT_RESULT"
    // followed by space-separated key=value pairs.
    eprintln!(
        "TESTCLIENT_RESULT blocks={block_num} packets={total} elapsed_ns={ns} pkt_per_sec={pps:.0}",
        ns = elapsed.as_nanos(),
        pps = total as f64 / elapsed.as_secs_f64().max(1e-9),
    );
    Ok(())
}
