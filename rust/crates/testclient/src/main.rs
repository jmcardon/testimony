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
            "--help" | "-h" => {
                eprintln!("Usage: testclient --socket PATH [--fanout N] [--count N] [--dump]");
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
    eprintln!("connecting to {socket:?}");
    let mut conn = Conn::connect(&socket).map_err(|e| format!("connect: {e}"))?;
    eprintln!("setting fanout to {fanout}");
    conn.init(fanout).map_err(|e| format!("init: {e}"))?;

    eprintln!("reading blocks");
    let mut total = 0i64;
    let mut block_num = 0;
    let start = Instant::now();
    'outer: loop {
        eprintln!("getting block");
        let Some(block) = conn
            .next_block(None)
            .map_err(|e| format!("get block: {e}"))?
        else {
            // Should be impossible with timeout = None, but loop again to be safe.
            continue;
        };
        block_num += 1;
        let mut block_count: i64 = 0;
        let mut hit_zero = false;
        // Iterate packets in a short-lived scope so the iterator borrow ends
        // before we consume `block` with `return_block()`.
        {
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
                        // Writing into a String never errors.
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
        }
        eprintln!("returning block");
        block
            .return_block()
            .map_err(|e| format!("return block: {e}"))?;
        total = total.saturating_add(block_count);
        eprintln!(
            "block {block_num} had {block_count} packets, {total} total in {:?}",
            start.elapsed()
        );
        if hit_zero {
            break 'outer;
        }
    }
    Ok(())
}
