//! Microbenchmark for the buffered-recv hot path.
//!
//! Doesn't use Criterion — we want a single binary that prints a number,
//! suitable for `cargo bench` against `release` and for manual A/B runs.
//!
//! What this measures: the cost of `Conn::recv_exact` (the protocol-side
//! 4-byte read) vs. an unbuffered baseline that issues one `read(2)` per
//! 4 bytes. The harness wires up a `socketpair`, pre-fills the kernel
//! socket buffer with N u32 block indices BEFORE timing, then times only
//! the receiver. That way producer cost is paid up front and we measure
//! pure receiver overhead.
//!
//! Compile and run:
//!   cargo build --release -p testimony-client --benches
//!   ./target/release/deps/recv_throughput-XXXX
//!
//! The harness is Linux-only because it pokes `libc::recv` directly and
//! uses `SO_RCVBUF` / `SO_SNDBUF` tunables that aren't portable.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

/// Per-run iteration count. Big enough to amortise icache warmup but
/// small enough that 4 × N bytes (the per-run wire footprint) fits in a
/// generous SO_RCVBUF without the producer ever blocking. We bump
/// SO_RCVBUF to 32 MB; 4 × 2M = 8 MB fits with headroom.
const N: usize = 2_000_000;
const WARMUP: usize = 100_000;
const RECV_BUF_SIZE: usize = 256;

/// Buffered receiver — same shape as `Conn::recv_exact`. One `recv(2)`
/// fills 256 bytes; subsequent 4-byte reads come "free" from the buffer.
struct Buffered {
    fd: i32,
    buf: [u8; RECV_BUF_SIZE],
    start: u16,
    limit: u16,
    syscalls: u64,
}

impl Buffered {
    fn new(fd: i32) -> Self {
        Self {
            fd,
            buf: [0u8; RECV_BUF_SIZE],
            start: 0,
            limit: 0,
            syscalls: 0,
        }
    }
    #[inline]
    fn read_u32_be(&mut self) -> u32 {
        let mut out = [0u8; 4];
        let mut written = 0;
        while written < 4 {
            let avail = (self.limit - self.start) as usize;
            if avail > 0 {
                let n = avail.min(4 - written);
                out[written..written + n]
                    .copy_from_slice(&self.buf[self.start as usize..self.start as usize + n]);
                self.start += n as u16;
                written += n;
                continue;
            }
            self.syscalls += 1;
            // SAFETY: buf is a valid array; cap = its length.
            let r = unsafe {
                libc::recv(self.fd, self.buf.as_mut_ptr().cast(), RECV_BUF_SIZE, 0)
            };
            assert!(r > 0, "recv: {}", std::io::Error::last_os_error());
            self.start = 0;
            self.limit = r as u16;
        }
        u32::from_be_bytes(out)
    }
}

/// Unbuffered receiver — one `recv(2)` per 4 bytes. This is what the
/// pre-buffering Rust port did.
struct Unbuffered {
    fd: i32,
    syscalls: u64,
}

impl Unbuffered {
    fn new(fd: i32) -> Self {
        Self { fd, syscalls: 0 }
    }
    #[inline]
    fn read_u32_be(&mut self) -> u32 {
        let mut out = [0u8; 4];
        let mut written = 0;
        while written < 4 {
            self.syscalls += 1;
            // SAFETY: out is a valid array; cap = remaining bytes.
            let r = unsafe {
                libc::recv(
                    self.fd,
                    out.as_mut_ptr().add(written).cast(),
                    4 - written,
                    0,
                )
            };
            assert!(r > 0, "recv: {}", std::io::Error::last_os_error());
            written += r as usize;
        }
        u32::from_be_bytes(out)
    }
}

/// Bump the unix-socket recv buffer so the producer can dump all N u32s
/// in one shot without blocking. 32 MB is well above 4 × 2M = 8 MB.
fn set_rcvbuf(fd: i32, want: i32) {
    // SAFETY: setsockopt with valid fd + matching arg type.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&want as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    // Best-effort: kernel may clamp, returns 0 even if it clamped. If
    // setsockopt errors we just print and continue — producer will block
    // when the socket buffer fills, which slows but doesn't break the
    // benchmark.
    if r < 0 {
        eprintln!(
            "warning: SO_RCVBUF={want} setsockopt failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Pre-fill the unix socket with `count` BE-encoded u32s, then drop the
/// producer so the receiver can drain at full speed. Returns the consumer
/// end. Producer cost is NOT included in any subsequent timing.
fn prefill(count: usize) -> UnixStream {
    let (mut producer, consumer) = UnixStream::pair().expect("pair");
    set_rcvbuf(consumer.as_raw_fd(), 32 * 1024 * 1024);
    // Build one big buffer in memory, write it in one syscall (or as
    // many as the kernel needs). All-at-once avoids the per-chunk
    // overhead we don't care about.
    let mut buf: Vec<u8> = Vec::with_capacity(count * 4);
    for i in 0..count {
        buf.extend_from_slice(&((i as u32) & 0x7FFF_FFFF).to_be_bytes());
    }
    producer.write_all(&buf).expect("prefill write");
    drop(producer);
    consumer
}

fn main() {
    eprintln!("recv_throughput: N={N} block-index reads per pass, WARMUP={WARMUP}\n");

    // Run each variant in this order; report wall time + syscall ratio.
    // We do warmup first so the receive-side icache is hot before the
    // timed loop. Producer cost is paid up front via `prefill`.

    {
        let consumer = prefill(WARMUP + N);
        let fd = consumer.as_raw_fd();
        let mut r = Unbuffered::new(fd);
        // Warmup.
        for _ in 0..WARMUP {
            let _ = r.read_u32_be();
        }
        // Reset syscall counter so the printed number is purely the timed loop.
        r.syscalls = 0;
        let start = Instant::now();
        let mut sum: u64 = 0;
        for _ in 0..N {
            sum = sum.wrapping_add(r.read_u32_be() as u64);
        }
        let elapsed = start.elapsed();
        eprintln!(
            "[unbuffered] {N} ops in {elapsed:?} = {rate:.0} ops/sec; {syscalls} syscalls (avg {ops_per:.2} ops/syscall); checksum={sum:x}",
            rate = (N as f64) / elapsed.as_secs_f64(),
            syscalls = r.syscalls,
            ops_per = N as f64 / r.syscalls.max(1) as f64,
        );
    }

    {
        let consumer = prefill(WARMUP + N);
        let fd = consumer.as_raw_fd();
        let mut r = Buffered::new(fd);
        for _ in 0..WARMUP {
            let _ = r.read_u32_be();
        }
        r.syscalls = 0;
        let start = Instant::now();
        let mut sum: u64 = 0;
        for _ in 0..N {
            sum = sum.wrapping_add(r.read_u32_be() as u64);
        }
        let elapsed = start.elapsed();
        eprintln!(
            "[buffered]   {N} ops in {elapsed:?} = {rate:.0} ops/sec; {syscalls} syscalls (avg {ops_per:.2} ops/syscall); checksum={sum:x}",
            rate = (N as f64) / elapsed.as_secs_f64(),
            syscalls = r.syscalls,
            ops_per = N as f64 / r.syscalls.max(1) as f64,
        );
    }
}
