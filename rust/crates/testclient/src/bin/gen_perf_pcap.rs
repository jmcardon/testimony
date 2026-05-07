//! Synthesise a large pcap for the perf comparison.
//!
//! The repo's `test.pcap` is 10 packets × 116 bytes = ~1 KB, designed
//! for byte-exact golden-output verification. That's useless for
//! throughput testing because tcpreplay finishes in microseconds.
//!
//! This tool emits a deterministic pcap with `--count` packets of size
//! `--size` bytes (default 1 MB total at 100k packets × 100 bytes), with
//! varying source/destination IPs so a BPF filter can be exercised
//! without dropping every frame.
//!
//! Output: libpcap format, little-endian, microsecond timestamps,
//! LINKTYPE_ETHERNET. Reproducible — uses an LCG seeded from a constant,
//! so two runs produce the same bytes.
//!
//! Usage:
//!   cargo run --release --bin gen_perf_pcap -- \
//!     --count 100000 --size 100 --out /tmp/perf.pcap
//!
//! Linked into the perf test image at /work/tests/perf.pcap.

use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::process::ExitCode;

const PCAP_MAGIC: u32 = 0xa1b2_c3d4; // microsecond timestamps, little-endian
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const LINKTYPE_ETHERNET: u32 = 1;

/// Minimum on-the-wire Ethernet frame: 14-byte L2 + 46-byte payload = 60.
/// We pick payloads ≥ 64 so every packet looks like a valid frame to
/// AF_PACKET. (The kernel doesn't care what we put on a `dummy`
/// interface, but staying realistic future-proofs against running this
/// against a real NIC.)
const MIN_PACKET: usize = 64;
const MAX_PACKET: usize = 1500;

fn write_u32_le<W: Write>(w: &mut W, v: u32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_u16_le<W: Write>(w: &mut W, v: u16) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}
fn write_i32_le<W: Write>(w: &mut W, v: i32) -> std::io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn write_pcap_header<W: Write>(w: &mut W, snaplen: u32) -> std::io::Result<()> {
    write_u32_le(w, PCAP_MAGIC)?;
    write_u16_le(w, PCAP_VERSION_MAJOR)?;
    write_u16_le(w, PCAP_VERSION_MINOR)?;
    write_i32_le(w, 0)?; // thiszone
    write_u32_le(w, 0)?; // sigfigs
    write_u32_le(w, snaplen)?;
    write_u32_le(w, LINKTYPE_ETHERNET)?;
    Ok(())
}

fn write_packet<W: Write>(
    w: &mut W,
    ts_sec: u32,
    ts_usec: u32,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).expect("payload len fits in u32");
    write_u32_le(w, ts_sec)?;
    write_u32_le(w, ts_usec)?;
    write_u32_le(w, len)?; // incl_len
    write_u32_le(w, len)?; // orig_len (no truncation)
    w.write_all(payload)
}

/// Build one Ethernet/IPv4/UDP-shaped frame. Source/dest MAC and IP are
/// derived from the packet index so a BPF filter on (say) host
/// 10.0.0.1 still gets a meaningful match rate. The L4 payload is
/// incompressible-ish (LCG output) so realistic CPU is spent in any
/// hashing / checksum the receiver might do.
fn build_frame(index: u64, size: usize, scratch: &mut Vec<u8>) {
    scratch.clear();
    scratch.resize(size, 0);

    // Dest MAC: 02:00:00:00:00:01 (locally-administered, unicast).
    scratch[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // Source MAC: 02:00:00:00:00:02.
    scratch[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    // EtherType: IPv4 (0x0800).
    scratch[12..14].copy_from_slice(&[0x08, 0x00]);

    // IPv4 header (20 bytes, no options).
    let total_len = (size - 14) as u16; // L3+ length
    scratch[14] = 0x45; // version=4, IHL=5
    scratch[15] = 0x00; // DSCP/ECN
    scratch[16..18].copy_from_slice(&total_len.to_be_bytes());
    let id = (index as u16).to_be_bytes();
    scratch[18..20].copy_from_slice(&id);
    scratch[20..22].copy_from_slice(&[0x00, 0x00]); // flags+fragoff
    scratch[22] = 64; // TTL
    scratch[23] = 17; // protocol = UDP
    scratch[24..26].copy_from_slice(&[0x00, 0x00]); // checksum (not validated here)
    // Source IP: 10.0.0.{1..254} chosen by index so a `host 10.0.0.1`
    // filter matches ~1/254 of packets — enough to see filtered traffic
    // but still mostly-noise to stress the kernel's BPF eval cost.
    scratch[26..30].copy_from_slice(&[10, 0, 0, ((index % 254) as u8) + 1]);
    // Dest IP: 10.0.0.255 (broadcast-shaped — every packet has the same dst).
    scratch[30..34].copy_from_slice(&[10, 0, 0, 255]);

    // UDP header (8 bytes).
    let udp_len = (size - 14 - 20) as u16;
    scratch[34..36].copy_from_slice(&((index as u16).wrapping_add(40000)).to_be_bytes()); // sport
    scratch[36..38].copy_from_slice(&9999u16.to_be_bytes()); // dport
    scratch[38..40].copy_from_slice(&udp_len.to_be_bytes());
    scratch[40..42].copy_from_slice(&[0x00, 0x00]); // checksum

    // L7 payload: deterministic pseudo-random bytes via xorshift seeded
    // by the index. Avoids degenerate all-zeros which the kernel might
    // optimise oddly.
    let mut s: u64 = index.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    for byte in scratch.iter_mut().skip(42) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *byte = (s & 0xFF) as u8;
    }
}

fn parse_args() -> Result<(usize, usize, String), String> {
    let mut count: usize = 100_000;
    let mut size: usize = 100;
    let mut out: Option<String> = None;

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--count" => {
                i += 1;
                count = args
                    .get(i)
                    .ok_or_else(|| "--count needs a value".to_string())?
                    .parse()
                    .map_err(|e| format!("invalid --count: {e}"))?;
            }
            "--size" => {
                i += 1;
                size = args
                    .get(i)
                    .ok_or_else(|| "--size needs a value".to_string())?
                    .parse()
                    .map_err(|e| format!("invalid --size: {e}"))?;
            }
            "--out" => {
                i += 1;
                out = Some(
                    args.get(i)
                        .ok_or_else(|| "--out needs a value".to_string())?
                        .clone(),
                );
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: gen_perf_pcap --count N --size BYTES --out PATH\n\
                     \n\
                     Synthesise a deterministic pcap for throughput testing.\n\
                     \n\
                     Defaults:\n  \
                       --count {count} (number of packets)\n  \
                       --size  {size}  (bytes per frame, must be {MIN_PACKET}..={MAX_PACKET})"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
        i += 1;
    }

    let out = out.ok_or_else(|| "--out is required".to_string())?;
    if !(MIN_PACKET..=MAX_PACKET).contains(&size) {
        return Err(format!("--size must be in {MIN_PACKET}..={MAX_PACKET}"));
    }
    Ok((count, size, out))
}

fn main() -> ExitCode {
    let (count, size, out_path) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let f = match File::create(&out_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: cannot create {out_path}: {e}");
            return ExitCode::from(1);
        }
    };
    let mut w = BufWriter::with_capacity(1 << 20, f);

    if let Err(e) = write_pcap_header(&mut w, MAX_PACKET as u32) {
        eprintln!("error writing header: {e}");
        return ExitCode::from(1);
    }

    let mut frame = Vec::with_capacity(size);
    let base_sec: u32 = 1_700_000_000; // 2023-11-14ish; deterministic
    for i in 0..count {
        // 1 microsecond per packet → tcpreplay --topspeed will pace from
        // the captured timestamps anyway, so spacing here doesn't affect
        // the perf measurement (we override with --topspeed).
        let ts_sec = base_sec + (i / 1_000_000) as u32;
        let ts_usec = (i % 1_000_000) as u32;
        build_frame(i as u64, size, &mut frame);
        if let Err(e) = write_packet(&mut w, ts_sec, ts_usec, &frame) {
            eprintln!("error writing packet {i}: {e}");
            return ExitCode::from(1);
        }
    }

    if let Err(e) = w.flush() {
        eprintln!("error flushing: {e}");
        return ExitCode::from(1);
    }
    eprintln!(
        "wrote {count} packets × {size} bytes = {} MB to {out_path}",
        (count * (size + 16)) / (1024 * 1024)
    );
    ExitCode::SUCCESS
}
