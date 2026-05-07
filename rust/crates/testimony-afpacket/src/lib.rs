//! AF_PACKET TPACKET_V3 ring socket for testimony.
//!
//! Linux-only operationally. The cross-platform pieces (plain-data types,
//! BPF parser, error ADT) live in this top module so their tests run on
//! any host.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Mirrors the kernel `struct sock_filter`: a single BPF instruction.
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub iface: String,
    pub block_size: u32,
    pub num_blocks: u32,
    pub block_timeout_ms: u32,
    pub fanout_id: u16,
    pub fanout_size: u16,
    pub fanout_type: u16,
    pub bpf_filter: Option<Vec<SockFilter>>,
}

/// Structured errors out of this crate. Every libc-touching function
/// surfaces an `AfpacketError` whose Display gives the syscall name, the
/// arguments that mattered, and the underlying `errno` text.
///
/// The variants exist so callers (the daemon's panic-or-log decision, the
/// stats reporter, the dispatcher's "should I trigger global shutdown?"
/// logic) can pattern-match instead of grepping log strings.
#[derive(Debug)]
pub enum AfpacketError {
    /// `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` failed.
    SocketCreate(io::Error),
    /// `setsockopt` failed. `name` is the option name (e.g. "PACKET_VERSION").
    Setsockopt {
        name: &'static str,
        source: io::Error,
    },
    /// `mmap(PACKET_RX_RING)` failed. `len` is the requested length.
    MmapRing { len: usize, source: io::Error },
    /// `bind` to an interface failed.
    Bind {
        iface: String,
        ifindex: u32,
        source: io::Error,
    },
    /// `if_nametoindex` failed (interface not present, etc.).
    InterfaceNotFound { iface: String, source: io::Error },
    /// Interface name contained a NUL.
    InterfaceNameInvalid { iface: String },
    /// `block_size * num_blocks` overflowed `usize`.
    RingSizeOverflow { block_size: u32, num_blocks: u32 },
    /// A BPF program had > 65535 instructions (kernel `sock_fprog.len` is `u16`).
    BpfTooLarge(usize),
    /// `tcpdump -ddd` produced unexpected output.
    BpfCompile {
        iface: String,
        filter: String,
        reason: String,
    },
    /// We tried to compile BPF but couldn't even spawn `tcpdump`.
    BpfCompileSpawn { tcpdump: PathBuf, source: io::Error },
    /// `getsockopt(PACKET_STATISTICS)` failed.
    Stats(io::Error),
    /// `poll` on the AF_PACKET fd failed (other than EINTR).
    Poll(io::Error),
    /// A block index passed in by an internal caller was out of range. The
    /// daemon never produces an invalid index in practice; this exists so
    /// we don't have to use indexing-or-panic in any call path.
    BlockIndexOutOfRange { idx: u32, num_blocks: u32 },
}

impl fmt::Display for AfpacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AfpacketError::SocketCreate(e) => {
                write!(f, "socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) failed: {e}")
            }
            AfpacketError::Setsockopt { name, source } => {
                write!(f, "setsockopt({name}) failed: {source}")
            }
            AfpacketError::MmapRing { len, source } => {
                write!(f, "mmap(PACKET_RX_RING, len={len}) failed: {source}")
            }
            AfpacketError::Bind { iface, ifindex, source } => {
                write!(
                    f,
                    "bind to interface {iface:?} (ifindex={ifindex}) failed: {source}"
                )
            }
            AfpacketError::InterfaceNotFound { iface, source } => {
                write!(f, "if_nametoindex({iface:?}) failed: {source}")
            }
            AfpacketError::InterfaceNameInvalid { iface } => {
                write!(
                    f,
                    "interface name {iface:?} is not a valid C string (contains NUL)"
                )
            }
            AfpacketError::RingSizeOverflow { block_size, num_blocks } => {
                write!(
                    f,
                    "block_size {block_size} * num_blocks {num_blocks} overflows usize \
                     (would request {} bytes)",
                    u128::from(*block_size) * u128::from(*num_blocks)
                )
            }
            AfpacketError::BpfTooLarge(n) => {
                write!(
                    f,
                    "BPF program too large: {n} instructions (max 65535 — kernel \
                     sock_fprog.len is a u16)"
                )
            }
            AfpacketError::BpfCompile { iface, filter, reason } => {
                write!(
                    f,
                    "BPF compile failed for filter {filter:?} on interface {iface:?}: {reason}"
                )
            }
            AfpacketError::BpfCompileSpawn { tcpdump, source } => {
                write!(
                    f,
                    "could not run tcpdump at {} to compile BPF: {source}",
                    tcpdump.display()
                )
            }
            AfpacketError::Stats(e) => {
                write!(f, "getsockopt(PACKET_STATISTICS) failed: {e}")
            }
            AfpacketError::Poll(e) => write!(f, "poll on AF_PACKET fd failed: {e}"),
            AfpacketError::BlockIndexOutOfRange { idx, num_blocks } => {
                write!(
                    f,
                    "block index {idx} out of range (num_blocks={num_blocks})"
                )
            }
        }
    }
}

impl std::error::Error for AfpacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AfpacketError::SocketCreate(e)
            | AfpacketError::Setsockopt { source: e, .. }
            | AfpacketError::MmapRing { source: e, .. }
            | AfpacketError::Bind { source: e, .. }
            | AfpacketError::InterfaceNotFound { source: e, .. }
            | AfpacketError::Stats(e)
            | AfpacketError::Poll(e)
            | AfpacketError::BpfCompileSpawn { source: e, .. } => Some(e),
            AfpacketError::InterfaceNameInvalid { .. }
            | AfpacketError::RingSizeOverflow { .. }
            | AfpacketError::BpfTooLarge(_)
            | AfpacketError::BpfCompile { .. }
            | AfpacketError::BlockIndexOutOfRange { .. } => None,
        }
    }
}

mod bpf;
pub use bpf::parse_tcpdump_ddd;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::*;

/// Off-Linux stubs so `cargo check` / `cargo test` work on dev hosts.
#[cfg(not(target_os = "linux"))]
mod stub {
    use super::AfpacketError;

    pub struct CaptureSocket;

    impl CaptureSocket {
        pub fn new(_: &super::CaptureConfig) -> Result<Self, AfpacketError> {
            Err(AfpacketError::SocketCreate(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "AF_PACKET is Linux-only",
            )))
        }
    }

    pub fn compile_bpf(_iface: &str, _filter: &str) -> Result<Vec<super::SockFilter>, AfpacketError> {
        Err(AfpacketError::BpfCompile {
            iface: _iface.into(),
            filter: _filter.into(),
            reason: "BPF compile is Linux-only".into(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub::*;
