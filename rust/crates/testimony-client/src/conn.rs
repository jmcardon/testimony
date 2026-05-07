//! Native Rust client API mirroring `go/testimony/testimony.go`.
//!
//! Errors are typed (`Error` enum below). Every libc call surfaces a
//! variant that names the syscall and any structured arguments — operators
//! get one log line that says exactly what failed and why.

use std::fmt;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use testimony_protocol::{
    self as proto, Category, PROTOCOL_VERSION, TYPE_BLOCK_INDEX, TYPE_BLOCK_SIZE,
    TYPE_FANOUT_INDEX, TYPE_FANOUT_SIZE, TYPE_NUM_BLOCKS, TYPE_WAITING_FOR_FANOUT_INDEX,
};

/// Stage labels used in the `Handshake*` error variants. Pure cosmetic
/// strings carried with the error so the message says *which step* tripped.
pub const STAGE_VERSION: &str = "version byte";
pub const STAGE_TLV_HEADER: &str = "TLV header";
pub const STAGE_TLV_VALUE: &str = "TLV value";
pub const STAGE_FANOUT_INDEX: &str = "fanout-index TLV";
pub const STAGE_RECV_FD: &str = "fd-passing recvmsg";
pub const STAGE_BLOCK_INDEX: &str = "block-index";

#[derive(Debug)]
pub enum Error {
    /// `connect(AF_UNIX)` failed.
    Connect { path: PathBuf, source: io::Error },
    /// Socket name had a NUL byte (can't form a CString).
    InvalidSocketName(String),
    /// Read on the unix socket failed at a specific handshake stage.
    Read {
        stage: &'static str,
        source: io::Error,
    },
    /// Write on the unix socket failed.
    Write {
        stage: &'static str,
        source: io::Error,
    },
    /// Peer closed the unix socket while we were mid-read.
    PeerClosed { stage: &'static str },
    /// Server announced a different protocol version.
    UnexpectedVersion { got: u8, want: u8 },
    /// Server sent a TLV whose category isn't ServerToClient.
    UnexpectedTlvCategory { typ: u16, length: u16 },
    /// Server sent a known TLV with a length we can't interpret.
    UnexpectedTlvLength {
        typ: u16,
        got_length: u16,
        want_length: u16,
    },
    /// Handshake completed without one of the required TLVs.
    MissingHandshakeFields {
        fanout_size: u32,
        block_size: u32,
        num_blocks: u32,
    },
    /// Server sent a block index out of range.
    BlockIndexOutOfRange { idx: u32, num_blocks: u32 },
    /// `mmap` of the AF_PACKET ring failed.
    Mmap { len: usize, source: io::Error },
    /// `block_size * num_blocks` overflowed `usize`.
    RingSizeOverflow { block_size: u32, num_blocks: u32 },
    /// `poll` on the unix socket failed.
    Poll(io::Error),
    /// `recvmsg` for the AF_PACKET fd failed.
    RecvFd(io::Error),
    /// `recvmsg` succeeded but didn't include the SCM_RIGHTS payload.
    NoFdInCmsg,
    /// `recvmsg` returned an unexpected number of payload bytes.
    RecvFdBytes { got: isize, want: usize },
    /// `init()` called twice on the same Conn.
    AlreadyInitialized,
    /// `next_block` / `return_block` called before `init()`.
    NotInitialized,
    /// `next_block` returned `Ok(None)` because of timeout.
    Timeout,
    /// Caller-side bookkeeping detected a state we shouldn't reach.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Connect { path, source } => {
                write!(f, "connect to {} failed: {source}", path.display())
            }
            Error::InvalidSocketName(s) => {
                write!(f, "socket name {s:?} contains a NUL byte")
            }
            Error::Read { stage, source } => write!(f, "read of {stage} failed: {source}"),
            Error::Write { stage, source } => write!(f, "write of {stage} failed: {source}"),
            Error::PeerClosed { stage } => {
                write!(f, "server closed the connection while reading {stage}")
            }
            Error::UnexpectedVersion { got, want } => {
                write!(f, "server announced protocol version {got}, expected {want}")
            }
            Error::UnexpectedTlvCategory { typ, length } => write!(
                f,
                "received TLV with type {typ:#06x} (length {length}); not a ServerToClient type"
            ),
            Error::UnexpectedTlvLength { typ, got_length, want_length } => write!(
                f,
                "TLV type {typ:#06x} had length {got_length}, expected {want_length}"
            ),
            Error::MissingHandshakeFields { fanout_size, block_size, num_blocks } => write!(
                f,
                "handshake incomplete: fanout_size={fanout_size}, block_size={block_size}, \
                 num_blocks={num_blocks} (all must be > 0)"
            ),
            Error::BlockIndexOutOfRange { idx, num_blocks } => {
                write!(f, "server sent block index {idx}, valid range is [0, {num_blocks})")
            }
            Error::Mmap { len, source } => {
                write!(f, "mmap of AF_PACKET ring (len={len}) failed: {source}")
            }
            Error::RingSizeOverflow { block_size, num_blocks } => write!(
                f,
                "block_size {block_size} * num_blocks {num_blocks} overflows usize"
            ),
            Error::Poll(e) => write!(f, "poll on unix socket failed: {e}"),
            Error::RecvFd(e) => write!(f, "recvmsg(SCM_RIGHTS) failed: {e}"),
            Error::NoFdInCmsg => {
                write!(f, "recvmsg succeeded but the cmsg payload had no SCM_RIGHTS fd")
            }
            Error::RecvFdBytes { got, want } => write!(
                f,
                "recvmsg(SCM_RIGHTS) returned {got} bytes, expected exactly {want}"
            ),
            Error::AlreadyInitialized => {
                write!(f, "testimony_init: connection already initialized")
            }
            Error::NotInitialized => write!(f, "testimony connection not initialized; call init() first"),
            Error::Timeout => write!(f, "operation timed out"),
            Error::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Connect { source, .. }
            | Error::Read { source, .. }
            | Error::Write { source, .. }
            | Error::Mmap { source, .. } => Some(source),
            Error::Poll(e) | Error::RecvFd(e) => Some(e),
            _ => None,
        }
    }
}

/// Holds the live AF_PACKET ring + fd + per-block packet counters. The
/// counters are managed by the caller — both the native `Block` wrapper
/// and the FFI's `testimony_return_packets` reach in via accessors. There
/// is no internal "expected zero" sanity check that a forgotten Block
/// could leave poisoned (see B1 in the audit history).
pub struct Conn {
    sock: UnixStream,
    fanout_size: u32,
    block_size: u32,
    num_blocks: u32,
    /// AF_PACKET fd received from server. Owned so we close on Drop.
    pkt_fd: Option<OwnedFd>,
    ring_ptr: *mut u8,
    ring_len: usize,
}

// Conn owns its own resources; the *mut u8 is to a shared mmap which is
// safe to read concurrently.
unsafe impl Send for Conn {}

impl Conn {
    pub fn fanout_size(&self) -> u32 {
        self.fanout_size
    }
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
    pub fn num_blocks(&self) -> u32 {
        self.num_blocks
    }

    /// Two-phase: `connect` does the handshake up to "WaitingForFanoutIndex";
    /// then `init(fanout_index)` sends the index and receives the fd.
    pub fn connect(socket_name: &str) -> Result<Self, Error> {
        let path = PathBuf::from(socket_name);
        // Refuse NUL early so error messages are obvious.
        if socket_name.as_bytes().contains(&0) {
            return Err(Error::InvalidSocketName(socket_name.to_owned()));
        }
        let mut s = UnixStream::connect(&path).map_err(|source| Error::Connect {
            path: path.clone(),
            source,
        })?;
        // Read 1-byte version.
        let mut v = [0u8; 1];
        read_full(&mut s, &mut v, STAGE_VERSION)?;
        if v[0] != PROTOCOL_VERSION {
            return Err(Error::UnexpectedVersion {
                got: v[0],
                want: PROTOCOL_VERSION,
            });
        }
        let mut conn = Conn {
            sock: s,
            fanout_size: 0,
            block_size: 0,
            num_blocks: 0,
            pkt_fd: None,
            ring_ptr: ptr::null_mut(),
            ring_len: 0,
        };
        // Read TLVs until WaitingForFanoutIndex.
        loop {
            let mut hdr = [0u8; 4];
            read_full(&mut conn.sock, &mut hdr, STAGE_TLV_HEADER)?;
            let raw = u32::from_be_bytes(hdr);
            let (typ, length) = proto::tl_from(raw);
            if proto::category_of(typ) != Category::ServerToClient {
                return Err(Error::UnexpectedTlvCategory { typ, length });
            }
            if typ == TYPE_WAITING_FOR_FANOUT_INDEX && length == 0 {
                break;
            }
            // Read value.
            let mut val = vec![0u8; length as usize];
            read_full(&mut conn.sock, &mut val, STAGE_TLV_VALUE)?;
            match typ {
                TYPE_FANOUT_SIZE => {
                    conn.fanout_size = parse_u32_strict(typ, &val)?;
                }
                TYPE_BLOCK_SIZE => {
                    conn.block_size = parse_u32_strict(typ, &val)?;
                }
                TYPE_NUM_BLOCKS => {
                    conn.num_blocks = parse_u32_strict(typ, &val)?;
                }
                _ => {
                    // ignore unknown TLVs by design; matches Go/C clients.
                }
            }
        }
        if conn.fanout_size == 0 || conn.block_size == 0 || conn.num_blocks == 0 {
            return Err(Error::MissingHandshakeFields {
                fanout_size: conn.fanout_size,
                block_size: conn.block_size,
                num_blocks: conn.num_blocks,
            });
        }
        Ok(conn)
    }

    pub fn init(&mut self, fanout_index: u32) -> Result<(), Error> {
        // Match the C client (`testimony.c::testimony_init`): refuse a
        // double-init rather than leak the previous mmap.
        if !self.ring_ptr.is_null() {
            return Err(Error::AlreadyInitialized);
        }
        // Send fanout-index TLV.
        let mut hdr = [0u8; 8];
        let tl = proto::to_tl(TYPE_FANOUT_INDEX, 4).to_be_bytes();
        let val = fanout_index.to_be_bytes();
        // Use copy_from_slice on fixed slices: never panics for matching lengths.
        hdr[..4].copy_from_slice(&tl);
        hdr[4..].copy_from_slice(&val);
        write_full(&mut self.sock, &hdr, STAGE_FANOUT_INDEX)?;

        // Receive fd via SCM_RIGHTS.
        let fd = recv_fd(&self.sock)?;
        // SAFETY: fd is a freshly received owned descriptor.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        // mmap it. Use checked multiplication: a hostile or buggy server
        // sending huge block_size/num_blocks could otherwise wrap to a
        // small allocation that we later index past.
        let Some(len) = (self.block_size as usize).checked_mul(self.num_blocks as usize) else {
            return Err(Error::RingSizeOverflow {
                block_size: self.block_size,
                num_blocks: self.num_blocks,
            });
        };
        // SAFETY: arguments are valid; PROT_READ since clients only read.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED | libc::MAP_NORESERVE,
                owned.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Error::Mmap {
                len,
                source: io::Error::last_os_error(),
            });
        }
        self.pkt_fd = Some(owned);
        self.ring_ptr = p.cast();
        self.ring_len = len;
        Ok(())
    }

    /// Wait up to `timeout` for the next block. Pass `None` to block forever,
    /// `Some(Duration::ZERO)` for non-blocking.
    pub fn next_block(&mut self, timeout: Option<Duration>) -> Result<Option<Block<'_>>, Error> {
        if self.ring_ptr.is_null() {
            return Err(Error::NotInitialized);
        }
        loop {
            if let Some(t) = timeout {
                let ms: i32 = if t == Duration::ZERO {
                    0
                } else {
                    t.as_millis().min(i32::MAX as u128) as i32
                };
                let mut pfd = libc::pollfd {
                    fd: self.sock.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: pfd is a valid &mut.
                let r = unsafe { libc::poll(&mut pfd, 1, ms) };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(Error::Poll(e));
                }
                if r == 0 {
                    return Ok(None);
                }
            }
            let mut hdr = [0u8; 4];
            read_full(&mut self.sock, &mut hdr, STAGE_BLOCK_INDEX)?;
            let raw = u32::from_be_bytes(hdr);
            let (typ, length) = proto::tl_from(raw);
            if typ == TYPE_BLOCK_INDEX {
                let i = raw;
                if i >= self.num_blocks {
                    return Err(Error::BlockIndexOutOfRange {
                        idx: i,
                        num_blocks: self.num_blocks,
                    });
                }
                // SAFETY: bounds checked above; ring_len = block_size * num_blocks.
                let bptr = unsafe {
                    self.ring_ptr
                        .add((i as usize) * (self.block_size as usize))
                };
                return Ok(Some(Block {
                    conn: self,
                    index: i,
                    ptr: bptr,
                    returned: false,
                }));
            }
            // Non-block-index header: must be a server-to-client TLV.
            if proto::category_of(typ) != Category::ServerToClient {
                return Err(Error::UnexpectedTlvCategory { typ, length });
            }
            // Drain TLV payload.
            let mut val = vec![0u8; length as usize];
            read_full(&mut self.sock, &mut val, STAGE_TLV_VALUE)?;
        }
    }

    fn return_block_index(&mut self, idx: u32) -> Result<(), Error> {
        write_full(&mut self.sock, &idx.to_be_bytes(), STAGE_BLOCK_INDEX)?;
        Ok(())
    }

    /// Public-to-this-crate accessor for the FFI shim.
    #[doc(hidden)]
    pub fn return_block_index_pub(&mut self, idx: u32) -> Result<(), Error> {
        self.return_block_index(idx)
    }

    /// Public-to-this-crate accessor for the FFI shim.
    #[doc(hidden)]
    pub fn ring_base_for_ffi(&self) -> *const u8 {
        self.ring_ptr
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if !self.ring_ptr.is_null() && self.ring_len > 0 {
            // SAFETY: ptr/len returned by a successful mmap call we own.
            let r = unsafe { libc::munmap(self.ring_ptr.cast(), self.ring_len) };
            if r != 0 {
                let e = io::Error::last_os_error();
                eprintln!(
                    "testimony-client: munmap(ptr={:p}, len={}) failed during Drop: {e}",
                    self.ring_ptr, self.ring_len
                );
            }
            self.ring_ptr = ptr::null_mut();
            self.ring_len = 0;
        }
        // OwnedFd and UnixStream close themselves.
    }
}

pub struct Block<'c> {
    conn: &'c mut Conn,
    index: u32,
    ptr: *mut u8,
    /// Set true once the block has been explicitly returned so Drop is a no-op.
    returned: bool,
}

impl<'c> Block<'c> {
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn raw_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn block_size(&self) -> u32 {
        self.conn.block_size
    }
    /// Number of packets in this block, read from the kernel-provided header.
    pub fn num_pkts(&self) -> u32 {
        // SAFETY: ptr is a valid in-range block pointer for the lifetime of `self`.
        unsafe { read_block_num_pkts(self.ptr) }
    }
    pub fn offset_to_first_pkt(&self) -> u32 {
        // SAFETY: same as num_pkts.
        unsafe { read_block_offset_first(self.ptr) }
    }
    /// Return the block to the server. Consumes the block.
    pub fn return_block(mut self) -> Result<(), Error> {
        let idx = self.index;
        self.returned = true;
        self.conn.return_block_index(idx)
    }
    /// Iterate through packets in TPACKET_V3 order.
    pub fn iter_packets(&self) -> PacketIter<'_> {
        PacketIter {
            ptr_block_start: self.ptr,
            current: ptr::null(),
            left: self.num_pkts(),
            offset_first: self.offset_to_first_pkt(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'c> Drop for Block<'c> {
    fn drop(&mut self) {
        if !self.returned {
            // Best-effort return so the kernel block isn't leaked. If the
            // socket is already dead this fails silently — there's nowhere
            // useful to surface the error from a Drop.
            let _ = self.conn.return_block_index(self.index);
        }
    }
}

pub struct PacketIter<'b> {
    ptr_block_start: *const u8,
    current: *const u8,
    /// Remaining packets. Use `u32` rather than `i32` so we never have to
    /// reason about negative-on-overflow behavior.
    left: u32,
    offset_first: u32,
    _phantom: std::marker::PhantomData<&'b [u8]>,
}

impl<'b> Iterator for PacketIter<'b> {
    type Item = Packet<'b>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        if self.current.is_null() {
            // SAFETY: offset_first comes from the kernel-populated block header.
            self.current = unsafe { self.ptr_block_start.add(self.offset_first as usize) };
        } else {
            // Read tp_next_offset (the first u32 of tpacket3_hdr) without
            // requiring the pointer to be aligned.
            // SAFETY: current points inside the mapped block.
            let next_off = unsafe { ptr::read_unaligned(self.current as *const u32) };
            // SAFETY: same; if the kernel populated a bogus next_off the
            // pointer will run off the block, but the iter is bounded by `left`.
            self.current = unsafe { self.current.add(next_off as usize) };
        }
        Some(Packet {
            ptr: self.current,
            _phantom: std::marker::PhantomData,
        })
    }
}

pub struct Packet<'b> {
    ptr: *const u8,
    _phantom: std::marker::PhantomData<&'b [u8]>,
}

/// Field offsets inside `struct tpacket3_hdr` (linux/if_packet.h):
/// tp_next_offset(u32) tp_sec(u32) tp_nsec(u32) tp_snaplen(u32) tp_len(u32)
/// tp_status(u32) tp_mac(u16) tp_net(u16) ...
const TP_SEC_OFF: usize = 4;
const TP_NSEC_OFF: usize = 8;
const TP_SNAPLEN_OFF: usize = 12;
const TP_LEN_OFF: usize = 16;
const TP_MAC_OFF: usize = 4 * 6; // 24

#[inline]
unsafe fn read_u32_at(ptr: *const u8, off: usize) -> u32 {
    ptr::read_unaligned(ptr.add(off) as *const u32)
}
#[inline]
unsafe fn read_u16_at(ptr: *const u8, off: usize) -> u16 {
    ptr::read_unaligned(ptr.add(off) as *const u16)
}

impl<'b> Packet<'b> {
    pub fn raw_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn snaplen(&self) -> u32 {
        // SAFETY: ptr lives in the block; offsets are inside tpacket3_hdr.
        unsafe { read_u32_at(self.ptr, TP_SNAPLEN_OFF) }
    }
    pub fn original_len(&self) -> u32 {
        unsafe { read_u32_at(self.ptr, TP_LEN_OFF) }
    }
    pub fn nanos(&self) -> i64 {
        // SAFETY: ptr lives in the block.
        unsafe {
            let sec = read_u32_at(self.ptr, TP_SEC_OFF);
            let nsec = read_u32_at(self.ptr, TP_NSEC_OFF);
            (sec as i64) * 1_000_000_000 + (nsec as i64)
        }
    }
    pub fn data(&self) -> &'b [u8] {
        // SAFETY: tp_mac and snaplen are populated by the kernel.
        unsafe {
            let tp_mac = read_u16_at(self.ptr, TP_MAC_OFF);
            let snaplen = read_u32_at(self.ptr, TP_SNAPLEN_OFF);
            let start = self.ptr.add(tp_mac as usize);
            std::slice::from_raw_parts(start, snaplen as usize)
        }
    }
}

// --- block-header helpers ---

unsafe fn read_block_num_pkts(block_ptr: *const u8) -> u32 {
    // tpacket_block_desc layout: version(u32), offset_to_priv(u32), then
    // tpacket_hdr_v1: block_status(u32), num_pkts(u32), offset_to_first_pkt(u32) ...
    let p = block_ptr.add(8 + 4) as *const u32; // skip version+offset_to_priv+block_status
    ptr::read_unaligned(p)
}

unsafe fn read_block_offset_first(block_ptr: *const u8) -> u32 {
    let p = block_ptr.add(8 + 4 + 4) as *const u32;
    ptr::read_unaligned(p)
}

// --- low-level io helpers ---

/// Strict u32 parse from a TLV value, surfacing a typed error if the
/// length doesn't match.
fn parse_u32_strict(typ: u16, val: &[u8]) -> Result<u32, Error> {
    if val.len() != 4 {
        return Err(Error::UnexpectedTlvLength {
            typ,
            got_length: val.len() as u16,
            want_length: 4,
        });
    }
    // val.len() == 4, so the four indices below are in bounds. We use
    // try_into to avoid even the appearance of an indexing panic vector.
    let arr: [u8; 4] = match val.try_into() {
        Ok(a) => a,
        Err(_) => {
            return Err(Error::Internal(
                "TLV value len-check passed but try_into failed".into(),
            ))
        }
    };
    Ok(u32::from_be_bytes(arr))
}

fn read_full(s: &mut UnixStream, buf: &mut [u8], stage: &'static str) -> Result<(), Error> {
    use std::io::Read;
    let mut read = 0;
    while read < buf.len() {
        // Indexing here is the conventional `&mut buf[read..]` slice; `read`
        // is bounded by `buf.len()` so this never panics.
        let dst = match buf.get_mut(read..) {
            Some(d) => d,
            None => {
                return Err(Error::Internal(format!(
                    "read_full: buf.get_mut({read}..) returned None on len={}",
                    buf.len()
                )))
            }
        };
        match s.read(dst) {
            Ok(0) => return Err(Error::PeerClosed { stage }),
            Ok(n) => read += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => return Err(Error::Read { stage, source }),
        }
    }
    Ok(())
}

fn write_full(s: &mut UnixStream, buf: &[u8], stage: &'static str) -> Result<(), Error> {
    use std::io::Write;
    s.write_all(buf).map_err(|source| Error::Write { stage, source })
}

/// Receive one fd from the unix stream via SCM_RIGHTS, plus the 1 dummy data byte.
fn recv_fd(s: &UnixStream) -> Result<RawFd, Error> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg_buf = [0u8; 64]; // generous
    // SAFETY: msghdr is plain old data; zero-init is valid.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_buf.len() as _;
    // Retry on EINTR so a stray signal doesn't drop the handshake.
    let n = loop {
        // SAFETY: msg lives for the duration of this call.
        let r = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, 0) };
        if r >= 0 {
            break r;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(Error::RecvFd(e));
    };
    if n != 1 {
        return Err(Error::RecvFdBytes { got: n, want: 1 });
    }
    // SAFETY: msg was populated by recvmsg; cmsg traversal macros are
    // safe with valid msghdr.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let p = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
                return Ok(ptr::read(p));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Err(Error::NoFdInCmsg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strictly checked TLV parse: wrong length yields a typed error
    /// whose message includes the type and the length we got.
    #[test]
    fn parse_u32_strict_rejects_wrong_length() {
        let err = parse_u32_strict(0xABCD, &[1, 2, 3]).expect_err("len 3 must fail");
        let s = format!("{err}");
        assert!(s.contains("0xabcd"), "got {s:?}");
        assert!(s.contains("length 3"), "got {s:?}");
        assert!(s.contains("expected 4"), "got {s:?}");
    }

    #[test]
    fn parse_u32_strict_round_trip() {
        let v = parse_u32_strict(0x1234, &[0xDE, 0xAD, 0xBE, 0xEF]).expect("len 4");
        assert_eq!(v, 0xDEAD_BEEF);
    }

    /// Connect errors carry the exact path the operator typed so they can
    /// correlate "connect to /tmp/foo failed" against their config.
    /// (`expect_err` would need `Conn: Debug`, which we don't want to derive
    /// just for this test — match on the result instead.)
    #[test]
    fn connect_error_carries_path() {
        match Conn::connect("/tmp/nonexistent_testimony_socket_for_test") {
            Ok(_) => panic!("missing socket must error"),
            Err(e) => {
                let s = format!("{e}");
                assert!(
                    s.contains("/tmp/nonexistent_testimony_socket_for_test"),
                    "got {s:?}"
                );
            }
        }
    }

    /// Socket-name-with-NUL refused before we hit the kernel.
    #[test]
    fn connect_rejects_nul_in_socket_name() {
        match Conn::connect("/tmp/has\0nul") {
            Ok(_) => panic!("nul-in-name must error"),
            Err(e) => assert!(matches!(e, Error::InvalidSocketName(_))),
        }
    }

    /// Pure formatting check: every Error variant's Display contains enough
    /// context for a log line to be diagnostic.
    #[test]
    fn error_messages_are_descriptive() {
        let cases: Vec<(Error, &[&str])> = vec![
            (
                Error::UnexpectedVersion { got: 9, want: 2 },
                &["version 9", "expected 2"],
            ),
            (
                Error::BlockIndexOutOfRange { idx: 99, num_blocks: 16 },
                &["block index 99", "[0, 16)"],
            ),
            (
                Error::RingSizeOverflow { block_size: 1 << 31, num_blocks: 4 },
                &["overflows usize"],
            ),
            (
                Error::MissingHandshakeFields { fanout_size: 0, block_size: 0, num_blocks: 0 },
                &["fanout_size=0", "block_size=0", "num_blocks=0"],
            ),
            (
                Error::UnexpectedTlvLength { typ: 0x8003, got_length: 8, want_length: 4 },
                &["0x8003", "length 8", "expected 4"],
            ),
            (Error::PeerClosed { stage: STAGE_VERSION }, &["server closed", "version byte"]),
            (Error::NoFdInCmsg, &["SCM_RIGHTS"]),
            (Error::AlreadyInitialized, &["already initialized"]),
            (Error::NotInitialized, &["not initialized"]),
        ];
        for (err, expected_substrings) in cases {
            let s = format!("{err}");
            for needle in expected_substrings {
                assert!(s.contains(needle), "{:?} should contain {:?}", s, needle);
            }
        }
    }
}
