//! Linux AF_PACKET TPACKET_V3 implementation.
//!
//! Replaces `c/socket.c` and the cgo glue in `go/testimonyd/internal/socket`.
//! All socket lifecycle is RAII: `OwnedFd` closes on drop, `MmapRing` calls
//! `munmap` on drop. That is the structural fix for the SHM-leak-on-bad-shutdown
//! bug — combined with `panic = "unwind"` and the daemon's panic hook, the
//! kernel ring is released on every shutdown path that doesn't involve SIGKILL.
//!
//! Every libc call here is wrapped: the typed `AfpacketError` carries the
//! syscall name and the relevant arguments so logs are immediately
//! diagnostic.

use std::ffi::{CString, OsStr};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use std::sync::atomic::AtomicU32;

use crate::bpf::parse_tcpdump_ddd_for;
use crate::{AfpacketError, CaptureConfig, SockFilter};

/// An mmap'd region. `Drop` calls `munmap` so the kernel ring is always
/// released, even on panic-driven shutdown.
pub struct MmapRing {
    ptr: *mut u8,
    len: usize,
}

// The mapping is shared and read-mostly from many threads. Access is mediated
// via `*const u8` pointers; we never hand out `&mut` to the buffer.
unsafe impl Send for MmapRing {}
unsafe impl Sync for MmapRing {}

impl MmapRing {
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for MmapRing {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            // SAFETY: ptr/len returned by a successful mmap call we own.
            // munmap can fail (EINVAL on garbage args), but we constructed
            // these args ourselves and there's nothing useful to recover
            // — log if it fires so we have a breadcrumb for debugging.
            let r = unsafe { libc::munmap(self.ptr.cast(), self.len) };
            if r != 0 {
                // We may be running in a panic unwind; logging from Drop
                // is best-effort. `eprintln!` writes to fd 2 directly so
                // it works even after env_logger has been torn down.
                let e = io::Error::last_os_error();
                eprintln!(
                    "testimony-afpacket: munmap(ptr={:p}, len={}) failed during Drop: {e}",
                    self.ptr, self.len
                );
            }
            self.ptr = ptr::null_mut();
            self.len = 0;
        }
    }
}

/// A ready-to-serve AF_PACKET capture socket: fd + mmap'd ring + per-block
/// reference counts.
///
/// Field declaration order matters: Rust drops fields in declaration order,
/// so `ring` (munmap) runs **before** `fd` (close). Closing the fd before
/// unmapping is technically permitted on Linux (the mapping holds its own
/// reference), but munmap-then-close is what `c/testimony.c` and the
/// AF_PACKET examples do, and it's the order most kernel paths exercise.
pub struct CaptureSocket {
    ring: MmapRing,
    fd: OwnedFd,
    block_size: u32,
    num_blocks: u32,
    refcounts: Box<[AtomicU32]>,
}

impl CaptureSocket {
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
    pub fn block_size(&self) -> u32 {
        self.block_size
    }
    pub fn num_blocks(&self) -> u32 {
        self.num_blocks
    }
    pub fn ring_ptr(&self) -> *mut u8 {
        self.ring.as_ptr()
    }
    pub fn ring_len(&self) -> usize {
        self.ring.len()
    }

    /// Get a pointer to block `i`'s `tpacket_block_desc`.
    /// Returns an error rather than panicking if `i` is out of range, so
    /// no caller has to use indexing-or-unwrap.
    fn block_ptr(&self, i: u32) -> Result<*mut u8, AfpacketError> {
        if i >= self.num_blocks {
            return Err(AfpacketError::BlockIndexOutOfRange {
                idx: i,
                num_blocks: self.num_blocks,
            });
        }
        let off = (i as usize) * (self.block_size as usize);
        // SAFETY: bounds checked above; offset stays inside the mmap region
        // because `ring_len = num_blocks * block_size` (validated by
        // `create_capture_socket`'s checked_mul).
        Ok(unsafe { self.ring.as_ptr().add(off) })
    }

    /// Read the `block_status` field of block `i`. Returns 0 (the same value
    /// the kernel writes when a block is unavailable) if `i` is out of range,
    /// matching the dispatcher's "not ready" semantics — but the dispatcher
    /// also checks via `refs(idx)` which is `Option`, so out-of-range never
    /// reaches here in practice.
    pub fn block_status(&self, i: u32) -> u32 {
        let Ok(base) = self.block_ptr(i) else {
            return 0;
        };
        // SAFETY: base is in-range; BLOCK_STATUS_OFFSET=8 lies within the
        // first block_size bytes (tpacket_block_desc layout).
        let p = unsafe { base.add(BLOCK_STATUS_OFFSET) } as *const u32;
        unsafe { ptr::read_volatile(p) }
    }

    /// Clear (set to 0) block `i`'s `block_status`, returning it to the
    /// kernel. No-op if `i` is out of range.
    pub fn clear_block(&self, i: u32) {
        let Ok(base) = self.block_ptr(i) else {
            return;
        };
        // SAFETY: same as block_status.
        let p = unsafe { base.add(BLOCK_STATUS_OFFSET) } as *mut u32;
        unsafe { ptr::write_volatile(p, 0) }
    }

    /// Refcount slot for block `i`. Returns `None` if the index is out of
    /// range — callers must propagate; the daemon never produces an invalid
    /// index in practice.
    pub fn refs(&self, i: u32) -> Option<&AtomicU32> {
        self.refcounts.get(i as usize)
    }

    /// Wait up to ~1s for new packet activity on the socket. Returns Ok(()) on
    /// readable-or-timeout. EINTR is swallowed (a stray signal isn't a
    /// failure). Mirrors `WaitForBlocks` in `go/testimonyd/internal/socket/socket.c`,
    /// but unlike that function we don't panic the daemon on errors — we
    /// surface a typed error and let the dispatcher decide.
    pub fn wait_for_blocks(&self) -> Result<(), AfpacketError> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a valid &mut.
        let r = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                return Ok(());
            }
            return Err(AfpacketError::Poll(e));
        }
        Ok(())
    }

    /// Get tpacket statistics, clearing the kernel counters.
    pub fn stats(&self) -> Result<libc::tpacket_stats_v3, AfpacketError> {
        // SAFETY: tpacket_stats_v3 is plain old data; zero-init is valid.
        let mut out: libc::tpacket_stats_v3 = unsafe { mem::zeroed() };
        let mut size = mem::size_of::<libc::tpacket_stats_v3>() as libc::socklen_t;
        // SAFETY: out and size are valid pointers.
        let r = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                (&mut out as *mut libc::tpacket_stats_v3).cast(),
                &mut size,
            )
        };
        if r < 0 {
            return Err(AfpacketError::Stats(io::Error::last_os_error()));
        }
        Ok(out)
    }
}

/// Offset of `block_status` within a TPACKET_V3 block. The kernel layout
/// is `tpacket_block_desc { version: u32, offset_to_priv: u32, hdr: union { bh1 } }`
/// where `hdr` is 8-byte aligned (already at offset 8) and `bh1` starts
/// with `block_status: u32`.
pub(crate) const BLOCK_STATUS_OFFSET: usize = 8;

/// Construct an AF_PACKET socket with TPACKET_V3, an mmap'd RX ring,
/// optional locked BPF filter, and optional fanout.
pub fn create_capture_socket(cfg: &CaptureConfig) -> Result<CaptureSocket, AfpacketError> {
    // socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    // SAFETY: socket(2) is safe to call with these constants.
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    if raw < 0 {
        return Err(AfpacketError::SocketCreate(io::Error::last_os_error()));
    }
    // SAFETY: fd is a freshly opened, owned descriptor. From here on, every
    // early return drops `fd`, which closes the descriptor — RAII keeps us
    // honest on the partial-init paths.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    setsockopt_int(
        fd.as_raw_fd(),
        libc::SOL_PACKET,
        libc::PACKET_VERSION,
        libc::tpacket_versions::TPACKET_V3 as i32,
        "PACKET_VERSION",
    )?;

    if let Some(filter) = &cfg.bpf_filter {
        attach_locked_bpf(fd.as_raw_fd(), filter)?;
    }

    // Request RX_RING.
    // SAFETY: tpacket_req3 is plain old data; zero-init is valid.
    let mut tp3: libc::tpacket_req3 = unsafe { mem::zeroed() };
    tp3.tp_block_size = cfg.block_size;
    tp3.tp_frame_size = cfg.block_size; // matches the C code
    tp3.tp_block_nr = cfg.num_blocks;
    tp3.tp_frame_nr = cfg.num_blocks;
    tp3.tp_retire_blk_tov = cfg.block_timeout_ms;
    // SAFETY: tp3 is a valid &T for the duration of the call.
    let r = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_RX_RING,
            (&tp3 as *const libc::tpacket_req3).cast(),
            mem::size_of::<libc::tpacket_req3>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(AfpacketError::Setsockopt {
            name: "PACKET_RX_RING",
            source: io::Error::last_os_error(),
        });
    }

    // mmap the ring. Use checked multiplication so a hostile config
    // (e.g. block_size = u32::MAX, num_blocks = u32::MAX) can't silently
    // wrap to a small allocation that we'd then index past.
    let Some(ring_len) = (cfg.block_size as usize).checked_mul(cfg.num_blocks as usize) else {
        return Err(AfpacketError::RingSizeOverflow {
            block_size: cfg.block_size,
            num_blocks: cfg.num_blocks,
        });
    };
    // SAFETY: arguments are valid. PROT/MAP flags match c/socket.c.
    let ptr = unsafe {
        libc::mmap(
            ptr::null_mut(),
            ring_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_LOCKED | libc::MAP_NORESERVE,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(AfpacketError::MmapRing {
            len: ring_len,
            source: io::Error::last_os_error(),
        });
    }
    // From here on, an early return drops `ring` (munmap) before `fd`
    // (close), thanks to declaration order on `CaptureSocket` AND the
    // local-variable reverse-of-declaration drop order on this stack
    // frame. Both bind() and the fanout setsockopt below benefit.
    let ring = MmapRing {
        ptr: ptr.cast(),
        len: ring_len,
    };

    // bind() to the interface.
    let ifindex = if_nametoindex(&cfg.iface)?;
    // SAFETY: sockaddr_ll is plain old data; zero-init is valid.
    let mut ll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    ll.sll_family = libc::AF_PACKET as u16;
    ll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    ll.sll_ifindex = ifindex as i32;
    // SAFETY: ll is a valid &T.
    let r = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&ll as *const libc::sockaddr_ll).cast(),
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(AfpacketError::Bind {
            iface: cfg.iface.clone(),
            ifindex,
            source: io::Error::last_os_error(),
        });
    }

    // Fanout (if requested). FanoutSize == 1 is a single-socket no-fanout setup.
    if cfg.fanout_size != 1 {
        let fanout = (cfg.fanout_id as i32 & 0xFFFF) | ((cfg.fanout_type as i32) << 16);
        setsockopt_int(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_FANOUT,
            fanout,
            "PACKET_FANOUT",
        )?;
    }

    let refcounts = (0..cfg.num_blocks)
        .map(|_| AtomicU32::new(0))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    Ok(CaptureSocket {
        ring,
        fd,
        block_size: cfg.block_size,
        num_blocks: cfg.num_blocks,
        refcounts,
    })
}

fn setsockopt_int(
    fd: RawFd,
    level: i32,
    name: i32,
    val: i32,
    label: &'static str,
) -> Result<(), AfpacketError> {
    let v: libc::c_int = val;
    // SAFETY: &v is valid for the duration of the call; size matches.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&v as *const libc::c_int).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(AfpacketError::Setsockopt {
            name: label,
            source: io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn attach_locked_bpf(fd: RawFd, filter: &[SockFilter]) -> Result<(), AfpacketError> {
    // The kernel struct sock_filter is { code: u16, jt: u8, jf: u8, k: u32 }.
    // Our SockFilter has the same layout but to be safe we marshal explicitly.
    let prog: Vec<libc::sock_filter> = filter
        .iter()
        .map(|f| libc::sock_filter {
            code: f.code,
            jt: f.jt,
            jf: f.jf,
            k: f.k,
        })
        .collect();
    // The on-wire `sock_fprog.len` is a u16. Refuse oversized programs
    // explicitly rather than silently truncating.
    let Ok(len_u16) = u16::try_from(prog.len()) else {
        return Err(AfpacketError::BpfTooLarge(prog.len()));
    };
    let fprog = libc::sock_fprog {
        len: len_u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: fprog and prog live for the duration of this call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&fprog as *const libc::sock_fprog).cast(),
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(AfpacketError::Setsockopt {
            name: "SO_ATTACH_FILTER",
            source: io::Error::last_os_error(),
        });
    }
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_LOCK_FILTER, 1, "SO_LOCK_FILTER")?;
    Ok(())
}

fn if_nametoindex(name: &str) -> Result<u32, AfpacketError> {
    let Ok(c) = CString::new(name) else {
        return Err(AfpacketError::InterfaceNameInvalid {
            iface: name.to_owned(),
        });
    };
    // SAFETY: c is a valid NUL-terminated string for the lifetime of this call.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        // if_nametoindex(3) sets errno on failure. If it's somehow 0,
        // synthesize ENODEV so the message is still meaningful.
        let err = io::Error::last_os_error();
        let err = if err.raw_os_error() == Some(0) {
            io::Error::from_raw_os_error(libc::ENODEV)
        } else {
            err
        };
        return Err(AfpacketError::InterfaceNotFound {
            iface: name.to_owned(),
            source: err,
        });
    }
    Ok(idx)
}

/// Compile a BPF expression by shelling out to `tcpdump -ddd`, matching what
/// the existing Go daemon does. Output of `-ddd` is a decimal listing:
/// first int is N, followed by N rows of 4 ints (code, jt, jf, k).
pub fn compile_bpf(iface: &str, filter: &str) -> Result<Vec<SockFilter>, AfpacketError> {
    compile_bpf_with(OsStr::new("/usr/sbin/tcpdump"), iface, filter)
}

pub fn compile_bpf_with(
    tcpdump_path: &OsStr,
    iface: &str,
    filter: &str,
) -> Result<Vec<SockFilter>, AfpacketError> {
    let out = Command::new(tcpdump_path)
        .arg("-i")
        .arg(iface)
        .arg("-ddd")
        .arg(filter)
        .output()
        .map_err(|e| AfpacketError::BpfCompileSpawn {
            tcpdump: PathBuf::from(tcpdump_path),
            source: e,
        })?;
    if !out.status.success() {
        return Err(AfpacketError::BpfCompile {
            iface: iface.to_owned(),
            filter: filter.to_owned(),
            reason: format!(
                "tcpdump exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_tcpdump_ddd_for(iface, filter, &text)
}
