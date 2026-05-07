//! C ABI shim: `extern "C"` symbols compatible with the existing
//! `c/testimony.h` so legacy C consumers re-link against `libtestimony.so`
//! without changes.
//!
//! All functions return 0 on success, -errno on failure, matching the
//! original C library. The error string is also stashed in a per-handle
//! errbuf so `testimony_error()` can surface a more descriptive message
//! than `strerror(-rc)`. On every error path we both:
//!   - return `-errno` (legacy ABI),
//!   - and write `format!("{:#}", err)` into the per-handle errbuf so
//!     C consumers see the structured Rust-side reason (e.g.
//!     "mmap of AF_PACKET ring (len=16777216) failed: Cannot allocate
//!     memory" instead of just "ENOMEM").

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::conn::{Conn, Error};

const TESTIMONY_ERRBUF_SIZE: usize = 256;

#[repr(C)]
pub struct testimony_connection {
    pub fanout_size: c_int,
    pub block_size: usize,
    pub block_nr: usize,
    pub fanout_index: c_int,
}

#[repr(C)]
pub struct testimony_internal {
    conn_view: testimony_connection,
    /// Boxed inner Rust state.
    inner: *mut Inner,
    errbuf: [u8; TESTIMONY_ERRBUF_SIZE],
}

struct Inner {
    conn: Conn,
    /// Per-block remaining-packet counts (mirrors `block_counts` in `testimony.c`).
    /// This is the **only** packet-count tracker on the FFI path: the
    /// underlying `Conn` no longer keeps its own. (Audit B1.)
    counts: Box<[AtomicU32]>,
}

// `testimony` in the C header is `struct testimony_internal*`.
pub type testimony = *mut testimony_internal;

/// Map every typed `Error` to a stable errno-style integer. The C ABI
/// promises `-errno`; we honour that. Detail goes in errbuf via `set_err`.
fn err_neg(e: &Error) -> c_int {
    match e {
        Error::Connect { source, .. }
        | Error::Read { source, .. }
        | Error::Write { source, .. }
        | Error::Mmap { source, .. } => -(source.raw_os_error().unwrap_or(libc::EIO)),
        Error::Poll(io) | Error::RecvFd(io) => -(io.raw_os_error().unwrap_or(libc::EIO)),
        Error::PeerClosed { .. } => -libc::ECANCELED,
        Error::UnexpectedVersion { .. } => -libc::EPROTONOSUPPORT,
        Error::UnexpectedTlvCategory { .. }
        | Error::UnexpectedTlvLength { .. }
        | Error::MissingHandshakeFields { .. }
        | Error::BlockIndexOutOfRange { .. }
        | Error::NoFdInCmsg
        | Error::RecvFdBytes { .. } => -libc::EPROTO,
        Error::RingSizeOverflow { .. } => -libc::EOVERFLOW,
        Error::AlreadyInitialized => -libc::EALREADY,
        Error::NotInitialized => -libc::EINVAL,
        Error::Timeout => -libc::ETIMEDOUT,
        Error::InvalidSocketName(_) => -libc::EINVAL,
        Error::Internal(_) => -libc::EIO,
    }
}

/// Write a formatted error into the per-handle errbuf, NUL-terminated.
/// Truncates if the message is longer than the buffer.
fn set_err(t: *mut testimony_internal, err: &Error) {
    if t.is_null() {
        return;
    }
    let msg = format!("{err}");
    let bytes = msg.as_bytes();
    let n = bytes.len().min(TESTIMONY_ERRBUF_SIZE - 1);
    // SAFETY: t is non-null; errbuf is a fixed inline array.
    unsafe {
        let dst = (*t).errbuf.as_mut_ptr();
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n);
        *dst.add(n) = 0;
    }
}

/// As above, but for ad-hoc string errors that aren't a typed `Error`.
fn set_err_str(t: *mut testimony_internal, msg: &str) {
    if t.is_null() {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(TESTIMONY_ERRBUF_SIZE - 1);
    // SAFETY: t is non-null; errbuf is a fixed inline array.
    unsafe {
        let dst = (*t).errbuf.as_mut_ptr();
        ptr::copy_nonoverlapping(bytes.as_ptr(), dst, n);
        *dst.add(n) = 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn testimony_connect(
    out: *mut testimony,
    socket_name: *const c_char,
) -> c_int {
    if out.is_null() || socket_name.is_null() {
        return -libc::EINVAL;
    }
    let cstr = CStr::from_ptr(socket_name);
    let name = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -libc::EINVAL,
    };
    match Conn::connect(name) {
        Ok(conn) => {
            let inner = Box::new(Inner {
                counts: (0..conn.num_blocks())
                    .map(|_| AtomicU32::new(0))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                conn,
            });
            let view = testimony_connection {
                fanout_size: inner.conn.fanout_size() as c_int,
                block_size: inner.conn.block_size() as usize,
                block_nr: inner.conn.num_blocks() as usize,
                fanout_index: 0,
            };
            let t = Box::new(testimony_internal {
                conn_view: view,
                inner: Box::into_raw(inner),
                errbuf: [0u8; TESTIMONY_ERRBUF_SIZE],
            });
            *out = Box::into_raw(t);
            0
        }
        Err(e) => {
            // No handle to attach errbuf to yet — the caller has nowhere
            // to fish a message from. Log it via stderr so a misconfigured
            // C client at least sees something.
            eprintln!("testimony_connect: {e}");
            err_neg(&e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn testimony_conn(t: testimony) -> *mut testimony_connection {
    if t.is_null() {
        return ptr::null_mut();
    }
    &mut (*t).conn_view
}

#[no_mangle]
pub unsafe extern "C" fn testimony_error(t: testimony) -> *mut c_char {
    if t.is_null() {
        return ptr::null_mut();
    }
    (*t).errbuf.as_mut_ptr().cast()
}

#[no_mangle]
pub unsafe extern "C" fn testimony_init(t: testimony) -> c_int {
    if t.is_null() || (*t).inner.is_null() {
        return -libc::EINVAL;
    }
    let inner = &mut *(*t).inner;
    let idx = (*t).conn_view.fanout_index as u32;
    match inner.conn.init(idx) {
        Ok(()) => {
            // num_blocks doesn't change between connect and init in
            // practice, but rebuild the counter array anyway so we're
            // robust against any future protocol revision that does.
            inner.counts = (0..inner.conn.num_blocks())
                .map(|_| AtomicU32::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice();
            (*t).conn_view.block_size = inner.conn.block_size() as usize;
            (*t).conn_view.block_nr = inner.conn.num_blocks() as usize;
            0
        }
        Err(e) => {
            set_err(t, &e);
            err_neg(&e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn testimony_close(t: testimony) -> c_int {
    if t.is_null() {
        return -libc::EINVAL;
    }
    if !(*t).inner.is_null() {
        // Dropping Inner drops the `Conn` (closes the unix socket and
        // munmaps the AF_PACKET ring). RAII handles all cleanup; we
        // never need to second-guess it.
        drop(Box::from_raw((*t).inner));
        (*t).inner = ptr::null_mut();
    }
    drop(Box::from_raw(t));
    0
}

#[no_mangle]
pub unsafe extern "C" fn testimony_get_block(
    t: testimony,
    timeout_millis: c_int,
    out_block: *mut *const c_void,
) -> c_int {
    if t.is_null() || out_block.is_null() || (*t).inner.is_null() {
        return -libc::EINVAL;
    }
    *out_block = ptr::null();
    let inner = &mut *(*t).inner;
    let timeout = if timeout_millis < 0 {
        None
    } else {
        Some(std::time::Duration::from_millis(timeout_millis as u64))
    };
    match inner.conn.next_block(timeout) {
        Ok(Some(block)) => {
            let idx = block.index();
            let np = block.num_pkts();
            let raw = block.raw_ptr();
            // We must NOT let the Block's Drop fire — that would auto-return
            // the block to the server. We're handing ownership of the index
            // back to the C caller, who'll call testimony_return_block /
            // testimony_return_packets later.
            std::mem::forget(block);
            // No `Conn::block_counts` to poison anymore (audit B1).
            // Stash the kernel-reported packet count for return_packets.
            let Some(slot) = inner.counts.get(idx as usize) else {
                set_err_str(
                    t,
                    &format!(
                        "internal: block {idx} returned by next_block but counts has only {} slots",
                        inner.counts.len()
                    ),
                );
                return -libc::EIO;
            };
            slot.store(np, Ordering::SeqCst);
            *out_block = raw.cast();
            0
        }
        Ok(None) => 0, // timeout
        Err(e) => {
            set_err(t, &e);
            err_neg(&e)
        }
    }
}

unsafe fn block_index_of(inner: &Inner, block_ptr: *const c_void) -> Option<u32> {
    let base = inner.conn.ring_base_for_ffi();
    if base.is_null() {
        return None;
    }
    let diff = (block_ptr as usize).checked_sub(base as usize)?;
    let bs = inner.conn.block_size() as usize;
    if bs == 0 || diff % bs != 0 {
        return None;
    }
    let i = diff / bs;
    if i >= inner.conn.num_blocks() as usize {
        return None;
    }
    Some(i as u32)
}

#[no_mangle]
pub unsafe extern "C" fn testimony_return_block(
    t: testimony,
    block: *const c_void,
) -> c_int {
    if t.is_null() || block.is_null() || (*t).inner.is_null() {
        return -libc::EINVAL;
    }
    let inner = &mut *(*t).inner;
    let Some(idx) = block_index_of(inner, block) else {
        set_err_str(
            t,
            "block does not appear to have come from this testimony instance \
             (out of ring range or misaligned to block_size)",
        );
        return -libc::EINVAL;
    };
    let Some(slot) = inner.counts.get(idx as usize) else {
        set_err_str(
            t,
            &format!(
                "internal: block index {idx} out of range (counts.len()={})",
                inner.counts.len()
            ),
        );
        return -libc::EIO;
    };
    slot.store(0, Ordering::SeqCst);
    match inner.conn.return_block_index_pub(idx) {
        Ok(()) => 0,
        Err(e) => {
            set_err(t, &e);
            err_neg(&e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn testimony_return_packets(
    t: testimony,
    block: *const c_void,
    packets: u32,
) -> c_int {
    if t.is_null() || block.is_null() || (*t).inner.is_null() {
        return -libc::EINVAL;
    }
    let inner = &mut *(*t).inner;
    let Some(idx) = block_index_of(inner, block) else {
        set_err_str(
            t,
            "block does not appear to have come from this testimony instance",
        );
        return -libc::EINVAL;
    };
    let Some(slot) = inner.counts.get(idx as usize) else {
        set_err_str(
            t,
            &format!(
                "internal: block index {idx} out of range (counts.len()={})",
                inner.counts.len()
            ),
        );
        return -libc::EIO;
    };
    // Pre-check rather than fetch_sub-then-restore: fetch_sub on AtomicU32
    // wraps on underflow, and a concurrent reader could observe the wrapped
    // value before we restore. Using a CAS loop keeps the count monotone.
    loop {
        let cur = slot.load(Ordering::SeqCst);
        if cur < packets {
            set_err_str(
                t,
                &format!(
                    "return_packets: caller wants to return {packets} packets but block {idx} \
                     only has {cur} remaining"
                ),
            );
            return -libc::EINVAL;
        }
        let next = cur - packets;
        if slot
            .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            if next == 0 {
                match inner.conn.return_block_index_pub(idx) {
                    Ok(()) => return 0,
                    Err(e) => {
                        set_err(t, &e);
                        return err_neg(&e);
                    }
                }
            }
            return 0;
        }
        // Loser of the CAS retries.
    }
}

// --- iterator ---

#[repr(C)]
pub struct testimony_iter_internal {
    block: *const c_void,
    pkt: *const u8,
    /// Remaining packets. Stored as `i64` so we can never confuse "no packets
    /// left" (0) with "negative count from a corrupt header".
    left: i64,
}
pub type testimony_iter = *mut testimony_iter_internal;

#[no_mangle]
pub unsafe extern "C" fn testimony_iter_init(out: *mut testimony_iter) -> c_int {
    if out.is_null() {
        return -libc::EINVAL;
    }
    *out = Box::into_raw(Box::new(testimony_iter_internal {
        block: ptr::null(),
        pkt: ptr::null(),
        left: 0,
    }));
    0
}

#[no_mangle]
pub unsafe extern "C" fn testimony_iter_close(it: testimony_iter) -> c_int {
    if it.is_null() {
        return -libc::EINVAL;
    }
    drop(Box::from_raw(it));
    0
}

#[no_mangle]
pub unsafe extern "C" fn testimony_iter_reset(
    it: testimony_iter,
    block: *const c_void,
) -> c_int {
    if it.is_null() || block.is_null() {
        return -libc::EINVAL;
    }
    // version is the very first u32 of tpacket_block_desc.
    let version = ptr::read_unaligned(block.cast::<u32>());
    if version != libc::tpacket_versions::TPACKET_V3 as u32 {
        return -libc::EPROTONOSUPPORT;
    }
    let bptr = block.cast::<u8>();
    let num_pkts = ptr::read_unaligned(bptr.add(8 + 4) as *const u32);
    (*it).block = block;
    (*it).pkt = ptr::null();
    (*it).left = num_pkts as i64;
    0
}

#[no_mangle]
pub unsafe extern "C" fn testimony_iter_next(it: testimony_iter) -> *const c_void {
    if it.is_null() || (*it).left <= 0 {
        return ptr::null();
    }
    (*it).left -= 1;
    if (*it).pkt.is_null() {
        let bptr = (*it).block.cast::<u8>();
        let off = ptr::read_unaligned(bptr.add(8 + 4 + 4) as *const u32);
        (*it).pkt = bptr.add(off as usize);
    } else {
        let next_off = ptr::read_unaligned((*it).pkt.cast::<u32>()); // tp_next_offset is first
        (*it).pkt = (*it).pkt.add(next_off as usize);
    }
    (*it).pkt.cast()
}

#[no_mangle]
pub unsafe extern "C" fn testimony_packet_data(pkt: *const c_void) -> *const u8 {
    if pkt.is_null() {
        return ptr::null();
    }
    // tpacket3_hdr layout: tp_next_offset(u32), tp_sec(u32), tp_nsec(u32),
    // tp_snaplen(u32), tp_len(u32), tp_status(u32), tp_mac(u16), tp_net(u16) ...
    let p = pkt.cast::<u8>();
    let tp_mac = ptr::read_unaligned(p.add(4 * 6) as *const u16);
    p.add(tp_mac as usize)
}

#[no_mangle]
pub unsafe extern "C" fn testimony_packet_nanos(pkt: *const c_void) -> i64 {
    if pkt.is_null() {
        return 0;
    }
    let p = pkt.cast::<u8>();
    let tp_sec = ptr::read_unaligned(p.add(4) as *const u32);
    let tp_nsec = ptr::read_unaligned(p.add(8) as *const u32);
    (tp_sec as i64) * 1_000_000_000 + (tp_nsec as i64)
}
