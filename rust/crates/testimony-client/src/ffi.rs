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
/// promises `-errno`; we honour that.
///
/// The mapping is kept bug-for-bug compatible with `c/testimony.c` so
/// existing C clients' `switch (errno)` blocks keep matching the same
/// branches. In particular:
///   - missing handshake fields → `EINVAL` (`testimony.c:280`)
///   - already-initialised → `EINVAL` (`testimony.c:297`)
///   - bad block index from server → `EIO` (`testimony.c:393`)
///   - peer hung up mid-recv → `ECANCELED` (`testimony.c:96`)
///   - bad protocol version → `EPROTONOSUPPORT` (`testimony.c:236`)
fn err_neg(e: &Error) -> c_int {
    match e {
        Error::Connect { source, .. }
        | Error::Read { source, .. }
        | Error::Write { source, .. }
        | Error::Mmap { source, .. } => -(source.raw_os_error().unwrap_or(libc::EIO)),
        Error::Poll(io) | Error::RecvFd(io) => -(io.raw_os_error().unwrap_or(libc::EIO)),
        Error::PeerClosed { .. } => -libc::ECANCELED,
        Error::UnexpectedVersion { .. } => -libc::EPROTONOSUPPORT,
        // `BlockIndexOutOfRange` is the same condition as `testimony.c:393`
        // (server sent an index >= block_nr); the legacy lib returns EIO.
        Error::BlockIndexOutOfRange { .. } => -libc::EIO,
        // `MissingHandshakeFields` matches the legacy "didn't get fanout
        // size and block size/nr" path at `testimony.c:280`, which sets
        // EINVAL before goto fail.
        Error::MissingHandshakeFields { .. } => -libc::EINVAL,
        Error::UnexpectedTlvCategory { .. }
        | Error::UnexpectedTlvLength { .. }
        | Error::NoFdInCmsg
        | Error::RecvFdBytes { .. } => -libc::EPROTO,
        Error::RingSizeOverflow { .. } => -libc::EOVERFLOW,
        // Legacy `testimony_init` (`testimony.c:297`) returns EINVAL when
        // called twice; preserve that exact errno even though EALREADY
        // would be more descriptive.
        Error::AlreadyInitialized => -libc::EINVAL,
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
            // Stash the kernel-reported packet count for return_packets.
            // Match `testimony.c:401`'s CAS: the slot must be 0 here. If
            // it isn't, the daemon re-emitted a block we still hold —
            // legacy behaviour returns -EIO so we do too.
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
            if let Err(old) = slot.compare_exchange(0, np, Ordering::SeqCst, Ordering::SeqCst) {
                set_err_str(
                    t,
                    &format!(
                        "block count CAS failed for block {idx}, current count {old} != 0"
                    ),
                );
                return -libc::EIO;
            }
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
    // Match `testimony.c:434`: atomically swap the count to 0 and verify
    // the old value was either 0 (return called twice or never started
    // counting) or exactly num_pkts (return_packets never called). Any
    // other value means return_block and return_packets were both called
    // on the same block — the legacy lib returns -EINVAL.
    let old_count = slot.swap(0, Ordering::SeqCst);
    if old_count != 0 {
        // SAFETY: `block` is a non-null pointer that block_index_of just
        // proved lies inside our mmap'd ring at a valid block boundary.
        // num_pkts is at offset 12 (version+offset_to_priv+block_status).
        let num_pkts = std::ptr::read_unaligned(block.cast::<u8>().add(12) as *const u32);
        if old_count != num_pkts {
            set_err_str(
                t,
                "block count invalid... maybe testimony_return_block and \
                 testimony_return_packet were both called?",
            );
            return -libc::EINVAL;
        }
    }
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

#[cfg(test)]
mod ffi_tests {
    //! Pure-Rust tests of the C-ABI surface. These do NOT exercise a real
    //! testimonyd — they verify the errno-mapping table matches the bytes
    //! the legacy C library would have returned, and the null-pointer
    //! safety wrappers behave.

    use super::*;
    use std::ffi::CString;

    /// Errno mapping must match `c/testimony.c` bug-for-bug. A C client
    /// switching on `errno == EALREADY` would never have hit that branch
    /// against the legacy lib (which uses EINVAL); preserve that.
    #[test]
    fn err_neg_matches_legacy_c_lib() {
        let cases: &[(Error, c_int)] = &[
            // testimony.c:96 — EOF mid-recv → ECANCELED.
            (Error::PeerClosed { stage: "x" }, -libc::ECANCELED),
            // testimony.c:236 — bad version → EPROTONOSUPPORT.
            (
                Error::UnexpectedVersion { got: 9, want: 2 },
                -libc::EPROTONOSUPPORT,
            ),
            // testimony.c:280 — missing handshake fields → EINVAL.
            (
                Error::MissingHandshakeFields {
                    fanout_size: 0,
                    block_size: 0,
                    num_blocks: 0,
                },
                -libc::EINVAL,
            ),
            // testimony.c:297 — already initialised → EINVAL.
            (Error::AlreadyInitialized, -libc::EINVAL),
            // testimony.c:359 — not initialised → EINVAL.
            (Error::NotInitialized, -libc::EINVAL),
            // testimony.c:393 — server sent OOR block index → EIO.
            (
                Error::BlockIndexOutOfRange {
                    idx: 99,
                    num_blocks: 16,
                },
                -libc::EIO,
            ),
            // overflow on usize math → EOVERFLOW (no exact legacy match;
            // closest legacy behaviour is EINVAL but the Rust port gets
            // a more specific code, and it doesn't break legacy switches
            // because legacy code never produced this scenario).
            (
                Error::RingSizeOverflow {
                    block_size: u32::MAX,
                    num_blocks: u32::MAX,
                },
                -libc::EOVERFLOW,
            ),
            // Protocol-shape errors (TLV cat, length, fd-cmsg) → EPROTO.
            (
                Error::UnexpectedTlvCategory {
                    typ: 0x8001,
                    length: 0,
                },
                -libc::EPROTO,
            ),
            (
                Error::UnexpectedTlvLength {
                    typ: 0x8003,
                    got_length: 8,
                    want_length: 4,
                },
                -libc::EPROTO,
            ),
            (Error::NoFdInCmsg, -libc::EPROTO),
            (Error::RecvFdBytes { got: 0, want: 1 }, -libc::EPROTO),
            (Error::Timeout, -libc::ETIMEDOUT),
            (Error::InvalidSocketName("x".into()), -libc::EINVAL),
            (Error::Internal("x".into()), -libc::EIO),
        ];
        for (err, expected) in cases {
            let got = err_neg(err);
            assert_eq!(got, *expected, "err_neg({err:?}) = {got}, want {expected}");
        }
    }

    /// `testimony_close(NULL)` must not segfault and returns -EINVAL.
    /// The legacy C lib at `testimony.c:332` blindly dereferences (so
    /// passing NULL crashed). Rust's defensive null-check is an
    /// improvement we keep.
    #[test]
    fn testimony_close_null_returns_einval() {
        let r = unsafe { testimony_close(ptr::null_mut()) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_conn(NULL)` returns NULL — must not deref.
    #[test]
    fn testimony_conn_null_returns_null() {
        let p = unsafe { testimony_conn(ptr::null_mut()) };
        assert!(p.is_null());
    }

    /// `testimony_error(NULL)` returns NULL — matches Rust safety, even
    /// though legacy `testimony.c:472` would deref (bug there).
    #[test]
    fn testimony_error_null_returns_null() {
        let p = unsafe { testimony_error(ptr::null_mut()) };
        assert!(p.is_null());
    }

    /// `testimony_init(NULL)` → -EINVAL.
    #[test]
    fn testimony_init_null_returns_einval() {
        let r = unsafe { testimony_init(ptr::null_mut()) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_get_block(NULL, …)` → -EINVAL.
    #[test]
    fn testimony_get_block_null_returns_einval() {
        let mut block: *const c_void = ptr::null();
        let r = unsafe { testimony_get_block(ptr::null_mut(), 0, &mut block) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_return_block(NULL, …)` → -EINVAL.
    #[test]
    fn testimony_return_block_null_returns_einval() {
        let r = unsafe { testimony_return_block(ptr::null_mut(), ptr::null()) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_return_packets(NULL, …)` → -EINVAL.
    #[test]
    fn testimony_return_packets_null_returns_einval() {
        let r = unsafe { testimony_return_packets(ptr::null_mut(), ptr::null(), 1) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_iter_init(NULL)` → -EINVAL.
    #[test]
    fn testimony_iter_init_null_returns_einval() {
        let r = unsafe { testimony_iter_init(ptr::null_mut()) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_iter_close(NULL)` → -EINVAL.
    #[test]
    fn testimony_iter_close_null_returns_einval() {
        let r = unsafe { testimony_iter_close(ptr::null_mut()) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_iter_next(NULL)` → NULL pointer.
    #[test]
    fn testimony_iter_next_null_returns_null() {
        let p = unsafe { testimony_iter_next(ptr::null_mut()) };
        assert!(p.is_null());
    }

    /// `testimony_packet_data(NULL)` → NULL.
    #[test]
    fn testimony_packet_data_null_returns_null() {
        let p = unsafe { testimony_packet_data(ptr::null()) };
        assert!(p.is_null());
    }

    /// `testimony_packet_nanos(NULL)` → 0.
    #[test]
    fn testimony_packet_nanos_null_returns_zero() {
        let n = unsafe { testimony_packet_nanos(ptr::null()) };
        assert_eq!(n, 0);
    }

    /// Iter init then close round-trip without leaking.
    #[test]
    fn testimony_iter_init_close_round_trip() {
        let mut iter: testimony_iter = ptr::null_mut();
        let r = unsafe { testimony_iter_init(&mut iter) };
        assert_eq!(r, 0);
        assert!(!iter.is_null());
        let r = unsafe { testimony_iter_close(iter) };
        assert_eq!(r, 0);
    }

    /// `testimony_connect` against an obviously-bogus path returns a
    /// negative errno. The exact errno depends on libc (ENOENT or
    /// ECONNREFUSED), but it must be < 0.
    #[test]
    fn testimony_connect_bogus_path_negative_errno() {
        let mut t: testimony = ptr::null_mut();
        let bogus = CString::new("/tmp/_testimony_test_does_not_exist_xx").unwrap();
        let r = unsafe { testimony_connect(&mut t, bogus.as_ptr()) };
        assert!(r < 0, "expected negative errno, got {r}");
        assert!(t.is_null(), "no handle should be returned on failure");
    }

    /// `testimony_connect` with NULL out-pointer → -EINVAL without crash.
    #[test]
    fn testimony_connect_null_out_returns_einval() {
        let bogus = CString::new("/tmp/x").unwrap();
        let r = unsafe { testimony_connect(ptr::null_mut(), bogus.as_ptr()) };
        assert_eq!(r, -libc::EINVAL);
    }

    /// `testimony_connect` with NULL socket name → -EINVAL.
    #[test]
    fn testimony_connect_null_name_returns_einval() {
        let mut t: testimony = ptr::null_mut();
        let r = unsafe { testimony_connect(&mut t, ptr::null()) };
        assert_eq!(r, -libc::EINVAL);
    }
}
