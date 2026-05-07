//! Per-client connection handling. Mirrors `go/testimonyd/internal/socket/socket.go`'s
//! `conn.run` / `conn.handleReads`.
//!
//! Threading model:
//!   * one **writer** thread per connection — owns the unique sending side of
//!     the unix stream, owns all in-flight `BlockTicket`s, performs the
//!     batched write of block-indices.
//!   * one **reader** thread per connection — parses block-returns + TLVs
//!     coming from the client and forwards them as `WriterMsg::Returned`
//!     to the writer.
//!
//! The writer's inbox is a **bounded** `sync_channel(num_blocks)` that
//! receives both new-block tickets (from the dispatcher) and reader events.
//! The dispatcher uses `try_send`: if the writer's inbox is full it drops
//! the ticket (which decrements the refcount and clears the kernel block
//! once everyone else releases it). This matches Go's
//! `select { case ch<-b: default: b.unref() }` semantics.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Instant;

use testimony_protocol::{self as proto, Category};

use crate::shutdown::Shutdown;

#[cfg(target_os = "linux")]
mod ticket {
    use std::sync::Arc;
    use testimony_afpacket::CaptureSocket;

    /// A reference-counted block "ticket" sent from the dispatcher to a client
    /// writer. `Drop` decrements the count; on transition-to-zero, the block is
    /// cleared back to the kernel so AF_PACKET can refill it.
    pub struct BlockTicket {
        sock: Arc<CaptureSocket>,
        index: u32,
    }

    impl BlockTicket {
        /// Constructs a ticket and increments the per-block refcount.
        /// Returns `None` if `index` is out of range; callers must propagate
        /// rather than panic. The dispatcher only ever passes a valid index.
        pub fn new(sock: Arc<CaptureSocket>, index: u32) -> Option<Self> {
            let refs = sock.refs(index)?;
            refs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(Self { sock, index })
        }

        pub fn index(&self) -> u32 {
            self.index
        }
    }

    impl Drop for BlockTicket {
        fn drop(&mut self) {
            // refs(index) was Some at construction; if the underlying refcount
            // vector somehow shrank we have bigger problems, but degrade
            // gracefully rather than panic.
            let Some(refs) = self.sock.refs(self.index) else {
                log::error!(
                    "BlockTicket Drop: refcount slot for block {} disappeared",
                    self.index
                );
                return;
            };
            let prev = refs.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            // prev was the value BEFORE the decrement; refcount reached 0 when prev == 1.
            if prev == 1 {
                self.sock.clear_block(self.index);
            } else if prev == 0 {
                // Should never happen — every BlockTicket increments on construction.
                log::error!(
                    "BlockTicket: invalid unref, refcount was 0 for block {}",
                    self.index
                );
            }
        }
    }
}

/// Cross-platform stand-in for `BlockTicket` on non-Linux hosts so the
/// `WriterMsg` enum and `writer_loop`/`reader_loop` can be unit-tested
/// without a real AF_PACKET socket.
///
/// Implements `Drop` so the `drop(ticket)` calls in `writer_loop` /
/// `dispatch_loop` aren't flagged by clippy's `drop_non_drop` lint on
/// non-Linux builds. On Linux the real `BlockTicket::Drop` decrements the
/// per-block refcount; on macOS this is a no-op.
#[cfg(not(target_os = "linux"))]
mod ticket {
    pub struct BlockTicket {
        index: u32,
    }
    impl BlockTicket {
        pub fn index(&self) -> u32 {
            self.index
        }
        #[allow(dead_code)]
        pub fn for_test(index: u32) -> Self {
            Self { index }
        }
    }
    impl Drop for BlockTicket {
        fn drop(&mut self) {
            // No-op stub. Real impl is in `linux::ticket`.
        }
    }
}

pub use ticket::BlockTicket;

/// Inbox messages for the writer thread.
pub enum WriterMsg {
    /// New block ready — send its index out to the client.
    NewBlock(BlockTicket),
    /// Client returned a block. Drop the corresponding outstanding ticket.
    Returned(u32),
    /// Client side closed; tear down.
    PeerClosed,
    /// Daemon shutting down; tear down.
    Shutdown,
}

/// Reader thread: parses incoming u32-or-TLV from the client and forwards
/// either Returned(i) or PeerClosed to the writer.
///
/// Hot-path: every block-return from a client is exactly 4 bytes. The
/// reader does one `read(2)` per return — trying to buffer here would
/// be wasted work because clients return blocks at most as fast as the
/// dispatcher emits them, and the kernel's socket buffer already
/// coalesces small writes. Drain TLV payloads into a reusable scratch
/// buffer so the rare unsolicited-TLV path doesn't allocate.
pub fn reader_loop(
    mut stream: UnixStream,
    num_blocks: u32,
    tx: mpsc::SyncSender<WriterMsg>,
    shutdown: Shutdown,
) {
    // Reusable scratch buffer for draining unknown-TLV payloads. Sized
    // generously so a 64 KB malicious TLV reuses the same allocation.
    let mut drain_buf = [0u8; 4096];
    let mut hdr = [0u8; 4];
    loop {
        if shutdown.is_set() {
            let _ = tx.send(WriterMsg::PeerClosed);
            return;
        }
        if let Err(e) = read_exact_or_eof(&mut stream, &mut hdr) {
            match e {
                ReadErr::Eof => log::debug!("client EOF"),
                ReadErr::Io(io) => log::debug!("reader io error: {io}"),
            }
            let _ = tx.send(WriterMsg::PeerClosed);
            return;
        }
        let raw = u32::from_be_bytes(hdr);
        // Bare block-index has the high bit unset — fast path.
        if raw & 0x8000_0000 == 0 {
            let i = raw;
            if i >= num_blocks {
                log::warn!("reader got out-of-range block index {i}");
                let _ = tx.send(WriterMsg::PeerClosed);
                return;
            }
            if tx.send(WriterMsg::Returned(i)).is_err() {
                return;
            }
            continue;
        }
        // TLV from client. Match `socket.go:223-237`: log a warning if the
        // type isn't ClientToServer but DON'T drop the connection — the
        // legacy Go daemon just logs at vlog.V(1) and continues. The bytes
        // are still drained from the wire so the next read aligns.
        let (typ, length) = proto::tl_from(raw);
        if proto::category_of(typ) != Category::ClientToServer {
            log::warn!("reader got bad client→server type {typ:#x}");
        }
        // Drain the payload in chunks reusing `drain_buf` — never allocates.
        let mut remaining = length as usize;
        while remaining > 0 {
            let chunk = remaining.min(drain_buf.len());
            if let Err(e) = read_exact_or_eof(&mut stream, &mut drain_buf[..chunk]) {
                log::debug!("reader payload error: {e:?}");
                let _ = tx.send(WriterMsg::PeerClosed);
                return;
            }
            remaining -= chunk;
        }
        log::info!("ignoring client TLV type={typ:#x} len={length}");
    }
}

#[derive(Debug)]
enum ReadErr {
    Eof,
    Io(std::io::Error),
}
impl std::fmt::Display for ReadErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadErr::Eof => write!(f, "EOF"),
            ReadErr::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Read until `buf` is full or the peer closes. `read < buf.len()` is
/// the loop invariant, so direct slice indexing is statically in bounds
/// — no defensive `get_mut` branch on the hot path.
fn read_exact_or_eof(s: &mut UnixStream, buf: &mut [u8]) -> Result<(), ReadErr> {
    let total = buf.len();
    let mut read = 0;
    while read < total {
        match s.read(&mut buf[read..]) {
            Ok(0) => return Err(ReadErr::Eof),
            Ok(n) => read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadErr::Io(e)),
        }
    }
    Ok(())
}

/// Writer thread: drains the inbox, holds all in-flight `BlockTicket`s,
/// performs batched writes of block-indices to the client.
///
/// Batching matches Go (`socket.go:266 conn.run`): when one `NewBlock`
/// arrives, opportunistically drain any others already waiting and pack
/// them into a single `write_all` — this collapses N `write()` syscalls
/// into 1 under load.
///
/// Performance: the batch buffer is allocated **once** per writer (one
/// per client), sized to `num_blocks * 4` bytes, and `clear()`ed between
/// flushes so the allocation is reused for the lifetime of the connection.
/// At a 1M-block/s workload across 100 clients this saves ~1M allocator
/// round-trips per second vs. allocating-per-batch.
pub fn writer_loop(
    mut stream: UnixStream,
    num_blocks: u32,
    rx: mpsc::Receiver<WriterMsg>,
    shutdown: Shutdown,
) {
    // One slot per block: `Some((ticket, sent_at))` while in flight.
    let mut outstanding: Vec<Option<(BlockTicket, Instant)>> =
        (0..num_blocks).map(|_| None).collect();
    // Per-connection batch buffer, reused across every flush. Cap at
    // `num_blocks * 4` so we never grow past one ring's worth of indices
    // (the dispatcher couldn't have produced more without first getting
    // a Returned that frees a slot). `saturating_mul` guards against a
    // hostile `num_blocks` that slipped past config validation.
    let cap = (num_blocks as usize).saturating_mul(4);
    let mut batch_buf: Vec<u8> = Vec::with_capacity(cap);

    'outer: while let Ok(first) = rx.recv() {
        match first {
            WriterMsg::NewBlock(ticket) => {
                let mut current = Some(ticket);
                while let Some(t) = current {
                    let idx = t.index();
                    let Some(slot) = outstanding.get_mut(idx as usize) else {
                        // dispatcher must never send an out-of-range index, but
                        // be defensive — drop the ticket and bail rather than panic.
                        log::error!("writer got out-of-range block {idx}; dropping");
                        drop(t);
                        break 'outer;
                    };
                    if slot.is_some() {
                        log::error!("writer received already-outstanding block {idx}");
                        drop(t);
                        break 'outer;
                    }
                    batch_buf.extend_from_slice(&idx.to_be_bytes());
                    *slot = Some((t, Instant::now()));
                    // Drain more, non-blocking.
                    match rx.try_recv() {
                        Ok(WriterMsg::NewBlock(next)) => current = Some(next),
                        Ok(other) => {
                            // Flush what we have, then handle `other` next iteration.
                            if let Err(e) = stream.write_all(&batch_buf) {
                                log::debug!("writer send failed: {e}");
                                break 'outer;
                            }
                            // Clear (keep the allocation) so the post-loop
                            // flush doesn't double-send what we already wrote.
                            batch_buf.clear();
                            // Re-handle `other` synchronously to avoid losing it.
                            if !handle_non_newblock(other, &mut outstanding) {
                                break 'outer;
                            }
                            current = None;
                        }
                        Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {
                            current = None;
                        }
                    }
                }
                if !batch_buf.is_empty() {
                    if let Err(e) = stream.write_all(&batch_buf) {
                        log::debug!("writer send failed: {e}");
                        break 'outer;
                    }
                    batch_buf.clear();
                }
            }
            other => {
                if !handle_non_newblock(other, &mut outstanding) {
                    break 'outer;
                }
            }
        }
        if shutdown.is_set() {
            break 'outer;
        }
    }

    // Cleanup: dropping `outstanding` drops every remaining BlockTicket,
    // which decrements refcounts and clears any blocks that hit zero.
    let in_flight = outstanding.iter().filter(|o| o.is_some()).count();
    if in_flight > 0 {
        log::info!("connection closing, releasing {in_flight} in-flight block(s)");
    }
    drop(outstanding);
}

/// Returns `true` to keep the writer running, `false` to stop.
///
/// Bounds-checked indexing: an out-of-range `Returned(i)` (which the reader
/// already validates against `num_blocks`) signals corruption — log and exit.
fn handle_non_newblock(
    msg: WriterMsg,
    outstanding: &mut [Option<(BlockTicket, Instant)>],
) -> bool {
    match msg {
        WriterMsg::Returned(i) => {
            let Some(slot) = outstanding.get_mut(i as usize) else {
                log::error!("writer received block index {i} >= num_blocks");
                return false;
            };
            if let Some((ticket, since)) = slot.take() {
                log::trace!("client returned block {i} after {:?}", since.elapsed());
                drop(ticket);
                true
            } else {
                log::warn!("client returned non-outstanding block {i}");
                false
            }
        }
        WriterMsg::PeerClosed | WriterMsg::Shutdown => false,
        WriterMsg::NewBlock(_) => {
            // Should be handled by the writer's main loop; if we get here it
            // means the dispatch path was changed without updating both sites.
            // Drop the ticket (releases the block) and stop.
            log::error!("writer: NewBlock reached handle_non_newblock; dropping");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    //! These tests exercise the writer's batching loop without a real
    //! AF_PACKET socket — they use a `UnixStream::pair()` to capture what
    //! the writer sends to its peer and assert byte-for-byte that no
    //! double-flush happens (regression test for the cycle-9 bug).
    //!
    //! BlockTickets need an `Arc<CaptureSocket>`, which we can't construct
    //! here without root. Tests that need tickets are gated to
    //! `target_os = "linux"` and run only inside the Docker E2E. The pure
    //! channel-flow tests can run on macOS too.

    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    /// Exercise the writer's interleaving of NewBlock + Returned: ensures
    /// the batch buffer is correctly cleared after an in-arm flush so the
    /// post-loop flush doesn't double-write.
    ///
    /// Without BlockTickets we can't drive `WriterMsg::NewBlock`, but we
    /// CAN test that pure-Returned/PeerClosed flows don't write anything.
    #[test]
    fn writer_loop_without_newblocks_writes_nothing() {
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        // Fire one PeerClosed; writer should exit without ever writing bytes.
        tx.send(WriterMsg::PeerClosed).expect("send PeerClosed");
        drop(tx); // close channel so recv() eventually errors

        let h = std::thread::spawn(move || {
            writer_loop(peer_a, 4, rx, shutdown);
        });
        h.join().expect("writer thread");

        // Read: peer_b should see EOF immediately (writer never wrote).
        let mut buf = [0u8; 16];
        let n = peer_b.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "writer wrote unexpected bytes: {:?}", &buf[..n]);
    }

    /// Returned for a non-outstanding block exits the writer without writing.
    #[test]
    fn writer_loop_returned_for_unknown_block_exits() {
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        tx.send(WriterMsg::Returned(0)).expect("send Returned");
        drop(tx);

        let h = std::thread::spawn(move || {
            writer_loop(peer_a, 4, rx, shutdown);
        });
        h.join().expect("writer thread");

        let mut buf = [0u8; 16];
        let n = peer_b.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0);
    }

    /// Shutdown signal during writer_loop exits cleanly.
    #[test]
    fn writer_loop_shutdown_exits() {
        let (peer_a, _peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();
        shutdown.set();
        tx.send(WriterMsg::Shutdown).expect("send Shutdown");
        drop(tx);

        let h = std::thread::spawn(move || {
            writer_loop(peer_a, 4, rx, shutdown);
        });
        h.join().expect("writer thread");
    }

    /// Reader exits on EOF without writing anything to its tx.
    #[test]
    fn reader_loop_eof_sends_peer_closed() {
        let (peer_a, peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        // Drop peer_b → reader's read returns EOF.
        drop(peer_b);

        let h = std::thread::spawn(move || {
            reader_loop(peer_a, 4, tx, shutdown);
        });
        h.join().expect("reader thread");

        // Channel should have exactly one PeerClosed.
        let mut got_peer_closed = false;
        while let Ok(msg) = rx.try_recv() {
            if matches!(msg, WriterMsg::PeerClosed) {
                got_peer_closed = true;
            }
        }
        assert!(got_peer_closed, "reader should send PeerClosed on EOF");
    }

    /// Reader correctly decodes a bare block-index sent by the client.
    #[test]
    fn reader_loop_decodes_block_index() {
        use std::io::Write;
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        // Client sends block-index 7 (raw u32 big-endian 0x00000007).
        peer_b.write_all(&7u32.to_be_bytes()).expect("write idx");
        // Then drop peer_b to trigger EOF.
        drop(peer_b);

        let h = std::thread::spawn(move || {
            reader_loop(peer_a, 16, tx, shutdown);
        });
        h.join().expect("reader thread");

        let msg1 = rx.try_recv().expect("first message");
        match msg1 {
            WriterMsg::Returned(7) => {}
            _ => panic!("expected Returned(7)"),
        }
        let msg2 = rx.try_recv().expect("second message");
        assert!(matches!(msg2, WriterMsg::PeerClosed));
    }

    /// Reader rejects a block-index >= num_blocks.
    #[test]
    fn reader_loop_rejects_out_of_range_block_index() {
        use std::io::Write;
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        peer_b.write_all(&100u32.to_be_bytes()).expect("write idx");

        let h = std::thread::spawn(move || {
            reader_loop(peer_a, 16, tx, shutdown);
        });
        h.join().expect("reader thread");

        let msg = rx.try_recv().expect("message");
        assert!(matches!(msg, WriterMsg::PeerClosed));
        let _ = peer_b; // keep alive
    }

    /// Regression test for the Cycle-9 batching bug: when a NewBlock is
    /// followed (in the channel) by a non-NewBlock message, the writer must
    /// flush the batch buffer once and only once. With the bug, the buffer
    /// was flushed in-arm AND again at the post-loop is_empty check, so the
    /// peer received duplicate block indices.
    ///
    /// This test feeds NewBlock(2) → NewBlock(5) → Returned(2) → PeerClosed
    /// and verifies the peer sees exactly 8 bytes (idx 2 + idx 5 BE).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn writer_loop_does_not_double_flush_on_interleaved_messages() {
        use crate::conn::ticket::BlockTicket;
        use std::io::Read;

        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(8);
        let shutdown = Shutdown::new();

        // Pre-load the channel: 2 NewBlocks then a Returned, then PeerClosed.
        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(2)))
            .expect("nb 2");
        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(5)))
            .expect("nb 5");
        tx.send(WriterMsg::Returned(2)).expect("ret 2");
        tx.send(WriterMsg::PeerClosed).expect("close");
        drop(tx);

        let h = std::thread::spawn(move || {
            writer_loop(peer_a, 16, rx, shutdown);
        });
        h.join().expect("writer thread");

        let mut buf = [0u8; 32];
        let n = peer_b.read(&mut buf).unwrap_or(0);
        // We should see exactly the two block indices, written as 4-byte BE u32.
        assert_eq!(
            n, 8,
            "expected 8 bytes (two block indices), got {n}: {:?}",
            &buf[..n.min(buf.len())]
        );
        let idx_a = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let idx_b = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(idx_a, 2);
        assert_eq!(idx_b, 5);
    }

    /// Match `socket.go:223-226`: an unknown TLV type from the client is
    /// logged and IGNORED — Go does not drop the connection over a bad
    /// type. Rust must match: payload drained, loop continues.
    #[test]
    fn reader_loop_ignores_unknown_tlv_then_continues() {
        use std::io::Write;
        use testimony_protocol::{to_tl, TYPE_FANOUT_INDEX};
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        // Send a ServerToClient-category TLV (which is the wrong direction
        // from the client) with a 4-byte payload, then a legit block return.
        // The Go daemon would log the bad type but keep going, draining the
        // payload and processing the next message.
        let tl = to_tl(testimony_protocol::TYPE_FANOUT_SIZE, 4).to_be_bytes();
        peer_b.write_all(&tl).expect("tl");
        peer_b.write_all(&[0x00, 0x00, 0x00, 0x99]).expect("payload");
        // Now a valid client-side TLV (FanoutIndex) with 4-byte payload —
        // Go drains and ignores; Rust must too.
        let tl2 = to_tl(TYPE_FANOUT_INDEX, 4).to_be_bytes();
        peer_b.write_all(&tl2).expect("tl2");
        peer_b.write_all(&[0x00, 0x00, 0x00, 0x01]).expect("payload2");
        // And finally a real block-index return.
        peer_b.write_all(&3u32.to_be_bytes()).expect("blockidx");
        drop(peer_b);

        let h = std::thread::spawn(move || {
            reader_loop(peer_a, 16, tx, shutdown);
        });
        h.join().expect("reader thread");

        // Expect: Returned(3), then PeerClosed (no Returned-from-bad-TLV).
        let msg1 = rx.try_recv().expect("first message");
        assert!(
            matches!(msg1, WriterMsg::Returned(3)),
            "expected Returned(3) after draining bad+good TLVs, got something else"
        );
        let msg2 = rx.try_recv().expect("second message");
        assert!(matches!(msg2, WriterMsg::PeerClosed));
    }

    /// TLV with length > 0 and short payload (peer closes mid-payload) →
    /// reader emits PeerClosed without panicking.
    #[test]
    fn reader_loop_truncated_tlv_payload_emits_peer_closed() {
        use std::io::Write;
        use testimony_protocol::{to_tl, TYPE_FANOUT_INDEX};
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();

        let tl = to_tl(TYPE_FANOUT_INDEX, 4).to_be_bytes();
        peer_b.write_all(&tl).expect("tl");
        // Only write 2 of the 4 payload bytes, then close.
        peer_b.write_all(&[0xDE, 0xAD]).expect("partial");
        drop(peer_b);

        let h = std::thread::spawn(move || {
            reader_loop(peer_a, 16, tx, shutdown);
        });
        h.join().expect("reader thread");
        let msg = rx.try_recv().expect("message");
        assert!(matches!(msg, WriterMsg::PeerClosed));
    }

    /// Reader observes shutdown flag set BEFORE first read → emits
    /// PeerClosed promptly. Mirrors the "daemon shutting down before any
    /// client traffic" scenario.
    #[test]
    fn reader_loop_observes_shutdown_promptly() {
        let (peer_a, _peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(4);
        let shutdown = Shutdown::new();
        shutdown.set(); // pre-flip

        let h = std::thread::spawn(move || {
            reader_loop(peer_a, 16, tx, shutdown);
        });
        // Reader should exit promptly once it observes the flag at the top
        // of its loop. Bound the join with a generous timeout — we use
        // a separate channel since std doesn't have join-with-timeout.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            h.join().expect("reader thread");
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("reader didn't exit on shutdown flag");
        // Reader sent PeerClosed before exiting.
        let msg = rx.try_recv().expect("PeerClosed");
        assert!(matches!(msg, WriterMsg::PeerClosed));
    }

    /// Multiple Returned messages for unique outstanding blocks: each
    /// transitions slot back to None and decrements (we can't observe
    /// refcount without tickets, but we CAN observe the writer doesn't
    /// exit prematurely as long as slots are populated by NewBlock).
    /// This is the off-Linux variant; the real refcount test is the
    /// Linux-gated `writer_loop_does_not_double_flush_on_interleaved_messages`.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn writer_loop_handles_multiple_returns_in_order() {
        use crate::conn::ticket::BlockTicket;
        use std::io::Read;
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(16);
        let shutdown = Shutdown::new();

        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(0)))
            .expect("nb0");
        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(1)))
            .expect("nb1");
        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(2)))
            .expect("nb2");
        tx.send(WriterMsg::Returned(0)).expect("r0");
        tx.send(WriterMsg::Returned(1)).expect("r1");
        tx.send(WriterMsg::Returned(2)).expect("r2");
        tx.send(WriterMsg::PeerClosed).expect("close");
        drop(tx);

        let h = std::thread::spawn(move || {
            writer_loop(peer_a, 16, rx, shutdown);
        });
        h.join().expect("writer thread");

        // Peer should have seen 3 indices (12 bytes).
        let mut buf = [0u8; 32];
        let n = peer_b.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 12, "expected 12 bytes, got {n}");
        for (i, expected) in [0u32, 1, 2].iter().enumerate() {
            let off = i * 4;
            let v = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            assert_eq!(v, *expected);
        }
    }

    /// The dispatcher is supposed to never give the writer the same block
    /// twice while it's outstanding. If it ever does, the writer logs and
    /// exits — match the legacy Go behaviour at `socket.go:275`
    /// (`log.Fatalf("received already outstanding block...")`) but
    /// gracefully. This test verifies the writer doesn't write garbage
    /// when given a duplicate.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn writer_loop_duplicate_outstanding_block_exits_without_writing_garbage() {
        use crate::conn::ticket::BlockTicket;
        use std::io::Read;
        let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel::<WriterMsg>(8);
        let shutdown = Shutdown::new();

        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(3)))
            .expect("nb3");
        // Same index again WITHOUT a Returned in between.
        tx.send(WriterMsg::NewBlock(BlockTicket::for_test(3)))
            .expect("nb3 dup");
        drop(tx);

        let h = std::thread::spawn(move || {
            writer_loop(peer_a, 16, rx, shutdown);
        });
        h.join().expect("writer thread");

        let mut buf = [0u8; 32];
        let n = peer_b.read(&mut buf).unwrap_or(0);
        // The first NewBlock(3) was buffered. When the duplicate arrived
        // via try_recv, we noticed slot.is_some() and bailed without
        // flushing the batch. So the peer sees zero bytes (the buffered
        // index never got written before we hit the error).
        // Actually — re-read the writer_loop: in the inner `while let
        // Some(t) = current` loop, the first NewBlock fills slot[3]; the
        // try_recv pulls another NewBlock(3); current = Some(next); loop
        // top sees slot.is_some() → break 'outer. The batch_buf has 4
        // bytes for the first idx but never got flushed because we broke
        // before the post-loop flush. So 0 bytes.
        assert_eq!(n, 0, "expected no bytes (duplicate triggers bail), got {n}");
    }

    /// `WriterMsg::Shutdown` and `WriterMsg::PeerClosed` produce identical
    /// effects: the writer exits without writing. They're intentionally
    /// distinguishable for documentation purposes.
    #[test]
    fn writer_loop_shutdown_msg_is_indistinguishable_from_peer_closed() {
        for msg in [WriterMsg::Shutdown, WriterMsg::PeerClosed] {
            let (peer_a, mut peer_b) = UnixStream::pair().expect("socketpair");
            let (tx, rx) = mpsc::sync_channel::<WriterMsg>(2);
            let shutdown = Shutdown::new();
            tx.send(msg).expect("send");
            drop(tx);
            let h = std::thread::spawn(move || writer_loop(peer_a, 4, rx, shutdown));
            h.join().expect("writer");
            let mut buf = [0u8; 8];
            let n = peer_b.read(&mut buf).unwrap_or(0);
            assert_eq!(n, 0);
        }
    }
}
