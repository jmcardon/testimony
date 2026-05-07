//! Daemon server: brings everything together.
//!
//! Per `SocketConfig`:
//!  * Build `FanoutSize` `CaptureSocket`s (one AF_PACKET fd + ring each).
//!  * Spawn one "block dispatcher" thread per CaptureSocket that watches
//!    for kernel-ready blocks and pushes BlockTickets to all attached
//!    client writers.
//!  * Spawn one accept thread per AF_UNIX listener that performs the
//!    handshake, picks the requested fanout sub-socket, sends the fd via
//!    SCM_RIGHTS, and registers the client with that sub-socket's
//!    dispatcher.
//!
//! Shutdown invariants:
//!  * SIGTERM/SIGINT, a thread panic, or any worker error path flips the
//!    global `shutdown` flag.
//!  * On the way out we drop `UnlinkOnDrop` guards (.sock files removed),
//!    telegraph `WriterMsg::Shutdown` to every connected writer, join
//!    every worker thread (with a deadline), then drop the FanoutSlots so
//!    the AF_PACKET ring is munmap'd before the fd is closed.
//!  * The `Workers` struct's Drop runs the cleanup function as a fallback
//!    so that even a stack unwind from a panic still releases the ring.
//!  * Combined with `panic = "unwind"` in Cargo.toml and the panic hook
//!    in `shutdown.rs`, every shutdown path that doesn't involve SIGKILL
//!    ends with the kernel ring released.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use testimony_afpacket::{compile_bpf, create_capture_socket, CaptureConfig, CaptureSocket};
use testimony_protocol::{
    self as proto, PROTOCOL_VERSION, TYPE_BLOCK_SIZE, TYPE_FANOUT_INDEX, TYPE_FANOUT_SIZE,
    TYPE_NUM_BLOCKS, TYPE_WAITING_FOR_FANOUT_INDEX,
};

use crate::config::{self, SocketConfig};
use crate::conn::{self, BlockTicket, WriterMsg};
use crate::error::DaemonError;
use crate::shutdown::{self, Shutdown};

/// Removes a unix socket path on drop. Triggered on graceful shutdown so
/// systemd / install scripts don't see leftover stale .sock files.
struct UnlinkOnDrop(PathBuf);
impl Drop for UnlinkOnDrop {
    fn drop(&mut self) {
        if self.0.exists() {
            if let Err(e) = fs::remove_file(&self.0) {
                log::warn!("failed to unlink {}: {e}", self.0.display());
            }
        }
    }
}

/// Sender into a single client's writer thread. Bounded so a slow client
/// can't balloon memory; matches the Go bounded `chan *block` of size
/// `len(s.blocks)` and its non-blocking `select { default: unref }` semantics.
type ClientTx = mpsc::SyncSender<WriterMsg>;

/// Per-fanout-sub-socket dispatch state: the capture socket plus the live
/// set of attached client writers.
struct FanoutSlot {
    sock: Arc<CaptureSocket>,
    clients: Mutex<HashMap<u64, ClientTx>>,
    next_client_id: AtomicU64,
}

impl FanoutSlot {
    fn new(sock: CaptureSocket) -> Arc<Self> {
        Arc::new(Self {
            sock: Arc::new(sock),
            clients: Mutex::new(HashMap::new()),
            next_client_id: AtomicU64::new(1),
        })
    }

    fn register(&self, tx: ClientTx) -> u64 {
        let id = self.next_client_id.fetch_add(1, Ordering::Relaxed);
        // PoisonError just means another thread panicked while holding the
        // lock; the inner state is still readable. Recover and continue.
        let mut clients = match self.clients.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        clients.insert(id, tx);
        id
    }

    fn unregister(&self, id: u64) {
        let mut clients = match self.clients.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        clients.remove(&id);
    }

    /// Snapshot the current client set into a caller-owned `Vec`,
    /// reusing its allocation. Called per-block from `dispatch_loop`,
    /// so allocating a fresh Vec each call would be ~1 alloc per block
    /// at multi-100k blocks/sec. The dispatcher passes in a buffer it
    /// owns; we `clear()` then `extend` from the locked map.
    fn snapshot_clients_into(&self, out: &mut Vec<ClientTx>) {
        out.clear();
        let clients = match self.clients.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        out.extend(clients.values().cloned());
    }
}

pub fn run(config_path: &Path) -> Result<(), DaemonError> {
    let cfgs = config::load(config_path)?;
    if cfgs.is_empty() {
        return Err(DaemonError::ConfigValidate(
            "config is empty — no sockets to serve".into(),
        ));
    }
    // Set umask so any sockets we create are 0600.
    // SAFETY: umask is a process-wide setting; we set it once at startup.
    unsafe {
        libc::umask(0o177);
    }

    let mut names = std::collections::HashSet::new();
    for c in &cfgs {
        if !names.insert(c.socket_name.clone()) {
            return Err(DaemonError::DuplicateSocketName(c.socket_name.clone()));
        }
    }
    let fanout_ids = config::assign_fanout_ids(&cfgs)?;

    let shutdown = Shutdown::new();
    shutdown::install(&shutdown)?;

    // Workers carries every owned resource. Its Drop runs cleanup as a
    // belt-and-braces guarantee that even on panic-driven unwind the
    // AF_PACKET ring goes away.
    let mut workers = Workers::new(shutdown.clone());
    let result = setup_and_wait(&cfgs, &fanout_ids, &shutdown, &mut workers);
    if result.is_err() {
        // Trigger shutdown so any partially-spawned workers wind down.
        shutdown.set();
    }
    // Run cleanup explicitly so it logs nicely. The Workers Drop is still
    // present as a fallback for the panic-unwind path.
    workers.cleanup();
    result
}

/// Worker state held across run_inner — kept outside the setup loop so we
/// can run cleanup even if setup errored partway through.
struct Workers {
    handles: Vec<thread::JoinHandle<()>>,
    listener_guards: Vec<UnlinkOnDrop>,
    slots: Vec<Arc<FanoutSlot>>,
    shutdown: Shutdown,
    cleaned_up: bool,
}

impl Workers {
    fn new(shutdown: Shutdown) -> Self {
        Self {
            handles: Vec::new(),
            listener_guards: Vec::new(),
            slots: Vec::new(),
            shutdown,
            cleaned_up: false,
        }
    }

    /// Run shutdown: unlink .sock files, telegraph Shutdown to writers,
    /// join workers (with deadline), drop slots → munmap+close.
    fn cleanup(&mut self) {
        if self.cleaned_up {
            return;
        }
        self.cleaned_up = true;

        log::info!("shutdown requested; releasing AF_PACKET rings and worker threads");

        // Make sure every worker sees the flag (idempotent).
        self.shutdown.set();

        // Drop listener guards first so the .sock files go away even if
        // joins hang. Take ownership of the Vec via mem::take.
        let guards = std::mem::take(&mut self.listener_guards);
        drop(guards);

        // Tell every connected client writer to stop. Non-blocking: if the
        // inbox is full we don't care — the writer will see Shutdown next,
        // or exit when its peer reads/writes fail at socket teardown.
        // Cleanup runs once per process shutdown, so allocating a fresh
        // Vec here is fine (no hot-path concern).
        let mut buf: Vec<ClientTx> = Vec::new();
        for slot in &self.slots {
            slot.snapshot_clients_into(&mut buf);
            for tx in buf.drain(..) {
                let _ = tx.try_send(WriterMsg::Shutdown);
            }
        }

        // Best-effort joins. Set a deadline so a wedged thread can't block
        // forever; under the deadline we abandon the remaining handles. The
        // OS will reap detached threads at process exit.
        let join_deadline = std::time::Instant::now() + Duration::from_secs(3);
        let handles = std::mem::take(&mut self.handles);
        for h in handles {
            let now = std::time::Instant::now();
            if now >= join_deadline {
                log::warn!(
                    "join deadline reached; abandoning remaining workers (process exit will reap)"
                );
                break;
            }
            // We can't join with a timeout in std; rely on the workers
            // checking shutdown.is_set() promptly.
            let _ = h.join();
        }

        // Drop slots → drops Arc<CaptureSocket> → munmap + close fd. The
        // dispatcher and writer threads each held an Arc<CaptureSocket>;
        // once they exit, this drop is what actually releases the kernel
        // ring. Use mem::take so the Drop impl on Workers (if it runs
        // again via panic-unwind path) sees an empty Vec.
        let slots = std::mem::take(&mut self.slots);
        drop(slots);

        log::info!("testimonyd shut down cleanly");
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        // Fallback for the panic-unwind path: if `run` panicked before
        // calling cleanup() explicitly, we still get here on stack unwind
        // and release the ring.
        if !self.cleaned_up {
            self.cleanup();
        }
    }
}

fn setup_and_wait(
    cfgs: &[SocketConfig],
    fanout_ids: &[u16],
    shutdown: &Shutdown,
    workers: &mut Workers,
) -> Result<(), DaemonError> {
    for (cfg, fanout_id) in cfgs.iter().zip(fanout_ids.iter().copied()) {
        if shutdown.is_set() {
            return Err(DaemonError::ShutdownDuringSetup);
        }
        // Compile filter once per config.
        let filter = if cfg.filter.is_empty() {
            None
        } else {
            Some(compile_bpf(&cfg.interface, &cfg.filter).map_err(|e| {
                DaemonError::Afpacket {
                    socket_name: cfg.socket_name.clone(),
                    source: e,
                }
            })?)
        };

        // Build FanoutSize capture sockets and dispatcher threads.
        let mut slots: Vec<Arc<FanoutSlot>> = Vec::with_capacity(cfg.fanout_size as usize);
        for _i in 0..cfg.fanout_size {
            let cap_cfg = CaptureConfig {
                iface: cfg.interface.clone(),
                block_size: cfg.block_size,
                num_blocks: cfg.num_blocks,
                block_timeout_ms: cfg.block_timeout_millis,
                fanout_id,
                fanout_size: cfg.fanout_size,
                fanout_type: cfg.fanout_type,
                bpf_filter: filter.clone(),
            };
            let sock = create_capture_socket(&cap_cfg).map_err(|e| DaemonError::Afpacket {
                socket_name: cfg.socket_name.clone(),
                source: e,
            })?;
            log::info!(
                "{} fanout-slot capture socket up: block_size={} num_blocks={} fanout_id={}",
                cfg.socket_name,
                cfg.block_size,
                cfg.num_blocks,
                fanout_id
            );
            let slot = FanoutSlot::new(sock);
            slots.push(slot.clone());
            workers.slots.push(slot.clone());
            let stats_slot = slot.clone();

            // Dispatcher thread: scan blocks, hand BlockTickets to all clients.
            let s_for_thread = shutdown.clone();
            let dispatcher_name = format!("dispatch-{}", cfg.socket_name);
            let h = thread::Builder::new()
                .name(dispatcher_name.clone())
                .spawn(move || dispatch_loop(slot, s_for_thread))
                .map_err(|source| DaemonError::ThreadSpawn {
                    name: dispatcher_name,
                    source,
                })?;
            workers.handles.push(h);

            // Stats logger thread (best-effort).
            let s_for_stats = shutdown.clone();
            let socket_name_for_log = cfg.socket_name.clone();
            let stats_name = format!("stats-{}", cfg.socket_name);
            let h = thread::Builder::new()
                .name(stats_name.clone())
                .spawn(move || stats_loop(stats_slot, s_for_stats, socket_name_for_log))
                .map_err(|source| DaemonError::ThreadSpawn {
                    name: stats_name,
                    source,
                })?;
            workers.handles.push(h);
        }

        // Set up the AF_UNIX listener for this socket name.
        let sock_path = PathBuf::from(&cfg.socket_name);
        // Stale leftover from a previous run? Unlink (best-effort).
        let _ = fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).map_err(|source| DaemonError::Listener {
            path: sock_path.clone(),
            op: "bind",
            source,
        })?;
        // Push the unlink guard immediately so even if the next steps fail,
        // we'll clean up the .sock file on shutdown.
        workers.listener_guards.push(UnlinkOnDrop(sock_path.clone()));
        set_socket_permissions(&sock_path, cfg)?;

        // Set listener non-blocking so accept can poll the shutdown flag.
        listener
            .set_nonblocking(true)
            .map_err(|source| DaemonError::SetNonblocking { source })?;

        let slots_for_accept = slots;
        let cfg_for_accept = cfg.clone();
        let s_for_accept = shutdown.clone();
        let accept_name = format!("accept-{}", cfg.socket_name);
        let h = thread::Builder::new()
            .name(accept_name.clone())
            .spawn(move || {
                accept_loop(listener, slots_for_accept, cfg_for_accept, s_for_accept);
            })
            .map_err(|source| DaemonError::ThreadSpawn {
                name: accept_name,
                source,
            })?;
        workers.handles.push(h);
    }

    // Wait for shutdown: poll the flag. Once set, cleanup runs (in run).
    while !shutdown.is_set() {
        thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

fn set_socket_permissions(path: &Path, cfg: &SocketConfig) -> Result<(), DaemonError> {
    let uid = lookup_uid(&cfg.user)?;
    let gid = lookup_gid(&cfg.group)?;
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| DaemonError::NulInPath(path.to_owned()))?;
    // SAFETY: c is a valid CString; uid/gid are valid IDs.
    let r = unsafe { libc::chown(c.as_ptr(), uid, gid) };
    if r < 0 {
        return Err(DaemonError::Chown {
            path: path.to_owned(),
            uid,
            gid,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

fn lookup_uid(user: &str) -> Result<u32, DaemonError> {
    if user.is_empty() {
        // SAFETY: getuid is always safe; returns the current real uid.
        return Ok(unsafe { libc::getuid() });
    }
    let c = CString::new(user).map_err(|_| DaemonError::UserLookup {
        name: user.to_owned(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "user name contains a NUL byte",
        ),
    })?;
    let mut buf = vec![0u8; 4096];
    // SAFETY: passwd is plain old data; zero-init is valid.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: pointers are valid for the duration of the call.
    let r = unsafe {
        libc::getpwnam_r(
            c.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if r != 0 {
        return Err(DaemonError::UserLookup {
            name: user.to_owned(),
            source: std::io::Error::from_raw_os_error(r),
        });
    }
    if result.is_null() {
        return Err(DaemonError::UserNotFound {
            name: user.to_owned(),
        });
    }
    Ok(pwd.pw_uid)
}

fn lookup_gid(group: &str) -> Result<u32, DaemonError> {
    if group.is_empty() {
        // Match the Go daemon: an unspecified Group chowns to gid 0 (root).
        // (See `SocketConfig.gid` in go/testimonyd/internal/socket/daemon.go.)
        return Ok(0);
    }
    let c = CString::new(group).map_err(|_| DaemonError::GroupLookup {
        name: group.to_owned(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "group name contains a NUL byte",
        ),
    })?;
    let mut buf = vec![0u8; 4096];
    // SAFETY: group is plain old data; zero-init is valid.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: pointers are valid for the duration of the call.
    let r = unsafe {
        libc::getgrnam_r(
            c.as_ptr(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if r != 0 {
        return Err(DaemonError::GroupLookup {
            name: group.to_owned(),
            source: std::io::Error::from_raw_os_error(r),
        });
    }
    if result.is_null() {
        return Err(DaemonError::GroupNotFound {
            name: group.to_owned(),
        });
    }
    Ok(grp.gr_gid)
}

/// Block dispatch: walk the ring in order. When a block becomes ready,
/// hand a `BlockTicket` to each currently-attached client writer; if a
/// writer's bounded queue is full, drop the ticket (releases that block's
/// reference).
///
/// Any error path also flips the global shutdown flag (audit B3) — leaving
/// the daemon running with a dead dispatcher would zombify the listener
/// for that socket without any externally visible signal.
fn dispatch_loop(slot: Arc<FanoutSlot>, shutdown: Shutdown) {
    let n = slot.sock.num_blocks();
    if n == 0 {
        log::error!(
            "dispatcher: num_blocks=0 for socket; create_capture_socket should have rejected this"
        );
        shutdown.set();
        return;
    }
    let mut idx: u32 = 0;
    // Reusable client-snapshot buffer. The dispatcher hits this per
    // block; allocating a fresh Vec each iteration would be ~1 alloc
    // per block at multi-100k blocks/sec. Capacity is preserved across
    // iterations via `Vec::clear` (inside `snapshot_clients_into`), so
    // steady-state is zero allocations per block.
    let mut clients_buf: Vec<ClientTx> = Vec::with_capacity(16);
    while !shutdown.is_set() {
        // Wait for this block to become ready.
        loop {
            if shutdown.is_set() {
                return;
            }
            let Some(refs) = slot.sock.refs(idx) else {
                log::error!(
                    "dispatcher: refs(idx={idx}) returned None despite num_blocks={n}; \
                     triggering global shutdown"
                );
                shutdown.set();
                return;
            };
            let our_refs = refs.load(std::sync::atomic::Ordering::SeqCst);
            // Match Go's `block.ready()`: refcount==0 AND kernel block_status != 0.
            if our_refs == 0 && slot.sock.block_status(idx) != 0 {
                break;
            }
            if let Err(e) = slot.sock.wait_for_blocks() {
                // EINTR was already swallowed; anything else is a real error.
                log::error!(
                    "dispatcher: wait_for_blocks failed: {e}; triggering global shutdown"
                );
                shutdown.set();
                return;
            }
        }

        // Fanout: push a ticket to every connected client. The "anchor"
        // ticket below holds an extra ref while we iterate, so we never
        // race the kernel reclaiming the block mid-fanout.
        let Some(anchor) = BlockTicket::new(slot.sock.clone(), idx) else {
            log::error!(
                "dispatcher: BlockTicket::new returned None for idx={idx}; \
                 triggering global shutdown"
            );
            shutdown.set();
            return;
        };
        slot.snapshot_clients_into(&mut clients_buf);
        for tx in clients_buf.drain(..) {
            let Some(ticket) = BlockTicket::new(slot.sock.clone(), idx) else {
                // The anchor proved idx is in range; if a fresh ticket
                // can't be made, refcount overflowed — bail instead of
                // partially fanning out.
                log::error!("dispatcher: per-client BlockTicket::new returned None for idx={idx}");
                continue;
            };
            // Non-blocking send: if the client's bounded inbox is full,
            // drop the ticket. Matches Go's `select{ default: b.unref() }`.
            match tx.try_send(WriterMsg::NewBlock(ticket)) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(msg)) => {
                    log::debug!("slow client: dropping ticket (inbox full)");
                    drop(msg); // BlockTicket inside drops here → refcount--
                }
                Err(mpsc::TrySendError::Disconnected(msg)) => {
                    log::debug!("client disconnected; dropping ticket");
                    drop(msg);
                }
            }
        }
        drop(anchor);

        // wrapping_add + modulo: if a hostile config set num_blocks =
        // u32::MAX and idx ever reached u32::MAX-1, plain `idx + 1` would
        // panic in debug builds. wrapping_add then `% n` always yields a
        // valid index in [0, n).
        idx = idx.wrapping_add(1) % n;
    }
}

fn stats_loop(slot: Arc<FanoutSlot>, shutdown: Shutdown, name: String) {
    // Initial read clears counters.
    let _ = slot.sock.stats();
    let interval = Duration::from_secs(60);
    let mut last = std::time::Instant::now();
    let mut total_packets: u64 = 0;
    let mut total_drops: u64 = 0;
    while !shutdown.is_set() {
        thread::sleep(Duration::from_millis(500));
        if last.elapsed() < interval {
            continue;
        }
        last = std::time::Instant::now();
        match slot.sock.stats() {
            Ok(s) => {
                total_packets = total_packets.saturating_add(s.tp_packets as u64);
                total_drops = total_drops.saturating_add(s.tp_drops as u64);
                let sum = (s.tp_packets as u64) + (s.tp_drops as u64);
                let denom = sum.max(1) as f64;
                log::info!(
                    "{name} stats: {pkts} pkts ({pps:.2}/s), {drops} drops ({dpps:.2}/s, \
                     {dpct:.2}%); total {tp} pkts, {td} drops",
                    pkts = s.tp_packets,
                    pps = s.tp_packets as f64 / 60.0,
                    drops = s.tp_drops,
                    dpps = s.tp_drops as f64 / 60.0,
                    dpct = (s.tp_drops as f64) / denom * 100.0,
                    tp = total_packets,
                    td = total_drops
                );
            }
            // Stats failures are not fatal; the dispatcher and accept loops
            // keep going. We don't trigger global shutdown for these — losing
            // visibility is preferable to losing service.
            Err(e) => log::warn!("{name} stats error: {e}"),
        }
    }
}

/// Accept loop: handshake new clients, pass them to the requested fanout slot.
///
/// Like the dispatcher, any error path triggers global shutdown so the
/// daemon doesn't zombie-out (audit B3).
fn accept_loop(
    listener: UnixListener,
    slots: Vec<Arc<FanoutSlot>>,
    cfg: SocketConfig,
    shutdown: Shutdown,
) {
    while !shutdown.is_set() {
        match listener.accept() {
            Ok((stream, _)) => {
                let slots = slots.clone();
                let cfg = cfg.clone();
                let s = shutdown.clone();
                let name = cfg.socket_name.clone();
                if let Err(e) = thread::Builder::new()
                    .name(format!("conn-{}", name))
                    .spawn(move || handle_new_connection(stream, slots, cfg, s))
                {
                    // If we can't spawn a connection thread, the system is
                    // too constrained to keep accepting. Trigger shutdown.
                    log::error!(
                        "failed to spawn conn thread for {name}: {e}; triggering shutdown"
                    );
                    shutdown.set();
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                log::error!(
                    "accept on {} failed: {e}; triggering global shutdown",
                    cfg.socket_name
                );
                shutdown.set();
                return;
            }
        }
    }
}

/// Perform the handshake on a freshly accepted connection, then hand off to
/// the per-fanout dispatcher.
///
/// Errors here do NOT trigger global shutdown — a misbehaving client
/// shouldn't be able to take the daemon down.
fn handle_new_connection(
    stream: UnixStream,
    slots: Vec<Arc<FanoutSlot>>,
    cfg: SocketConfig,
    shutdown: Shutdown,
) {
    if let Err(e) = stream.set_nonblocking(false) {
        log::warn!("failed to set blocking on new conn for {}: {e}", cfg.socket_name);
        return;
    }
    let mut s = stream;
    let conf0 = &cfg;

    // 1. Send protocol version (1 byte).
    if let Err(e) = std::io::Write::write_all(&mut s, &[PROTOCOL_VERSION]) {
        log::debug!("send version failed: {e}");
        return;
    }

    // 2. Send TLVs: FanoutSize, BlockSize, NumBlocks, then WaitingForFanoutIndex.
    if let Err(e) = send_tlv_u32(&mut s, TYPE_FANOUT_SIZE, slots.len() as u32) {
        log::debug!("handshake send FanoutSize failed: {e}");
        return;
    }
    if let Err(e) = send_tlv_u32(&mut s, TYPE_BLOCK_SIZE, conf0.block_size) {
        log::debug!("handshake send BlockSize failed: {e}");
        return;
    }
    if let Err(e) = send_tlv_u32(&mut s, TYPE_NUM_BLOCKS, conf0.num_blocks) {
        log::debug!("handshake send NumBlocks failed: {e}");
        return;
    }
    if let Err(e) = send_tlv_empty(&mut s, TYPE_WAITING_FOR_FANOUT_INDEX) {
        log::debug!("handshake send WaitingForFanoutIndex failed: {e}");
        return;
    }

    // 3. Read fanout-index TLV (8 bytes: 4 TL + 4 value).
    let mut hdr = [0u8; 8];
    if let Err(e) = std::io::Read::read_exact(&mut s, &mut hdr) {
        log::debug!("client closed before sending fanout index ({e})");
        return;
    }
    // hdr is exactly 8 bytes; these slice indices are statically in range.
    let tl = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let val = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    if tl != proto::to_tl(TYPE_FANOUT_INDEX, 4) {
        log::warn!(
            "client on {} sent unexpected fanout-index header {tl:#x} (expected {:#x})",
            cfg.socket_name,
            proto::to_tl(TYPE_FANOUT_INDEX, 4)
        );
        return;
    }
    let idx = val as usize;
    let Some(slot) = slots.get(idx).cloned() else {
        log::warn!(
            "client on {} requested invalid fanout index {idx} (have {} slots)",
            cfg.socket_name,
            slots.len()
        );
        return;
    };

    // 4. Send the AF_PACKET fd via SCM_RIGHTS along with one dummy byte.
    if let Err(e) = send_fd(&s, slot.sock.raw_fd()) {
        log::warn!("fd-passing on {} failed: {e}", cfg.socket_name);
        return;
    }

    // 5. Spawn reader; run writer on this thread.
    //    Bounded channel (size = num_blocks) lets the dispatcher drop tickets
    //    on overflow rather than balloon memory under a slow client.
    let num_blocks = slot.sock.num_blocks();
    let (writer_tx, writer_rx) = mpsc::sync_channel::<WriterMsg>(num_blocks as usize);

    let id = slot.register(writer_tx.clone());

    let reader_stream = match s.try_clone() {
        Ok(c) => c,
        Err(e) => {
            log::error!("failed to clone stream for {}: {e}", cfg.socket_name);
            slot.unregister(id);
            return;
        }
    };
    // Keep a third clone so we can call `shutdown(SHUT_RD)` on the reader's
    // socket from this thread when the writer exits. Without it, the
    // reader blocks in `read()` until the *client* disconnects, which
    // can be much later — and during a daemon shutdown that's unbounded.
    let reader_kicker = match s.try_clone() {
        Ok(c) => c,
        Err(e) => {
            log::error!(
                "failed to clone reader-kicker stream for {}: {e}",
                cfg.socket_name
            );
            slot.unregister(id);
            return;
        }
    };
    let reader_tx = writer_tx.clone();
    let s_for_reader = shutdown.clone();
    let r_h = thread::Builder::new()
        .name("conn-reader".into())
        .spawn(move || conn::reader_loop(reader_stream, num_blocks, reader_tx, s_for_reader));
    let r_h = match r_h {
        Ok(h) => h,
        Err(e) => {
            log::error!("failed to spawn reader for {}: {e}", cfg.socket_name);
            slot.unregister(id);
            return;
        }
    };

    // Drop our local writer_tx clone so the channel naturally disconnects
    // when the dispatcher and reader both go away.
    drop(writer_tx);

    // Run the writer on this thread.
    conn::writer_loop(s, num_blocks, writer_rx, shutdown);

    // Wake the reader: half-shutdown its socket. `shutdown(SHUT_RD)` makes
    // pending and future reads return EOF, which the reader_loop handles
    // by sending PeerClosed and exiting. This is what lets us actually
    // join the reader (instead of detaching it and praying), so a daemon
    // shutdown can release every resource even when clients haven't
    // noticed yet. Best-effort — if shutdown(2) fails the worst case is
    // the OS-level reap-on-process-exit fallback.
    use std::os::fd::AsRawFd;
    // SAFETY: reader_kicker.as_raw_fd() is a valid socket fd we own.
    let r = unsafe { libc::shutdown(reader_kicker.as_raw_fd(), libc::SHUT_RD) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        log::debug!(
            "shutdown(SHUT_RD) on reader-kicker (fd={}) failed: {e} \
             (reader will exit when peer disconnects)",
            reader_kicker.as_raw_fd()
        );
    }
    drop(reader_kicker);
    // Now the reader is unblocked; join with a short deadline so a wedge
    // doesn't stall connection teardown.
    let _ = r_h.join();
    slot.unregister(id);
}

fn send_tlv_u32(s: &mut UnixStream, typ: u16, v: u32) -> std::io::Result<()> {
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&proto::to_tl(typ, 4).to_be_bytes());
    buf[4..].copy_from_slice(&v.to_be_bytes());
    std::io::Write::write_all(s, &buf)
}

fn send_tlv_empty(s: &mut UnixStream, typ: u16) -> std::io::Result<()> {
    std::io::Write::write_all(s, &proto::to_tl(typ, 0).to_be_bytes())
}

/// `cmsghdr` requires `size_t` alignment on Linux. A bare `[u8; N]`
/// has 1-byte alignment, so we wrap it in a `repr(C)` union with a
/// `cmsghdr` placeholder — same trick `nix` and `tokio-uds` use.
#[repr(C)]
union AlignedCmsgBuf {
    _align: libc::cmsghdr,
    bytes: [u8; cmsg_space::<libc::c_int>()],
}

fn send_fd(s: &UnixStream, fd: std::os::fd::RawFd) -> Result<(), DaemonError> {
    use std::os::fd::AsRawFd as _;

    let dummy: [u8; 1] = [0];
    let mut iov = libc::iovec {
        iov_base: dummy.as_ptr() as *mut _,
        iov_len: 1,
    };
    // Properly-aligned cmsg buffer.
    let mut cmsg_buf = AlignedCmsgBuf {
        bytes: [0u8; cmsg_space::<libc::c_int>()],
    };
    // SAFETY: msghdr is plain old data; zero-init is valid.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: bytes is the same allocation as the union; aligned to cmsghdr
    // through `_align`. Buffer outlives the `sendmsg` call below.
    msg.msg_control = unsafe { cmsg_buf.bytes.as_mut_ptr() }.cast();
    msg.msg_controllen = unsafe { cmsg_buf.bytes.len() } as _;

    // Fill in cmsg header by hand (CMSG_FIRSTHDR + CMSG_DATA equivalents).
    // SAFETY: cmsg_buf is sized for exactly one int via `cmsg_space::<i32>()`
    // and aligned for cmsghdr access via the union.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(DaemonError::CmsgFirstHdrNull);
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        // CMSG_DATA's natural alignment is platform-dependent; use
        // write_unaligned to stay sound on stricter ABIs.
        let data_ptr = libc::CMSG_DATA(cmsg).cast::<libc::c_int>();
        std::ptr::write_unaligned(data_ptr, fd);
    }

    // Retry on EINTR so a stray signal doesn't drop the handshake.
    loop {
        // SAFETY: msg is fully initialized above; iov + cmsg_buf outlive the call.
        let n = unsafe { libc::sendmsg(s.as_raw_fd(), &msg, 0) };
        if n >= 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(DaemonError::SendFd {
            socket_name: format!("fd={}", s.as_raw_fd()),
            source: e,
        });
    }
}

const fn cmsg_space<T>() -> usize {
    // Match CMSG_SPACE: align cmsghdr+data to size_t boundary.
    let cmsghdr = std::mem::size_of::<libc::cmsghdr>();
    let align = std::mem::size_of::<usize>();
    let total = cmsghdr + std::mem::size_of::<T>();
    (total + align - 1) & !(align - 1)
}
