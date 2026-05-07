//! Daemon-side error ADT.
//!
//! Every libc / nix call goes through one of these variants. Matching on
//! the variant lets the panic hook, the dispatcher's "should I trigger
//! global shutdown?" decision, and the structured logger all do the right
//! thing without grepping log strings.

use std::fmt;
use std::io;
use std::path::PathBuf;

use testimony_afpacket::AfpacketError;

#[derive(Debug)]
pub enum DaemonError {
    /// Reading the config file from disk failed.
    ConfigRead { path: PathBuf, source: io::Error },
    /// Parsing the config JSON failed.
    ConfigParse { path: PathBuf, reason: String },
    /// The config was syntactically valid but semantically wrong.
    ConfigValidate(String),
    /// AF_PACKET / BPF / mmap setup error from the afpacket crate.
    Afpacket {
        socket_name: String,
        source: AfpacketError,
    },
    /// Removing or binding the unix listener failed.
    Listener {
        path: PathBuf,
        op: &'static str,
        source: io::Error,
    },
    /// `chown` of the unix socket failed (post-bind).
    Chown {
        path: PathBuf,
        uid: u32,
        gid: u32,
        source: io::Error,
    },
    /// `getpwnam_r` failed (or returned not-found) for a configured `User`.
    UserLookup { name: String, source: io::Error },
    /// Configured `User` resolves to no entry.
    UserNotFound { name: String },
    /// `getgrnam_r` failed (or returned not-found) for a configured `Group`.
    GroupLookup { name: String, source: io::Error },
    /// Configured `Group` resolves to no entry.
    GroupNotFound { name: String },
    /// `signal()` or `signal-hook` registration failed.
    SignalSetup {
        which: &'static str,
        source: io::Error,
    },
    /// Spawning a worker thread failed.
    ThreadSpawn { name: String, source: io::Error },
    /// Setting non-blocking on the listener failed.
    SetNonblocking { source: io::Error },
    /// We started shutdown before setup finished.
    ShutdownDuringSetup,
    /// Out of fanout IDs (auto-assignment overflowed u16).
    FanoutIdsExhausted,
    /// Duplicate explicit FanoutID in the config.
    DuplicateFanoutId(u16),
    /// Duplicate SocketName in the config.
    DuplicateSocketName(String),
    /// SCM_RIGHTS sendmsg failed during handshake.
    SendFd {
        socket_name: String,
        source: io::Error,
    },
    /// Constructing a CMSG header for SCM_RIGHTS returned NULL.
    CmsgFirstHdrNull,
    /// CString conversion of a path with NUL byte.
    NulInPath(PathBuf),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::ConfigRead { path, source } => {
                write!(f, "could not read config {}: {source}", path.display())
            }
            DaemonError::ConfigParse { path, reason } => {
                write!(f, "could not parse config {}: {reason}", path.display())
            }
            DaemonError::ConfigValidate(s) => write!(f, "invalid config: {s}"),
            DaemonError::Afpacket { socket_name, source } => {
                write!(f, "AF_PACKET setup for {socket_name}: {source}")
            }
            DaemonError::Listener { path, op, source } => {
                write!(f, "{op} on listener {}: {source}", path.display())
            }
            DaemonError::Chown { path, uid, gid, source } => write!(
                f,
                "chown({}, uid={uid}, gid={gid}) failed: {source}",
                path.display()
            ),
            DaemonError::UserLookup { name, source } => {
                write!(f, "getpwnam_r({name:?}) failed: {source}")
            }
            DaemonError::UserNotFound { name } => write!(f, "user {name:?} not found in /etc/passwd"),
            DaemonError::GroupLookup { name, source } => {
                write!(f, "getgrnam_r({name:?}) failed: {source}")
            }
            DaemonError::GroupNotFound { name } => {
                write!(f, "group {name:?} not found in /etc/group")
            }
            DaemonError::SignalSetup { which, source } => {
                write!(f, "registering signal handler for {which}: {source}")
            }
            DaemonError::ThreadSpawn { name, source } => {
                write!(f, "spawning worker thread {name:?}: {source}")
            }
            DaemonError::SetNonblocking { source } => {
                write!(f, "set_nonblocking on listener: {source}")
            }
            DaemonError::ShutdownDuringSetup => {
                write!(f, "shutdown signal arrived before all sockets were brought up")
            }
            DaemonError::FanoutIdsExhausted => write!(
                f,
                "ran out of fanout IDs while auto-assigning (u16 space exhausted)"
            ),
            DaemonError::DuplicateFanoutId(id) => {
                write!(f, "duplicate FanoutID {id} in config")
            }
            DaemonError::DuplicateSocketName(s) => {
                write!(f, "duplicate SocketName {s:?} in config")
            }
            DaemonError::SendFd { socket_name, source } => {
                write!(f, "sendmsg(SCM_RIGHTS) on {socket_name}: {source}")
            }
            DaemonError::CmsgFirstHdrNull => write!(
                f,
                "CMSG_FIRSTHDR returned NULL on a buffer we sized ourselves \
                 (libc bug or kernel ABI mismatch)"
            ),
            DaemonError::NulInPath(p) => write!(
                f,
                "path {} contains a NUL byte (not a valid C string)",
                p.display()
            ),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DaemonError::ConfigRead { source, .. }
            | DaemonError::Listener { source, .. }
            | DaemonError::Chown { source, .. }
            | DaemonError::UserLookup { source, .. }
            | DaemonError::GroupLookup { source, .. }
            | DaemonError::SignalSetup { source, .. }
            | DaemonError::ThreadSpawn { source, .. }
            | DaemonError::SetNonblocking { source }
            | DaemonError::SendFd { source, .. } => Some(source),
            DaemonError::Afpacket { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Convenience: convert `DaemonError` to `io::Error` with `Other` kind for
/// the few places (e.g. `process::ExitCode` flow) that still want
/// `io::Result`. Preserves the message via `format!("{e:#}")`.
impl From<DaemonError> for io::Error {
    fn from(e: DaemonError) -> Self {
        io::Error::other(format!("{e}"))
    }
}
