//! Shutdown plumbing: a shared atomic flag plus signal & panic handlers
//! that flip it. Workers poll the flag between iterations.
//!
//! Why a panic hook: with `panic = "unwind"` (set in `Cargo.toml`), a
//! thread panic doesn't crash the process — it just unwinds that thread.
//! Without intervention, the rest of the daemon continues running but
//! short one worker. The panic hook flips the shutdown flag so the main
//! thread proceeds to orderly cleanup (munmap the AF_PACKET ring, unlink
//! the .sock files), which is what makes the Rust port a real fix for
//! the "leak /shm on bad shutdown" bug rather than a partial one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::DaemonError;

/// Shared shutdown flag. Workers poll `is_set()` between iterations.
#[derive(Clone, Default)]
pub struct Shutdown(Arc<AtomicBool>);

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Install SIGTERM/SIGINT handlers that flip the shutdown flag,
/// SIG_IGN for SIGPIPE so a closed client connection doesn't kill
/// the daemon, and a panic hook that also flips the flag so a
/// worker panic still drives cleanup.
pub fn install(s: &Shutdown) -> Result<(), DaemonError> {
    install_sigpipe_ignore()?;
    install_panic_hook(s.clone());
    install_signal_watcher(s.clone())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_sigpipe_ignore() -> Result<(), DaemonError> {
    // Without this, writing to a unix socket whose peer just disconnected
    // raises SIGPIPE → default action: terminate. We *must* keep running
    // so we can drive cleanup for the surviving clients.
    // SAFETY: setting a signal handler with SIG_IGN is async-signal-safe.
    let r = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    if r == libc::SIG_ERR {
        return Err(DaemonError::SignalSetup {
            which: "SIGPIPE",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_sigpipe_ignore() -> Result<(), DaemonError> {
    Ok(())
}

fn install_panic_hook(s: Shutdown) {
    // Compose with the previous hook (env_logger may have installed one)
    // so the default panic message still appears in stderr/syslog.
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Keep the original message visible.
        prev(info);
        // Flag a global shutdown: even if this thread is "just" a stats
        // logger that panicked because it printed a malformed format,
        // the ring still needs to come down cleanly. Better to take the
        // whole daemon down than to leave a half-broken one running.
        log::error!(
            "panic in thread {:?}: {info}; flipping shutdown flag",
            std::thread::current().name().unwrap_or("<unnamed>")
        );
        s.set();
    }));
}

fn install_signal_watcher(s: Shutdown) -> Result<(), DaemonError> {
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])
    .map_err(|source| DaemonError::SignalSetup {
        which: "SIGTERM/SIGINT",
        source,
    })?;
    std::thread::Builder::new()
        .name("signal-watch".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                log::info!("received signal {sig}, shutting down");
                s.set();
            }
        })
        .map_err(|source| DaemonError::ThreadSpawn {
            name: "signal-watch".into(),
            source,
        })?;
    Ok(())
}
