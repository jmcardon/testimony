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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn shutdown_starts_unset() {
        let s = Shutdown::new();
        assert!(!s.is_set());
    }

    #[test]
    fn shutdown_set_is_observable() {
        let s = Shutdown::new();
        s.set();
        assert!(s.is_set());
    }

    #[test]
    fn shutdown_set_is_idempotent() {
        let s = Shutdown::new();
        s.set();
        s.set();
        s.set();
        assert!(s.is_set());
    }

    /// Cloned Shutdown shares state — flipping one observed by the other.
    /// This is what makes the dispatcher / accept_loop / writer threads
    /// agree on shutdown.
    #[test]
    fn shutdown_clones_share_state() {
        let s1 = Shutdown::new();
        let s2 = s1.clone();
        assert!(!s2.is_set());
        s1.set();
        assert!(s2.is_set());
    }

    /// Many threads polling is_set() while one sets — every observer
    /// eventually sees true. SeqCst ordering is what guarantees this.
    #[test]
    fn shutdown_visible_across_threads() {
        let s = Shutdown::new();
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total: usize = 8;
        let mut handles = Vec::with_capacity(total);
        for _ in 0..total {
            let s_clone = s.clone();
            let obs = observed.clone();
            handles.push(std::thread::spawn(move || {
                while !s_clone.is_set() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                obs.fetch_add(1, Ordering::SeqCst);
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        s.set();
        for h in handles {
            h.join().expect("observer");
        }
        assert_eq!(observed.load(Ordering::SeqCst), total);
    }
}
