//! Testimony client library.
//!
//! Provides a Rust-native `Conn` / `Block` API and (on Linux) a `cdylib`
//! ABI compatible with `c/testimony.h`, so existing C consumers re-link
//! against `libtestimony.so` and keep working unchanged.

#[cfg(target_os = "linux")]
pub mod conn;
#[cfg(target_os = "linux")]
pub mod ffi;

#[cfg(target_os = "linux")]
pub use conn::*;
