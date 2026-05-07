//! Daemon configuration loaded from JSON.
//!
//! Field names mirror the Go daemon (`SocketName`, `Interface`, …) so the
//! same config file works against both binaries — that's the whole point
//! of being hot-swappable.

use serde::Deserialize;
use std::fs;
use std::path::Path;

use crate::error::DaemonError;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketConfig {
    #[serde(rename = "SocketName")]
    pub socket_name: String,
    #[serde(rename = "Interface")]
    pub interface: String,
    #[serde(rename = "BlockSize")]
    pub block_size: u32,
    #[serde(rename = "NumBlocks")]
    pub num_blocks: u32,
    #[serde(rename = "BlockTimeoutMillis")]
    pub block_timeout_millis: u32,
    #[serde(rename = "FanoutType", default)]
    pub fanout_type: u16,
    #[serde(rename = "FanoutSize", default)]
    pub fanout_size: u16,
    #[serde(rename = "FanoutID", default)]
    pub fanout_id: u16,
    #[serde(rename = "User", default)]
    pub user: String,
    #[serde(rename = "Group", default)]
    pub group: String,
    #[serde(rename = "Filter", default)]
    pub filter: String,
}

pub fn load(path: &Path) -> Result<Vec<SocketConfig>, DaemonError> {
    let bytes = fs::read(path).map_err(|source| DaemonError::ConfigRead {
        path: path.to_owned(),
        source,
    })?;
    let mut cfgs: Vec<SocketConfig> = serde_json::from_slice(&bytes).map_err(|e| {
        DaemonError::ConfigParse {
            path: path.to_owned(),
            reason: format!("{e}"),
        }
    })?;
    // Match the Go daemon: FanoutSize 0 → 1.
    for c in cfgs.iter_mut() {
        if c.fanout_size == 0 {
            c.fanout_size = 1;
        }
        // Validate non-zero ring dimensions early; AF_PACKET would otherwise
        // surface a confusing EINVAL way down the call stack.
        if c.block_size == 0 {
            return Err(DaemonError::ConfigValidate(format!(
                "{}: BlockSize must be > 0",
                c.socket_name
            )));
        }
        if c.num_blocks == 0 {
            return Err(DaemonError::ConfigValidate(format!(
                "{}: NumBlocks must be > 0",
                c.socket_name
            )));
        }
        if c.interface.is_empty() {
            return Err(DaemonError::ConfigValidate(format!(
                "{}: Interface must be specified",
                c.socket_name
            )));
        }
    }
    Ok(cfgs)
}

/// Pick fanout IDs the same way the Go daemon does:
/// honor explicit non-zero IDs; auto-assign starting at 1, skipping
/// any ID claimed manually.
pub fn assign_fanout_ids(cfgs: &[SocketConfig]) -> Result<Vec<u16>, DaemonError> {
    use std::collections::HashSet;
    let mut claimed: HashSet<u16> = HashSet::new();
    for c in cfgs {
        if c.fanout_id > 0 && !claimed.insert(c.fanout_id) {
            return Err(DaemonError::DuplicateFanoutId(c.fanout_id));
        }
    }
    let mut auto: u16 = 1;
    let mut out = Vec::with_capacity(cfgs.len());
    for c in cfgs {
        if c.fanout_id > 0 {
            out.push(c.fanout_id);
        } else {
            while claimed.contains(&auto) {
                auto = auto
                    .checked_add(1)
                    .ok_or(DaemonError::FanoutIdsExhausted)?;
            }
            out.push(auto);
            claimed.insert(auto);
            // saturating_add is correct here: if `auto` is already u16::MAX,
            // the next iteration will trigger the contains-check loop and
            // either find a free slot below or hit FanoutIdsExhausted via
            // checked_add.
            auto = auto.saturating_add(1);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: u16) -> SocketConfig {
        SocketConfig {
            socket_name: String::new(),
            interface: String::from("eth0"),
            block_size: 1024,
            num_blocks: 1,
            block_timeout_millis: 0,
            fanout_type: 0,
            fanout_size: 1,
            fanout_id: id,
            user: String::new(),
            group: String::new(),
            filter: String::new(),
        }
    }

    /// Mirrors `RunTestimony` in `go/testimonyd/internal/socket/daemon.go:91-124`:
    /// auto-IDs start at 1, skip explicit reservations.
    #[test]
    fn fanout_ids_auto_assign_skips_reserved() {
        let v = vec![cfg(0), cfg(0), cfg(3), cfg(0)];
        let out = assign_fanout_ids(&v).expect("assign");
        assert_eq!(out, vec![1, 2, 3, 4]);
    }

    #[test]
    fn fanout_ids_auto_jumps_over_taken() {
        let v = vec![cfg(2), cfg(0), cfg(0)];
        let out = assign_fanout_ids(&v).expect("assign");
        assert_eq!(out, vec![2, 1, 3]);
    }

    #[test]
    fn fanout_ids_duplicate_explicit_rejected() {
        let v = vec![cfg(5), cfg(5)];
        let err = assign_fanout_ids(&v).expect_err("dup");
        assert!(matches!(err, DaemonError::DuplicateFanoutId(5)));
    }

    #[test]
    fn fanout_ids_all_explicit() {
        let v = vec![cfg(7), cfg(11), cfg(2)];
        assert_eq!(assign_fanout_ids(&v).expect("assign"), vec![7, 11, 2]);
    }

    #[test]
    fn fanout_ids_all_auto() {
        let v = vec![cfg(0), cfg(0), cfg(0)];
        assert_eq!(assign_fanout_ids(&v).expect("assign"), vec![1, 2, 3]);
    }

    /// Operator-friendly error messages: the SocketName goes into every
    /// validation error so logs say "/tmp/foo: BlockSize must be > 0"
    /// instead of a context-free "invalid config".
    fn write_tmp(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "testimony_test_{}_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            name
        ));
        std::fs::write(&path, content).expect("write tmp");
        path
    }

    #[test]
    fn load_rejects_zero_block_size() {
        let p = write_tmp(
            "zero_bs",
            r#"[{
                "SocketName": "/tmp/foo",
                "Interface": "eth0",
                "BlockSize": 0,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1
            }]"#,
        );
        let err = load(&p).expect_err("zero block_size must error");
        let s = format!("{err}");
        assert!(s.contains("/tmp/foo"), "expected socket name in {s:?}");
        assert!(s.contains("BlockSize"), "expected BlockSize in {s:?}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn load_rejects_zero_num_blocks() {
        let p = write_tmp(
            "zero_nb",
            r#"[{
                "SocketName": "/tmp/foo",
                "Interface": "eth0",
                "BlockSize": 1024,
                "NumBlocks": 0,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1
            }]"#,
        );
        let err = load(&p).expect_err("zero num_blocks must error");
        let s = format!("{err}");
        assert!(s.contains("NumBlocks"), "expected NumBlocks in {s:?}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn load_rejects_empty_interface() {
        let p = write_tmp(
            "empty_iface",
            r#"[{
                "SocketName": "/tmp/foo",
                "Interface": "",
                "BlockSize": 1024,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000,
                "FanoutSize": 1
            }]"#,
        );
        let err = load(&p).expect_err("empty iface must error");
        let s = format!("{err}");
        assert!(s.contains("Interface"), "expected Interface in {s:?}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn load_promotes_zero_fanout_size_to_one() {
        let p = write_tmp(
            "fs_default",
            r#"[{
                "SocketName": "/tmp/foo",
                "Interface": "eth0",
                "BlockSize": 1024,
                "NumBlocks": 16,
                "BlockTimeoutMillis": 1000
            }]"#,
        );
        let cfgs = load(&p).expect("load");
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].fanout_size, 1, "default FanoutSize should become 1");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn load_carries_path_in_io_errors() {
        let nope = std::path::PathBuf::from("/tmp/this_file_does_not_exist_in_testimony_test");
        let err = load(&nope).expect_err("missing file must error");
        let s = format!("{err}");
        assert!(s.contains(nope.to_str().expect("path str")), "expected path in {s:?}");
    }
}
