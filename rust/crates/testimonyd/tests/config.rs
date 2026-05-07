//! Anchor that the JSON shape used by `configs/testimony.conf` and
//! `integration_test/test.sh` actually deserializes with the same field
//! names the daemon expects. A serde rename typo would fail this test.

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SC {
    #[serde(rename = "SocketName")]
    _socket_name: String,
    #[serde(rename = "Interface")]
    _interface: String,
    #[serde(rename = "BlockSize")]
    _block_size: u32,
    #[serde(rename = "NumBlocks")]
    _num_blocks: u32,
    #[serde(rename = "BlockTimeoutMillis")]
    _block_timeout_millis: u32,
    #[serde(rename = "FanoutType", default)]
    _fanout_type: u16,
    #[serde(rename = "FanoutSize", default)]
    _fanout_size: u16,
    #[serde(rename = "FanoutID", default)]
    _fanout_id: u16,
    #[serde(rename = "User", default)]
    _user: String,
    #[serde(rename = "Group", default)]
    _group: String,
    #[serde(rename = "Filter", default)]
    _filter: String,
}

#[test]
fn parses_default_config_shape() {
    let json = r#"
        [
          {
              "SocketName": "/tmp/testimony.sock"
            , "Interface": "eth0"
            , "BlockSize": 1048576
            , "NumBlocks": 16
            , "FanoutSize": 1
            , "BlockTimeoutMillis": 1000
            , "User": "root"
          }
        ]"#;
    let cfgs: Vec<SC> = serde_json::from_str(json).expect("parse");
    assert_eq!(cfgs.len(), 1);
}

#[test]
fn parses_full_config_shape() {
    // Mirrors the integration_test/test.sh inline config.
    let json = r#"
        [{
            "SocketName": "/tmp/socket"
          , "Interface": "dummy0"
          , "BlockSize": 1048576
          , "NumBlocks": 16
          , "BlockTimeoutMillis": 1000
          , "FanoutSize": 1
          , "User": "nobody"
          , "Filter": "host 169.254.1.1 and host 169.254.1.2"
        }]"#;
    let cfgs: Vec<SC> = serde_json::from_str(json).expect("parse");
    assert_eq!(cfgs.len(), 1);
}
