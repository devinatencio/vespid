use vespid_agent_enroll::{Credentials, EnrollmentConfig};

#[test]
fn credentials_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("creds.json");

    let creds = Credentials {
        api_key: "hvk_test123".into(),
        server_url: "https://example.com".into(),
        node_id: "node-1".into(),
        asset_id: "asset-1".into(),
        host_id: "host-1".into(),
        enrolled_at: chrono::Utc::now(),
    };

    creds.save(&path).unwrap();
    let loaded = Credentials::load(&path).unwrap().unwrap();
    assert_eq!(loaded.api_key, "hvk_test123");
    assert_eq!(loaded.host_id, "host-1");
    assert_eq!(loaded.node_id, "node-1");
}

#[test]
fn load_missing_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.json");
    let creds = Credentials::load(&path).unwrap();
    assert!(creds.is_none());
}

#[test]
fn config_base_url_strips_api_path() {
    let mut cfg = EnrollmentConfig {
        server_url: "https://example.com/api/v1/events".into(),
        ..Default::default()
    };
    assert_eq!(cfg.base_url(), "https://example.com");

    cfg.server_url = "https://example.com".into();
    assert_eq!(cfg.base_url(), "https://example.com");

    cfg.server_url = "https://example.com/".into();
    assert_eq!(cfg.base_url(), "https://example.com");
}
