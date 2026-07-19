use std::path::PathBuf;
use std::process::Command;

use box_proxy::config::{check_config, Paths, DEFAULT_LISTEN_ADDR};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn ensure_ca(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("ca.crt");
    let key = dir.join("ca.key");
    if !cert.exists() || !key.exists() {
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "3650",
                "-sha256",
                "-subj",
                "/CN=box MITM CA/O=box",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ])
            .status()
            .expect("failed to invoke openssl to generate a test CA");
        assert!(status.success(), "openssl CA generation failed");
    }
    (cert, key)
}

fn paths_over_fixtures(dir: &std::path::Path, secrets: PathBuf) -> Paths {
    let (cert, key) = ensure_ca(dir);
    Paths {
        global_allowlist: dir.join("allowlist.txt"),
        project_allowlist: dir.join("does-not-exist.project.txt"),
        shared_dir: dir.join("no-shared-dir"),
        secrets,
        ca_cert: cert,
        ca_key: key,
        access_log: std::env::temp_dir().join("box-proxy-test-access.log"),
        listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
    }
}

#[test]
fn check_config_succeeds_over_fixtures() {
    let dir = fixtures_dir();
    let paths = paths_over_fixtures(&dir, dir.join("secrets.json"));
    let summary = check_config(&paths).expect("check_config should succeed over the fixtures");
    assert!(summary.contains("allowlist:"), "summary: {summary}");
    assert!(summary.contains("secrets: 3 valid"), "summary: {summary}");
    assert!(summary.contains("CA: loaded"), "summary: {summary}");
}

#[test]
fn check_config_reports_missing_secrets_without_failing() {
    let dir = fixtures_dir();
    let paths = paths_over_fixtures(&dir, dir.join("no-such-secrets.json"));
    let summary = check_config(&paths).expect("missing secrets.json is not an error");
    assert!(summary.contains("secrets: none present"), "summary: {summary}");
}

#[test]
fn check_config_fails_on_invalid_secrets_json() {
    let dir = fixtures_dir();
    let bad = std::env::temp_dir().join("box-proxy-bad-secrets.json");
    std::fs::write(&bad, "{ not valid json").unwrap();
    let paths = paths_over_fixtures(&dir, bad.clone());
    let result = check_config(&paths);
    std::fs::remove_file(&bad).ok();
    assert!(result.is_err(), "invalid secrets.json should fail check-config");
}
