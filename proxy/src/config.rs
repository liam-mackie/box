use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use hudsucker::certificate_authority::OpensslAuthority;
use hudsucker::openssl::{hash::MessageDigest, nid::Nid, pkey::PKey, pkey::Private, x509::X509};
use hudsucker::rustls::crypto::aws_lc_rs;

use crate::allowlist::Allowlist;
use crate::inject::{self, Secret, SecretsFile};

pub const DEFAULT_GLOBAL_ALLOWLIST: &str = "/etc/box/allowlist.txt";
pub const DEFAULT_PROJECT_ALLOWLIST: &str = "/run/box-allowlist/allowlist.project.txt";
pub const DEFAULT_SHARED_DIR: &str = "/run/box-shared";
pub const DEFAULT_SECRETS: &str = "/run/box-inject/secrets.json";
pub const DEFAULT_CA_CERT: &str = "/run/box-ca/ca.crt";
pub const DEFAULT_CA_KEY: &str = "/run/box-ca/ca.key";
pub const DEFAULT_ACCESS_LOG: &str = "/var/log/box/access.log";
pub const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:3128";

#[derive(Debug, Clone)]
pub struct Paths {
    pub global_allowlist: PathBuf,
    pub project_allowlist: PathBuf,
    pub shared_dir: PathBuf,
    pub secrets: PathBuf,
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub access_log: PathBuf,
    pub listen_addr: String,
}

fn env_path(key: &str, default: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| default.to_string()))
}

impl Paths {
    pub fn from_env() -> Paths {
        Paths {
            global_allowlist: env_path("BOX_ALLOWLIST_GLOBAL", DEFAULT_GLOBAL_ALLOWLIST),
            project_allowlist: env_path("BOX_ALLOWLIST_PROJECT", DEFAULT_PROJECT_ALLOWLIST),
            shared_dir: env_path("BOX_SHARED_DIR", DEFAULT_SHARED_DIR),
            secrets: env_path("BOX_INJECT_SECRETS", DEFAULT_SECRETS),
            ca_cert: env_path("BOX_CA_CERT", DEFAULT_CA_CERT),
            ca_key: env_path("BOX_CA_KEY", DEFAULT_CA_KEY),
            access_log: env_path("BOX_ACCESS_LOG", DEFAULT_ACCESS_LOG),
            listen_addr: std::env::var("BOX_PROXY_ADDR").unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string()),
        }
    }
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub global: Allowlist,
    pub project: Allowlist,
    pub shared: HashMap<String, Allowlist>,
    pub secrets: Vec<Secret>,
}

impl Snapshot {
    pub fn allows(&self, client_ip: &str, host: &str) -> bool {
        if self.global.allows(host) || self.project.allows(host) {
            return true;
        }
        match self.shared.get(client_ip) {
            Some(list) => list.allows(host),
            None => false,
        }
    }
}

fn read_allowlist(path: &Path) -> Allowlist {
    match std::fs::read_to_string(path) {
        Ok(text) => Allowlist::parse(&text),
        Err(_) => Allowlist::default(),
    }
}

fn read_secrets(path: &Path) -> Vec<Secret> {
    match std::fs::read_to_string(path) {
        Ok(text) => match serde_json::from_str::<SecretsFile>(&text) {
            Ok(file) => file.secrets,
            Err(err) => {
                eprintln!("box-proxy: ignoring invalid {}: {err}", path.display());
                Vec::new()
            }
        },
        Err(_) => Vec::new(),
    }
}

fn read_shared(dir: &Path) -> HashMap<String, Allowlist> {
    let mut shared = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let source = entry.file_name().to_string_lossy().to_string();
            let list = read_allowlist(&dir.join(&source).join("allowlist.txt"));
            if !list.is_empty() {
                shared.insert(source, list);
            }
        }
    }
    shared
}

pub fn load_snapshot(paths: &Paths) -> Snapshot {
    Snapshot {
        global: read_allowlist(&paths.global_allowlist),
        project: read_allowlist(&paths.project_allowlist),
        shared: read_shared(&paths.shared_dir),
        secrets: read_secrets(&paths.secrets),
    }
}

fn stat_entry(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{}:{}:{}", path.display(), mtime, meta.len())
        }
        Err(_) => format!("{}:absent", path.display()),
    }
}

pub fn fingerprint(paths: &Paths) -> String {
    let mut entries = vec![
        stat_entry(&paths.global_allowlist),
        stat_entry(&paths.project_allowlist),
        stat_entry(&paths.secrets),
    ];
    if let Ok(dir) = std::fs::read_dir(&paths.shared_dir) {
        let mut names: Vec<_> = dir.flatten().map(|e| e.file_name()).collect();
        names.sort();
        for name in names {
            entries.push(stat_entry(&paths.shared_dir.join(&name).join("allowlist.txt")));
        }
    } else {
        entries.push(format!("{}:absent-dir", paths.shared_dir.display()));
    }
    entries.join("|")
}

pub fn parse_ca(cert_path: &Path, key_path: &Path) -> Result<(PKey<Private>, X509), String> {
    let key_pem =
        std::fs::read(key_path).map_err(|e| format!("read CA key {}: {e}", key_path.display()))?;
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| format!("read CA cert {}: {e}", cert_path.display()))?;
    let pkey = PKey::private_key_from_pem(&key_pem)
        .map_err(|e| format!("parse CA key {}: {e}", key_path.display()))?;
    let cert = X509::from_pem(&cert_pem)
        .map_err(|e| format!("parse CA cert {}: {e}", cert_path.display()))?;
    Ok((pkey, cert))
}

pub fn build_authority(pkey: PKey<Private>, cert: X509) -> OpensslAuthority {
    OpensslAuthority::new(pkey, cert, MessageDigest::sha256(), 1_000, aws_lc_rs::default_provider())
}

fn common_name(cert: &X509) -> Option<String> {
    cert.subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .map(|e| String::from_utf8_lossy(e.data().as_slice()).into_owned())
}

fn validate_placeholder_token(token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("placeholder token must not be empty".to_string());
    }
    let valid = token
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !valid {
        return Err(format!(
            "placeholder token \"{token}\" must contain only [A-Z0-9_]"
        ));
    }
    Ok(())
}

pub fn check_config(paths: &Paths) -> Result<String, String> {
    let mut out = String::new();

    let global = read_allowlist(&paths.global_allowlist);
    let project = read_allowlist(&paths.project_allowlist);
    let shared = read_shared(&paths.shared_dir);
    let shared_total: usize = shared.values().map(Allowlist::len).sum();
    let _ = writeln!(
        out,
        "allowlist: global={} ({}), project={} ({}), shared={} sources / {} rules ({})",
        global.len(),
        paths.global_allowlist.display(),
        project.len(),
        paths.project_allowlist.display(),
        shared.len(),
        shared_total,
        paths.shared_dir.display(),
    );

    match std::fs::read_to_string(&paths.secrets) {
        Ok(text) => {
            let file: SecretsFile = serde_json::from_str(&text)
                .map_err(|e| format!("secrets {}: {e}", paths.secrets.display()))?;
            for secret in &file.secrets {
                inject::render_template(secret.injection.template(), &secret.value)
                    .map_err(|e| format!("secret \"{}\": {e}", secret.name))?;
                if let inject::Injection::Placeholder { token, .. } = &secret.injection {
                    validate_placeholder_token(token)
                        .map_err(|e| format!("secret \"{}\": {e}", secret.name))?;
                }
                for scope in &secret.scopes {
                    if let Some(pattern) = &scope.path_regex {
                        regex::Regex::new(pattern).map_err(|e| {
                            format!("secret \"{}\" scope pathRegex: {e}", secret.name)
                        })?;
                    }
                }
            }
            let _ = writeln!(
                out,
                "secrets: {} valid ({})",
                file.secrets.len(),
                paths.secrets.display()
            );
        }
        Err(_) => {
            let _ = writeln!(out, "secrets: none present ({})", paths.secrets.display());
        }
    }

    let (pkey, cert) = parse_ca(&paths.ca_cert, &paths.ca_key)?;
    let cn = common_name(&cert).unwrap_or_else(|| "(no CN)".to_string());
    let _ = build_authority(pkey, cert);
    let _ = writeln!(
        out,
        "CA: loaded and forging authority built (CN={cn}, cert={}, key={})",
        paths.ca_cert.display(),
        paths.ca_key.display()
    );

    let _ = writeln!(out, "listen: {}", paths.listen_addr);
    let _ = writeln!(out, "access log: {}", paths.access_log.display());

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("box-proxy-cfg-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos() as u64
    }

    #[test]
    fn snapshot_unions_global_project_and_shared_per_source() {
        let dir = tmp();
        std::fs::write(dir.join("global.txt"), ".anthropic.com\n").unwrap();
        std::fs::write(dir.join("project.txt"), "pypi.org\n").unwrap();
        let shared_dir = dir.join("shared");
        std::fs::create_dir_all(shared_dir.join("10.0.0.5")).unwrap();
        std::fs::write(shared_dir.join("10.0.0.5").join("allowlist.txt"), "example.test\n").unwrap();

        let paths = Paths {
            global_allowlist: dir.join("global.txt"),
            project_allowlist: dir.join("project.txt"),
            shared_dir,
            secrets: dir.join("missing-secrets.json"),
            ca_cert: dir.join("nope.crt"),
            ca_key: dir.join("nope.key"),
            access_log: dir.join("access.log"),
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
        };
        let snap = load_snapshot(&paths);

        assert!(snap.allows("10.0.0.5", "api.anthropic.com"));
        assert!(snap.allows("10.0.0.5", "pypi.org"));
        assert!(snap.allows("10.0.0.5", "example.test"));
        assert!(!snap.allows("10.0.0.9", "example.test"));
        assert!(snap.allows("10.0.0.9", "pypi.org"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_changes_when_a_file_changes() {
        let dir = tmp();
        let global = dir.join("global.txt");
        std::fs::write(&global, "a.test\n").unwrap();
        let paths = Paths {
            global_allowlist: global.clone(),
            project_allowlist: dir.join("project.txt"),
            shared_dir: dir.join("shared"),
            secrets: dir.join("secrets.json"),
            ca_cert: dir.join("nope.crt"),
            ca_key: dir.join("nope.key"),
            access_log: dir.join("access.log"),
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
        };
        let before = fingerprint(&paths);
        std::fs::write(&global, "a.test\nb.test\n").unwrap();
        let after = fingerprint(&paths);
        assert_ne!(before, after);

        std::fs::remove_dir_all(&dir).ok();
    }
}
