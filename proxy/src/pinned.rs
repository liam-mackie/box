use crate::allowlist::{normalize_host, subdomain_or_apex};

pub const PINNED_DOMAINS: &[&str] = &[
    "anthropic.com",
    "claude.ai",
    "claude.com",
    "npmjs.org",
    "npmjs.com",
    "github.com",
    "githubusercontent.com",
];

pub fn is_pinned(host: &str) -> bool {
    let host = normalize_host(host);
    PINNED_DOMAINS.iter().any(|base| subdomain_or_apex(base, &host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_is_pinned() {
        assert!(is_pinned("github.com"));
        assert!(is_pinned("anthropic.com"));
        assert!(is_pinned("claude.ai"));
    }

    #[test]
    fn subdomains_are_pinned() {
        assert!(is_pinned("api.github.com"));
        assert!(is_pinned("raw.githubusercontent.com"));
        assert!(is_pinned("registry.npmjs.org"));
    }

    #[test]
    fn unrelated_hosts_are_not_pinned() {
        assert!(!is_pinned("pypi.org"));
        assert!(!is_pinned("example.com"));
        assert!(!is_pinned("notgithub.com"));
        assert!(!is_pinned("github.com.evil.test"));
    }

    #[test]
    fn pinning_is_case_insensitive() {
        assert!(is_pinned("API.GitHub.com"));
    }
}
