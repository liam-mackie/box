pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn subdomain_or_apex(base: &str, host: &str) -> bool {
    if host == base {
        return true;
    }
    host.len() > base.len()
        && host.ends_with(base)
        && host.as_bytes()[host.len() - base.len() - 1] == b'.'
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Exact(String),
    Subdomain(String),
}

impl Rule {
    pub fn matches(&self, normalized_host: &str) -> bool {
        match self {
            Rule::Exact(domain) => normalized_host == domain,
            Rule::Subdomain(base) => subdomain_or_apex(base, normalized_host),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    pub rules: Vec<Rule>,
}

impl Allowlist {
    pub fn parse(text: &str) -> Allowlist {
        let mut rules = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let entry = line.to_ascii_lowercase();
            if let Some(base) = entry.strip_prefix('.') {
                if !base.is_empty() {
                    rules.push(Rule::Subdomain(base.to_string()));
                }
            } else {
                rules.push(Rule::Exact(entry));
            }
        }
        Allowlist { rules }
    }

    pub fn allows(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.rules.iter().any(|r| r.matches(&host))
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_matches_only_the_apex() {
        let a = Allowlist::parse("example.com\n");
        assert!(a.allows("example.com"));
        assert!(!a.allows("www.example.com"));
        assert!(!a.allows("notexample.com"));
    }

    #[test]
    fn leading_dot_matches_apex_and_subdomains() {
        let a = Allowlist::parse(".example.com\n");
        assert!(a.allows("example.com"));
        assert!(a.allows("www.example.com"));
        assert!(a.allows("a.b.example.com"));
    }

    #[test]
    fn leading_dot_does_not_match_sibling_suffix() {
        let a = Allowlist::parse(".example.com\n");
        assert!(!a.allows("notexample.com"));
        assert!(!a.allows("example.com.evil.test"));
    }

    #[test]
    fn non_match_returns_false() {
        let a = Allowlist::parse(".example.com\nfoo.test\n");
        assert!(!a.allows("bar.test"));
        assert!(!a.allows("other.org"));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let a = Allowlist::parse("# a comment\n\n   \n.example.com\n  # indented comment\nfoo.test\n");
        assert_eq!(a.len(), 2);
        assert!(a.allows("x.example.com"));
        assert!(a.allows("foo.test"));
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        let a = Allowlist::parse(".Example.COM\n");
        assert!(a.allows("WWW.EXAMPLE.COM"));
        assert!(a.allows("www.example.com."));
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        let a = Allowlist::default();
        assert!(!a.allows("example.com"));
        assert!(a.is_empty());
    }
}
