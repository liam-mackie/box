use base64::{engine::general_purpose::STANDARD, Engine};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use regex::Regex;
use serde::Deserialize;

use crate::allowlist::{normalize_host, subdomain_or_apex};

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
pub struct SecretsFile {
    #[serde(default)]
    pub secrets: Vec<Secret>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Secret {
    pub name: String,
    pub value: String,
    pub injection: Injection,
    #[serde(default)]
    pub scopes: Vec<Scope>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "location", rename_all = "lowercase")]
pub enum Injection {
    Header { field: String, template: String },
    Cookie { field: String, template: String },
    Query { field: String, template: String },
    Placeholder { token: String, template: String },
}

impl Injection {
    pub fn template(&self) -> &str {
        match self {
            Injection::Header { template, .. }
            | Injection::Cookie { template, .. }
            | Injection::Query { template, .. }
            | Injection::Placeholder { template, .. } => template,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    pub host: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateError {
    Unterminated,
    MustStartWithValue(String),
    UnknownTransform(String),
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateError::Unterminated => write!(f, "template has an unterminated \"${{\""),
            TemplateError::MustStartWithValue(t) => {
                write!(f, "template token \"${{{t}}}\" must start with \"value\"")
            }
            TemplateError::UnknownTransform(t) => {
                write!(f, "template uses unknown transform \"{t}\" (known: base64, urlencode)")
            }
        }
    }
}

fn apply_transform(name: &str, value: &str) -> Result<String, TemplateError> {
    match name {
        "base64" => Ok(STANDARD.encode(value.as_bytes())),
        "urlencode" => Ok(utf8_percent_encode(value, UNRESERVED).to_string()),
        other => Err(TemplateError::UnknownTransform(other.to_string())),
    }
}

pub fn render_template(template: &str, value: &str) -> Result<String, TemplateError> {
    let chars: Vec<char> = template.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '$' && i + 1 < chars.len() && chars[i + 1] == '{' {
            let close = (i + 2..chars.len())
                .find(|&j| chars[j] == '}')
                .ok_or(TemplateError::Unterminated)?;
            let inner: String = chars[i + 2..close].iter().collect();
            let parts: Vec<String> = inner.split('|').map(|p| p.trim().to_string()).collect();
            if parts.first().map(String::as_str) != Some("value") {
                return Err(TemplateError::MustStartWithValue(inner));
            }
            let mut rendered = value.to_string();
            for transform in &parts[1..] {
                rendered = apply_transform(transform, &rendered)?;
            }
            out.push_str(&rendered);
            i = close + 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn host_scope_matches(scope_host: &str, host: &str) -> bool {
    let base = normalize_host(scope_host.trim_start_matches('.'));
    subdomain_or_apex(&base, host)
}

pub fn scope_matches(scope: &Scope, normalized_host: &str, path: &str) -> bool {
    if !host_scope_matches(&scope.host, normalized_host) {
        return false;
    }
    if let Some(prefix) = &scope.path_prefix {
        if !path.starts_with(prefix.as_str()) {
            return false;
        }
    }
    if let Some(pattern) = &scope.path_regex {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(path) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rendered {
    Header { field: String, value: String },
    Cookie { field: String, value: String },
    Query { field: String, value: String },
    Placeholder { token: String, value: String },
}

pub fn applicable(secrets: &[Secret], normalized_host: &str, path: &str) -> Vec<Rendered> {
    let mut out = Vec::new();
    for secret in secrets {
        let matched = secret
            .scopes
            .iter()
            .any(|scope| scope_matches(scope, normalized_host, path));
        if !matched {
            continue;
        }
        let Ok(value) = render_template(secret.injection.template(), &secret.value) else {
            continue;
        };
        out.push(match &secret.injection {
            Injection::Header { field, .. } => Rendered::Header {
                field: field.clone(),
                value,
            },
            Injection::Cookie { field, .. } => Rendered::Cookie {
                field: field.clone(),
                value,
            },
            Injection::Query { field, .. } => Rendered::Query {
                field: field.clone(),
                value,
            },
            Injection::Placeholder { token, .. } => Rendered::Placeholder {
                token: token.clone(),
                value,
            },
        });
    }
    out
}

pub fn replace_token_str(text: &str, token: &str, value: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    let mut out: Option<String> = None;
    let mut rest = text;
    while let Some(idx) = rest.find(token) {
        let acc = out.get_or_insert_with(|| String::with_capacity(text.len()));
        acc.push_str(&rest[..idx]);
        acc.push_str(value);
        rest = &rest[idx + token.len()..];
    }
    out.map(|mut acc| {
        acc.push_str(rest);
        acc
    })
}

pub fn replace_token_bytes(body: &[u8], token: &str, value: &str) -> Option<Vec<u8>> {
    let token = token.as_bytes();
    if token.is_empty() || body.len() < token.len() {
        return None;
    }
    let value = value.as_bytes();
    let mut out: Option<Vec<u8>> = None;
    let mut cursor = 0;
    let mut copied = 0;
    while cursor + token.len() <= body.len() {
        if &body[cursor..cursor + token.len()] == token {
            let acc = out.get_or_insert_with(|| Vec::with_capacity(body.len()));
            acc.extend_from_slice(&body[copied..cursor]);
            acc.extend_from_slice(value);
            cursor += token.len();
            copied = cursor;
        } else {
            cursor += 1;
        }
    }
    out.map(|mut acc| {
        acc.extend_from_slice(&body[copied..]);
        acc
    })
}

pub fn append_cookie(existing: Option<&str>, field: &str, value: &str) -> String {
    match existing {
        Some(cookie) if !cookie.trim().is_empty() => format!("{cookie}; {field}={value}"),
        _ => format!("{field}={value}"),
    }
}

pub fn set_query_param(existing: Option<&str>, key: &str, value: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(query) = existing {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let name = pair.split('=').next().unwrap_or("");
            if name == key {
                continue;
            }
            parts.push(pair.to_string());
        }
    }
    parts.push(format!("{key}={value}"));
    parts.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(injection: Injection, value: &str, scopes: Vec<Scope>) -> Secret {
        Secret {
            name: "TEST".to_string(),
            value: value.to_string(),
            injection,
            scopes,
        }
    }

    fn header(field: &str, template: &str) -> Injection {
        Injection::Header {
            field: field.to_string(),
            template: template.to_string(),
        }
    }

    fn placeholder(token: &str, template: &str) -> Injection {
        Injection::Placeholder {
            token: token.to_string(),
            template: template.to_string(),
        }
    }

    fn scope(host: &str, path_prefix: Option<&str>, path_regex: Option<&str>) -> Scope {
        Scope {
            host: host.to_string(),
            path_prefix: path_prefix.map(String::from),
            path_regex: path_regex.map(String::from),
        }
    }

    #[test]
    fn parses_the_box_secrets_schema() {
        let json = r#"{
            "secrets": [
                {
                    "name": "GH_TOKEN",
                    "value": "ghp_abc",
                    "injection": { "location": "header", "field": "Authorization", "template": "Bearer ${value}" },
                    "scopes": [ { "host": "api.github.com", "pathPrefix": "/repos", "pathRegex": null } ]
                }
            ]
        }"#;
        let file: SecretsFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.secrets.len(), 1);
        let s = &file.secrets[0];
        assert_eq!(s.name, "GH_TOKEN");
        assert_eq!(s.injection, header("Authorization", "Bearer ${value}"));
        assert_eq!(s.scopes[0].host, "api.github.com");
        assert_eq!(s.scopes[0].path_prefix.as_deref(), Some("/repos"));
        assert_eq!(s.scopes[0].path_regex, None);
    }

    #[test]
    fn parses_placeholder_injection() {
        let json = r#"{"location":"placeholder","token":"BOX_SECRET_X","template":"${value}"}"#;
        let injection: Injection = serde_json::from_str(json).unwrap();
        assert_eq!(injection, placeholder("BOX_SECRET_X", "${value}"));
    }

    #[test]
    fn missing_secrets_file_body_is_empty() {
        let file: SecretsFile = serde_json::from_str("{}").unwrap();
        assert!(file.secrets.is_empty());
    }

    #[test]
    fn render_plain_value() {
        assert_eq!(render_template("Bearer ${value}", "abc").unwrap(), "Bearer abc");
    }

    #[test]
    fn render_base64_matches_standard_encoding() {
        assert_eq!(render_template("${value|base64}", "abc").unwrap(), "YWJj");
        assert_eq!(render_template("Basic ${value|base64}", "user:pass").unwrap(), "Basic dXNlcjpwYXNz");
    }

    #[test]
    fn render_urlencode_keeps_unreserved() {
        assert_eq!(render_template("${value|urlencode}", "a b/c").unwrap(), "a%20b%2Fc");
        assert_eq!(render_template("${value|urlencode}", "a-b_c.d~e").unwrap(), "a-b_c.d~e");
    }

    #[test]
    fn render_chained_transforms_left_to_right() {
        let expected = STANDARD.encode("a/b".as_bytes());
        let expected = utf8_percent_encode(&expected, UNRESERVED).to_string();
        assert_eq!(render_template("${value|base64|urlencode}", "a/b").unwrap(), expected);
    }

    #[test]
    fn render_rejects_unknown_transform_and_unterminated() {
        assert!(matches!(
            render_template("${value|rot13}", "x"),
            Err(TemplateError::UnknownTransform(_))
        ));
        assert!(matches!(
            render_template("${value", "x"),
            Err(TemplateError::Unterminated)
        ));
        assert!(matches!(
            render_template("${nope}", "x"),
            Err(TemplateError::MustStartWithValue(_))
        ));
    }

    #[test]
    fn scope_host_matches_exact_and_subdomain() {
        let s = scope("api.github.com", None, None);
        assert!(scope_matches(&s, "api.github.com", "/x"));
        assert!(scope_matches(&s, "sub.api.github.com", "/x"));
        assert!(!scope_matches(&s, "github.com", "/x"));
    }

    #[test]
    fn scope_leading_dot_host_matches_apex_and_subdomains() {
        let s = scope(".github.com", None, None);
        assert!(scope_matches(&s, "github.com", "/x"));
        assert!(scope_matches(&s, "api.github.com", "/x"));
    }

    #[test]
    fn scope_path_prefix_narrows() {
        let s = scope("api.github.com", Some("/repos"), None);
        assert!(scope_matches(&s, "api.github.com", "/repos/foo"));
        assert!(!scope_matches(&s, "api.github.com", "/users/foo"));
    }

    #[test]
    fn scope_path_regex_narrows() {
        let s = scope("api.github.com", None, Some(r"^/repos/[^/]+/issues"));
        assert!(scope_matches(&s, "api.github.com", "/repos/x/issues/1"));
        assert!(!scope_matches(&s, "api.github.com", "/repos/x/pulls/1"));
    }

    #[test]
    fn applicable_matches_any_scope_and_renders() {
        let secrets = vec![secret(
            header("Authorization", "Bearer ${value}"),
            "tok",
            vec![scope("other.test", None, None), scope("api.github.com", Some("/repos"), None)],
        )];
        let got = applicable(&secrets, "api.github.com", "/repos/x");
        assert_eq!(
            got,
            vec![Rendered::Header {
                field: "Authorization".to_string(),
                value: "Bearer tok".to_string(),
            }]
        );
    }

    #[test]
    fn applicable_leaves_non_matching_requests_untouched() {
        let secrets = vec![secret(
            header("Authorization", "Bearer ${value}"),
            "tok",
            vec![scope("api.github.com", Some("/repos"), None)],
        )];
        assert!(applicable(&secrets, "api.github.com", "/users/x").is_empty());
        assert!(applicable(&secrets, "example.com", "/repos/x").is_empty());
    }

    #[test]
    fn applicable_renders_placeholder_with_transforms() {
        let secrets = vec![secret(
            placeholder("BOX_SECRET_X", "${value|base64}"),
            "abc",
            vec![scope("api.github.com", None, None)],
        )];
        let got = applicable(&secrets, "api.github.com", "/anything");
        assert_eq!(
            got,
            vec![Rendered::Placeholder {
                token: "BOX_SECRET_X".to_string(),
                value: "YWJj".to_string(),
            }]
        );
    }

    #[test]
    fn applicable_skips_placeholder_on_scope_miss() {
        let secrets = vec![secret(
            placeholder("BOX_SECRET_X", "${value}"),
            "abc",
            vec![scope("api.github.com", Some("/repos"), None)],
        )];
        assert!(applicable(&secrets, "api.github.com", "/users/x").is_empty());
        assert!(applicable(&secrets, "other.test", "/repos/x").is_empty());
    }

    #[test]
    fn replace_token_str_replaces_every_occurrence() {
        assert_eq!(
            replace_token_str("a T b T c", "T", "X").as_deref(),
            Some("a X b X c")
        );
        assert_eq!(
            replace_token_str("TT", "T", "X").as_deref(),
            Some("XX")
        );
    }

    #[test]
    fn replace_token_str_returns_none_without_occurrence() {
        assert_eq!(replace_token_str("nothing here", "T", "X"), None);
        assert_eq!(replace_token_str("anything", "", "X"), None);
    }

    #[test]
    fn replace_token_str_does_not_re_expand_replacement() {
        assert_eq!(
            replace_token_str("T", "T", "aTb").as_deref(),
            Some("aTb")
        );
    }

    #[test]
    fn replace_token_bytes_replaces_every_occurrence() {
        assert_eq!(
            replace_token_bytes(b"a T b T c", "T", "X").as_deref(),
            Some(&b"a X b X c"[..])
        );
        assert_eq!(
            replace_token_bytes(b"TT", "T", "X").as_deref(),
            Some(&b"XX"[..])
        );
    }

    #[test]
    fn replace_token_bytes_returns_none_without_occurrence() {
        assert_eq!(replace_token_bytes(b"nothing here", "T", "X"), None);
        assert_eq!(replace_token_bytes(b"", "T", "X"), None);
        assert_eq!(replace_token_bytes(b"anything", "", "X"), None);
    }

    #[test]
    fn replace_token_bytes_does_not_re_expand_replacement() {
        assert_eq!(
            replace_token_bytes(b"T", "T", "aTb").as_deref(),
            Some(&b"aTb"[..])
        );
    }

    #[test]
    fn cookie_appends_to_existing() {
        assert_eq!(append_cookie(Some("a=1"), "session", "xyz"), "a=1; session=xyz");
        assert_eq!(append_cookie(None, "session", "xyz"), "session=xyz");
        assert_eq!(append_cookie(Some("   "), "session", "xyz"), "session=xyz");
    }

    #[test]
    fn query_param_replaces_existing_key() {
        assert_eq!(set_query_param(Some("a=1&b=2"), "b", "9"), "a=1&b=9");
        assert_eq!(set_query_param(Some("a=1"), "token", "t"), "a=1&token=t");
        assert_eq!(set_query_param(None, "token", "t"), "token=t");
    }
}
