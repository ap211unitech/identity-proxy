//! File-based authorization policy (YAML). Default deny.
//!
//! Matching rules (deliberately tiny so they are easy to reason about):
//!   * identity: exact string match
//!   * method:   exact, upper-case match
//!   * path:     exact match, OR a pattern ending in "/*" which matches any path that has
//!               that prefix plus at least one more character ("/reports/*" matches
//!               "/reports/q1" and "/reports/q1/x", but not "/reports" or "/reports2/x").
//!               "*" is not allowed anywhere else in a pattern (checked at load time).
//!   * the query string is never part of matching.
//!
//! Bypass protection: before matching, `is_safe_path` rejects any path whose meaning could
//! differ between us and the upstream (encoded slashes/dots/backslashes/NUL, "." / ".."
//! segments, empty segments). Matching and forwarding both use the *raw* path, so what we
//! authorize is byte-for-byte what the upstream receives.

use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct PolicyFile {
    policies: Vec<Policy>,
}

#[derive(Deserialize)]
struct Policy {
    identity: String,
    allow: Vec<Rule>,
}

#[derive(Deserialize, Clone)]
struct Rule {
    method: String,
    path: String,
}

pub struct PolicyEngine {
    rules: HashMap<String, Vec<Rule>>,
}

impl PolicyEngine {
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Self::from_yaml(&text)
    }

    pub fn from_yaml(text: &str) -> Result<Self, String> {
        let file: PolicyFile = serde_yaml::from_str(text).map_err(|e| format!("policy: {e}"))?;
        let mut rules: HashMap<String, Vec<Rule>> = HashMap::new();
        for policy in file.policies {
            for rule in &policy.allow {
                if !rule.path.starts_with('/') {
                    return Err(format!("policy path must start with '/': {}", rule.path));
                }
                let stars = rule.path.matches('*').count();
                if stars > 1 || (stars == 1 && !rule.path.ends_with("/*")) {
                    return Err(format!("'*' is only allowed as a trailing '/*': {}", rule.path));
                }
                if rule.method != rule.method.to_ascii_uppercase() {
                    return Err(format!("method must be upper-case: {}", rule.method));
                }
            }
            rules.entry(policy.identity).or_default().extend(policy.allow);
        }
        Ok(PolicyEngine { rules })
    }

    pub fn is_allowed(&self, identity: &str, method: &str, path: &str) -> bool {
        self.rules.get(identity).is_some_and(|rules| {
            rules.iter().any(|r| r.method == method && path_matches(&r.path, path))
        })
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => path.len() > prefix.len() && path.starts_with(prefix),
        None => pattern == path,
    }
}

/// False if the path is ambiguous or could be interpreted differently by the upstream.
pub fn is_safe_path(path: &str) -> bool {
    if !path.starts_with('/') || path.bytes().any(|b| b == b'\\' || b < 0x20 || b >= 0x7f) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if ["%2f", "%5c", "%2e", "%00", "%25"].iter().any(|bad| lower.contains(bad)) {
        return false;
    }
    // "/" alone is fine; otherwise every segment must be non-empty and not a dot-segment
    // (a single trailing slash is allowed; it is a *different* path and is matched exactly).
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    trimmed == "" || trimmed[1..].split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
policies:
  - identity: "spiffe://acme/prod/payment-agent"
    allow:
      - { method: POST, path: "/payments" }
  - identity: "spiffe://acme/prod/reporting-agent"
    allow:
      - { method: GET, path: "/reports/*" }
"#;

    #[test]
    fn exact_and_wildcard_matching() {
        let p = PolicyEngine::from_yaml(POLICY).unwrap();
        let pay = "spiffe://acme/prod/payment-agent";
        let rep = "spiffe://acme/prod/reporting-agent";
        assert!(p.is_allowed(pay, "POST", "/payments"));
        assert!(!p.is_allowed(pay, "GET", "/payments")); // wrong method
        assert!(!p.is_allowed(pay, "POST", "/payments/")); // exact means exact
        assert!(!p.is_allowed(pay, "POST", "/payments/1")); // no implicit prefix match
        assert!(p.is_allowed(rep, "GET", "/reports/q1"));
        assert!(p.is_allowed(rep, "GET", "/reports/q1/detail"));
        assert!(!p.is_allowed(rep, "GET", "/reports")); // wildcard needs >= 1 char
        assert!(!p.is_allowed(rep, "GET", "/reports/"));
        assert!(!p.is_allowed(rep, "GET", "/reports2/x")); // prefix is "/reports/"
        assert!(!p.is_allowed(rep, "get", "/reports/q1")); // methods are case-sensitive
        assert!(!p.is_allowed("spiffe://acme/prod/unknown", "GET", "/reports/q1"));
    }

    #[test]
    fn bad_policies_are_rejected() {
        for path in ["reports", "/rep*orts", "/reports/**", "*"] {
            let yaml = format!(
                "policies:\n  - identity: x\n    allow:\n      - {{ method: GET, path: \"{path}\" }}\n"
            );
            assert!(PolicyEngine::from_yaml(&yaml).is_err(), "{path}");
        }
    }

    #[test]
    fn ambiguous_paths_are_unsafe() {
        for path in [
            "/reports/../payments", "/reports/./x", "//payments", "/reports//x",
            "/reports/%2e%2e/payments", "/reports/%2F..", "/a%5Cb", "/a%00", "/a%252e", "/a\\b", "relative",
        ] {
            assert!(!is_safe_path(path), "{path}");
        }
        for path in ["/", "/payments", "/reports/q1", "/reports/a%20b", "/payments/"] {
            assert!(is_safe_path(path), "{path}");
        }
    }
}
