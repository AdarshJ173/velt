//! Offline secret hygiene auditing.
//!
//! The audit engine never calls a network service and never prints secret
//! values. It detects:
//!
//! - empty, placeholder and unresolved-reference values
//! - weak values for sensitive key names
//! - expired and soon-to-expire credentials (metadata and JWT `exp` claims)
//! - inline private key material
//! - values matching live credential formats (AWS, Stripe, GitHub, Slack, ...)
//! - duplicate values across keys
//! - plaintext `.env*` files in the repository, their permissions, and
//!   `.gitignore` coverage
//!
//! Findings are deterministic and safe to print in CI logs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use serde::Serialize;
use time::{Duration, OffsetDateTime};

use crate::vault::{now_unix, Entry};

/// How dangerous a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// A single audit finding. `subject` is a key name or `file:KEY`, never a value.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub code: &'static str,
    pub subject: String,
    pub message: String,
}

impl Finding {
    fn new(
        severity: Severity,
        code: &'static str,
        subject: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code,
            subject: subject.into(),
            message: message.into(),
        }
    }
}

/// Audit a set of vault entries.
pub fn audit_entries(entries: &BTreeMap<String, Entry>, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut values: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for (name, entry) in entries {
        let value = entry.value.expose();
        audit_value(name, value, now, &mut findings);
        if !value.is_empty() {
            values.entry(value).or_default().push(name);
        }

        match entry.expires_at {
            Some(expires_at) if expires_at <= now => {
                findings.push(Finding::new(
                    Severity::Error,
                    "expired",
                    name,
                    format!(
                        "expired {} day(s) ago; rotate this credential",
                        days_between(expires_at, now)
                    ),
                ));
            }
            Some(expires_at) if expires_at <= now + Duration::days(14).whole_seconds() => {
                findings.push(Finding::new(
                    Severity::Warning,
                    "expires_soon",
                    name,
                    format!(
                        "expires in {} day(s); rotate before it breaks deployments",
                        days_between(now, expires_at)
                    ),
                ));
            }
            _ => {}
        }
    }

    for (_, names) in values {
        if names.len() < 2 {
            continue;
        }
        for name in names {
            findings.push(Finding::new(
                Severity::Info,
                "duplicate_value",
                name,
                "the same value is used by more than one key; shared credentials broaden the blast radius",
            ));
        }
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.code.cmp(right.code))
    });
    findings
}

fn audit_value(name: &str, value: &str, now: i64, findings: &mut Vec<Finding>) {
    let trimmed = value.trim();

    if value.is_empty() {
        findings.push(Finding::new(
            Severity::Error,
            "empty_value",
            name,
            "value is empty; the application will start with a missing configuration",
        ));
        return;
    }

    if value.trim_end_matches(['\n', '\r']) != trimmed {
        findings.push(Finding::new(
            Severity::Warning,
            "surrounding_whitespace",
            name,
            "value has leading or trailing whitespace; most credential APIs reject it",
        ));
    }

    if is_placeholder(trimmed) {
        findings.push(Finding::new(
            Severity::Error,
            "placeholder_value",
            name,
            "value is a placeholder/dummy value; replace it with a real credential before shipping",
        ));
    }

    if trimmed.starts_with("${") && trimmed.contains('}') {
        findings.push(Finding::new(
            Severity::Error,
            "unresolved_reference",
            name,
            "value is an unresolved ${VAR} reference; child processes receive the literal string",
        ));
    }

    let recognized = credential_format(trimmed);
    if is_sensitive_name(name)
        && trimmed.chars().count() < 16
        && !is_placeholder(trimmed)
        && recognized.is_none()
    {
        findings.push(Finding::new(
            Severity::Warning,
            "short_secret",
            name,
            "value is shorter than 16 characters for a sensitive key; use a high-entropy credential",
        ));
    }

    if is_sensitive_name(name)
        && trimmed.chars().count() >= 10
        && !is_placeholder(trimmed)
        && recognized.is_none()
        && !trimmed.contains("://")
        && shannon_entropy(trimmed) < 2.5
    {
        findings.push(Finding::new(
            Severity::Warning,
            "low_entropy",
            name,
            "value has very low Shannon entropy (repeated or predictable pattern); generate a random credential",
        ));
    }

    if trimmed.contains("-----BEGIN") && trimmed.contains("PRIVATE KEY-----") {
        findings.push(Finding::new(
            Severity::Error,
            "inline_private_key",
            name,
            "value contains inline private key material; store it in a file or a dedicated secret store",
        ));
    }

    if let Some(kind) = recognized {
        findings.push(Finding::new(
            Severity::Info,
            "recognized_credential",
            name,
            format!(
                "value matches a {kind} format; confirm it is the intended environment and rotate on exposure"
            ),
        ));
    }

    if let Some(expires_at) = jwt_expiry(trimmed) {
        if expires_at <= now {
            findings.push(Finding::new(
                Severity::Error,
                "expired_jwt",
                name,
                format!(
                    "JWT expired {} day(s) ago; tokens will be rejected by the service",
                    days_between(expires_at, now)
                ),
            ));
        } else if expires_at <= now + Duration::days(14).whole_seconds() {
            findings.push(Finding::new(
                Severity::Warning,
                "jwt_expires_soon",
                name,
                format!(
                    "JWT expires in {} day(s); refresh it before a deployment fails",
                    days_between(now, expires_at)
                ),
            ));
        }
    }
}

/// Shannon entropy in bits per character. Used to flag predictable secrets
/// such as `aaaaaaaaaaaa` or `abcdabcdabcd`.
pub fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    let mut total = 0usize;
    for character in value.chars() {
        *counts.entry(character).or_insert(0) += 1;
        total += 1;
    }
    let total = total as f64;
    counts.values().fold(0.0, |entropy, count| {
        let probability = *count as f64 / total;
        entropy - probability * probability.log2()
    })
}

fn is_sensitive_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    const MARKERS: &[&str] = &[
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "API_KEY",
        "APIKEY",
        "PRIVATE",
        "CREDENTIAL",
        "ACCESS_KEY",
        "SIGNING_KEY",
    ];
    MARKERS.iter().any(|marker| upper.contains(marker)) || upper.ends_with("_KEY")
}

fn is_placeholder(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    const EXACT: &[&str] = &[
        "replace_me",
        "replaceme",
        "changeme",
        "change_me",
        "todo",
        "fixme",
        "tbd",
        "placeholder",
        "dummy",
        "example",
        "secret",
        "password",
        "your_key_here",
        "your_api_key_here",
        "your_token_here",
        "your_password_here",
        "insert_key_here",
        "insert_token_here",
        "none",
        "null",
        "undefined",
        "xxx",
        "xxxx",
        "xxxxx",
    ];
    if EXACT.contains(&lower.as_str()) {
        return true;
    }
    if lower.starts_with('<') && lower.ends_with('>') {
        return true;
    }
    if lower.starts_with("your_") || lower.starts_with("your-") {
        return true;
    }
    if lower.starts_with("insert_") || lower.starts_with("replace_") {
        return true;
    }
    if lower.contains("replace_me") || lower.contains("change_me") || lower.contains("changeme") {
        return true;
    }
    // A run of x's or a bare token word is a dummy value.
    if lower.len() >= 3 && lower.chars().all(|c| c == 'x') {
        return true;
    }
    false
}

fn days_between(earlier: i64, later: i64) -> i64 {
    (later - earlier) / 86_400
}

/// Returns the credential family when a value matches a well-known live token
/// format. This is a format heuristic, not a leak check.
pub fn credential_format(value: &str) -> Option<&'static str> {
    struct Matcher {
        regex: Regex,
        name: &'static str,
    }
    static MATCHERS: LazyLock<Vec<Matcher>> = LazyLock::new(|| {
        let patterns = [
            (r"^AKIA[0-9A-Z]{16}$", "AWS access key"),
            (r"^ASIA[0-9A-Z]{16}$", "AWS temporary access key"),
            (r"^sk_live_[0-9A-Za-z]{16,}$", "Stripe live secret key"),
            (r"^rk_live_[0-9A-Za-z]{16,}$", "Stripe restricted live key"),
            (r"^gh[pousr]_[A-Za-z0-9]{30,}$", "GitHub token"),
            (r"^github_pat_[A-Za-z0-9_]{50,}$", "GitHub fine-grained token"),
            (r"^glpat-[A-Za-z0-9_\-]{20,}$", "GitLab personal access token"),
            (r"^xox[abposr]-[A-Za-z0-9\-]{10,}$", "Slack token"),
            (r"^AIza[0-9A-Za-z\-_]{35}$", "Google API key"),
            (
                r"^SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}$",
                "SendGrid API key",
            ),
            (r"^sk-ant-[A-Za-z0-9_\-]{20,}$", "Anthropic API key"),
            (r"^sk-proj-[A-Za-z0-9_\-]{20,}$", "OpenAI project API key"),
            (r"^npm_[A-Za-z0-9]{30,}$", "npm token"),
            (r"^pypi-[A-Za-z0-9_\-]{40,}$", "PyPI token"),
            (r"^hf_[A-Za-z0-9]{30,}$", "Hugging Face token"),
            (
                r"^(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss)://[^/\s:@]+:[^/\s@]+@",
                "credential-bearing database URL",
            ),
        ];
        patterns
            .iter()
            .filter_map(|(pattern, name)| {
                Regex::new(pattern).ok().map(|regex| Matcher { regex, name })
            })
            .collect()
    });

    MATCHERS
        .iter()
        .find(|matcher| matcher.regex.is_match(value))
        .map(|matcher| matcher.name)
}

/// Decode a JWT payload without verifying its signature and return `exp`.
pub fn jwt_expiry(value: &str) -> Option<i64> {
    if value.len() > 16 * 1024 {
        return None;
    }
    let mut parts = value.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("exp")?.as_i64()
}

/// Audit plaintext `.env*` files in a directory.
///
/// The scan is deliberately shallow (one directory, regular files only), does
/// not follow symlinks, caps file count and size, and never prints values.
pub fn audit_directory(directory: &Path, now: i64) -> Vec<Finding> {
    let mut findings = Vec::new();
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return findings,
    };

    let mut env_files: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten().take(10_000) {
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if !file_type.is_file() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".env" || name.starts_with(".env.") {
            if env_files.len() < 20 {
                env_files.push(path);
            }
        }
    }

    if env_files.is_empty() {
        return findings;
    }

    for path in &env_files {
        audit_env_file(path, now, &mut findings);
    }

    if !is_gitignore_covered(directory) {
        findings.push(Finding::new(
            Severity::Error,
            "env_file_not_ignored",
            "gitignore",
            "plaintext .env files exist and .gitignore does not cover them; a single `git add -A` can leak credentials",
        ));
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.code.cmp(right.code))
    });
    findings
}

fn audit_env_file(path: &Path, now: i64, findings: &mut Vec<Finding>) {
    const MAX_ENV_BYTES: u64 = 1024 * 1024;
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };
    if metadata.len() > MAX_ENV_BYTES {
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            findings.push(Finding::new(
                Severity::Warning,
                "env_file_permissions",
                format!("{}", path.display()),
                format!(
                    "plaintext env file has mode {:o}; restrict it to 0600",
                    mode
                ),
            ));
        }
    }

    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(_) => return,
    };
    let file_label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());

    let mut jwt_checked = 0usize;
    for line in contents.lines().take(5_000) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, raw_value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !crate::vault::validate_name(name).is_ok() {
            continue;
        }
        let value = raw_value
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim();
        let subject = format!("{file_label}:{name}");
        if value.is_empty() {
            findings.push(Finding::new(
                Severity::Warning,
                "plaintext_empty_value",
                subject.as_str(),
                "plaintext env file contains an empty value",
            ));
            continue;
        }
        if is_placeholder(value) {
            findings.push(Finding::new(
                Severity::Warning,
                "plaintext_placeholder",
                subject.as_str(),
                "plaintext env file contains a placeholder value",
            ));
        }
        if let Some(kind) = credential_format(value) {
            findings.push(Finding::new(
                Severity::Error,
                "plaintext_credential",
                subject.as_str(),
                format!(
                    "a {kind} is stored in plaintext on disk; move it into the encrypted vault and rotate it"
                ),
            ));
        }
        if jwt_checked < 100 {
            jwt_checked += 1;
            if let Some(expires_at) = jwt_expiry(value) {
                if expires_at <= now {
                    findings.push(Finding::new(
                        Severity::Warning,
                        "plaintext_expired_jwt",
                        subject.as_str(),
                        "plaintext env file contains an expired JWT",
                    ));
                }
            }
        }
    }
}

fn is_gitignore_covered(directory: &Path) -> bool {
    let path = directory.join(".gitignore");
    let Ok(contents) = fs::read_to_string(path) else {
        return false;
    };
    let mut patterns: BTreeSet<&str> = BTreeSet::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        patterns.insert(line);
    }
    patterns.iter().any(|pattern| {
        matches!(
            *pattern,
            ".env"
                | "/.env"
                | ".env*"
                | "/.env*"
                | "*.env"
                | ".env.*"
                | "/.env.*"
                | "*/.env"
                | "**/.env"
                | "**/.env*"
        )
    })
}

/// Current time helper for callers that do not want to import `time`.
pub fn current_timestamp() -> i64 {
    now_unix()
}

/// Human-readable expiry timestamp.
pub fn format_timestamp(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| timestamp.to_string())
        })
        .unwrap_or_else(|_| timestamp.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use std::io::Write;
    use tempfile::TempDir;

    fn entry(value: &str, expires_at: Option<i64>) -> Entry {
        Entry {
            value: SecretValue::new(value),
            updated_at: now_unix(),
            expires_at,
        }
    }

    fn audit(pairs: &[(&str, &str)]) -> Vec<Finding> {
        let entries = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), entry(value, None)))
            .collect();
        audit_entries(&entries, now_unix())
    }

    #[test]
    fn placeholders_are_errors() {
        let findings = audit(&[("STRIPE_KEY", "replace_me")]);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "placeholder_value" && finding.severity == Severity::Error));
    }

    #[test]
    fn empty_values_are_errors() {
        let findings = audit(&[("TOKEN", "")]);
        assert!(findings.iter().any(|finding| finding.code == "empty_value"));
    }

    #[test]
    fn short_sensitive_values_warn() {
        let findings = audit(&[("API_TOKEN", "abc")]);
        assert!(findings.iter().any(|finding| finding.code == "short_secret"));
    }

    #[test]
    fn entropy_flags_repeated_secrets() {
        let findings = audit(&[("API_TOKEN", "aaaaaaaaaaaaaaaaaaaa")]);
        assert!(findings.iter().any(|finding| finding.code == "low_entropy"));
        assert!(shannon_entropy("aaaaaaaa") < 1.0);
        assert!(shannon_entropy("aB3xK9mQ2pL7vN4r") > 3.0);
    }

    #[test]
    fn live_formats_are_recognized() {
        let findings = audit(&[("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")]);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "recognized_credential"));
        assert_eq!(credential_format("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), Some("GitHub token"));
    }

    #[test]
    fn expired_metadata_is_an_error() {
        let now = now_unix();
        let mut entries = BTreeMap::new();
        entries.insert("OLD".to_owned(), entry("a-real-looking-secret", Some(now - 3600)));
        let findings = audit_entries(&entries, now);
        assert!(findings.iter().any(|finding| finding.code == "expired"));
    }

    #[test]
    fn jwt_expiry_is_parsed() {
        // {"exp": 1700000000}
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MDAwMDAwMDB9.signature";
        assert_eq!(jwt_expiry(token), Some(1_700_000_000));
        let findings = audit(&[("JWT", token)]);
        assert!(findings.iter().any(|finding| finding.code == "expired_jwt"));
    }

    #[test]
    fn unresolved_reference_is_an_error() {
        let findings = audit(&[("URL", "${BASE_URL}/api")]);
        assert!(findings
            .iter()
            .any(|finding| finding.code == "unresolved_reference"));
    }

    #[test]
    fn duplicate_values_are_reported() {
        let findings = audit(&[("A", "same-long-value"), ("B", "same-long-value")]);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.code == "duplicate_value")
                .count(),
            2
        );
    }

    #[test]
    fn plaintext_env_files_are_flagged() {
        let dir = TempDir::new().unwrap();
        let mut file = fs::File::create(dir.path().join(".env")).unwrap();
        writeln!(file, "STRIPE_SECRET=sk_live_abcdefghijklmnopqrstuvwx").unwrap();
        writeln!(file, "PLACEHOLDER=replace_me").unwrap();
        drop(file);

        let findings = audit_directory(dir.path(), now_unix());
        assert!(findings.iter().any(|finding| finding.code == "plaintext_credential"));
        assert!(findings.iter().any(|finding| finding.code == "plaintext_placeholder"));
        assert!(findings.iter().any(|finding| finding.code == "env_file_not_ignored"));
    }

    #[test]
    fn gitignored_env_files_do_not_raise_gitignore_error() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        fs::write(dir.path().join(".env"), "A=1\n").unwrap();
        let findings = audit_directory(dir.path(), now_unix());
        assert!(!findings.iter().any(|finding| finding.code == "env_file_not_ignored"));
    }

    #[test]
    fn placeholder_detection_does_not_flag_real_values() {
        assert!(!is_placeholder("sk_live_abcdefghijklmnopqrstuvwx"));
        assert!(is_placeholder("your_key_here"));
        assert!(is_placeholder("<insert-token>"));
        assert!(is_placeholder("xxxx"));
    }
}
