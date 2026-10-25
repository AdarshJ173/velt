//! Cryptographically signed audit rule packs.
//!
//! Built-in heuristics cannot anticipate every credential format. Rule packs
//! add regular expressions without rebuilding velt:
//!
//! ```json
//! {
//!   "version": 1,
//!   "rules": [
//!     {
//!       "id": "internal-token",
//!       "pattern": "^int_[A-Za-z0-9]{40}$",
//!       "severity": "warning",
//!       "message": "internal service token"
//!     }
//!   ]
//! }
//! ```
//!
//! Packs can be signed with Ed25519. The CLI verifies the signature over the
//! exact file bytes against an operator-supplied public key. Rule patterns are
//! treated as untrusted input and validated before use (count, length, regex
//! compilation).

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::audit::{Finding, Severity};
use crate::error::{CoreError, Result};
use crate::vault::Entry;

pub const MAX_RULES: usize = 500;
pub const MAX_PATTERN_LEN: usize = 4096;
pub const MAX_RULE_FILE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub message: String,
}

fn default_severity() -> String {
    "warning".to_owned()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSet {
    pub version: u32,
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RULE_FILE_BYTES {
            return Err(CoreError::InvalidCrypto("rule pack exceeds 1 MiB"));
        }
        let ruleset: Self = serde_json::from_slice(bytes)?;
        ruleset.validate()?;
        Ok(ruleset)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(CoreError::InvalidCrypto(
                "unsupported rule pack version (expected 1)",
            ));
        }
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::InvalidCrypto("rule pack has too many rules"));
        }
        for rule in &self.rules {
            if rule.id.is_empty()
                || rule.id.len() > 64
                || !rule
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            {
                return Err(CoreError::InvalidCrypto(
                    "rule ids must be 1..=64 bytes of [A-Za-z0-9_.-]",
                ));
            }
            if rule.pattern.is_empty() || rule.pattern.len() > MAX_PATTERN_LEN {
                return Err(CoreError::InvalidCrypto(
                    "rule patterns must be 1..=4096 bytes",
                ));
            }
            severity_from_str(&rule.severity)?;
            Regex::new(&rule.pattern).map_err(|_| {
                CoreError::InvalidCrypto("rule pattern is not a valid regular expression")
            })?;
        }
        Ok(())
    }

    /// Apply custom rules to vault entries.
    pub fn apply(&self, entries: &BTreeMap<String, Entry>) -> Vec<Finding> {
        let compiled: Vec<(Regex, &Rule)> = self
            .rules
            .iter()
            .filter_map(|rule| Regex::new(&rule.pattern).ok().map(|regex| (regex, rule)))
            .collect();
        let mut findings = Vec::new();
        for (name, entry) in entries {
            let value = entry.value.expose();
            for (regex, rule) in &compiled {
                if regex.is_match(value) {
                    findings.push(Finding {
                        severity: severity_from_str(&rule.severity).unwrap_or(Severity::Warning),
                        code: "custom_rule",
                        subject: name.clone(),
                        message: if rule.message.is_empty() {
                            format!("matched custom rule {}", rule.id)
                        } else {
                            format!("{} (rule {})", rule.message, rule.id)
                        },
                    });
                }
            }
        }
        findings
    }
}

fn severity_from_str(value: &str) -> Result<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "error" => Ok(Severity::Error),
        _ => Err(CoreError::InvalidCrypto(
            "rule severity must be info, warning or error",
        )),
    }
}

/// Sign exact rule-pack bytes with an Ed25519 key.
pub fn sign(bytes: &[u8], signing_key: &SigningKey) -> [u8; 64] {
    signing_key.sign(bytes).to_bytes()
}

/// Verify a detached Ed25519 signature over exact rule-pack bytes.
pub fn verify_signature(
    bytes: &[u8],
    signature: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<()> {
    if signature.len() != 64 {
        return Err(CoreError::InvalidCrypto(
            "rule signature must be 64 bytes",
        ));
    }
    let signature = Signature::from_slice(signature)
        .map_err(|_| CoreError::InvalidCrypto("rule signature is malformed"))?;
    verifying_key
        .verify(bytes, &signature)
        .map_err(|_| CoreError::InvalidCrypto("rule signature verification failed"))
}

/// Parse a hex-encoded Ed25519 verifying key.
pub fn parse_verifying_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(hex_key.trim())
        .map_err(|_| CoreError::InvalidCrypto("rule public key is not valid hex"))?;
    if bytes.len() != 32 {
        return Err(CoreError::InvalidCrypto(
            "rule public key must be 32 bytes",
        ));
    }
    VerifyingKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::InvalidCrypto("rule public key must be 32 bytes"))?,
    )
    .map_err(|_| CoreError::InvalidCrypto("rule public key is not a valid Ed25519 key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use crate::vault::now_unix;
    use rand::rngs::OsRng;

    fn ruleset_json() -> Vec<u8> {
        br#"{
          "version": 1,
          "rules": [
            {"id": "internal", "pattern": "^int_[A-Za-z0-9]{8}$", "severity": "error", "message": "internal token"}
          ]
        }"#
        .to_vec()
    }

    fn entries() -> BTreeMap<String, Entry> {
        let mut entries = BTreeMap::new();
        entries.insert(
            "TOKEN".to_owned(),
            Entry {
                value: SecretValue::new("int_abcd1234"),
                updated_at: now_unix(),
                expires_at: None,
            },
        );
        entries.insert(
            "OTHER".to_owned(),
            Entry {
                value: SecretValue::new("unrelated"),
                updated_at: now_unix(),
                expires_at: None,
            },
        );
        entries
    }

    #[test]
    fn rules_match_values() {
        let ruleset = RuleSet::parse(&ruleset_json()).unwrap();
        let findings = ruleset.apply(&entries());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].subject, "TOKEN");
    }

    #[test]
    fn invalid_rules_are_rejected() {
        let bad = br#"{"version":1,"rules":[{"id":"x","pattern":"(","severity":"error"}]}"#;
        assert!(RuleSet::parse(bad).is_err());
        let bad_severity =
            br#"{"version":1,"rules":[{"id":"x","pattern":"a","severity":"nuke"}]}"#;
        assert!(RuleSet::parse(bad_severity).is_err());
    }

    #[test]
    fn signatures_roundtrip_and_reject_tampering() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let bytes = ruleset_json();
        let signature = sign(&bytes, &signing_key);
        assert!(verify_signature(&bytes, &signature, &verifying_key).is_ok());
        let mut tampered = bytes.clone();
        tampered.push(b' ');
        assert!(verify_signature(&tampered, &signature, &verifying_key).is_err());
        assert!(verify_signature(&bytes, &signature[..63], &verifying_key).is_err());
    }

    #[test]
    fn public_key_parsing() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let hex_key = hex::encode(signing_key.verifying_key().to_bytes());
        assert!(parse_verifying_key(&hex_key).is_ok());
        assert!(parse_verifying_key("zz").is_err());
    }
}
