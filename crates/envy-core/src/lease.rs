//! Offline, cryptographically scoped capability leases.
//!
//! A lease is an HMAC-SHA256 bearer token issued by the vault owner. It grants
//! access to a subset of environment variable names for a bounded time, and can
//! be attenuated further for sub-agents. The signing key never leaves the OS
//! credential store; verification requires only the key and the token.
//!
//! This is a *local capability* mechanism, not a sandbox. A lease limits what
//! `envy run --lease` injects and redacts. Any process running as the same OS
//! user can still ask envy to mint a different lease; use OS isolation for
//! stronger boundaries.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::vault::now_unix;

type HmacSha256 = Hmac<Sha256>;

pub const LEASE_PREFIX: &str = "envy_lease";
pub const LEASE_VERSION: u32 = 1;
pub const MAX_LEASE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const MAX_LEASE_PATTERNS: usize = 64;
pub const MAX_LEASE_PATTERN_BYTES: usize = 128;
pub const MAX_LEASE_TOKEN_BYTES: usize = 16 * 1024;

/// Decoded lease claims. Contains no secret material.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeasePayload {
    pub v: u32,
    pub vault_id: String,
    pub lease_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// A verified lease with its wire token.
#[derive(Clone, Debug)]
pub struct Lease {
    payload: LeasePayload,
    token: String,
}

impl Lease {
    pub fn payload(&self) -> &LeasePayload {
        &self.payload
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Whether this lease permits injecting `name`.
    ///
    /// Deny rules take precedence over allow rules.
    pub fn allows(&self, name: &str) -> bool {
        if self
            .payload
            .deny
            .iter()
            .any(|pattern| glob_match(pattern, name))
        {
            return false;
        }
        self.payload
            .allow
            .iter()
            .any(|pattern| glob_match(pattern, name))
    }
}

/// Issue a lease for the given key name patterns.
pub fn issue(
    secret: &[u8; 32],
    vault_id: &str,
    allow: &[String],
    deny: &[String],
    ttl_seconds: i64,
    label: Option<String>,
    parent: Option<String>,
) -> Result<Lease> {
    validate_vault_id(vault_id)?;
    if allow.is_empty() {
        return Err(CoreError::InvalidCrypto(
            "a lease must allow at least one key pattern",
        ));
    }
    validate_patterns(allow)?;
    validate_patterns(deny)?;
    if ttl_seconds <= 0 || ttl_seconds > MAX_LEASE_TTL_SECONDS {
        return Err(CoreError::InvalidCrypto(
            "lease TTL must be between 1 second and 7 days",
        ));
    }
    if let Some(label) = &label {
        if label.len() > 128 {
            return Err(CoreError::InvalidCrypto("lease label exceeds 128 bytes"));
        }
    }
    let issued_at = now_unix();
    let mut lease_id = [0u8; 16];
    crypto::fill_random(&mut lease_id)?;
    let payload = LeasePayload {
        v: LEASE_VERSION,
        vault_id: vault_id.to_owned(),
        lease_id: hex::encode(lease_id),
        issued_at,
        expires_at: issued_at + ttl_seconds,
        allow: allow.to_vec(),
        deny: deny.to_vec(),
        label,
        parent,
    };
    let token = sign_payload(secret, &payload)?;
    Ok(Lease { payload, token })
}

/// Verify a lease token for a vault at the current time.
pub fn verify(secret: &[u8; 32], token: &str, vault_id: &str, now: i64) -> Result<Lease> {
    if token.len() > MAX_LEASE_TOKEN_BYTES {
        return Err(CoreError::InvalidCrypto("lease token is too large"));
    }
    let mut parts = token.split('.');
    let prefix = parts
        .next()
        .ok_or(CoreError::InvalidCrypto("malformed lease token"))?;
    let payload_b64 = parts
        .next()
        .ok_or(CoreError::InvalidCrypto("malformed lease token"))?;
    let signature_b64 = parts
        .next()
        .ok_or(CoreError::InvalidCrypto("malformed lease token"))?;
    if parts.next().is_some() || prefix != LEASE_PREFIX {
        return Err(CoreError::InvalidCrypto("malformed lease token"));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| CoreError::InvalidCrypto("lease payload is not valid base64"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| CoreError::InvalidCrypto("lease signature is not valid base64"))?;

    let signing_input = format!("{LEASE_PREFIX}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| CoreError::InvalidCrypto("invalid lease signing key"))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| CoreError::InvalidCrypto("lease signature verification failed"))?;

    let mut payload: LeasePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| CoreError::InvalidCrypto("lease payload is malformed"))?;
    if payload.v != LEASE_VERSION {
        payload.v = 0;
        return Err(CoreError::InvalidCrypto("unsupported lease version"));
    }
    if payload.vault_id != vault_id {
        return Err(CoreError::InvalidCrypto(
            "lease belongs to a different vault",
        ));
    }
    validate_vault_id(&payload.vault_id)?;
    validate_patterns(&payload.allow)?;
    validate_patterns(&payload.deny)?;
    if payload.allow.is_empty() {
        return Err(CoreError::InvalidCrypto("lease allows no key patterns"));
    }
    if now < payload.issued_at - 60 {
        return Err(CoreError::InvalidCrypto(
            "lease is not valid yet (clock skew or forged issuance time)",
        ));
    }
    if now >= payload.expires_at {
        return Err(CoreError::InvalidCrypto("lease has expired"));
    }
    Ok(Lease {
        payload,
        token: token.to_owned(),
    })
}

fn sign_payload(secret: &[u8; 32], payload: &LeasePayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&bytes);
    let signing_input = format!("{LEASE_PREFIX}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| CoreError::InvalidCrypto("invalid lease signing key"))?;
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{LEASE_PREFIX}.{payload_b64}.{signature_b64}"))
}

fn validate_vault_id(vault_id: &str) -> Result<()> {
    if vault_id.len() != 32 || !vault_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CoreError::InvalidCrypto(
            "lease vault id must be 32 hex characters",
        ));
    }
    Ok(())
}

fn validate_patterns(patterns: &[String]) -> Result<()> {
    if patterns.len() > MAX_LEASE_PATTERNS {
        return Err(CoreError::InvalidCrypto("too many lease patterns"));
    }
    for pattern in patterns {
        if pattern.is_empty() || pattern.len() > MAX_LEASE_PATTERN_BYTES {
            return Err(CoreError::InvalidCrypto(
                "lease patterns must be 1..=128 bytes",
            ));
        }
        if !pattern.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'*' | b'?' | b'.' | b'[' | b']')
        }) {
            return Err(CoreError::InvalidCrypto(
                "lease patterns may only contain letters, digits, _, -, ., * and ?",
            ));
        }
    }
    Ok(())
}

/// Glob matching for environment variable names.
///
/// Supports `*` (any sequence, including empty) and `?` (exactly one
/// character). Matching is ASCII and case-sensitive.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern = pattern.as_bytes();
    let name = name.as_bytes();
    let (mut p, mut n) = (0usize, 0usize);
    let (mut star, mut star_match) = (usize::MAX, 0usize);

    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = p;
            star_match = n;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            star_match += 1;
            n = star_match;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Decode a hex-encoded 32-byte lease signing key.
pub fn decode_secret(encoded: &[u8]) -> Result<[u8; 32]> {
    if encoded.len() != 64 {
        return Err(CoreError::MalformedKey);
    }
    let mut bytes = [0u8; 32];
    let decoded = hex::decode(encoded).map_err(|_| CoreError::MalformedKey)?;
    bytes.copy_from_slice(&decoded);
    let mut decoded = decoded;
    decoded.zeroize();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; 32] {
        [3u8; 32]
    }

    fn vault_id() -> String {
        "ab".repeat(16)
    }

    pub(super) fn allow() -> Vec<String> {
        vec!["DB_*".to_owned(), "STRIPE_*".to_owned()]
    }

    #[test]
    fn issue_and_verify() {
        let lease = issue(&secret(), &vault_id(), &allow(), &[], 600, None, None).unwrap();
        let verified = verify(&secret(), lease.token(), &vault_id(), now_unix()).unwrap();
        assert_eq!(verified.payload().allow, allow());
        assert!(verified.allows("DB_URL"));
        assert!(verified.allows("STRIPE_SECRET_KEY"));
        assert!(!verified.allows("OPENAI_API_KEY"));
    }

    #[test]
    fn tampering_is_rejected() {
        let lease = issue(&secret(), &vault_id(), &allow(), &[], 600, None, None).unwrap();
        let token = lease.token();
        let payload_start = token.find('.').unwrap() + 1;
        let mut chars: Vec<char> = token.chars().collect();
        chars[payload_start] = if chars[payload_start] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(verify(&secret(), &tampered, &vault_id(), now_unix()).is_err());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let lease = issue(&secret(), &vault_id(), &allow(), &[], 600, None, None).unwrap();
        assert!(verify(&[4u8; 32], lease.token(), &vault_id(), now_unix()).is_err());
    }

    #[test]
    fn wrong_vault_is_rejected() {
        let lease = issue(&secret(), &vault_id(), &allow(), &[], 600, None, None).unwrap();
        assert!(verify(&secret(), lease.token(), &"cd".repeat(16), now_unix()).is_err());
    }

    #[test]
    fn expiry_is_enforced() {
        let now = now_unix();
        let lease = issue(&secret(), &vault_id(), &allow(), &[], 1, None, None).unwrap();
        assert!(verify(&secret(), lease.token(), &vault_id(), now + 10).is_err());
    }

    #[test]
    fn deny_wins() {
        let lease = issue(
            &secret(),
            &vault_id(),
            &allow(),
            &["DB_PROD_*".to_owned()],
            600,
            None,
            None,
        )
        .unwrap();
        assert!(lease.allows("DB_URL"));
        assert!(!lease.allows("DB_PROD_PASSWORD"));
    }

    #[test]
    fn glob_semantics() {
        assert!(glob_match("DB_*", "DB_URL"));
        assert!(glob_match("*_KEY", "STRIPE_KEY"));
        assert!(glob_match("A?C", "ABC"));
        assert!(!glob_match("A?C", "AC"));
        assert!(glob_match("*", "ANYTHING"));
        assert!(!glob_match("DB_*", "database_url"));
    }

    #[test]
    fn ttl_limits_are_enforced() {
        assert!(issue(&secret(), &vault_id(), &allow(), &[], 0, None, None).is_err());
        assert!(issue(
            &secret(),
            &vault_id(),
            &allow(),
            &[],
            MAX_LEASE_TTL_SECONDS + 1,
            None,
            None
        )
        .is_err());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(verify(&secret(), "", &vault_id(), now_unix()).is_err());
        assert!(verify(&secret(), "envy_lease.a.b", &vault_id(), now_unix()).is_err());
        assert!(verify(&secret(), "nope", &vault_id(), now_unix()).is_err());
    }

    #[test]
    fn lease_secret_decoding() {
        let encoded = hex::encode([9u8; 32]);
        assert_eq!(decode_secret(encoded.as_bytes()).unwrap(), [9u8; 32]);
        assert!(decode_secret(b"short").is_err());
    }
}
