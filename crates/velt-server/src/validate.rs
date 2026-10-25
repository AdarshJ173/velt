//! Input validation shared by API handlers.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;

use crate::error::{ApiError, ApiResult};
use crate::models::{BlobMaterial, EnvelopeInput, EnvelopeMaterial, PushBlobRequest};

pub const MAX_USERNAME_LEN: usize = 32;
pub const MAX_TEAM_NAME_LEN: usize = 64;
pub const MAX_ENV_LEN: usize = 32;
pub const MAX_GRANTS: usize = 64;

pub fn username(input: &str) -> ApiResult<String> {
    let normalized = input.trim().to_ascii_lowercase();
    if normalized.len() < 2 || normalized.len() > MAX_USERNAME_LEN {
        return Err(ApiError::BadRequest(
            "username must be 2..=32 characters".to_owned(),
        ));
    }
    let bytes = normalized.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(ApiError::BadRequest(
            "username must start with a letter or digit".to_owned(),
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ApiError::BadRequest(
            "username may contain letters, digits, underscore and hyphen".to_owned(),
        ));
    }
    Ok(normalized)
}

pub fn team_name(input: &str) -> ApiResult<String> {
    let name = input.trim();
    if name.is_empty() || name.chars().count() > MAX_TEAM_NAME_LEN {
        return Err(ApiError::BadRequest(
            "team name must be 1..=64 characters".to_owned(),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(
            "team name must not contain control characters".to_owned(),
        ));
    }
    Ok(name.to_owned())
}

pub fn environment(input: &str) -> ApiResult<String> {
    let environment = input.trim();
    if environment.is_empty() || environment.len() > MAX_ENV_LEN {
        return Err(ApiError::BadRequest(
            "environment must be 1..=32 characters".to_owned(),
        ));
    }
    let bytes = environment.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(ApiError::BadRequest(
            "environment must start with a lowercase letter or digit".to_owned(),
        ));
    }
    if !bytes.iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
    }) {
        return Err(ApiError::BadRequest(
            "environment may contain lowercase letters, digits, underscore and hyphen".to_owned(),
        ));
    }
    Ok(environment.to_owned())
}

pub fn grants(grants: Vec<String>) -> ApiResult<Vec<String>> {
    if grants.len() > MAX_GRANTS {
        return Err(ApiError::BadRequest(
            "too many environment grants".to_owned(),
        ));
    }
    let mut validated = Vec::with_capacity(grants.len());
    for grant in grants {
        let environment = environment(&grant)?;
        if !validated.contains(&environment) {
            validated.push(environment);
        }
    }
    Ok(validated)
}

pub fn role(input: &str) -> ApiResult<&'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "owner" => Ok("owner"),
        "admin" => Ok("admin"),
        "developer" => Ok("developer"),
        "ci_bot" => Ok("ci_bot"),
        _ => Err(ApiError::BadRequest(
            "role must be owner, admin, developer or ci_bot".to_owned(),
        )),
    }
}

pub fn role_rank(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "developer" => 2,
        "ci_bot" => 1,
        _ => 0,
    }
}

pub fn decode_b64(input: &str, field: &str) -> ApiResult<Vec<u8>> {
    if input.len() > 64 * 1024 {
        return Err(ApiError::BadRequest(format!("{field} is too large")));
    }
    STANDARD_NO_PAD
        .decode(input)
        .or_else(|_| STANDARD.decode(input))
        .or_else(|_| URL_SAFE_NO_PAD.decode(input))
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid base64")))
}

pub fn encode_b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

pub fn envelope(input: &EnvelopeInput, expected_epoch: u32) -> ApiResult<EnvelopeMaterial> {
    if input.epoch != expected_epoch {
        return Err(ApiError::BadRequest(format!(
            "envelope epoch {} does not match the current key epoch {expected_epoch}",
            input.epoch
        )));
    }
    let ephemeral_public_key = decode_b64(&input.ephemeral_public_key, "ephemeral_public_key")?;
    if ephemeral_public_key.len() != 32 {
        return Err(ApiError::BadRequest(
            "ephemeral_public_key must be 32 bytes".to_owned(),
        ));
    }
    let nonce = decode_b64(&input.nonce, "nonce")?;
    if nonce.len() != 12 {
        return Err(ApiError::BadRequest("nonce must be 12 bytes".to_owned()));
    }
    let ciphertext = decode_b64(&input.ciphertext, "ciphertext")?;
    if ciphertext.len() < 16 || ciphertext.len() > 4096 {
        return Err(ApiError::BadRequest(
            "envelope ciphertext must be 16..=4096 bytes".to_owned(),
        ));
    }
    Ok(EnvelopeMaterial {
        epoch: input.epoch,
        ephemeral_public_key,
        nonce,
        ciphertext,
    })
}

pub fn blob(input: &PushBlobRequest, max_bytes: usize) -> ApiResult<BlobMaterial> {
    if let Some(base_version) = input.base_version {
        if base_version < 0 {
            return Err(ApiError::BadRequest(
                "base_version must be non-negative".to_owned(),
            ));
        }
    }
    let nonce = decode_b64(&input.nonce, "nonce")?;
    if nonce.len() != 12 {
        return Err(ApiError::BadRequest("nonce must be 12 bytes".to_owned()));
    }
    let ciphertext = decode_b64(&input.ciphertext, "ciphertext")?;
    if ciphertext.len() < 17 || ciphertext.len() > max_bytes {
        return Err(ApiError::PayloadTooLarge);
    }
    let checksum = decode_b64(&input.checksum, "checksum")?;
    if checksum.len() != 32 {
        return Err(ApiError::BadRequest("checksum must be 32 bytes".to_owned()));
    }
    Ok(BlobMaterial {
        nonce,
        ciphertext,
        checksum,
    })
}

pub fn ensure_ed25519_public_key(openssh: &str) -> ApiResult<String> {
    let key = ssh_key::PublicKey::from_openssh(openssh.trim()).map_err(|_| {
        ApiError::BadRequest("ssh_public_key is not a valid OpenSSH key".to_owned())
    })?;
    if key.algorithm() != ssh_key::Algorithm::Ed25519 {
        return Err(ApiError::BadRequest(
            "only Ed25519 SSH keys are supported".to_owned(),
        ));
    }
    key.to_openssh()
        .map_err(|_| ApiError::BadRequest("could not encode ssh_public_key".to_owned()))
}

pub fn encryption_public_key(encoded: &str) -> ApiResult<String> {
    let bytes = decode_b64(encoded, "encryption_public_key")?;
    if bytes.len() != 32 {
        return Err(ApiError::BadRequest(
            "encryption_public_key must be 32 bytes".to_owned(),
        ));
    }
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ApiError::BadRequest(
            "encryption_public_key is not a valid X25519 public key".to_owned(),
        ));
    }
    Ok(encode_b64(&bytes))
}
