//! Authenticated encryption primitives.
//!
//! - ChaCha20-Poly1305 (RFC 8439) with a 256-bit key and a 96-bit OS-random
//!   nonce protects legacy vaults and team protocol payloads.
//! - AES-256-SIV (RFC 5297) protects individual entries in the line-oriented
//!   vault format. Its nonce is deterministic by design; SIV is misuse-
//!   resistant and the format deliberately trades equality hiding for mergeable
//!   ciphertext.
//!
//! Random-nonce callers must never supply their own nonce.

use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::{Aes256SivAead, Nonce as SivNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const SIV_KEY_LEN: usize = 64;
pub const SIV_NONCE_LEN: usize = 16;
pub const SIV_TAG_LEN: usize = 16;

/// Fill `out` with bytes from the operating system CSPRNG.
pub fn fill_random(out: &mut [u8]) -> Result<()> {
    OsRng.try_fill_bytes(out).map_err(|_| CoreError::Rng)
}

/// Generate a fresh random nonce.
pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

/// Generate a random 32-byte key.
pub fn random_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(&mut key[..])?;
    Ok(key)
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Constant-time equality for equal-length byte slices.
///
/// Digests and MACs compared here are public metadata, but timing-safe
/// comparison is still the correct default.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encrypt `plaintext`, binding `aad` to the resulting ciphertext.
///
/// Returns ciphertext with the 16-byte Poly1305 tag appended.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::InvalidCrypto("encryption failed"))
}

/// Decrypt `ciphertext`, verifying `aad` and the Poly1305 tag.
///
/// The returned buffer is zeroized on drop and is the only plaintext copy
/// produced by the crypto layer.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Derive the 64-byte AES-256-SIV key used by the line-oriented vault format.
///
/// This is a key-derivation step, not a password KDF: the input is the
/// 256-bit random vault key from the OS credential store.
pub fn derive_siv_key(master: &[u8; KEY_LEN]) -> Result<Zeroizing<[u8; SIV_KEY_LEN]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"velt-vault-siv-salt-v2"), master);
    let mut key = Zeroizing::new([0u8; SIV_KEY_LEN]);
    hkdf.expand(b"velt-vault-siv-key-v2", &mut key[..])
        .map_err(|_| CoreError::InvalidCrypto("SIV key derivation failed"))?;
    Ok(key)
}

/// Deterministic AES-256-SIV encryption for one vault entry.
///
/// AES-SIV is misuse-resistant: a repeated nonce leaks equality between
/// plaintexts but does not break confidentiality or integrity. Velt derives the
/// nonce from the vault id and entry name, so unchanged entries produce
/// byte-identical lines and unrelated entries never share a nonce.
pub fn siv_encrypt(
    key: &[u8; SIV_KEY_LEN],
    nonce: &[u8; SIV_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256SivAead::new_from_slice(&key[..])
        .map_err(|_| CoreError::InvalidCrypto("invalid SIV key"))?;
    cipher
        .encrypt(
            &SivNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::InvalidCrypto("SIV encryption failed"))
}

/// Decrypt one AES-256-SIV entry; the returned plaintext is zeroized on drop.
pub fn siv_decrypt(
    key: &[u8; SIV_KEY_LEN],
    nonce: &[u8; SIV_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256SivAead::new_from_slice(&key[..])
        .map_err(|_| CoreError::InvalidCrypto("invalid SIV key"))?;
    let plaintext = cipher
        .decrypt(
            &SivNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CoreError::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// Derive the public deterministic nonce for an entry.
pub fn entry_nonce(vault_id: &[u8], name: &str, suffix: &str) -> [u8; SIV_NONCE_LEN] {
    let digest = sha256(
        format!(
            "velt-vault-entry-nonce-v2|{}|{name}{suffix}",
            hex::encode(vault_id)
        )
        .as_bytes(),
    );
    let mut nonce = [0u8; SIV_NONCE_LEN];
    nonce.copy_from_slice(&digest[..SIV_NONCE_LEN]);
    nonce
}

/// Derive the public deterministic nonce for the binding record.
pub fn binding_nonce(vault_id: &[u8], suffix: &str) -> [u8; SIV_NONCE_LEN] {
    let digest = sha256(
        format!(
            "velt-vault-binding-nonce-v2|{}{suffix}",
            hex::encode(vault_id)
        )
        .as_bytes(),
    );
    let mut nonce = [0u8; SIV_NONCE_LEN];
    nonce.copy_from_slice(&digest[..SIV_NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    #[test]
    fn roundtrip() {
        let nonce = [3u8; NONCE_LEN];
        let plaintext = b"STRIPE_KEY=sk_live_example";
        let ct = encrypt(&key(), &nonce, b"ctx", plaintext).unwrap();
        assert_ne!(ct.as_slice(), plaintext);
        let pt = decrypt(&key(), &nonce, b"ctx", &ct).unwrap();
        assert_eq!(&pt[..], plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let nonce = [3u8; NONCE_LEN];
        let ct = encrypt(&key(), &nonce, b"ctx", b"secret").unwrap();
        let mut other = key();
        other[0] ^= 1;
        assert!(matches!(
            decrypt(&other, &nonce, b"ctx", &ct),
            Err(CoreError::AuthenticationFailed)
        ));
    }

    #[test]
    fn aad_is_authenticated() {
        let nonce = [3u8; NONCE_LEN];
        let ct = encrypt(&key(), &nonce, b"vault-a", b"secret").unwrap();
        assert!(decrypt(&key(), &nonce, b"vault-b", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let nonce = [3u8; NONCE_LEN];
        let mut ct = encrypt(&key(), &nonce, b"ctx", b"secret").unwrap();
        ct[0] ^= 1;
        assert!(decrypt(&key(), &nonce, b"ctx", &ct).is_err());
    }

    #[test]
    fn random_nonces_do_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            assert!(seen.insert(random_nonce().unwrap()));
        }
    }
}
