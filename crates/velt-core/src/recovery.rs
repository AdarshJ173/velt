//! Shamir's Secret Sharing over GF(2^8) for vault master-key recovery.
//!
//! Recovery shares are generated locally and never leave the machine unless the
//! operator deliberately distributes them. A share string contains:
//!
//! ```text
//! velt1.<vault-id-hex>.<threshold>.<total>.<index>.<base32-data>.<checksum>
//! ```
//!
//! The data is 32 bytes of a degree `threshold - 1` polynomial evaluated at
//! `x = index`. Combining `threshold` distinct shares reconstructs the key at
//! `x = 0`. Every share carries a vault id and a checksum so that mismatched,
//! duplicated or truncated share sets fail closed.
//!
//! This implementation uses the AES irreducible polynomial `x^8 + x^4 + x^3 +
//! x + 1` (0x11b) and constant-time equality for checksums. It is deliberately
//! small and auditable; there are no hidden tables or external crypto crates.

use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::vault::{MasterKey, VaultId, VAULT_ID_LEN};

const SHARE_PREFIX: &str = "velt1";
const MIN_THRESHOLD: u8 = 2;
const SECRET_LEN: usize = crypto::KEY_LEN;

/// A single parsed recovery share.
struct RecoveryShare {
    vault_id: VaultId,
    threshold: u8,
    total: u8,
    index: u8,
    data: Zeroizing<[u8; SECRET_LEN]>,
}

impl RecoveryShare {
    fn encode(&self) -> Zeroizing<String> {
        let checksum = share_checksum(
            &self.vault_id,
            self.threshold,
            self.total,
            self.index,
            &self.data[..],
        );
        let encoded = Zeroizing::new(format!(
            "{SHARE_PREFIX}.{}.{}.{}.{}.{}.{}",
            hex::encode(self.vault_id),
            self.threshold,
            self.total,
            self.index,
            BASE32_NOPAD.encode(&self.data[..]),
            hex::encode(checksum),
        ));
        encoded
    }

    fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let parts: Vec<&str> = input.split('.').collect();
        if parts.len() != 7 {
            return Err(CoreError::InvalidShare(
                "expected 7 dot-separated fields".to_owned(),
            ));
        }
        if parts[0] != SHARE_PREFIX {
            return Err(CoreError::InvalidShare(
                "unknown or missing share prefix".to_owned(),
            ));
        }
        if parts[1].len() != VAULT_ID_LEN * 2 {
            return Err(CoreError::InvalidShare(
                "invalid vault id length".to_owned(),
            ));
        }
        let vault_bytes = hex::decode(parts[1])
            .map_err(|_| CoreError::InvalidShare("vault id is not valid hex".to_owned()))?;
        let mut vault_id = [0u8; VAULT_ID_LEN];
        vault_id.copy_from_slice(&vault_bytes);

        let threshold = parse_u8(parts[2], "threshold")?;
        let total = parse_u8(parts[3], "total")?;
        let index = parse_u8(parts[4], "index")?;

        if threshold < MIN_THRESHOLD {
            return Err(CoreError::InvalidShare(
                "threshold must be at least 2".to_owned(),
            ));
        }
        if total < threshold || total == 0 {
            return Err(CoreError::InvalidShare(
                "total must be greater than or equal to threshold".to_owned(),
            ));
        }
        if index == 0 || index > total {
            return Err(CoreError::InvalidShare(
                "share index is outside 1..=total".to_owned(),
            ));
        }

        let encoded_data = parts[5].to_ascii_uppercase();
        let decoded = BASE32_NOPAD
            .decode(encoded_data.as_bytes())
            .map_err(|_| CoreError::InvalidShare("share data is not valid base32".to_owned()))?;
        if decoded.len() != SECRET_LEN {
            return Err(CoreError::InvalidShare(format!(
                "share data must be {SECRET_LEN} bytes"
            )));
        }
        let mut data = Zeroizing::new([0u8; SECRET_LEN]);
        data.copy_from_slice(&decoded);
        drop(decoded);

        let expected = share_checksum(&vault_id, threshold, total, index, &data[..]);
        let actual = hex::decode(parts[6])
            .map_err(|_| CoreError::InvalidShare("share checksum is not valid hex".to_owned()))?;
        if !crypto::constant_time_eq(&expected, &actual) {
            return Err(CoreError::InvalidShare(
                "share checksum mismatch (truncated or modified share)".to_owned(),
            ));
        }

        Ok(Self {
            vault_id,
            threshold,
            total,
            index,
            data,
        })
    }
}

fn parse_u8(input: &str, field: &str) -> Result<u8> {
    input.parse::<u8>().map_err(|_| {
        CoreError::InvalidShare(format!("{field} is not a valid 8-bit unsigned integer"))
    })
}

fn share_checksum(vault_id: &VaultId, threshold: u8, total: u8, index: u8, data: &[u8]) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"velt-recovery-v1");
    hasher.update(vault_id);
    hasher.update([threshold, total, index]);
    hasher.update(data);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut checksum = [0u8; 8];
    checksum.copy_from_slice(&digest[..8]);
    checksum
}

/// Split a vault master key into `total` shares, any `threshold` of which
/// reconstruct it.
///
/// `total` is capped at 255 because share indices are non-zero GF(2^8) values.
pub fn split(
    key: &MasterKey,
    vault_id: VaultId,
    threshold: u8,
    total: u8,
) -> Result<Vec<Zeroizing<String>>> {
    if threshold < MIN_THRESHOLD {
        return Err(CoreError::InconsistentShares(
            "threshold must be at least 2".to_owned(),
        ));
    }
    if total < threshold {
        return Err(CoreError::InconsistentShares(
            "total shares must be at least the threshold".to_owned(),
        ));
    }
    if total == 0 {
        return Err(CoreError::InconsistentShares(
            "total shares must be positive".to_owned(),
        ));
    }

    // Polynomial coefficients: c0 is the secret, c1..c(k-1) are random.
    let mut coefficients: Vec<Zeroizing<[u8; SECRET_LEN]>> = Vec::with_capacity(threshold as usize);
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    secret.copy_from_slice(key.expose());
    coefficients.push(secret);
    for _ in 1..threshold {
        coefficients.push(crypto::random_key()?);
    }

    let mut shares = Vec::with_capacity(total as usize);
    for index in 1..=total {
        let mut data = Zeroizing::new([0u8; SECRET_LEN]);
        for byte in 0..SECRET_LEN {
            data[byte] = evaluate(&coefficients, index, byte);
        }
        shares.push(
            RecoveryShare {
                vault_id,
                threshold,
                total,
                index,
                data,
            }
            .encode(),
        );
    }
    Ok(shares)
}

fn evaluate(coefficients: &[Zeroizing<[u8; SECRET_LEN]>], x: u8, byte: usize) -> u8 {
    let mut acc = 0u8;
    for coefficient in coefficients.iter().rev() {
        acc = gf_mul(acc, x) ^ coefficient[byte];
    }
    acc
}

/// Reconstruct the master key and vault id from a set of shares.
///
/// Extra shares beyond the threshold are used to cross-check consistency; a
/// mismatched set is rejected rather than silently producing a wrong key.
pub fn combine(shares: &[&str]) -> Result<(MasterKey, VaultId)> {
    if shares.is_empty() {
        return Err(CoreError::InvalidShare(
            "no recovery shares provided".to_owned(),
        ));
    }

    let mut parsed = Vec::with_capacity(shares.len());
    for share in shares {
        parsed.push(RecoveryShare::parse(share)?);
    }

    let first = &parsed[0];
    let vault_id = first.vault_id;
    let threshold = first.threshold;
    let total = first.total;
    for share in &parsed[1..] {
        if share.vault_id != vault_id {
            return Err(CoreError::ShareVaultMismatch);
        }
        if share.threshold != threshold || share.total != total {
            return Err(CoreError::InconsistentShares(
                "shares use different threshold/total parameters".to_owned(),
            ));
        }
    }

    let mut seen = [false; 256];
    for share in &parsed {
        if seen[share.index as usize] {
            return Err(CoreError::InconsistentShares(
                "the same share index was provided twice".to_owned(),
            ));
        }
        seen[share.index as usize] = true;
    }

    if parsed.len() < threshold as usize {
        return Err(CoreError::NotEnoughShares {
            needed: threshold as usize,
            got: parsed.len(),
        });
    }

    let selected: Vec<&RecoveryShare> = parsed.iter().take(threshold as usize).collect();
    let secret = reconstruct(&selected)?;

    // Cross-check any additional shares against the reconstructed polynomial.
    for extra in parsed.iter().skip(threshold as usize) {
        let mut subset: Vec<&RecoveryShare> = selected
            .iter()
            .take(threshold as usize - 1)
            .copied()
            .collect();
        subset.push(extra);
        let candidate = reconstruct(&subset)?;
        if !crypto::constant_time_eq(&candidate[..], &secret[..]) {
            return Err(CoreError::InconsistentShares(
                "provided shares do not belong to the same secret".to_owned(),
            ));
        }
    }

    let master_key = MasterKey::from_slice(&secret[..])?;
    Ok((master_key, vault_id))
}

fn reconstruct(shares: &[&RecoveryShare]) -> Result<Zeroizing<[u8; SECRET_LEN]>> {
    if shares.is_empty() {
        return Err(CoreError::InvalidShare("no shares selected".to_owned()));
    }
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    for (position, share) in shares.iter().enumerate() {
        let x_i = share.index;
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (other_position, other) in shares.iter().enumerate() {
            if position == other_position {
                continue;
            }
            let x_j = other.index;
            numerator = gf_mul(numerator, x_j);
            denominator = gf_mul(denominator, x_i ^ x_j);
        }
        let denominator_inverse = gf_inverse(denominator).ok_or_else(|| {
            CoreError::InconsistentShares("duplicate x coordinates in share set".to_owned())
        })?;
        let basis = gf_mul(numerator, denominator_inverse);
        for byte in 0..SECRET_LEN {
            secret[byte] ^= gf_mul(share.data[byte], basis);
        }
    }
    Ok(secret)
}

/// Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(mut base: u8, mut exponent: u8) -> u8 {
    let mut result = 1u8;
    while exponent > 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn gf_inverse(value: u8) -> Option<u8> {
    if value == 0 {
        None
    } else {
        Some(gf_pow(value, 254))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn key() -> MasterKey {
        MasterKey::from_slice(&[0x42u8; 32]).unwrap()
    }

    fn vault_id() -> VaultId {
        [0xab; VAULT_ID_LEN]
    }

    fn combos(items: &[usize], k: usize) -> Vec<Vec<usize>> {
        if k == 0 {
            return vec![Vec::new()];
        }
        let mut result = Vec::new();
        for (index, item) in items.iter().enumerate() {
            for mut tail in combos(&items[index + 1..], k - 1) {
                let mut combination = vec![*item];
                combination.append(&mut tail);
                result.push(combination);
            }
        }
        result
    }

    #[test]
    fn every_threshold_combination_recovers_the_key() {
        let shares = split(&key(), vault_id(), 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        for combination in combos(&[0, 1, 2], 2) {
            let refs: Vec<&str> = combination
                .iter()
                .map(|index| shares[*index].as_str())
                .collect();
            let (recovered, id) = combine(&refs).unwrap();
            assert_eq!(recovered.expose(), key().expose());
            assert_eq!(id, vault_id());
        }
    }

    #[test]
    fn three_of_five_recovers() {
        let shares = split(&key(), vault_id(), 3, 5).unwrap();
        for combination in combos(&[0, 1, 2, 3, 4], 3) {
            let refs: Vec<&str> = combination
                .iter()
                .map(|index| shares[*index].as_str())
                .collect();
            let (recovered, _) = combine(&refs).unwrap();
            assert_eq!(recovered.expose(), key().expose());
        }
    }

    #[test]
    fn all_five_shares_still_recover() {
        let shares = split(&key(), vault_id(), 3, 5).unwrap();
        let refs: Vec<&str> = shares.iter().map(|share| share.as_str()).collect();
        let (recovered, _) = combine(&refs).unwrap();
        assert_eq!(recovered.expose(), key().expose());
    }

    #[test]
    fn too_few_shares_fail() {
        let shares = split(&key(), vault_id(), 3, 5).unwrap();
        let refs = [shares[0].as_str(), shares[1].as_str()];
        assert!(matches!(
            combine(&refs),
            Err(CoreError::NotEnoughShares { needed: 3, got: 2 })
        ));
    }

    #[test]
    fn duplicate_shares_fail() {
        let shares = split(&key(), vault_id(), 2, 3).unwrap();
        let refs = [shares[0].as_str(), shares[0].as_str()];
        assert!(matches!(
            combine(&refs),
            Err(CoreError::InconsistentShares(_))
        ));
    }

    #[test]
    fn corrupted_share_is_rejected() {
        let shares = split(&key(), vault_id(), 2, 3).unwrap();
        let mut corrupted = shares[0].as_str().to_owned();
        // Flip one base32 character in the data field.
        let replaced = corrupted.replacen('A', "B", 1);
        corrupted = replaced;
        let refs = [corrupted.as_str(), shares[1].as_str()];
        assert!(combine(&refs).is_err());
    }

    #[test]
    fn mismatched_vaults_fail() {
        let first = split(&key(), vault_id(), 2, 3).unwrap();
        let second = split(&key(), [0xcd; VAULT_ID_LEN], 2, 3).unwrap();
        let refs = [first[0].as_str(), second[1].as_str()];
        assert!(matches!(combine(&refs), Err(CoreError::ShareVaultMismatch)));
    }

    #[test]
    fn inconsistent_thresholds_fail() {
        let first = split(&key(), vault_id(), 2, 3).unwrap();
        let second = split(&key(), vault_id(), 2, 4).unwrap();
        let refs = [first[0].as_str(), second[1].as_str()];
        assert!(matches!(
            combine(&refs),
            Err(CoreError::InconsistentShares(_))
        ));
    }

    #[test]
    fn invalid_parameters_fail() {
        assert!(split(&key(), vault_id(), 1, 3).is_err());
        assert!(split(&key(), vault_id(), 4, 3).is_err());
        assert!(split(&key(), vault_id(), 2, 0).is_err());
    }

    #[test]
    fn gf_inverse_is_correct() {
        for value in 1u8..=255 {
            let inverse = gf_inverse(value).unwrap();
            assert_eq!(gf_mul(value, inverse), 1, "inverse failed for {value}");
        }
    }

    #[test]
    fn shares_do_not_contain_the_key() {
        let shares = split(&key(), vault_id(), 2, 3).unwrap();
        let key_hex = hex::encode(key().expose());
        for share in &shares {
            assert!(!share.as_str().contains(&key_hex));
        }
    }

    #[test]
    fn checksum_detects_modified_metadata() {
        let shares = split(&key(), vault_id(), 2, 3).unwrap();
        let modified = shares[0].as_str().replacen(".2.", ".3.", 1);
        let refs = [modified.as_str(), shares[1].as_str()];
        assert!(combine(&refs).is_err());
        // Silence unused import when crypto is only used in this module.
        let _ = crypto::sha256(b"");
    }
}
