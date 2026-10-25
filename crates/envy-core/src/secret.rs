//! Secret values that zero their memory when dropped.
//!
//! `SecretValue` deliberately does not implement `Display`. Values can only be
//! exposed through [`SecretValue::expose`], making every read site auditable.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A UTF-8 secret value whose backing allocation is wiped on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the secret. Callers must not log or persist the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Replace the secret, zeroizing the previous allocation in place.
    pub fn replace(&mut self, value: impl Into<String>) {
        self.0.zeroize();
        self.0 = value.into();
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

impl From<String> for SecretValue {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretValue {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretValue::new("super-secret-token");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn replace_removes_previous_value() {
        let mut secret = SecretValue::new("first");
        secret.replace("second");
        assert_eq!(secret.expose(), "second");
    }
}
