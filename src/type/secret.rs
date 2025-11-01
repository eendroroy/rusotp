// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

/// Error type for secret-related operations.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretError;

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "must not be empty")
    }
}

/// Result type for secret operations.
pub type SecretResult<T> = Result<T, SecretError>;

/// Represents a secret as a vector of bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Secret(pub Vec<u8>);

impl Secret {
    /// Creates a new `Secret` from a string slice.
    ///
    /// # Errors
    ///
    /// Returns `SecretError` if the input string is empty.
    pub fn new(secret: &str) -> SecretResult<Self> {
        if secret.is_empty() {
            return Err(SecretError);
        }
        Ok(Self(secret.as_bytes().to_vec()))
    }

    /// Consumes the `Secret` and returns the underlying byte vector.
    pub fn get(self) -> Vec<u8> {
        self.0
    }
}
