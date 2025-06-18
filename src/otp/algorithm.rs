use hmac::Mac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Trait for defining common behavior for different hashing algorithms.
///
/// # Methods
///
/// * `to_string` - Converts the algorithm to its string representation.
/// * `from_string` - Creates an algorithm instance from its string representation.
/// * `hash` - Hashes the given secret and data using the algorithm.
///
/// # Errors
///
/// The `hash` method returns an error if the hashing process fails.
pub trait AlgorithmTrait {
    fn to_string(&self) -> String;
    fn from_string(s: String) -> Option<Self>
    where
        Self: Sized;
    fn hash(&self, secret: Vec<u8>, data: u64) -> Result<Vec<u8>, String>;
}

/// Enum representing the supported hashing algorithms.
///
/// # Variants
///
/// * `SHA1` - Represents the SHA-1 hashing algorithm.
/// * `SHA256` - Represents the SHA-256 hashing algorithm.
/// * `SHA512` - Represents the SHA-512 hashing algorithm.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl AlgorithmTrait for Algorithm {
    /// Converts the algorithm to its string representation.
    ///
    /// # Returns
    ///
    /// A `String` representing the algorithm name.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusotp::{Algorithm, AlgorithmTrait};
    ///
    /// let algo = Algorithm::SHA256;
    /// ```
    fn to_string(&self) -> String {
        match self {
            Algorithm::SHA1 => "SHA1".into(),
            Algorithm::SHA256 => "SHA256".into(),
            Algorithm::SHA512 => "SHA512".into(),
        }
    }

    /// Creates an `Algorithm` instance from its string representation.
    ///
    /// # Arguments
    ///
    /// * `name` - A `String` representing the algorithm name (e\.g\., `"SHA1"`, `"SHA256"`, or `"SHA512"`)\.
    ///
    /// # Returns
    ///
    /// An `Option<Algorithm>` corresponding to the string\. Returns `None` if the string does not match any supported algorithm\.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusotp::{Algorithm, AlgorithmTrait};
    ///
    /// let algo = Algorithm::from_string("SHA256".to_string());
    /// assert_eq!(algo, Some(Algorithm::SHA256));
    /// ```
    fn from_string(name: String) -> Option<Self> {
        match name.as_str() {
            "SHA1" => Some(Algorithm::SHA1),
            "SHA256" => Some(Algorithm::SHA256),
            "SHA512" => Some(Algorithm::SHA512),
            _ => None,
        }
    }

    /// Hashes the given secret and data using the selected algorithm.
    ///
    /// # Arguments
    ///
    /// * `secret` - A `Vec<u8>` representing the shared secret key.
    /// * `data` - A `u64` value representing the data to be hashed.
    ///
    /// # Returns
    ///
    /// A `Result` containing a `Vec<u8>` with the hashed value if successful, or a `String` with the error message if the hashing process fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the HMAC construction or finalization fails.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::{Algorithm, AlgorithmTrait};
    ///
    /// let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
    /// let data = 123456u64;
    /// let algo = Algorithm::SHA256;
    /// let result = algo.hash(secret, data);
    /// assert!(result.is_ok());
    /// ```
    fn hash(&self, secret: Vec<u8>, data: u64) -> Result<Vec<u8>, String> {
        match self {
            Algorithm::SHA1 => match hmac::Hmac::<Sha1>::new_from_slice(secret.as_ref()) {
                Ok(mut mac) => {
                    mac.update(&data.to_be_bytes());
                    Ok(mac.finalize().into_bytes().to_vec())
                }
                Err(e) => Err(e.to_string()),
            },
            Algorithm::SHA256 => match hmac::Hmac::<Sha256>::new_from_slice(secret.as_ref()) {
                Ok(mut mac) => {
                    mac.update(&data.to_be_bytes());
                    Ok(mac.finalize().into_bytes().to_vec())
                }
                Err(e) => Err(e.to_string()),
            },
            Algorithm::SHA512 => match hmac::Hmac::<Sha512>::new_from_slice(secret.as_ref()) {
                Ok(mut mac) => {
                    mac.update(&data.to_be_bytes());
                    Ok(mac.finalize().into_bytes().to_vec())
                }
                Err(e) => Err(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod algorithm_test;
