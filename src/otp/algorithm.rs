use crate::messages::UNSUPPORTED_ALGORITHM;

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
    fn from_string(s: String) -> Self;
    fn hash(&self, secret: Vec<u8>, data: u64) -> Result<Vec<u8>, String>;
}

/// Enum representing the supported hashing algorithms.
///
/// # Variants
///
/// * `SHA1` - Represents the SHA-1 hashing algorithm.
/// * `SHA256` - Represents the SHA-256 hashing algorithm.
/// * `SHA512` - Represents the SHA-512 hashing algorithm.
#[derive(Copy, Clone, Debug)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }

    fn ne(&self, other: &Self) -> bool {
        self.to_string() != other.to_string()
    }
}

impl AlgorithmTrait for Algorithm {
    /// Converts the algorithm to its string representation.
    ///
    /// # Returns
    ///
    /// A `String` representing the algorithm.
    fn to_string(&self) -> String {
        match self {
            Algorithm::SHA1 => "SHA1".to_string(),
            Algorithm::SHA256 => "SHA256".to_string(),
            Algorithm::SHA512 => "SHA512".to_string(),
        }
    }

    /// Creates an algorithm instance from its string representation.
    ///
    /// # Arguments
    ///
    /// * `name` - A `String` representing the algorithm.
    ///
    /// # Returns
    ///
    /// An `Algorithm` instance corresponding to the string representation.
    ///
    /// # Panics
    ///
    /// This function will panic if the string does not match any supported algorithm.
    fn from_string(name: String) -> Self {
        match name.as_str() {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => panic!("{:?}", UNSUPPORTED_ALGORITHM),
        }
    }

    /// Hashes the given secret and data using the algorithm.
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
    /// This function returns an error if the hashing process fails.
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
