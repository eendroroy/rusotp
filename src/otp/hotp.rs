// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::otp::algorithm::Algorithm;
use crate::otp::base::otp;
use crate::{
    HOTPUri, OtpGenericError, OtpResult, Radix, Secret, UnsupportedAlgorithmError, UnsupportedLengthError,
    UnsupportedRadixError,
};
use std::num::NonZeroU8;

/// Represents an HOTP (HMAC-based One-Time Password) generator.
///
/// # Fields
///
/// * `algorithm` - The hashing algorithm used for HOTP generation.
/// * `secret` - The shared secret key used for HOTP generation.
/// * `length` - The length of the generated OTP.
/// * `radix` - The radix (base) used for the OTP representation.
///
/// # Example
///
/// ```
/// use std::num::NonZeroU8;
/// use rusotp::{Radix, Secret, HOTP};
/// use rusotp::Algorithm;
///
/// let secret = Secret::new("12345678901234567890").unwrap();
/// let radix = Radix::new(10).unwrap();
/// let length = NonZeroU8::new(6).unwrap();
///
/// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
/// let otp = hotp.generate(1).unwrap();
/// println!("Generated OTP: {}", otp);
/// ```
#[derive(Debug, PartialEq)]
pub struct HOTP {
    algorithm: Algorithm,
    secret: Secret,
    length: NonZeroU8,
    radix: Radix,
}

impl HOTP {
    /// Creates a new HOTP instance with the specified algorithm, secret, length, and radix.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hashing algorithm to be used.
    /// * `secret` - The shared secret key as a string.
    /// * `length` - The length of the OTP to be generated.
    /// * `radix` - The radix (base) for the OTP representation.
    ///
    /// # Returns
    ///
    /// A `HOTP` instance
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU8;
    /// use rusotp::{Radix, Secret, HOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::new("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
    /// ```
    pub fn new(algorithm: Algorithm, secret: Secret, length: NonZeroU8, radix: Radix) -> HOTP {
        Self {
            algorithm,
            secret,
            length,
            radix,
        }
    }

    /// Creates a `HOTP` instance from a provisioning URI.
    ///
    /// # Arguments
    ///
    /// * `uri` - A string slice that holds the provisioning URI.
    ///
    /// # Returns
    ///
    /// A `HOTP` instance initialized with the secret parsed from the URI, using RFC 4226 defaults.
    ///
    /// # Panics
    ///
    /// This function will panic if the URI cannot be parsed.
    ///
    /// # Example
    /// ```
    /// use rusotp::HOTP;
    ///
    /// let uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=1";
    /// let hotp = HOTP::from_uri(uri);
    /// ```
    pub fn from_uri(uri: &str) -> OtpResult<HOTP> {
        let huri = HOTPUri::parse(uri);
        match huri {
            Ok(h) => Ok(Self::default(h.secret)),
            Err(e) => Err(Box::new(OtpGenericError(e))),
        }
    }

    /// Returns a HOTP configured with RFC 4226 recommended defaults:
    /// - `algorithm`: SHA1
    /// - `length`: 6 digits
    /// - `radix`: 10 (decimal)
    ///
    /// The provided `secret` is used as the shared key for HOTP generation.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::{Secret};
    ///
    /// let secret = Secret::new("12345678901234567890").unwrap();
    ///
    /// let hotp = HOTP::default(secret);
    /// ```
    pub fn default(secret: Secret) -> HOTP {
        Self::new(Algorithm::SHA1, secret, NonZeroU8::new(6).unwrap(), Radix::new(10).unwrap())
    }

    /// Returns a HOTP configured with RFC 4226 recommended defaults:
    /// - Algorithm: SHA1
    /// - Length: 6 digits
    /// - Radix: 10 (decimal)
    ///
    /// The provided `secret` is used as the shared key for HOTP generation.
    ///
    /// Convenience constructor equivalent to `HOTP::default`.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::{Secret};
    ///
    /// let secret = Secret::new("12345678901234567890").unwrap();
    ///
    /// let hotp = HOTP::rfc4226_default(secret);
    /// ```
    pub fn rfc4226_default(secret: Secret) -> HOTP {
        Self::default(secret)
    }

    /// Generates an OTP based on the provided counter value.
    ///
    /// # Arguments
    ///
    /// * `counter` - A counter value used in the OTP generation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated OTP as a `String` if successful,
    /// or a `String` with the error message if the generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU8;
    /// use rusotp::{Radix, Secret, HOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::new("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
    /// let otp = hotp.generate(1).unwrap();
    /// println!("Generated OTP: {}", otp);
    /// ```
    pub fn generate(&self, counter: u64) -> OtpResult<String> {
        otp(&self.algorithm, self.secret.clone().get(), self.length.get(), self.radix.get(), counter)
    }

    /// Verifies an OTP based on the provided counter value and retries.
    ///
    /// # Arguments
    ///
    /// * `otp` - The OTP to be verified as a string.
    /// * `counter` - A counter value used in the OTP verification.
    /// * `retries` - The number of retries allowed for the OTP verification.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<u64>` with the counter value if the OTP is verified, or `None` if the OTP is not verified. Returns a `String` with the error message if the verification fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the length of the provided OTP does not match the expected length.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU8;
    /// use rusotp::{Radix, Secret, HOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::new("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
    /// let otp = hotp.generate(1).unwrap();
    /// let verified = hotp.verify(&otp, 1, 0).unwrap();
    /// assert_eq!(verified, Some(1));
    /// ```
    pub fn verify(&self, otp: &str, counter: u64, retries: u64) -> OtpResult<Option<u64>> {
        if self.length.get() != otp.len() as u8 {
            Ok(None)
        } else {
            for i in counter..=(counter + retries) {
                match self.generate(i) {
                    Ok(generated_otp) => {
                        if otp == generated_otp {
                            return Ok(Some(i));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(None)
        }
    }

    /// Generates a provisioning URI for HOTP based on the provided name and initial counter value.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the user or account as a string.
    /// * `initial_count` - The initial counter value used in the HOTP generation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the provisioning URI as a `String` if successful, or a `&'static str` with the error message if the URI generation fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the length is not 6, the radix is not 10, or the algorithm is not SHA-1.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::NonZeroU8;
    /// use rusotp::{Radix, Secret, HOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::new("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
    /// let uri = hotp.provisioning_uri("rusotp", 1).unwrap();
    /// println!("Provisioning URI: {}", uri);
    /// ```
    pub fn provisioning_uri(&self, name: &str, initial_count: u64) -> OtpResult<String> {
        if self.length.get() != 6 {
            Err(Box::new(UnsupportedLengthError(self.length.get())))
        } else if self.radix.get() != 10 {
            Err(Box::new(UnsupportedRadixError(self.radix.get())))
        } else if self.algorithm != Algorithm::SHA1 {
            Err(Box::new(UnsupportedAlgorithmError(self.algorithm)))
        } else {
            Ok(HOTPUri::new(name, self.secret.clone(), initial_count).uri())
        }
    }
}
