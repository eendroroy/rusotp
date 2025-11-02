// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::otp::algorithm::Algorithm;
use crate::otp::base::otp;
use crate::{
    InvalidSecretError, OtpResult, Radix, Secret, UnsupportedAlgorithmError, UnsupportedLengthError,
    UnsupportedRadixError,
};
use base32ct::{Base32, Encoding};
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
/// let secret = Secret::from_str("12345678901234567890").unwrap();
/// let radix = Radix::new(10).unwrap();
/// let length = NonZeroU8::new(6).unwrap();
///
/// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
/// let otp = hotp.generate(1).unwrap();
/// println!("Generated OTP: {}", otp);
/// ```
#[derive(Debug, PartialEq)]
pub struct HOTP {
    pub(crate) algorithm: Algorithm,
    pub(crate) secret: Secret,
    pub(crate) length: NonZeroU8,
    pub(crate) radix: Radix,
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
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
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
    /// use rusotp::{Secret, HOTP};
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
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
    /// use rusotp::{Secret, HOTP};
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
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
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
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
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
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
    /// * `issuer` - The issuer of the TOTP as a string.
    /// * `name` - The name of the user or account as a string.
    /// * `counter` - The initial counter value used in the HOTP generation.
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
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, secret, length, radix);
    /// let uri = hotp.provisioning_uri("rusotp", "rusotp", 1).unwrap();
    /// println!("Provisioning URI: {}", uri);
    /// ```
    pub fn provisioning_uri(&self, issuer: &str, user: &str, counter: u64) -> OtpResult<String> {
        if self.length.get() != 6 {
            Err(Box::new(UnsupportedLengthError(self.length.get())))
        } else if self.radix.get() != 10 {
            Err(Box::new(UnsupportedRadixError(self.radix.get())))
        } else if self.algorithm != Algorithm::SHA1 {
            Err(Box::new(UnsupportedAlgorithmError(self.algorithm)))
        } else {
            Ok(format!(
                "otpauth://hotp/{}?secret={}&counter={}&issuer={}",
                urlencoding::encode(&format!("{}:{}", issuer, user)),
                urlencoding::encode(Base32::encode_string(&self.secret.clone().get()).as_str()),
                urlencoding::encode(&counter.to_string()),
                urlencoding::encode(issuer)
            ))
        }
    }

    /// Parse an `otpauth://hotp/...` provisioning URI and construct an `HOTP` instance.
    ///
    /// The function extracts query parameters from the provided `uri` and uses them to
    /// populate an `HOTP`. The following query keys are recognized:
    /// - `secret` (required): Base32-encoded shared secret. If missing, returns `InvalidSecretError`.
    /// - `counter` (optional): Initial counter value (parsed as `u64`).
    /// - `issuer` (optional): Issuer string.
    ///
    /// # Arguments
    ///
    /// * `uri` - A provisioning URI string in the `otpauth` HOTP format.
    ///
    /// # Returns
    ///
    /// Returns `OtpResult<HOTP>`:
    /// - `Ok(HOTP)` on success (the returned `HOTP` uses RFC4226 defaults except for the provided secret).
    /// - `Err` if the `secret` parameter is missing or if parsing/decoding fails (note: this implementation
    ///   uses `unwrap()` on some decoding/parsing operations, which will panic on invalid input).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusotp::HOTP;
    ///
    /// // Example URI with a Base32 secret for "1234"
    /// let uri = "otpauth://hotp/rusotp%3Aeendroroy%40rusotp?secret=gezdgna%3D&counter=0&issuer=rusotp";
    /// let hotp = HOTP::from_uri(uri).unwrap();
    /// let otp = hotp.generate(1).unwrap();
    /// assert_eq!(otp.len(), 6);
    /// ```
    pub fn from_uri(uri: &str) -> OtpResult<HOTP> {
        let params = uri.split('?').last().unwrap().split('&');

        let mut secret: Option<Secret> = None;

        for param in params {
            if let Some((key, value)) = param.split_once('=') {
                match key {
                    "secret" => {
                        if !value.is_empty() {
                            secret = Some(Secret::from_vec(
                                Base32::decode_vec(urlencoding::decode(value).unwrap().trim()).unwrap(),
                            ))
                        }
                    }
                    _ => {}
                }
            }
        }

        if secret.is_none() {
            return Err(Box::new(InvalidSecretError()));
        }

        Ok(HOTP::default(secret.ok_or(InvalidSecretError()).unwrap()))
    }
}
