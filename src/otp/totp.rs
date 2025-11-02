// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::otp::algorithm::Algorithm;
use crate::otp::base::otp;
use crate::{
    AfterError, DriftBehindError, InvalidSecretError, OtpResult, Radix, Secret, UnsupportedAlgorithmError,
    UnsupportedIntervalError, UnsupportedLengthError, UnsupportedRadixError,
};
use base32ct::{Base32, Encoding};
use std::num::{NonZeroU64, NonZeroU8};

/// Represents a TOTP (Time-based One-Time Password) generator.
///
/// # Fields
///
/// * `algorithm` - The hashing algorithm used for TOTP generation.
/// * `secret` - The shared secret key used for TOTP generation.
/// * `length` - The length of the generated OTP.
/// * `radix` - The radix (base) used for the OTP representation.
/// * `interval` - The time interval in seconds for TOTP generation.
#[derive(Debug, PartialEq)]
pub struct TOTP {
    pub(crate) algorithm: Algorithm,
    pub(crate) secret: Secret,
    pub(crate) length: NonZeroU8,
    pub(crate) radix: Radix,
    pub(crate) interval: NonZeroU64,
}

impl TOTP {
    /// Creates a new TOTP instance with the specified algorithm, secret, length, radix, and interval.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hashing algorithm to be used.
    /// * `secret` - The shared secret key as a string.
    /// * `length` - The length of the OTP to be generated.
    /// * `radix` - The radix (base) for the OTP representation.
    /// * `interval` - The time interval in seconds for TOTP generation.
    ///
    /// # Returns
    ///
    /// A `TOTP` instance
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::{NonZeroU64, NonZeroU8};
    /// use rusotp::{Radix, Secret, TOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    /// let interval = NonZeroU64::new(30).unwrap();
    ///
    /// let totp = TOTP::new(Algorithm::SHA1, secret , length, radix, interval);
    /// let otp = totp.generate().unwrap();
    /// println!("Generated OTP: {}", otp);
    /// ```
    pub fn new(algorithm: Algorithm, secret: Secret, length: NonZeroU8, radix: Radix, interval: NonZeroU64) -> TOTP {
        Self {
            algorithm,
            secret,
            length,
            radix,
            interval,
        }
    }

    /// Returns a TOTP configured with RFC 4226 recommended defaults:
    /// - `algorithm`: SHA1
    /// - `length`: 6 digits
    /// - `radix`: 10 (decimal)
    ///
    /// The provided `secret` is used as the shared key for TOTP generation.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::{Secret, TOTP};
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    ///
    /// let totp = TOTP::default(secret);
    /// ```
    pub fn default(secret: Secret) -> TOTP {
        Self::new(
            Algorithm::SHA1,
            secret,
            NonZeroU8::new(6).unwrap(),
            Radix::new(10).unwrap(),
            NonZeroU64::new(30).unwrap(),
        )
    }

    /// Returns a TOTP configured with RFC 4226 recommended defaults:
    /// - Algorithm: SHA1
    /// - Length: 6 digits
    /// - Radix: 10 (decimal)
    ///
    /// The provided `secret` is used as the shared key for TOTP generation.
    ///
    /// Convenience constructor equivalent to `TOTP::default`.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::{Secret, TOTP};
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    ///
    /// let totp = TOTP::rfc6238_default(secret);
    /// ```
    pub fn rfc6238_default(secret: Secret) -> TOTP {
        Self::default(secret)
    }

    /// Generates an OTP based on the current time.
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated OTP as a `String` if successful, or a `String` with the error message if the generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::{NonZeroU64, NonZeroU8};
    /// use rusotp::{Radix, Secret, TOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    /// let interval = NonZeroU64::new(30).unwrap();
    ///
    /// let totp = TOTP::new(Algorithm::SHA1, secret, length, radix, interval);
    /// let otp = totp.generate().unwrap();
    /// println!("Generated OTP: {}", otp);
    /// ```
    pub fn generate(&self) -> OtpResult<String> {
        otp(
            &self.algorithm,
            self.secret.clone().get(),
            self.length.get(),
            self.radix.get(),
            self.time_code(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()),
        )
    }

    /// Generates an OTP based on the provided timestamp.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - A timestamp value used in the OTP generation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated OTP as a `String` if successful, or a `String` with the error message if the generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::{NonZeroU64, NonZeroU8};
    /// use rusotp::{Radix, Secret, TOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    /// let interval = NonZeroU64::new(30).unwrap();
    ///
    /// let totp = TOTP::new(Algorithm::SHA1, secret, length, radix, interval);
    /// let otp = totp.generate_at(1622548800).unwrap();
    /// println!("Generated OTP: {}", otp);
    /// ```
    pub fn generate_at(&self, timestamp: u64) -> OtpResult<String> {
        otp(&self.algorithm, self.secret.clone().get(), self.length.get(), self.radix.get(), self.time_code(timestamp))
    }

    /// Verifies an OTP based on the current time and drift values.
    ///
    /// # Arguments
    ///
    /// * `otp` - The OTP to be verified as a string.
    /// * `after` - An optional timestamp value after which the OTP is valid.
    /// * `drift_ahead` - The allowed drift ahead in seconds.
    /// * `drift_behind` - The allowed drift behind in seconds.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<u64>` with the timestamp value if the OTP is verified, or `None` if the OTP is not verified. Returns a `String` with the error message if the verification fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the length of the provided OTP does not match the expected length or if the drift behind is greater than or equal to the current timestamp.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::{NonZeroU64, NonZeroU8};
    /// use rusotp::{Radix, Secret, TOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    /// let interval = NonZeroU64::new(30).unwrap();
    ///
    /// let totp = TOTP::new(Algorithm::SHA1, secret, length, radix, interval);
    /// let otp = totp.generate().unwrap();
    /// let verified = totp.verify(&otp, None, 30, 30).unwrap();
    /// assert!(verified.is_some());
    /// ```
    pub fn verify(&self, otp: &str, after: Option<u64>, drift_ahead: u64, drift_behind: u64) -> OtpResult<Option<u64>> {
        self.verify_at(otp, std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(), after, drift_ahead, drift_behind)
    }

    /// Verifies an OTP based on the provided timestamp and drift values.
    ///
    /// # Arguments
    ///
    /// * `otp` - The OTP to be verified as a string.
    /// * `at` - A timestamp value used in the OTP verification.
    /// * `after` - An optional timestamp value after which the OTP is valid.
    /// * `drift_ahead` - The allowed drift ahead in seconds.
    /// * `drift_behind` - The allowed drift behind in seconds.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `Option<u64>` with the timestamp value if the OTP is verified, or `None` if the OTP is not verified. Returns a `String` with the error message if the verification fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the length of the provided OTP does not match the expected length or if the drift behind is greater than or equal to the timestamp.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::{NonZeroU64, NonZeroU8};
    /// use rusotp::{Radix, Secret, TOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    /// let interval = NonZeroU64::new(30).unwrap();
    ///
    /// let totp = TOTP::new(Algorithm::SHA1, secret, length, radix, interval);
    /// let otp = totp.generate_at(1622548800).unwrap();
    /// let verified = totp.verify_at(&otp, 1622548800, None, 30, 30).unwrap();
    /// assert_eq!(verified, Some(1622548800));
    /// ```
    pub fn verify_at(
        &self,
        otp: &str,
        at: u64,
        after: Option<u64>,
        drift_ahead: u64,
        drift_behind: u64,
    ) -> OtpResult<Option<u64>> {
        if self.length.get() != otp.len() as u8 {
            Ok(None)
        } else if drift_behind >= at {
            Err(Box::new(DriftBehindError(drift_behind, at)))
        } else {
            let mut start = at - drift_behind;

            if let Some(after_value) = after {
                if after_value > at {
                    return Err(Box::new(AfterError(after.unwrap(), at)));
                }
                if start < after_value {
                    start = after_value;
                }
            }

            let end = at + drift_ahead;

            for i in start..=end {
                match self.generate_at(i) {
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

    /// Generates a provisioning URI for TOTP based on the provided issuer and name.
    ///
    /// # Arguments
    ///
    /// * `issuer` - The issuer of the TOTP as a string.
    /// * `user` - The name of the user or account as a string.
    ///
    /// # Returns
    ///
    /// A `Result` containing the provisioning URI as a `String` if successful, or a `String` with the error message if the URI generation fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the interval is less than 30, the length is not 6, the radix is not 10, or the algorithm is not SHA-1.
    ///
    /// # Example
    ///
    /// ```
    /// use std::num::{NonZeroU64, NonZeroU8};
    /// use rusotp::{Radix, Secret, TOTP};
    /// use rusotp::Algorithm;
    ///
    /// let secret = Secret::from_str("12345678901234567890").unwrap();
    /// let radix = Radix::new(10).unwrap();
    /// let length = NonZeroU8::new(6).unwrap();
    /// let interval = NonZeroU64::new(30).unwrap();
    ///
    /// let totp = TOTP::new(Algorithm::SHA1, secret, length, radix, interval);
    /// let uri = totp.provisioning_uri("ExampleIssuer", "example@example.com").unwrap();
    /// println!("Provisioning URI: {}", uri);
    /// ```
    pub fn provisioning_uri(&self, issuer: &str, user: &str) -> OtpResult<String> {
        if self.interval.get() < 30 {
            Err(Box::new(UnsupportedIntervalError(self.interval.get())))
        } else if self.length.get() != 6 {
            Err(Box::new(UnsupportedLengthError(self.length.get())))
        } else if self.radix.get() != 10 {
            Err(Box::new(UnsupportedRadixError(self.radix.get())))
        } else if self.algorithm != Algorithm::SHA1 {
            Err(Box::new(UnsupportedAlgorithmError(self.algorithm)))
        } else {
            Ok(format!(
                "otpauth://totp/{}?secret={}&issuer={}",
                urlencoding::encode(&format!("{}:{}", issuer, user)),
                Base32::encode_string(&self.secret.clone().get()),
                urlencoding::encode(issuer)
            ))
        }
    }

    /// Parse an `otpauth://totp/...` provisioning URI and construct a `TOTP` instance.
    ///
    /// This function extracts query parameters from the provided `uri` and builds a `TOTP`
    /// configured with RFC 6238 defaults (Algorithm: SHA1, Length: 6, Radix: 10, Interval: 30)
    /// except for the `secret` which is taken from the URI. The following query keys are recognized:
    /// - `secret` (required): Base32-encoded shared secret. Must be present and non-empty.
    /// - `issuer` (optional): Issuer string (ignored by this constructor other than parsing).
    ///
    /// # Arguments:
    /// * `uri` - A provisioning URI string in the `otpauth` TOTP format, e.g.
    ///   `otpauth://totp/Label?secret=BASE32SECRET&issuer=Example`.
    ///
    /// # Returns:
    /// * `Ok(TOTP)` on success (uses RFC6238 defaults except for the provided secret).
    /// * `Err` if the `secret` parameter is missing or if decoding fails (note: current
    ///   implementation may panic on invalid encoding instead of returning an `Err`).
    ///
    /// # Example:
    /// ```rust
    /// use rusotp::TOTP;
    ///
    /// // Example URI with a Base32 secret for "1234"
    /// let uri = "otpauth://totp/rusotp%3Aeendroroy%40rusotp?secret=gezdgna=&issuer=rusotp";
    /// let hotp = TOTP::from_uri(uri).unwrap();
    /// let otp = hotp.generate().unwrap();
    /// assert_eq!(otp.len(), 6);
    /// ```
    pub fn from_uri(uri: &str) -> OtpResult<TOTP> {
        let params = uri.split('?').next_back().unwrap().split('&');

        let mut secret: Option<Secret> = None;

        for param in params {
            if let Some((key, value)) = param.split_once('=') {
                if key == "secret" {
                    if !value.is_empty() {
                        secret = Some(Secret::from_vec(
                            Base32::decode_vec(urlencoding::decode(value).unwrap().trim()).unwrap(),
                        ))
                    }
                }
            }
        }

        if secret.is_none() {
            return Err(Box::new(InvalidSecretError()));
        }

        Ok(TOTP::default(secret.ok_or(InvalidSecretError()).unwrap()))
    }

    fn time_code(&self, timestamp: u64) -> u64 {
        timestamp / self.interval.get()
    }
}
