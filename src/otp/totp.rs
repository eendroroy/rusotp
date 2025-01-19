use crate::messages::{
    DRIFT_BEHIND_INVALID, INTERVAL_INVALID, OTP_LENGTH_INVALID, OTP_LENGTH_NOT_MATCHED,
    PROV_OTP_LENGTH_INVALID, PROV_OTP_RADIX_INVALID, RADIX_INVALID, SECRET_EMPTY,
    UNSUPPORTED_ALGORITHM,
};
use crate::otp::algorithm::Algorithm;
use crate::otp::otp::otp;

/// Represents a TOTP (Time-based One-Time Password) generator.
///
/// # Fields
///
/// * `algorithm` - The hashing algorithm used for TOTP generation.
/// * `secret` - The shared secret key used for TOTP generation.
/// * `length` - The length of the generated OTP.
/// * `radix` - The radix (base) used for the OTP representation.
/// * `interval` - The time interval in seconds for TOTP generation.
#[derive(Debug)]
pub struct TOTP {
    algorithm: Algorithm,
    secret: Vec<u8>,
    length: u8,
    radix: u8,
    interval: u8,
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
    /// A `Result` containing the TOTP instance if successful, or a `String` with the error message if the creation fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the secret is empty, the length is less than 1, or the radix is not between 2 and 36.
    pub fn new(
        algorithm: Algorithm,
        secret: &str,
        length: u8,
        radix: u8,
        interval: u8,
    ) -> Result<TOTP, String> {
        if secret.len() < 1 {
            Err(SECRET_EMPTY.to_string())
        } else if length < 1 {
            Err(OTP_LENGTH_INVALID.to_string())
        } else if radix < 2 || radix > 36 {
            Err(RADIX_INVALID.to_string())
        } else {
            Ok(Self {
                algorithm,
                secret: Vec::from(secret),
                length,
                radix,
                interval,
            })
        }
    }

    /// Generates an OTP based on the current time.
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated OTP as a `String` if successful, or a `String` with the error message if the generation fails.
    pub fn now(&self) -> Result<String, String> {
        otp(
            &self.algorithm,
            self.secret.clone(),
            self.length,
            self.radix,
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
    pub fn at_timestamp(&self, timestamp: u64) -> Result<String, String> {
        otp(
            &self.algorithm,
            self.secret.clone(),
            self.length,
            self.radix,
            self.time_code(timestamp),
        )
    }

    /// Verifies an OTP based on the provided timestamp and drift values.
    ///
    /// # Arguments
    ///
    /// * `otp` - The OTP to be verified as a string.
    /// * `timestamp` - A timestamp value used in the OTP verification.
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
    pub fn verify(
        &self,
        otp: &str,
        timestamp: u64,
        after: Option<u64>,
        drift_ahead: u64,
        drift_behind: u64,
    ) -> Result<Option<u64>, String> {
        if self.length != otp.len() as u8 {
            Err(OTP_LENGTH_NOT_MATCHED.to_string())
        } else if drift_behind >= timestamp {
            Err(DRIFT_BEHIND_INVALID.to_string())
        } else {
            let mut start = timestamp - drift_behind;

            if let Some(after_time) = after {
                let after_code = after_time;
                if start < after_code {
                    start = after_code;
                }
            }

            let end = timestamp + drift_ahead;

            for i in start..=end {
                match self.at_timestamp(i) {
                    Ok(generated_otp) => {
                        if otp == generated_otp {
                            return Ok(Some(i));
                        }
                    }
                    Err(e) => panic!("{}", e),
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
    /// * `name` - The name of the user or account as a string.
    ///
    /// # Returns
    ///
    /// A `Result` containing the provisioning URI as a `String` if successful, or a `String` with the error message if the URI generation fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the interval is less than 30, the length is not 6, the radix is not 10, or the algorithm is not SHA-1.
    pub fn provisioning_uri(&self, issuer: &str, name: &str) -> Result<String, String> {
        if self.interval < 30 {
            Err(INTERVAL_INVALID.to_string())
        } else if self.length != 6 {
            Err(PROV_OTP_LENGTH_INVALID.to_string())
        } else if self.radix != 10 {
            Err(PROV_OTP_RADIX_INVALID.to_string())
        } else if self.algorithm != Algorithm::SHA1 {
            Err(UNSUPPORTED_ALGORITHM.to_string())
        } else {
            let issuer_str = if !issuer.is_empty() {
                format!(
                    "{}{}",
                    urlencoding::encode(&issuer.to_owned()),
                    urlencoding::encode(":")
                )
            } else {
                String::new()
            };

            let query = format!(
                "secret={}&issuer={}",
                urlencoding::encode(&String::from_utf8_lossy(&self.secret)),
                urlencoding::encode(&issuer)
            );

            Ok(format!(
                "otpauth://totp/{}{}?{}",
                issuer_str,
                urlencoding::encode(name),
                query
            ))
        }
    }

    /// Converts a timestamp to a time code based on the interval.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - A timestamp value.
    ///
    /// # Returns
    ///
    /// A `u64` representing the time code.
    fn time_code(&self, timestamp: u64) -> u64 {
        timestamp / self.interval as u64
    }
}
