use crate::messages::{
    OTP_LENGTH_INVALID, OTP_LENGTH_NOT_MATCHED, PROV_OTP_LENGTH_INVALID, PROV_OTP_RADIX_INVALID,
    RADIX_INVALID, SECRET_EMPTY, UNSUPPORTED_ALGORITHM,
};
use crate::otp::algorithm::Algorithm;
use crate::otp::otp::otp;

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
/// use rusotp::HOTP;
/// use rusotp::Algorithm;
///
/// let hotp = HOTP::new(Algorithm::SHA1, "12345678901234567890", 6, 10).unwrap();
/// let otp = hotp.generate(1).unwrap();
/// println!("Generated OTP: {}", otp);
/// ```
#[derive(Debug)]
pub struct HOTP {
    algorithm: Algorithm,
    secret: Vec<u8>,
    length: u8,
    radix: u8,
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
    /// A `Result` containing the HOTP instance if successful, or a `String` with the error message if the creation fails.
    ///
    /// # Errors
    ///
    /// This function returns an error if the secret is empty, the length is less than 1, or the radix is not between 2 and 36.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::HOTP;
    /// use rusotp::Algorithm;
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, "12345678901234567890", 6, 10).unwrap();
    /// ```
    pub fn new(algorithm: Algorithm, secret: &str, length: u8, radix: u8) -> Result<HOTP, String> {
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
            })
        }
    }

    /// Generates an OTP based on the provided counter value.
    ///
    /// # Arguments
    ///
    /// * `counter` - A counter value used in the OTP generation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated OTP as a `String` if successful, or a `String` with the error message if the generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use rusotp::HOTP;
    /// use rusotp::Algorithm;
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, "12345678901234567890", 6, 10).unwrap();
    /// let otp = hotp.generate(1).unwrap();
    /// println!("Generated OTP: {}", otp);
    /// ```
    pub fn generate(&self, counter: u64) -> Result<String, String> {
        otp(
            &self.algorithm,
            self.secret.clone(),
            self.length,
            self.radix,
            counter,
        )
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
    /// use rusotp::HOTP;
    /// use rusotp::Algorithm;
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, "12345678901234567890", 6, 10).unwrap();
    /// let otp = hotp.generate(1).unwrap();
    /// let verified = hotp.verify(&otp, 1, 0).unwrap();
    /// assert_eq!(verified, Some(1));
    /// ```
    pub fn verify(&self, otp: &str, counter: u64, retries: u64) -> Result<Option<u64>, String> {
        if self.length != otp.len() as u8 {
            Err(OTP_LENGTH_NOT_MATCHED.to_string())
        } else {
            for i in counter..=(counter + retries) {
                match self.generate(i) {
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
    /// use rusotp::HOTP;
    /// use rusotp::Algorithm;
    ///
    /// let hotp = HOTP::new(Algorithm::SHA1, "12345678901234567890", 6, 10).unwrap();
    /// let uri = hotp.provisioning_uri("rusotp", 1).unwrap();
    /// println!("Provisioning URI: {}", uri);
    /// ```
    pub fn provisioning_uri(&self, name: &str, initial_count: u64) -> Result<String, &'static str> {
        if self.length != 6 {
            Err(PROV_OTP_LENGTH_INVALID)
        } else if self.radix != 10 {
            Err(PROV_OTP_RADIX_INVALID)
        } else if self.algorithm != Algorithm::SHA1 {
            Err(UNSUPPORTED_ALGORITHM)
        } else {
            let query = format!(
                "secret={}&counter={}",
                urlencoding::encode(&String::from_utf8_lossy(&self.secret)),
                initial_count
            );

            Ok(format!(
                "otpauth://hotp/{}?{}",
                urlencoding::encode(name),
                query
            ))
        }
    }
}
