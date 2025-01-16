use crate::messages::{
    COUNTER_INVALID, OTP_LENGTH_INVALID, OTP_LENGTH_NOT_MATCHED, PROV_OTP_LENGTH_INVALID,
    PROV_OTP_RADIX_INVALID, RADIX_INVALID, SECRET_EMPTY, UNSUPPORTED_ALGORITHM,
};
use crate::otp::algorithm::Algorithm;
use crate::otp::otp::otp;

pub struct HOTP {
    algorithm: Algorithm,
    secret: Vec<u8>,
    length: u8,
    radix: u8,
}

impl HOTP {
    pub fn new(
        algorithm: Algorithm,
        secret: &str,
        length: u8,
        radix: u8,
    ) -> Result<HOTP, &'static str> {
        if secret.len() < 1 {
            Err(SECRET_EMPTY)
        } else if length < 4 {
            Err(OTP_LENGTH_INVALID)
        } else if radix < 2 || radix > 36 {
            Err(RADIX_INVALID)
        } else {
            Ok(Self {
                algorithm,
                secret: Vec::from(secret),
                length,
                radix,
            })
        }
    }

    pub fn generate(&self, counter: u64) -> Result<String, &'static str> {
        if counter < 1 {
            Err(COUNTER_INVALID)
        } else {
            Ok(otp(
                &self.algorithm,
                self.secret.clone(),
                self.length,
                self.radix,
                counter,
            ))
        }
    }

    pub fn verify(
        &self,
        otp: &str,
        counter: u64,
        retries: u64,
    ) -> Result<Option<u64>, &'static str> {
        if self.length != otp.len() as u8 {
            Err(OTP_LENGTH_NOT_MATCHED)
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

pub fn generate_hotp(
    algorithm: Algorithm,
    secret: &str,
    length: u8,
    radix: u8,
    counter: u64,
) -> String {
    match HOTP::new(algorithm, secret, length, radix) {
        Ok(hotp_tool) => match hotp_tool.generate(counter) {
            Ok(hotp) => hotp,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn verify_hotp(
    algorithm: Algorithm,
    secret: &str,
    otp: &str,
    length: u8,
    radix: u8,
    counter: u64,
    retries: u64,
) -> bool {
    match HOTP::new(algorithm, secret, length, radix) {
        Ok(hotp_tool) => match hotp_tool.verify(otp, counter, retries) {
            Ok(verified) => verified.is_some(),
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn hotp_provisioning_uri(
    algorithm: Algorithm,
    secret: &str,
    length: u8,
    radix: u8,
    name: &str,
    initial_count: u64,
) -> String {
    match HOTP::new(algorithm, secret, length, radix) {
        Ok(hotp) => match hotp.provisioning_uri(name, initial_count) {
            Ok(provisioning_uri) => provisioning_uri,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}
