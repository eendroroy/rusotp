use crate::messages::{
    DRIFT_BEHIND_INVALID, INTERVAL_INVALID, OTP_LENGTH_NOT_MATCHED, PROV_OTP_LENGTH_INVALID,
    PROV_OTP_RADIX_INVALID, TIMESTAMP_INVALID, UNSUPPORTED_ALGORITHM,
};
use crate::otp::algorithm::Algorithm;
use crate::otp::otp::otp;

pub struct TOTP {
    algorithm: Algorithm,
    secret: Vec<u8>,
    length: u8,
    radix: u8,
    interval: u8,
}

impl TOTP {
    pub fn new(
        algorithm: Algorithm,
        secret: &str,
        length: u8,
        radix: u8,
        interval: u8,
    ) -> Result<TOTP, String> {
        Ok(Self {
            algorithm,
            secret: Vec::from(secret),
            length,
            radix,
            interval,
        })
    }

    pub fn now(&self) -> Result<String, String> {
        otp(
            &self.algorithm,
            self.secret.clone(),
            self.length,
            self.radix,
            self.time_code(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()),
        )
    }

    pub fn at_timestamp(&self, timestamp: u64) -> Result<String, String> {
        if timestamp < 1 {
            Err(TIMESTAMP_INVALID.to_string())
        } else {
            otp(
                &self.algorithm,
                self.secret.clone(),
                self.length,
                self.radix,
                self.time_code(timestamp),
            )
        }
    }

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
        } else if timestamp < 1 {
            Err(TIMESTAMP_INVALID.to_string())
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

    pub fn provisioning_uri(&self, issuer: &str, name: &str) -> Result<String, String> {
        if self.interval < 30 {
            panic!("{}", INTERVAL_INVALID);
        } else if self.length != 6 {
            panic!("{}", PROV_OTP_LENGTH_INVALID);
        } else if self.radix != 10 {
            panic!("{}", PROV_OTP_RADIX_INVALID);
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

    fn time_code(&self, timestamp: u64) -> u64 {
        timestamp / self.interval as u64
    }
}

pub fn generate_totp_now(
    algorithm: Algorithm,
    secret: &str,
    length: u8,
    radix: u8,
    interval: u8,
) -> String {
    match TOTP::new(algorithm, secret, length, radix, interval) {
        Ok(totp) => match totp.now() {
            Ok(otp) => otp,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn generate_totp_at(
    algorithm: Algorithm,
    secret: &str,
    length: u8,
    radix: u8,
    interval: u8,
    timestamp: u64,
) -> String {
    match TOTP::new(algorithm, secret, length, radix, interval) {
        Ok(totp) => match totp.at_timestamp(timestamp) {
            Ok(otp) => otp,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn verify_totp(
    algorithm: Algorithm,
    secret: &str,
    length: u8,
    radix: u8,
    interval: u8,
    otp: &str,
    timestamp: u64,
    after: Option<u64>,
    drift_ahead: u64,
    drift_behind: u64,
) -> Option<u64> {
    match TOTP::new(algorithm, secret, length, radix, interval) {
        Ok(totp) => match totp.verify(otp, timestamp, after, drift_ahead, drift_behind) {
            Ok(verified) => verified,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn totp_provisioning_uri(
    algorithm: Algorithm,
    secret: &str,
    length: u8,
    radix: u8,
    interval: u8,
    issuer: &str,
    name: &str,
) -> String {
    match TOTP::new(algorithm, secret, length, radix, interval) {
        Ok(totp) => match TOTP::provisioning_uri(&totp, issuer, name) {
            Ok(provisioning_uri) => provisioning_uri,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}
