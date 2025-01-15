use crate::messages::{
    DRIFT_AHEAD_INVALID, DRIFT_BEHIND_INVALID, INTERVAL_INVALID, OTP_LENGTH_INVALID,
    OTP_LENGTH_NOT_MATCHED, PROV_OTP_LENGTH_INVALID, PROV_OTP_RADIX_INVALID, RADIX_INVALID,
    SECRET_EMPTY, TIMESTAMP_INVALID, UNSUPPORTED_ALGORITHM,
};
use crate::otp::algorithm::{Algorithm, AlgorithmTrait};
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
    ) -> Result<TOTP, &'static str> {
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
                interval,
            })
        }
    }

    pub fn now(&self) -> Result<String, &'static str> {
        Ok(otp(
            &self.algorithm,
            self.secret.clone(),
            self.length,
            self.radix,
            self.time_code(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()),
        ))
    }

    pub fn at_timestamp(&self, timestamp: i64) -> Result<String, &'static str> {
        if timestamp < 0 {
            Err(TIMESTAMP_INVALID)
        } else {
            Ok(otp(
                &self.algorithm,
                self.secret.clone(),
                self.length,
                self.radix,
                self.time_code(timestamp as u64),
            ))
        }
    }

    pub fn verify(
        &self,
        otp: &str,
        timestamp: i64,
        after: Option<i64>,
        drift_ahead: i64,
        drift_behind: i64,
    ) -> Result<Option<i64>, &'static str> {
        if self.length != otp.len() as u8 {
            Err(OTP_LENGTH_NOT_MATCHED)
        } else if timestamp < 1 {
            Err(TIMESTAMP_INVALID)
        } else if drift_behind >= timestamp {
            Err(DRIFT_BEHIND_INVALID)
        } else if drift_ahead < 0 {
            Err(DRIFT_AHEAD_INVALID)
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

    pub fn provisioning_uri(&self, issuer: &str, name: &str) -> Result<String, &'static str> {
        if self.interval < 30 {
            panic!("{}", INTERVAL_INVALID);
        } else if self.length != 6 {
            panic!("{}", PROV_OTP_LENGTH_INVALID);
        } else if self.radix != 10 {
            panic!("{}", PROV_OTP_RADIX_INVALID);
        } else if self.algorithm.to_str() != "SHA256" {
            Err(UNSUPPORTED_ALGORITHM)
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

pub fn generate_totp_now(algorithm: Algorithm, secret: &str, length: u8, radix: u8, interval: u8) -> String {
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
    timestamp: i64,
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
    timestamp: i64,
    after: Option<i64>,
    drift_ahead: i64,
    drift_behind: i64,
) -> Option<i64> {
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
