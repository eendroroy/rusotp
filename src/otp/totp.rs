use crate::otp::otp::otp;

pub struct TOTP {
    secret: Vec<u8>,
    length: u8,
    radix: u8,
    interval: u8,
}

impl TOTP {
    pub fn new(secret: &str, length: u8, radix: u8, interval: u8) -> Result<TOTP, &'static str> {
        if secret.len() < 1 {
            Err("Secret must not be empty")
        } else if length < 4 {
            Err("Length must be greater than or equal to 4")
        } else if radix < 2 || radix > 36 {
            Err("Radix must be between 2 and 36 inclusive")
        } else {
            Ok(Self {
                secret: Vec::from(secret),
                length,
                radix,
                interval,
            })
        }
    }

    pub fn now(&self) -> Result<String, &'static str> {
        Ok(otp(
            self.secret.clone(),
            self.length,
            self.radix,
            self.time_code(chrono::Local::now().timestamp() as u64),
        ))
    }

    pub fn at_timestamp(&self, timestamp: i64) -> Result<String, &'static str> {
        if timestamp < 0 {
            Err("Timestamp must be greater than or equal to 0")
        } else {
            Ok(otp(
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
            Err("OTP length does not match the length of the HOTP configuration")
        } else if timestamp < 1 {
            Err("Timestamp must be greater than or equal to 1")
        } else if drift_behind >= timestamp {
            Err("Drift behind must be less than timestamp")
        } else if drift_ahead < 0 {
            Err("Drift ahead must be greater than or equal to 0")
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
            panic!("Interval must be greater than or equal to 30");
        } else if self.length != 6 {
            panic!("HOTP length must be 6");
        } else if self.radix != 10 {
            panic!("HOTP radix must be 10");
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

pub fn generate_totp_now(secret: &str, length: u8, radix: u8, interval: u8) -> String {
    match TOTP::new(secret, length, radix, interval) {
        Ok(totp) => match totp.now() {
            Ok(otp) => otp,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn generate_totp_at(
    secret: &str,
    length: u8,
    radix: u8,
    interval: u8,
    timestamp: i64,
) -> String {
    match TOTP::new(secret, length, radix, interval) {
        Ok(totp) => match totp.at_timestamp(timestamp) {
            Ok(otp) => otp,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn verify_totp(
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
    match TOTP::new(secret, length, radix, interval) {
        Ok(totp) => match totp.verify(otp, timestamp, after, drift_ahead, drift_behind) {
            Ok(verified) => verified,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn totp_provisioning_uri(
    secret: &str,
    length: u8,
    radix: u8,
    interval: u8,
    issuer: &str,
    name: &str,
) -> String {
    match TOTP::new(secret, length, radix, interval) {
        Ok(totp) => match TOTP::provisioning_uri(&totp, issuer, name) {
            Ok(provisioning_uri) => provisioning_uri,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}
