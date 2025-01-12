use crate::otp::otp;

pub struct TOTP {
    secret: Vec<u8>,
    issuer: String,
    length: u8,
    radix: u8,
    interval: u8,
}

impl TOTP {
    pub fn new(secret: &str, issuer: &str, length: u8, radix: u8, interval: u8) -> Self {
        TOTP {
            secret: Vec::from(secret),
            issuer: String::from(issuer),
            length,
            radix,
            interval,
        }
    }

    pub fn now(&self) -> String {
        otp(
            self.time_code(chrono::Local::now().timestamp() as u64),
            self.secret.clone(),
            self.length,
            self.radix,
        )
    }

    pub fn at(&self, timestamp: i64) -> String {
        otp(
            self.time_code(timestamp as u64),
            self.secret.clone(),
            self.length,
            self.radix,
        )
    }

    pub fn verify(
        &self,
        otp: &str,
        at: i64,
        after: Option<i64>,
        drift_ahead: i64,
        drift_behind: i64,
    ) -> Option<i64> {
        let mut start = at - drift_behind;

        if let Some(after_time) = after {
            let after_code = after_time;
            if start < after_code {
                start = after_code;
            }
        }

        let end = at + drift_ahead;

        for i in start..=end {
            if otp == self.at(i) {
                return Some(i);
            }
        }

        None
    }

    pub fn provisioning_uri(&self, name: &str) -> String {
        let issuer_str = if !self.issuer.is_empty() {
            format!(
                "{}{}",
                urlencoding::encode(&self.issuer.to_owned()),
                urlencoding::encode(":")
            )
        } else {
            String::new()
        };

        let query = format!(
            "secret={}&issuer={}",
            urlencoding::encode(&String::from_utf8_lossy(&self.secret)),
            urlencoding::encode(&self.issuer)
        );

        format!(
            "otpauth://totp/{}{}?{}",
            issuer_str,
            urlencoding::encode(name),
            query
        )
    }

    fn time_code(&self, timestamp: u64) -> u64 {
        timestamp / self.interval as u64
    }
}
