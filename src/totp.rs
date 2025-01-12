use crate::otp::otp;

pub struct TOTP {
    secret: Vec<u8>,
    length: u8,
    radix: u8,
    interval: u8,
}

impl TOTP {
    pub fn new(secret: &str, length: u8, radix: u8, interval: u8) -> Self {
        TOTP {
            secret: Vec::from(secret),
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

    fn time_code(&self, timestamp: u64) -> u64 {
        timestamp / self.interval as u64
    }
}
