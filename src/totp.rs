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
            (chrono::Local::now().timestamp() / self.interval as i64) as u64,
            self.secret.clone(),
            self.length,
            self.radix,
        )
    }

    pub fn at(&self, timestamp: i64) -> String {
        otp(
            (timestamp / self.interval as i64) as u64,
            self.secret.clone(),
            self.length,
            self.radix,
        )
    }
}
