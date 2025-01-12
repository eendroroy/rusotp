use crate::otp::otp;

pub struct HOTP {
    secret: Vec<u8>,
    length: u8,
    radix: u8,
}

impl HOTP {
    pub fn new(secret: &str, length: u8, radix: u8) -> Self {
        HOTP {
            secret: Vec::from(secret),
            length,
            radix,
        }
    }

    pub fn generate(&self, counter: u64) -> String {
        otp(counter, self.secret.clone(), self.length, self.radix)
    }
}
