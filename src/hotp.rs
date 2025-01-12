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

    pub fn verify(&self, otp: &str, counter: u64, retries: u64) -> Option<u64> {
        for i in counter..(counter + retries) {
            if otp == self.generate(i) {
                return Some(i);
            }
        }
        None
    }

    pub fn provisioning_uri(&self, name: &str, initial_count: u64) -> String {
        let query = format!(
            "secret={}&counter={}",
            urlencoding::encode(&String::from_utf8_lossy(&self.secret)),
            initial_count
        );

        format!("otpauth://hotp/{}?{}", urlencoding::encode(name), query)
    }
}
