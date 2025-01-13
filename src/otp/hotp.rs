use crate::otp::otp::otp;

pub struct HOTP {
    secret: Vec<u8>,
    length: u8,
    radix: u8,
}

impl HOTP {
    pub fn new(secret: &str, length: u8, radix: u8) -> Result<HOTP, &'static str> {
        if secret.len() < 1 {
            return Err("Secret must not be empty");
        }

        if length < 4 {
            return Err("Length must be greater than or equal to 4");
        }

        if radix < 2 || radix > 36 {
            return Err("Radix must be between 2 and 36 inclusive");
        }

        Ok(Self {
            secret: Vec::from(secret),
            length,
            radix,
        })
    }

    pub fn generate(&self, counter: u64) -> Result<String, &'static str> {
        if counter < 1 {
            return Err("Counter must be greater than or equal to 1");
        }
        Ok(otp(counter, self.secret.clone(), self.length, self.radix))
    }

    pub fn verify(&self, otp: &str, counter: u64, retries: u64) -> Result<Option<u64>, &'static str> {
        if self.length != otp.len() as u8 {
            return Err("OTP length does not match the length of the HOTP configuration");
        }
        for i in counter..(counter + retries) {
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

    pub fn provisioning_uri(&self, name: &str, initial_count: u64) -> Result<String, &'static str> {
        if self.length != 6 {
            return Err("HOTP length must be 6");
        }

        if self.radix != 10 {
            return Err("HOTP radix must be 10");
        }

        let query = format!(
            "secret={}&counter={}",
            urlencoding::encode(&String::from_utf8_lossy(&self.secret)),
            initial_count
        );

        Ok(format!("otpauth://hotp/{}?{}", urlencoding::encode(name), query))
    }
}
