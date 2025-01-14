use crate::otp::otp::otp;

pub struct HOTP {
    secret: Vec<u8>,
    length: u8,
    radix: u8,
}

impl HOTP {
    pub fn new(secret: &str, length: u8, radix: u8) -> Result<HOTP, &'static str> {
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
            })
        }
    }

    pub fn generate(&self, counter: u64) -> Result<String, &'static str> {
        if counter < 1 {
            Err("Counter must be greater than or equal to 1")
        } else {
            Ok(otp(self.secret.clone(), self.length, self.radix, counter))
        }
    }

    pub fn verify(
        &self,
        otp: &str,
        counter: u64,
        retries: u64,
    ) -> Result<Option<u64>, &'static str> {
        if self.length != otp.len() as u8 {
            Err("OTP length does not match the length of the HOTP configuration")
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
            Err("HOTP length must be 6")
        } else if self.radix != 10 {
            Err("HOTP radix must be 10")
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

pub fn generate_hotp(secret: &str, length: u8, radix: u8, counter: u64) -> String {
    match HOTP::new(secret, length, radix) {
        Ok(hotp_tool) => match hotp_tool.generate(counter) {
            Ok(hotp) => hotp,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn verify_hotp(
    secret: &str,
    otp: &str,
    length: u8,
    radix: u8,
    counter: u64,
    retries: u64,
) -> bool {
    match HOTP::new(secret, length, radix) {
        Ok(hotp_tool) => match hotp_tool.verify(otp, counter, retries) {
            Ok(verified) => verified.is_some(),
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}

pub fn hotp_provisioning_uri(
    secret: &str,
    length: u8,
    radix: u8,
    name: &str,
    initial_count: u64,
) -> String {
    match HOTP::new(secret, length, radix) {
        Ok(hotp) => match hotp.provisioning_uri(name, initial_count) {
            Ok(provisioning_uri) => provisioning_uri,
            Err(e) => panic!("{}", e),
        },
        Err(e) => panic!("{}", e),
    }
}
