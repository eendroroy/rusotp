use std::ops::Rem;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;

pub struct OtpConfig {
    pub secret: Vec<u8>,
    pub length: u8,
    pub radix: u8,
}

pub fn totp(interval: u8, config: OtpConfig) -> String {
    let counter = (chrono::Local::now().timestamp() / interval as i64) as u64;
    otp(counter, config.secret, config.length, config.radix)
}

pub fn hotp(counter: u64, config: OtpConfig) -> String {
    otp(counter, config.secret, config.length, config.radix)
}

fn otp(counter: u64, secret: Vec<u8>, length: u8, radix: u8) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&*secret).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    let hmac_result = mac.finalize().into_bytes();

    let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

    let binary_code = ((hmac_result[offset] as u64 & 0x7f) << 24)
        | ((hmac_result[offset + 1] as u64 & 0xff) << 16)
        | ((hmac_result[offset + 2] as u64 & 0xff) << 8)
        | (hmac_result[offset + 3] as u64 & 0xff);

    let otp_value = binary_code.rem((radix as u64).pow(length as u32));

    let otp = format!(
        "{:0>width$}",
        BigUint::to_str_radix(&BigUint::from(otp_value), radix as u32),
        width = (length as usize)
    );


    otp.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp() {
        let secret = Vec::from("12345678901234567890");

        println!(
            "TOTP: {}",
            totp(
                5,
                OtpConfig {
                    secret: secret.clone(),
                    length: 8,
                    radix: 13
                }
            )
        );
    }
}
