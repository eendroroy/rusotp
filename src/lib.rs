pub mod otp;

pub use crate::otp::hotp::HOTP;
pub use crate::otp::totp::TOTP;

#[cfg(test)]
mod tests {
    use crate::{HOTP, TOTP};

    #[test]
    fn test() {
        let secret = "12345678901234567890";
        let hotp_tool = HOTP::new(secret, 8, 10);
        let hotp = HOTP::generate(&hotp_tool, 0);
        let hotp_is_valid = HOTP::verify(&hotp_tool, &*hotp, 0, 10).is_some();

        println!("HOTP: {}, Valid: {}, Url: {}", hotp, hotp_is_valid, hotp_tool.provisioning_uri("test", 0));

        let totp_tool = TOTP::new(secret, "IAM", 8, 10, 30);
        let totp = TOTP::at(&totp_tool, 31);
        let totp_is_valid = TOTP::verify(&totp_tool, &*totp, 59, None, 0, 0).is_some();

        println!("TOTP: {}, Valid: {}, Url: {}", totp, totp_is_valid, totp_tool.provisioning_uri("test@mail.com"));
    }
}
