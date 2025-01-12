pub mod hotp;
pub mod totp;
mod otp;

#[cfg(test)]
mod tests {
    use crate::hotp::HOTP;
    use crate::totp::TOTP;

    #[test]
    fn test_hotp() {
        let secret = "12345678901234567890";
        let hotp_tool = HOTP::new(secret, 8, 10);
        let hotp = hotp_tool.generate(0);
        let hotp_is_valid = hotp_tool.verify(&*hotp, 0, 10).is_some();

        println!("HOTP: {}, Valid: {}", hotp, hotp_is_valid);

        let totp_tool = TOTP::new(secret, 8, 10, 30);
        let totp = totp_tool.at(31);
        let totp_is_valid = totp_tool.verify(&*totp, 59, None, 0, 0).is_some();

        println!("TOTP: {}, Valid: {}", totp, totp_is_valid);
    }
}
