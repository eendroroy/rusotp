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

        println!("HOTP: {}", HOTP::new(secret, 8, 10).generate(0));

        println!("TOTP: {}", TOTP::new(secret, 8, 10, 30).now());
    }
}
