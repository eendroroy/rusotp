pub mod otp;

pub use crate::otp::hotp::HOTP;
pub use crate::otp::totp::TOTP;

#[cfg(test)]
mod tests {
    use crate::{HOTP, TOTP};

    #[test]
    fn test() {
        let secret = "12345678901234567890";

        let hotp_tool = match HOTP::new(secret, 6, 10) {
            Ok(hotp_tool) => hotp_tool,
            Err(e) => panic!("{}", e),
        };

        let hotp = match HOTP::generate(&hotp_tool, 1) {
            Ok(hotp) => hotp,
            Err(e) => panic!("{}", e),
        };

        let hotp_is_valid = match HOTP::verify(&hotp_tool, &*hotp, 1, 10) {
            Ok(verified) => verified.is_some(),
            Err(e) => panic!("{}", e),
        };

        let hotp_provisioning_uri = match hotp_tool.provisioning_uri("test", 0) {
            Ok(hotp_provisioning_uri) => hotp_provisioning_uri,
            Err(e) => panic!("{}", e),
        };

        println!(
            "HOTP: {}, Valid: {}, Url: {}",
            hotp, hotp_is_valid, hotp_provisioning_uri
        );

        let totp_tool = match TOTP::new(secret, "IAM", 6, 10, 30) {
            Ok(totp_tool) => totp_tool,
            Err(e) => panic!("{}", e),
        };

        let totp = match TOTP::at_timestamp(&totp_tool, 31) {
            Ok(totp) => totp,
            Err(e) => panic!("{}", e),
        };

        let totp_is_valid = match TOTP::verify(&totp_tool, &*totp, 59, None, 0, 0) {
            Ok(verified) => verified.is_some(),
            Err(e) => panic!("{}", e),
        };

        let totp_provisioning_uri = match TOTP::provisioning_uri(&totp_tool, "test@mail.com") {
            Ok(totp_provisioning_uri) => totp_provisioning_uri,
            Err(e) => panic!("{}", e),
        };

        println!(
            "TOTP: {}, Valid: {}, Url: {}",
            totp, totp_is_valid, totp_provisioning_uri
        );
    }
}
