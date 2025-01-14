use rusotp::TOTP;

fn main() {
    let secret = "12345678901234567890";

    let totp_tool = match TOTP::new(secret, 6, 10, 30) {
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

    let totp_provisioning_uri = match TOTP::provisioning_uri(&totp_tool, "IAM", "test@mail.com") {
        Ok(totp_provisioning_uri) => totp_provisioning_uri,
        Err(e) => panic!("{}", e),
    };

    println!(
        "TOTP: {}, Valid: {}, Url: {}",
        totp, totp_is_valid, totp_provisioning_uri
    );
}
