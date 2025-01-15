use rusotp::{Algorithm, HOTP};

fn main() {
    let secret = "12345678901234567890";
    let hotp_tool = match HOTP::new(Algorithm::SHA256, secret, 6, 10) {
        Ok(hotp_tool) => hotp_tool,
        Err(e) => panic!("{}", e),
    };

    let hotp = match HOTP::generate(&hotp_tool, 1) {
        Ok(hotp) => hotp,
        Err(e) => panic!("{}", e),
    };

    let hotp_is_valid = match HOTP::verify(&hotp_tool, hotp.as_ref(), 1, 1) {
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
}
