use rusotp::{Algorithm, TOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: u8 = 10;
const INTERVAL: u8 = 30;
const ISSUER: &str = "rusotp";
const NAME: &str = "user@email.mail";

#[test]
fn hotp_should_fail_with_empty_secret() {
    let result = TOTP::new(ALGORITHM, "", LENGTH, RADIX, INTERVAL);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Secret must not be empty");
}

#[test]
fn should_fail_with_otp_length_less_than_1() {
    let result = TOTP::new(ALGORITHM, SECRET, 0, RADIX, INTERVAL);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length must be greater than or equal to 1"
    );
}

#[test]
fn should_fail_with_radix_less_than_2() {
    let lesser_radix = TOTP::new(ALGORITHM, SECRET, LENGTH, 1, INTERVAL);
    assert!(lesser_radix.is_err(), "Expected an error");
    assert_eq!(
        lesser_radix.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn should_fail_with_radix_greater_than_36() {
    let greater_radix = TOTP::new(ALGORITHM, SECRET, LENGTH, 37, INTERVAL);
    assert!(greater_radix.is_err(), "Expected an error");
    assert_eq!(
        greater_radix.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn should_fail_with_otp_length_not_matched() {
    let hotp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();
    let result = hotp.verify("12345", 10, Some(0), 0, 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length does not match the length of the configuration"
    );
}







#[test]
fn provisioning_uri_should_be_correct() {
    let hotp_tool = TOTP::new(Algorithm::SHA1, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(
        result.unwrap(),
        "otpauth://totp/rusotp%3Auser%40email.mail?secret=12345678901234567890&issuer=rusotp"
    );
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let hotp_tool = TOTP::new(Algorithm::SHA256, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let hotp_tool = TOTP::new(Algorithm::SHA512, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let hotp_tool = TOTP::new(ALGORITHM, SECRET, 5, RADIX, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let hotp_tool = TOTP::new(ALGORITHM, SECRET, 7, RADIX, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let hotp_tool = TOTP::new(ALGORITHM, SECRET, LENGTH, 9, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let hotp_tool = TOTP::new(ALGORITHM, SECRET, LENGTH, 11, INTERVAL).unwrap();

    let result = hotp_tool.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}
