use rusotp::{Algorithm, Radix, HOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: Radix = Radix(10);

#[test]
fn provisioning_uri_should_be_correct() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, LENGTH, RADIX).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(result.unwrap(), "otpauth://hotp/test?secret=12345678901234567890&counter=0");
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let hotp_tool = HOTP::new(Algorithm::SHA256, SECRET, LENGTH, RADIX).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let hotp_tool = HOTP::new(Algorithm::SHA512, SECRET, LENGTH, RADIX).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let hotp_tool = HOTP::new(ALGORITHM, SECRET, 5, RADIX).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let hotp_tool = HOTP::new(ALGORITHM, SECRET, 7, RADIX).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let hotp_tool = HOTP::new(ALGORITHM, SECRET, LENGTH, Radix(9)).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let hotp_tool = HOTP::new(ALGORITHM, SECRET, LENGTH, Radix(11)).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}
