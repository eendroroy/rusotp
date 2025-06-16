use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZeroU8;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const RADIX: Radix = Radix(10);

#[test]
fn provisioning_uri_should_be_correct() {
    let hotp_tool =
        HOTP::new(Algorithm::SHA1, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(6).unwrap(), RADIX);

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(result.unwrap(), "otpauth://hotp/test?secret=12345678901234567890&counter=0");
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let hotp_tool =
        HOTP::new(Algorithm::SHA256, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(6).unwrap(), RADIX);

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let hotp_tool =
        HOTP::new(Algorithm::SHA512, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(6).unwrap(), RADIX);

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let hotp_tool =
        HOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(5).unwrap(), RADIX);

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let hotp_tool =
        HOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(7).unwrap(), RADIX);

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let hotp_tool =
        HOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(6).unwrap(), Radix(9));

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let hotp_tool =
        HOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(6).unwrap(), Radix(11));

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}
