use rusotp::{Algorithm, Radix, Secret, TOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const LENGTH: u8 = 6;
const RADIX: Radix = Radix(10);
const INTERVAL: u8 = 30;
const ISSUER: &str = "rusotp";
const NAME: &str = "user@email.mail";

#[test]
fn provisioning_uri_should_be_correct() {
    let totp =
        TOTP::new(Algorithm::SHA1, Secret::new("12345678901234567890").unwrap(), LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(result.unwrap(), "otpauth://totp/rusotp%3Auser%40email.mail?secret=12345678901234567890&issuer=rusotp");
}

#[test]
fn provisioning_uri_should_be_correct_if_issuer_is_empty() {
    let totp =
        TOTP::new(Algorithm::SHA1, Secret::new("12345678901234567890").unwrap(), LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri("", NAME);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(result.unwrap(), "otpauth://totp/user%40email.mail?secret=12345678901234567890");
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let totp =
        TOTP::new(Algorithm::SHA256, Secret::new("12345678901234567890").unwrap(), LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let totp =
        TOTP::new(Algorithm::SHA512, Secret::new("12345678901234567890").unwrap(), LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let totp = TOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), 5, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let totp = TOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), 7, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let totp = TOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), LENGTH, Radix(9), INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let totp = TOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), LENGTH, Radix(11), INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_interval_less_than_30() {
    let totp = TOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), LENGTH, RADIX, 29).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Interval must be greater than or equal to 30");
}
