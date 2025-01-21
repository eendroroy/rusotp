use rusotp::{Algorithm, TOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: u8 = 10;
const INTERVAL: u8 = 30;

#[test]
fn should_fail_with_empty_secret() {
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
