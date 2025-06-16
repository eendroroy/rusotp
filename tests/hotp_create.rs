use rusotp::{Algorithm, Radix, HOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: Radix = Radix(10);

#[test]
fn hotp_should_fail_with_empty_secret() {
    let result = HOTP::new(ALGORITHM, "", LENGTH, RADIX);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Secret must not be empty");
}

#[test]
fn should_fail_with_otp_length_less_than_1() {
    let result = HOTP::new(ALGORITHM, SECRET, 0, RADIX);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be greater than or equal to 1");
}
