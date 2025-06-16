use rusotp::{Algorithm, Radix, Secret, HOTP};

#[test]
fn should_fail_with_otp_length_less_than_1() {
    let result = HOTP::new(Algorithm::SHA256, Secret::new("12345678901234567890").unwrap(), 0, Radix(10));
    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be greater than or equal to 1");
}
