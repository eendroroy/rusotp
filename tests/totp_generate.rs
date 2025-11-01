use rusotp::{Algorithm, Radix, Secret, TOTP};
use std::num::NonZero;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const LENGTH: u8 = 6;
const RADIX: u8 = 10;
const INTERVAL: u64 = 30;

#[test]
fn should_generate_otp_now() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );
    let otp = totp.generate().unwrap();

    assert_eq!(otp.len(), LENGTH as usize);
}

#[test]
fn should_generate_otp_now_with_defaults() {
    let totp = TOTP::default(Secret::new("12345678901234567890").unwrap());
    let otp = totp.generate().unwrap();

    assert_eq!(otp.len(), LENGTH as usize);

    let totp = TOTP::rfc6238_default(Secret::new("12345678901234567890").unwrap());
    let otp = totp.generate().unwrap();

    assert_eq!(otp.len(), LENGTH as usize);
}

#[test]
fn should_generate_otp_now_using_current_at() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate().unwrap();
    let at = totp
        .generate_at(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
        .unwrap();

    assert_eq!(now.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at, now, "Expected OTPs to be equal");
}

#[test]
fn should_generate_otp_now_using_current_at_with_defaults() {
    let totp = TOTP::default(Secret::new("12345678901234567890").unwrap());

    let now = totp.generate().unwrap();
    let at = totp
        .generate_at(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
        .unwrap();

    assert_eq!(now.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at, now, "Expected OTPs to be equal");

    let totp = TOTP::rfc6238_default(Secret::new("12345678901234567890").unwrap());

    let now = totp.generate().unwrap();
    let at = totp
        .generate_at(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
        .unwrap();

    assert_eq!(now.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at, now, "Expected OTPs to be equal");
}
