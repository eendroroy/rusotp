use rusotp::{Algorithm, TOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: u8 = 10;
const INTERVAL: u8 = 30;

#[test]
fn should_generate_otp_now() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();
    let otp = totp.generate().unwrap();

    assert_eq!(otp.len(), LENGTH as usize);
}

#[test]
fn should_generate_otp_now_using_current_at() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.generate().unwrap();
    let at = totp
        .generate_at(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
        .unwrap();

    assert_eq!(now.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at, now, "Expected OTPs to be equal");
}
