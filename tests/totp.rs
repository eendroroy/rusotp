use rusotp::{Algorithm, TOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: u8 = 10;
const INTERVAL: u8 = 30;
const ISSUER: &str = "rusotp";
const NAME: &str = "user@email.mail";
const AFTER: u64 = 0;
const DRIFT_AHEAD: u64 = 0;
const DRIFT_BEHIND: u64 = 0;

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

#[test]
fn should_fail_with_otp_length_not_matched() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();
    let result = totp.verify("12345", 10, Some(AFTER), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length does not match the length of the configuration"
    );
}

#[test]
fn should_fail_if_after_timestamp_is_greater_than_timestamp() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();
    let otp = totp.at_timestamp(10000).unwrap();
    let result = totp.verify(&otp, 10000, Some(10000 + 1), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "After timestamp must be less than or equal to timestamp"
    );
}

#[test]
fn should_fail_if_drift_behind_is_greater_than_timestamp() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();
    let otp = totp.at_timestamp(10000).unwrap();
    let result = totp.verify(&otp, 10000, Some(10000), DRIFT_AHEAD, 10000 + 1);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "Drift behind must be less than timestamp"
    );
}

#[test]
fn should_generate_otp_now() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();
    let otp = totp.now().unwrap();

    assert_eq!(otp.len(), LENGTH as usize);
}

#[test]
fn should_generate_otp_now_using_current_timestamp() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.now().unwrap();
    let at = totp
        .at_timestamp(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs())
        .unwrap();

    assert_eq!(now.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at.len(), LENGTH as usize, "Expected OTP length to be 6");
    assert_eq!(at, now, "Expected OTPs to be equal");
}

#[test]
fn should_verify_within_interval() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.at_timestamp(1).unwrap();
    let verify = totp.verify(&now, 29, Some(AFTER), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_not_verify_after_interval() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.at_timestamp(1).unwrap();
    let verify = totp.verify(&now, 30, Some(AFTER), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(verify.unwrap().is_none(), "OTP should not be verified");
}

#[test]
fn should_verify_with_after_timestamp_less_than_timestamp() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.now().unwrap();
    let verify = totp.verify(
        &now,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        Some(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() - 100),
        DRIFT_AHEAD,
        DRIFT_BEHIND,
    );

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_verify_with_after_timestamp_less_than_timestamp_and_drift_behind() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.now().unwrap();
    let verify = totp.verify(
        &now,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        Some(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() - 100),
        DRIFT_AHEAD,
        101,
    );

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_not_verify_with_after_timestamp_greater_than_timestamp() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.now().unwrap();
    let verify = totp.verify(
        &now,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        Some(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() + 100),
        DRIFT_AHEAD,
        DRIFT_BEHIND,
    );

    assert!(verify.is_err(), "OTP should not be verified");
    assert_eq!(verify.err().unwrap(), "After timestamp must be less than or equal to timestamp");
}

#[test]
fn should_verify_without_after_timestamp() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.now().unwrap();
    let verify = totp.verify(
        &now,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        None,
        DRIFT_AHEAD,
        DRIFT_BEHIND,
    );

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_verify_with_drift_behind() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.at_timestamp(90).unwrap();
    let verify = totp.verify(&now, 91, Some(AFTER), DRIFT_AHEAD, 1);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_verify_with_drift_ahead() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let now = totp.at_timestamp(90).unwrap();
    let verify = totp.verify(&now, 89, Some(AFTER), 1, DRIFT_BEHIND);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn provisioning_uri_should_be_correct() {
    let totp = TOTP::new(Algorithm::SHA1, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(
        result.unwrap(),
        "otpauth://totp/rusotp%3Auser%40email.mail?secret=12345678901234567890&issuer=rusotp"
    );
}

#[test]
fn provisioning_uri_should_be_correct_if_issuer_is_empty() {
    let totp = TOTP::new(Algorithm::SHA1, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri("", NAME);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(
        result.unwrap(),
        "otpauth://totp/user%40email.mail?secret=12345678901234567890"
    );
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let totp = TOTP::new(Algorithm::SHA256, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let totp = TOTP::new(Algorithm::SHA512, SECRET, LENGTH, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let totp = TOTP::new(ALGORITHM, SECRET, 5, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let totp = TOTP::new(ALGORITHM, SECRET, 7, RADIX, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, 9, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, 11, INTERVAL).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_interval_less_than_30() {
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, RADIX, 29).unwrap();

    let result = totp.provisioning_uri(ISSUER, NAME);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "Interval must be greater than or equal to 30"
    );
}
