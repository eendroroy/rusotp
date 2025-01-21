use itertools::{iproduct, Itertools};
use rusotp::{Algorithm, HOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: u8 = 10;

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
    assert_eq!(
        result.err().unwrap(),
        "OTP length must be greater than or equal to 1"
    );
}

#[test]
fn should_fail_with_radix_less_than_2() {
    let lesser_radix = HOTP::new(ALGORITHM, SECRET, LENGTH, 1);
    assert!(lesser_radix.is_err(), "Expected an error");
    assert_eq!(
        lesser_radix.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn should_fail_with_radix_greater_than_36() {
    let greater_radix = HOTP::new(ALGORITHM, SECRET, LENGTH, 37);
    assert!(greater_radix.is_err(), "Expected an error");
    assert_eq!(
        greater_radix.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn should_fail_with_otp_length_not_matched() {
    let hotp = HOTP::new(ALGORITHM, SECRET, LENGTH, RADIX).unwrap();
    let result = hotp.verify("12345", 10, 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length does not match the length of the configuration"
    );
}

#[test]
fn otp_should_be_generated() {
    let algorithms = vec![Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let lengths = vec![6, 8, 4];
    let radixes = vec![10, 16, 24, 36];
    let counters = vec![10, 16, 24, 36];

    iproduct!(
        algorithms.iter(),
        lengths.iter(),
        radixes.iter(),
        counters.iter()
    )
    .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
    .unique()
    .for_each(|(algorithm, length, radix, counter)| {
        let hotp = HOTP::new(*algorithm, SECRET, *length, *radix).unwrap();
        let result = hotp.generate(*counter);
        assert!(result.is_ok(), "Expected a result");
    });
}

#[test]
fn wrong_otp_should_not_get_verified() {
    let algorithms = vec![Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let lengths = vec![6, 8, 4];
    let radixes = vec![10, 16, 24, 36];
    let counters = vec![10, 16, 24, 36];

    iproduct!(
        algorithms.iter(),
        lengths.iter(),
        radixes.iter(),
        counters.iter()
    )
    .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
    .unique()
    .for_each(|(algorithm, length, radix, counter)| {
        let hotp = HOTP::new(*algorithm, SECRET, *length, *radix).unwrap();
        let otp = hotp.generate(*counter).unwrap();
        let result = hotp.verify(otp.as_str(), *counter + 1, 0);
        assert!(result.is_ok(), "Expected a result");
        assert!(result.unwrap().is_none(), "Expected a failed verification");
    });
}

#[test]
fn otp_get_verified_with_retries() {
    let algorithms = vec![Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let lengths = vec![6, 8, 4];
    let radixes = vec![10, 16, 24, 36];
    let counters = vec![10, 16, 24, 36];
    let retries = vec![1, 2, 3];

    iproduct!(
        algorithms.iter(),
        lengths.iter(),
        radixes.iter(),
        counters.iter(),
        retries.iter(),
    )
    .map(|(algorithm, length, radix, counter, retry)| (algorithm, length, radix, counter, retry))
    .unique()
    .for_each(|(algorithm, length, radix, counter, retry)| {
        let hotp = HOTP::new(*algorithm, SECRET, *length, *radix).unwrap();
        let otp = hotp.generate(*counter).unwrap();
        let result = hotp.verify(otp.as_str(), *counter - *retry, *retry);
        assert!(result.is_ok(), "Expected a result");
        assert!(
            result.unwrap().is_some(),
            "Expected a successful verification"
        );
    });
}

#[test]
fn provisioning_uri_should_be_correct() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, LENGTH, RADIX).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(
        result.unwrap(),
        "otpauth://hotp/test?secret=12345678901234567890&counter=0"
    );
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
    let hotp_tool = HOTP::new(ALGORITHM, SECRET, LENGTH, 9).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let hotp_tool = HOTP::new(ALGORITHM, SECRET, LENGTH, 11).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}
