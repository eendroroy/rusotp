use rusotp::{generate_hotp, hotp_provisioning_uri, verify_hotp, Algorithm};

const SECRET: &str = "12345678901234567890";
const OTP_LENGTH: u8 = 6;
const RADIX: u8 = 10;
const COUNTER: u64 = 0;
const RETRIES: u64 = 0;
const NAME: &str = "rusotp";

#[test]
#[should_panic(expected = "Secret must not be empty")]
fn should_panic_with_empty_secret() {
    generate_hotp(Algorithm::SHA256, "", OTP_LENGTH, RADIX, COUNTER);
}

#[test]
#[should_panic(expected = "OTP length must be greater than or equal to 1")]
fn should_panic_with_otp_length_less_than_1() {
    generate_hotp(Algorithm::SHA256, SECRET, 0, RADIX, COUNTER);
}

#[test]
#[should_panic(expected = "Radix must be between 2 and 36 inclusive")]
fn should_panic_with_radix_less_than_2() {
    generate_hotp(Algorithm::SHA256, SECRET, OTP_LENGTH, 1, COUNTER);
}

#[test]
#[should_panic(expected = "Radix must be between 2 and 36 inclusive")]
fn should_panic_with_radix_greater_than_36() {
    generate_hotp(Algorithm::SHA256, SECRET, OTP_LENGTH, 37, COUNTER);
}

#[test]
#[should_panic(expected = "OTP length does not match the length of the configuration")]
fn should_panic_with_otp_length_not_matched() {
    verify_hotp(Algorithm::SHA256, SECRET, "12345", OTP_LENGTH, RADIX, COUNTER, RETRIES);
}

#[test]
fn generated_otp_should_be_verified() {
    let data = vec![
        (6, 10, 1, "247374"),
        (6, 10, 2, "254785"),
        (6, 10, 3, "496144"),
        (6, 16, 1, "687B4E"),
        (6, 24, 1, "N7C1B6"),
        (6, 36, 1, "M16ONI"),
        (8, 10, 100, "93583477"),
        (8, 16, 100, "23615D75"),
        (8, 24, 100, "032D2EKL"),
        (8, 36, 100, "009TEJXX"),
        (4, 36, 1, "6ONI"),
        (4, 36, 2, "KYWX"),
        (4, 36, 3, "ERBK"),
        (4, 36, 4, "ROTO"),
    ];

    data.iter().for_each(|(length, radix, counter, otp)| {
        let result = generate_hotp(Algorithm::SHA256, SECRET, *length, *radix, *counter);
        assert_eq!(result.len() as u8, *length, "OTP length does not match");
        assert_eq!(result, otp.to_string());
    });
}

#[test]
fn wrong_otp_should_not_get_verified() {
    let data = vec![
        (6, 10, 1, "247374"),
        (6, 10, 2, "254785"),
        (6, 10, 3, "496144"),
        (6, 16, 1, "687B4E"),
        (6, 24, 1, "N7C1B6"),
        (6, 36, 1, "M16ONI"),
        (8, 10, 100, "93583477"),
        (8, 16, 100, "23615D75"),
        (8, 24, 100, "032D2EKL"),
        (8, 36, 100, "009TEJXX"),
        (4, 36, 1, "6ONI"),
        (4, 36, 2, "KYWX"),
        (4, 36, 3, "ERBK"),
        (4, 36, 4, "ROTO"),
    ];

    data.iter().for_each(|(length, radix, counter, otp)| {
        let result = verify_hotp(
            Algorithm::SHA256,
            SECRET,
            otp,
            *length,
            *radix,
            *counter + 1,
            0,
        );
        assert_eq!(result, false, "OTP should not be verified");
    });
}

#[test]
fn provisioning_uri_should_be_correct() {
    let result = hotp_provisioning_uri(Algorithm::SHA1, SECRET, 6, 10, "test", 0);
    assert_eq!(
        result,
        "otpauth://hotp/test?secret=12345678901234567890&counter=0"
    );
}

#[test]
#[should_panic(expected = "Unsupported algorithm")]
fn provisioning_uri_should_fail_with_sha256() {
    hotp_provisioning_uri(Algorithm::SHA256, SECRET, OTP_LENGTH, RADIX, NAME, 0);
}

#[test]
#[should_panic(expected = "Unsupported algorithm")]
fn provisioning_uri_should_fail_with_sha512() {
    hotp_provisioning_uri(Algorithm::SHA512, SECRET, OTP_LENGTH, RADIX, NAME, 0);
}

#[test]
#[should_panic(expected = "OTP length must be 6")]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    hotp_provisioning_uri(Algorithm::SHA1, SECRET, 4, RADIX, NAME, 0);
}

#[test]
#[should_panic(expected = "OTP length must be 6")]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    hotp_provisioning_uri(Algorithm::SHA1, SECRET, 8, RADIX, NAME, 0);
}

#[test]
#[should_panic(expected = "Radix must be 10")]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    hotp_provisioning_uri(Algorithm::SHA1, SECRET, OTP_LENGTH, 9, NAME, 0);
}

#[test]
#[should_panic(expected = "Radix must be 10")]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    hotp_provisioning_uri(Algorithm::SHA1, SECRET, OTP_LENGTH, 11, NAME, 0);
}
