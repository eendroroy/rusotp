use rusotp::{generate_totp_at, generate_totp_now, verify_totp, Algorithm};

const SECRET: &str = "12345678901234567890";

#[test]
#[should_panic(expected = "Secret must not be empty")]
fn should_panic_with_empty_secret() {
    generate_totp_at(Algorithm::SHA1, "", 6, 10, 30, 1);
}

#[test]
#[should_panic(expected = "Radix must be between 2 and 36 inclusive")]
fn should_panic_with_radix_less_than_2() {
    generate_totp_at(Algorithm::SHA1, SECRET, 6, 1, 30, 1);
}

#[test]
#[should_panic(expected = "Radix must be between 2 and 36 inclusive")]
fn should_panic_with_radix_greater_than_36() {
    generate_totp_at(Algorithm::SHA1, SECRET, 6, 37, 30, 1);
}

#[test]
#[should_panic(expected = "OTP length must be greater than or equal to 1")]
fn should_panic_with_otp_length_less_than_1() {
    generate_totp_at(Algorithm::SHA1, SECRET, 0, 10, 30, 1);
}

#[test]
fn generated_otp_should_be_verified() {
    let data = vec![
        (6, 10, 30, 1),
        (6, 10, 30, 2),
        (6, 10, 30, 3),
        (6, 16, 30, 1),
        (6, 24, 30, 1),
        (6, 36, 30, 1),
        (8, 10, 30, 100),
        (8, 16, 30, 100),
        (8, 24, 30, 100),
        (8, 36, 30, 100),
        (4, 36, 30, 1),
        (4, 36, 30, 2),
        (4, 36, 30, 3),
        (4, 36, 30, 4),
    ];

    data.iter()
        .for_each(|(length, radix, interval, timestamp)| {
            let otp = generate_totp_at(
                Algorithm::SHA256,
                SECRET,
                *length,
                *radix,
                *interval,
                *timestamp,
            );
            assert_eq!(otp.is_empty(), false, "OTP should be generated");
            let verification = verify_totp(
                Algorithm::SHA256,
                SECRET,
                *length,
                *radix,
                *interval,
                &*otp,
                *timestamp,
                Some(0),
                0,
                0,
            );
            assert!(verification, "OTP should be verified");
        });
}

#[test]
fn generated_otp_now_should_be_verified() {
    let otp = generate_totp_now(Algorithm::SHA256, SECRET, 6, 10, 30);
    assert_eq!(otp.is_empty(), false, "OTP should be generated");
    let verification = verify_totp(
        Algorithm::SHA256,
        SECRET,
        6,
        10,
        30,
        &*otp,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        Some(0),
        0,
        1,
    );
    assert!(verification, "OTP should be verified");
}
