use rusotp::{Algorithm, HOTP};

const SECRET: &str = "12345678901234567890";

#[test]
fn hotp_should_fail_with_empty_secret() {
    let result = HOTP::new(Algorithm::SHA256, "", 1, 1);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Secret must not be empty");
}

#[test]
fn should_fail_with_otp_length_less_than_1() {
    let result = HOTP::new(Algorithm::SHA256, SECRET, 0, 10);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length must be greater than or equal to 1"
    );
}

#[test]
fn should_fail_with_radix_less_than_2() {
    let lesser_radix = HOTP::new(Algorithm::SHA256, SECRET, 4, 1);
    assert!(lesser_radix.is_err(), "Expected an error");
    assert_eq!(
        lesser_radix.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn should_fail_with_radix_greater_than_36() {
    let greater_radix = HOTP::new(Algorithm::SHA256, SECRET, 4, 37);
    assert!(greater_radix.is_err(), "Expected an error");
    assert_eq!(
        greater_radix.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn should_fail_with_otp_length_not_matched() {
    let hotp = HOTP::new(Algorithm::SHA256, SECRET, 4, 10).unwrap();
    let result = hotp.verify("12345", 10, 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length does not match the length of the configuration"
    );
}

#[test]
fn generated_otp_should_be_verified() {
    let data = vec![
        (Algorithm::SHA256, 6, 10, 1, "247374"),
        (Algorithm::SHA256, 6, 10, 2, "254785"),
        (Algorithm::SHA256, 6, 10, 3, "496144"),
        (Algorithm::SHA256, 6, 16, 1, "687B4E"),
        (Algorithm::SHA256, 6, 24, 1, "N7C1B6"),
        (Algorithm::SHA256, 6, 36, 1, "M16ONI"),
        (Algorithm::SHA256, 8, 10, 100, "93583477"),
        (Algorithm::SHA256, 8, 16, 100, "23615D75"),
        (Algorithm::SHA256, 8, 24, 100, "032D2EKL"),
        (Algorithm::SHA256, 8, 36, 100, "009TEJXX"),
        (Algorithm::SHA256, 4, 36, 1, "6ONI"),
        (Algorithm::SHA256, 4, 36, 2, "KYWX"),
        (Algorithm::SHA256, 4, 36, 3, "ERBK"),
        (Algorithm::SHA256, 4, 36, 4, "ROTO"),
    ];

    data.iter().for_each(|(algorithm, length, radix, counter, otp)| {
        let hotp = HOTP::new(*algorithm, SECRET, *length, *radix).unwrap();

        let result = hotp.generate(*counter);
        assert!(result.is_ok(), "Expected a result");
        assert_eq!(result.unwrap(), otp.to_string());
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
        let hotp = HOTP::new(Algorithm::SHA256, SECRET, *length, *radix).unwrap();

        let result = hotp.verify(otp, *counter + 1, 0);
        assert!(result.is_ok(), "Expected a result");
        assert!(result.unwrap().is_none(), "Expected a failed verification");
    });
}

#[test]
fn otp_get_verified_with_retries() {
    let data = vec![
        (6, 10, 2, "254785", 1),
        (6, 10, 3, "496144", 1),
        (8, 10, 100, "93583477", 5),
        (8, 16, 100, "23615D75", 1),
        (8, 24, 100, "032D2EKL", 1),
        (8, 36, 100, "009TEJXX", 1),
        (4, 36, 2, "KYWX", 1),
        (4, 36, 3, "ERBK", 1),
        (4, 36, 4, "ROTO", 1),
    ];

    data.iter()
        .for_each(|(length, radix, counter, otp, retries)| {
            let hotp = HOTP::new(Algorithm::SHA256, SECRET, *length, *radix).unwrap();

            let result = hotp.verify(otp, *counter - *retries, *retries);
            assert!(result.is_ok(), "Expected a result");
            assert!(
                result.unwrap().is_some(),
                "Expected a successful verification"
            );
        });
}

#[test]
fn generated_otp_gets_verified() {
    let secret = "12345678901234567890";

    let data = vec![
        (Algorithm::SHA256, 6, 10, 1),
        (Algorithm::SHA256, 6, 10, 2),
        (Algorithm::SHA256, 6, 10, 3),
        (Algorithm::SHA256, 6, 16, 1),
        (Algorithm::SHA256, 6, 24, 1),
        (Algorithm::SHA256, 6, 36, 1),
        (Algorithm::SHA256, 8, 10, 100),
        (Algorithm::SHA256, 8, 16, 100),
        (Algorithm::SHA256, 8, 24, 100),
        (Algorithm::SHA256, 8, 36, 100),
        (Algorithm::SHA256, 4, 36, 1),
        (Algorithm::SHA256, 4, 36, 2),
        (Algorithm::SHA256, 4, 36, 3),
    ];

    data.iter().for_each(|(algorithm, length, radix, counter)| {
        let hotp = HOTP::new(*algorithm, secret, *length, *radix).unwrap();
        let otp = hotp.generate(*counter).unwrap();

        let result = hotp.verify(&otp, *counter, 0);
        assert!(result.is_ok(), "Expected a result");
        assert!(
            result.unwrap().is_some(),
            "Expected a successful verification"
        );
    });
}

#[test]
fn provisioning_uri_should_be_correct() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, 6, 10).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(
        result.unwrap(),
        "otpauth://hotp/test?secret=12345678901234567890&counter=0"
    );
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let hotp_tool = HOTP::new(Algorithm::SHA256, SECRET, 6, 10).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let hotp_tool = HOTP::new(Algorithm::SHA512, SECRET, 6, 10).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Unsupported algorithm");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, 4, 10).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, 8, 10).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length must be 6");
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, 6, 9).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let hotp_tool = HOTP::new(Algorithm::SHA1, SECRET, 6, 11).unwrap();

    let result = hotp_tool.provisioning_uri("test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Radix must be 10");
}
