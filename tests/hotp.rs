use rusotp::Algorithm;

#[test]
fn fail_with_empty_secret() {
    let result = rusotp::HOTP::new(Algorithm::SHA256, "", 1, 1);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "Secret must not be empty");
}

#[test]
fn fail_with_invalid_otp_length() {
    let result = rusotp::HOTP::new(Algorithm::SHA256, "12312341234", 1, 10);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length must be greater than or equal to 4"
    );
}

#[test]
fn fail_with_invalid_radix() {
    let result = rusotp::HOTP::new(Algorithm::SHA256, "12312341234", 4, 1);
    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "Radix must be between 2 and 36 inclusive"
    );
}

#[test]
fn fail_with_invalid_counter() {
    let hotp = match rusotp::HOTP::new(Algorithm::SHA256, "12312341234", 4, 10) {
        Ok(hotp) => hotp,
        Err(e) => panic!("{}", e),
    };

    let result = hotp.generate(0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "Counter must be greater than or equal to 1"
    );
}

#[test]
fn fail_with_otp_length_not_matched() {
    let hotp = match rusotp::HOTP::new(Algorithm::SHA256, "12312341234", 4, 10) {
        Ok(hotp) => hotp,
        Err(e) => panic!("{}", e),
    };

    let result = hotp.verify("12345", 10, 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(
        result.err().unwrap(),
        "OTP length does not match the length of the configuration"
    );
}

#[test]
fn generated_otp_is_correct() {
    let secret = "12345678901234567890";

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
        match rusotp::HOTP::new(Algorithm::SHA256, secret, *length, *radix) {
            Ok(hotp) => {
                let result = hotp.generate(*counter);
                assert!(result.is_ok(), "Expected a result");
                assert_eq!(result.unwrap(), otp.to_string());
            }
            Err(e) => panic!("{}", e),
        };
    });
}

#[test]
fn generated_otp_gets_verified() {
    let secret = "12345678901234567890";

    let data = vec![
        (6, 10, 1),
        (6, 10, 2),
        (6, 10, 3),
        (6, 16, 1),
        (6, 24, 1),
        (6, 36, 1),
        (8, 10, 100),
        (8, 16, 100),
        (8, 24, 100),
        (8, 36, 100),
        (4, 36, 1),
        (4, 36, 2),
        (4, 36, 3),
    ];

    data.iter().for_each(|(length, radix, counter)| {
        match rusotp::HOTP::new(Algorithm::SHA256, secret, *length, *radix) {
            Ok(hotp) => {
                match hotp.generate(*counter) {
                    Ok(otp) => {
                        let result = hotp.verify(&otp, *counter, 0);
                        assert!(result.is_ok(), "Expected a result");
                        assert!(
                            result.unwrap().is_some(),
                            "Expected a successful verification"
                        );
                    }
                    Err(e) => panic!("{}", e),
                };
            }
            Err(e) => panic!("{}", e),
        };
    });
}
