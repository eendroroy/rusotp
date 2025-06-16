use rusotp::{Algorithm, Radix, Secret, HOTP};

#[test]
fn otp_should_match_with_rfc_samples() {
    let secret = Secret::new("12345678901234567890").unwrap();
    let radix = Radix(10);

    vec![
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ]
    .iter()
    .for_each(|(counter, otp)| {
        let hotp = HOTP::new(Algorithm::SHA1, secret.clone(), 6, radix).unwrap();
        let result = hotp.generate(*counter);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), *otp);
    });
}
