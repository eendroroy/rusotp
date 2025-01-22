use rusotp::{Algorithm, TOTP};

const SECRET_SHA1: &str = "12345678901234567890";
const SECRET_SHA256: &str = "12345678901234567890123456789012";
const SECRET_SHA512: &str = "1234567890123456789012345678901234567890123456789012345678901234";

#[test]
fn otp_should_match_with_rfc_samples() {
    vec![
        (SECRET_SHA1, 59, "94287082", Algorithm::SHA1),
        (SECRET_SHA256, 59, "46119246", Algorithm::SHA256),
        (SECRET_SHA512, 59, "90693936", Algorithm::SHA512),
        (SECRET_SHA1, 1111111109, "07081804", Algorithm::SHA1),
        (SECRET_SHA256, 1111111109, "68084774", Algorithm::SHA256),
        (SECRET_SHA512, 1111111109, "25091201", Algorithm::SHA512),
        (SECRET_SHA1, 1111111111, "14050471", Algorithm::SHA1),
        (SECRET_SHA256, 1111111111, "67062674", Algorithm::SHA256),
        (SECRET_SHA512, 1111111111, "99943326", Algorithm::SHA512),
        (SECRET_SHA1, 1234567890, "89005924", Algorithm::SHA1),
        (SECRET_SHA256, 1234567890, "91819424", Algorithm::SHA256),
        (SECRET_SHA512, 1234567890, "93441116", Algorithm::SHA512),
        (SECRET_SHA1, 2000000000, "69279037", Algorithm::SHA1),
        (SECRET_SHA256, 2000000000, "90698825", Algorithm::SHA256),
        (SECRET_SHA512, 2000000000, "38618901", Algorithm::SHA512),
        (SECRET_SHA1, 20000000000, "65353130", Algorithm::SHA1),
        (SECRET_SHA256, 20000000000, "77737706", Algorithm::SHA256),
        (SECRET_SHA512, 20000000000, "47863826", Algorithm::SHA512),
    ]
    .iter()
    .for_each(|(secret, timestamp, otp, algorithm)| {
        let totp = TOTP::new(*algorithm, secret, 8, 10, 30).unwrap();
        let result = totp.generate_at(*timestamp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), *otp);
    });
}
