use rusotp::{Algorithm, Radix, Secret, TOTP};
use std::num::NonZero;

#[test]
fn otp_should_match_with_rfc_samples() {
    let radix = Radix(10);
    let secret_sha1: Secret = Secret::new("12345678901234567890").unwrap();
    let secret_sha256: Secret = Secret::new("12345678901234567890123456789012").unwrap();
    let secret_sha512: Secret =
        Secret::new("1234567890123456789012345678901234567890123456789012345678901234").unwrap();

    vec![
        (secret_sha1.clone(), 59, "94287082", Algorithm::SHA1),
        (secret_sha256.clone(), 59, "46119246", Algorithm::SHA256),
        (secret_sha512.clone(), 59, "90693936", Algorithm::SHA512),
        (secret_sha1.clone(), 1111111109, "07081804", Algorithm::SHA1),
        (secret_sha256.clone(), 1111111109, "68084774", Algorithm::SHA256),
        (secret_sha512.clone(), 1111111109, "25091201", Algorithm::SHA512),
        (secret_sha1.clone(), 1111111111, "14050471", Algorithm::SHA1),
        (secret_sha256.clone(), 1111111111, "67062674", Algorithm::SHA256),
        (secret_sha512.clone(), 1111111111, "99943326", Algorithm::SHA512),
        (secret_sha1.clone(), 1234567890, "89005924", Algorithm::SHA1),
        (secret_sha256.clone(), 1234567890, "91819424", Algorithm::SHA256),
        (secret_sha512.clone(), 1234567890, "93441116", Algorithm::SHA512),
        (secret_sha1.clone(), 2000000000, "69279037", Algorithm::SHA1),
        (secret_sha256.clone(), 2000000000, "90698825", Algorithm::SHA256),
        (secret_sha512.clone(), 2000000000, "38618901", Algorithm::SHA512),
        (secret_sha1.clone(), 20000000000, "65353130", Algorithm::SHA1),
        (secret_sha256.clone(), 20000000000, "77737706", Algorithm::SHA256),
        (secret_sha512.clone(), 20000000000, "47863826", Algorithm::SHA512),
    ]
    .iter()
    .for_each(|(secret, timestamp, otp, algorithm)| {
        let totp =
            TOTP::new(*algorithm, secret.clone(), NonZero::new(8).unwrap(), radix, NonZero::new(30).unwrap()).unwrap();
        let result = totp.generate_at(*timestamp);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), *otp);
    });
}
