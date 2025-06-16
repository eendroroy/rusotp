use itertools::iproduct;
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZeroU8;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const RADIX: Radix = Radix(10);

#[test]
fn should_not_get_verified_with_otp_length_not_matched() {
    let hotp = HOTP::new(ALGORITHM, Secret::new("12345678901234567890").unwrap(), NonZeroU8::new(6).unwrap(), RADIX);
    let result = hotp.verify("12345", 10, 0);

    assert!(result.is_ok(), "Expected a result");
    assert!(result.unwrap().is_none(), "Expected a failed verification");
}

#[test]
fn wrong_otp_should_not_get_verified() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let secret = Secret::new("12345678901234567890").unwrap();
    let lengths = [
        NonZeroU8::new(6).unwrap(),
        NonZeroU8::new(8).unwrap(),
        NonZeroU8::new(4).unwrap(),
    ];
    let radixes = [Radix(10), Radix(16), Radix(24), Radix(36)];
    let counters = [10, 16, 24, 36];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter())
        .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
        .for_each(|(algorithm, length, radix, counter)| {
            let hotp = HOTP::new(*algorithm, secret.clone(), *length, *radix);
            let otp = hotp.generate(*counter).unwrap();
            let result = hotp.verify(otp.as_str(), *counter + 1, 0);
            assert!(result.is_ok(), "Expected a result");
            assert!(result.unwrap().is_none(), "Expected a failed verification");
        });
}

#[test]
fn otp_get_verified_with_retries() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let secret = Secret::new("12345678901234567890").unwrap();
    let lengths = [
        NonZeroU8::new(6).unwrap(),
        NonZeroU8::new(8).unwrap(),
        NonZeroU8::new(4).unwrap(),
    ];
    let radixes = [Radix(10), Radix(16), Radix(24), Radix(36)];
    let counters = [10, 16, 24, 36];
    let retries = [1, 2, 3];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter(), retries.iter(),)
        .map(|(algorithm, length, radix, counter, retry)| (algorithm, length, radix, counter, retry))
        .for_each(|(algorithm, length, radix, counter, retry)| {
            let hotp = HOTP::new(*algorithm, secret.clone(), *length, *radix);
            let otp = hotp.generate(*counter).unwrap();
            let result = hotp.verify(otp.as_str(), *counter - *retry, *retry);
            assert!(result.is_ok(), "Expected a result");
            assert!(result.unwrap().is_some(), "Expected a successful verification");
        });
}
