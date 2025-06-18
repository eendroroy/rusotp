use itertools::iproduct;
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::{NonZero, NonZeroU8};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const RADIX: u8 = 10;

#[test]
fn should_not_get_verified_with_otp_length_not_matched() {
    let hotp = HOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(RADIX).unwrap(),
    );
    let result = hotp.verify("12345", 10, 0);

    assert!(result.is_ok(), "Expected a result");
    assert!(result.unwrap().is_none(), "Expected a failed verification");
}

#[test]
fn wrong_otp_should_not_get_verified() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let secret = "12345678901234567890";
    let lengths = [6, 8, 4];
    let radixes = [10, 16, 24, 36];
    let counters = [10, 16, 24, 36];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter())
        .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
        .for_each(|(algorithm, length, radix, counter)| {
            let hotp = HOTP::new(
                *algorithm,
                Secret::new(secret).unwrap(),
                NonZero::new(*length).unwrap(),
                Radix::new(*radix).unwrap(),
            );
            let otp = hotp.generate(*counter).unwrap();
            let result = hotp.verify(otp.as_str(), *counter + 1, 0);
            assert!(result.is_ok(), "Expected a result");
            assert!(result.unwrap().is_none(), "Expected a failed verification");
        });
}

#[test]
fn otp_get_verified_with_retries() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let secret = "12345678901234567890";
    let lengths = [6, 8, 4];
    let radixes = [10, 16, 24, 36];
    let counters = [10, 16, 24, 36];
    let retries = [1, 2, 3];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter(), retries.iter(),)
        .map(|(algorithm, length, radix, counter, retry)| (algorithm, length, radix, counter, retry))
        .for_each(|(algorithm, length, radix, counter, retry)| {
            let hotp = HOTP::new(
                *algorithm,
                Secret::new(secret).unwrap(),
                NonZero::new(*length).unwrap(),
                Radix::new(*radix).unwrap(),
            );
            let otp = hotp.generate(*counter).unwrap();
            let result = hotp.verify(otp.as_str(), *counter - *retry, *retry);
            assert!(result.is_ok(), "Expected a result");
            assert!(result.unwrap().is_some(), "Expected a successful verification");
        });
}
