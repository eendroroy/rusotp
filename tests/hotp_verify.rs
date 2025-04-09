use itertools::{Itertools, iproduct};
use rusotp::{Algorithm, HOTP};

const ALGORITHM: Algorithm = Algorithm::SHA256;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const RADIX: u8 = 10;

#[test]
fn should_fail_with_otp_length_not_matched() {
    let hotp = HOTP::new(ALGORITHM, SECRET, LENGTH, RADIX).unwrap();
    let result = hotp.verify("12345", 10, 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap(), "OTP length does not match the length of the configuration");
}

#[test]
fn wrong_otp_should_not_get_verified() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let lengths = [6, 8, 4];
    let radixes = [10, 16, 24, 36];
    let counters = [10, 16, 24, 36];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter())
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
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let lengths = [6, 8, 4];
    let radixes = [10, 16, 24, 36];
    let counters = [10, 16, 24, 36];
    let retries = [1, 2, 3];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter(), retries.iter(),)
        .map(|(algorithm, length, radix, counter, retry)| (algorithm, length, radix, counter, retry))
        .unique()
        .for_each(|(algorithm, length, radix, counter, retry)| {
            let hotp = HOTP::new(*algorithm, SECRET, *length, *radix).unwrap();
            let otp = hotp.generate(*counter).unwrap();
            let result = hotp.verify(otp.as_str(), *counter - *retry, *retry);
            assert!(result.is_ok(), "Expected a result");
            assert!(result.unwrap().is_some(), "Expected a successful verification");
        });
}
