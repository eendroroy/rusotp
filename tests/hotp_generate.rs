use itertools::iproduct;
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZeroU8;

#[test]
fn otp_should_be_generated() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let secret = Secret::new("12345678901234567890").unwrap();
    let lengths = [
        NonZeroU8::new(6).unwrap(),
        NonZeroU8::new(8).unwrap(),
        NonZeroU8::new(4).unwrap(),
        NonZeroU8::new(10).unwrap(),
    ];
    let radixes = [Radix(10), Radix(16), Radix(24), Radix(36)];
    let counters = [10, 16, 24, 36];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter())
        .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
        .for_each(|(algorithm, length, radix, counter)| {
            let hotp = HOTP::new(*algorithm, secret.clone(), *length, *radix);
            let result = hotp.generate(*counter);
            assert!(result.is_ok(), "Expected a result");
        });
}
