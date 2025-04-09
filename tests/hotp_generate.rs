use itertools::{Itertools, iproduct};
use rusotp::{Algorithm, HOTP};

const SECRET: &str = "12345678901234567890";

#[test]
fn otp_should_be_generated() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let lengths = [6, 8, 4, 10];
    let radixes = [10, 16, 24, 36];
    let counters = [10, 16, 24, 36];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter())
        .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
        .unique()
        .for_each(|(algorithm, length, radix, counter)| {
            let hotp = HOTP::new(*algorithm, SECRET, *length, *radix).unwrap();
            let result = hotp.generate(*counter);
            assert!(result.is_ok(), "Expected a result");
        });
}
