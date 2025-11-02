// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use itertools::iproduct;
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZero;

#[test]
fn otp_should_be_generated() {
    let algorithms = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
    let secret = "12345678901234567890";
    let lengths = [6, 8, 4, 10];
    let radixes = [10, 16, 24, 36];
    let counters = [10, 16, 24, 36];

    iproduct!(algorithms.iter(), lengths.iter(), radixes.iter(), counters.iter())
        .map(|(algorithm, length, radix, counter)| (algorithm, length, radix, counter))
        .for_each(|(algorithm, length, radix, counter)| {
            let hotp = HOTP::new(
                *algorithm,
                Secret::from_str(secret).unwrap(),
                NonZero::new(*length).unwrap(),
                Radix::new(*radix).unwrap(),
            );
            let result = hotp.generate(*counter);

            assert!(result.is_ok(), "Expected a result");
        });
}

#[test]
fn otp_should_be_generated_with_defaults() {
    let secret = "12345678901234567890";
    let counters = [10, 16, 24, 36];
    let hotp = HOTP::default(Secret::from_str(secret).unwrap());
    let hotp_default = HOTP::rfc4226_default(Secret::from_str(secret).unwrap());

    counters.iter().for_each(|counter| {
        let result = hotp.generate(*counter);

        assert!(result.is_ok(), "Expected a result");
    });

    counters.iter().for_each(|counter| {
        let result = hotp_default.generate(*counter);

        assert!(result.is_ok(), "Expected a result");
    });
}

#[test]
fn otp_should_be_generated_from_uri() {
    let secret = "12345678901234567890";
    let uri =
        "otpauth://hotp/rusotp%3Aeendroroy%40rusotp?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&counter=0&issuer=rusotp";
    let counters = [10, 16, 24, 36];
    let hotp_raw = HOTP::default(Secret::from_str(secret).unwrap());
    let hotp_parsed = HOTP::from_uri(uri).unwrap();

    counters.iter().for_each(|counter| {
        let result_raw = hotp_raw.generate(*counter);
        let result_parsed = hotp_parsed.generate(*counter);

        assert!(result_raw.is_ok(), "Expected a result");
        assert!(result_parsed.is_ok(), "Expected a result");
        assert_eq!(result_raw.unwrap(), result_parsed.unwrap());
    });
}
