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
                Secret::new(secret).unwrap(),
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

    counters.iter().for_each(|counter| {
        let hotp = HOTP::default(Secret::new(secret).unwrap());
        let result = hotp.generate(*counter);
        assert!(result.is_ok(), "Expected a result");
    });

    counters.iter().for_each(|counter| {
        let hotp = HOTP::rfc4226_default(Secret::new(secret).unwrap());
        let result = hotp.generate(*counter);
        assert!(result.is_ok(), "Expected a result");
    });
}
