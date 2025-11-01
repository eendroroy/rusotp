// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{Secret, HOTP};

#[test]
fn otp_should_be_generated_with_defaults() {
    let secret = "12345678901234567890";
    let counters = [10, 16, 24, 36, 1001, 10002, 1004050];

    let uri1 = "otpauth://hotp/Github?secret=12345678901234567890&counter=0";
    let uri2 = "otpauth://hotp/Github?counter=0&secret=12345678901234567890";

    let hotp_parsed1 = HOTP::from_uri(uri1).unwrap();
    let hotp_parsed2 = HOTP::from_uri(uri2).unwrap();
    let hotp_raw = HOTP::default(Secret::new(secret).unwrap());

    counters.iter().for_each(|counter| {
        let raw = hotp_raw.generate(*counter);
        let parsed1 = hotp_parsed1.generate(*counter);
        let parsed2 = hotp_parsed2.generate(*counter);

        assert!(raw.is_ok(), "Expected a result");
        assert!(parsed1.is_ok(), "Expected a result");
        assert!(parsed2.is_ok(), "Expected a result");

        let v1 = raw.unwrap();
        let v2 = parsed1.unwrap();
        let v3 = parsed2.unwrap();

        assert_eq!(v1, v2);
        assert_eq!(v1, v3);
    });

    assert!(HOTP::from_uri("uri").is_err())
}
