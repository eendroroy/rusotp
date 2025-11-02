// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{Secret, HOTP};

#[test]
fn otp_should_match_with_rfc_samples() {
    let secret = Secret::from_str("12345678901234567890").unwrap();

    vec![
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ]
    .iter()
    .for_each(|(counter, otp)| {
        let hotp = HOTP::default(secret.clone());
        let result = hotp.generate(*counter);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), *otp);
    });
}
