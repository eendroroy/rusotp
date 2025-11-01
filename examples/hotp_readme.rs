// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZeroU8;

const ALGORITHM: Algorithm = Algorithm::SHA1;
const COUNTER: u64 = 1;

fn main() {
    let secret = Secret::new("12345678901234567890").unwrap();
    let radix = Radix::new(10).unwrap();

    // Generate an OTP
    let hotp = HOTP::new(ALGORITHM, secret, NonZeroU8::new(6).unwrap(), radix);
    let otp = hotp.generate(COUNTER).unwrap();
    println!("Generated OTP: {}", otp);

    // Verify an OTP
    let is_valid = hotp.verify("287082", COUNTER, 0).unwrap();
    println!("Is OTP valid? {}", is_valid.is_some());

    // Generate provisioning URI
    const ISSUER: &str = "MyService";
    let uri = hotp.provisioning_uri(ISSUER, COUNTER).unwrap();
    println!("Provisioning URI: {}", uri);
}
