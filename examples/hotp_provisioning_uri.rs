// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{Secret, HOTP};

fn main() {
    let secret = Secret::from_str("1234567890").unwrap();

    let hotp = HOTP::default(secret);

    // otpauth://hotp/Github?secret=1234567890&counter=0
    println!("{}", hotp.provisioning_uri("Github", "eendroroy@github.com", 0).unwrap());
}
