// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{Secret, TOTP};

fn main() {
    let secret = Secret::new("1234567890").unwrap();

    let totp = TOTP::default(secret);

    // otpauth://totp/Github%3Auser%40github.com?secret=1234567890&issuer=Github
    println!("{}", totp.provisioning_uri("Github", "user@github.com").unwrap());
}
