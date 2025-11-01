// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{HOTPUri, Secret, HOTP};

fn main() {
    let secret = Secret::new("1234567890").unwrap();

    let hotp = HOTP::default(secret);
    let url = hotp.provisioning_uri("Github", 0).unwrap();
    // otpauth://hotp/Github?secret=1234567890&counter=0
    println!("{}", url);

    let huri = HOTPUri::parse(url.as_str()).unwrap();

    println!("NAME: {}", huri.name);
    println!("SECRET: {:?}", String::from_utf8_lossy(&huri.secret.clone().get()));
    println!("INITIAL_COUNT: {:?}", huri.initial_count);
}
