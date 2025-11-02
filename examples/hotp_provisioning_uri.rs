// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{generate_qr_code_image, generate_qr_code_string, Secret, HOTP};

fn main() {
    let secret = Secret::new_from_str("1238*&^$*&JHGHJI^&@#^&*%%^*&hj1HJV761298").unwrap();

    let hotp = HOTP::default(secret);

    let data = hotp.provisioning_uri("Github", "eendroroy@github.com", 0).unwrap();
    println!("{}", data);
    generate_qr_code_image(data.clone(), "./code.png".to_string());
}
