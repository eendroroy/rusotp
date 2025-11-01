use rusotp::{Secret, HOTP};

fn main() {
    let secret = Secret::new("1234567890").unwrap();

    let hotp = HOTP::default(secret);

    // otpauth://hotp/Github?secret=1234567890&counter=0
    println!("{}", hotp.provisioning_uri("Github", 0).unwrap());
}
