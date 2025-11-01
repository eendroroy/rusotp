use rusotp::{Secret, TOTP};

fn main() {
    let secret = Secret::new("1234567890").unwrap();

    let totp = TOTP::default(secret);

    // otpauth://totp/Github%3Aeendroroy%40github.com?secret=1234567890&issuer=Github
    println!("{}", totp.provisioning_uri("Github", "eendroroy@github.com").unwrap());
}
