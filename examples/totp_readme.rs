use rusotp::{Algorithm, Radix, TOTP};

const ALGORITHM: Algorithm = Algorithm::SHA1;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const INTERVAL: u8 = 30;

fn main() {
    let radix = Radix::new(10).unwrap();

    // Generate an OTP
    let totp = TOTP::new(ALGORITHM, SECRET, LENGTH, radix, INTERVAL).unwrap();
    let otp = totp.generate().unwrap();
    println!("Generated OTP: {}", otp);

    // Verify an OTP
    let is_valid = totp.verify(&otp, None, 0, 0).unwrap();
    println!("Is OTP valid? {}", is_valid.is_some());

    // Generate provisioning URI
    const ISSUER: &str = "MyService";
    const NAME: &str = "user@example.com";
    let uri = totp.provisioning_uri(ISSUER, NAME).unwrap();
    println!("Provisioning URI: {}", uri);
}
