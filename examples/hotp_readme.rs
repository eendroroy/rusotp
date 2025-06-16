use rusotp::{Algorithm, Radix, HOTP};

const ALGORITHM: Algorithm = Algorithm::SHA1;
const SECRET: &str = "12345678901234567890";
const LENGTH: u8 = 6;
const COUNTER: u64 = 1;

fn main() {
    let radix = Radix::new(10).unwrap();

    // Generate an OTP
    let hotp = HOTP::new(ALGORITHM, SECRET, LENGTH, radix).unwrap();
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