use rusotp::{Algorithm, Radix};

fn main() {
    let secret = "12345678901234567890";

    let data = vec![
        (Algorithm::SHA1, 6, Radix(10), 1, "247374"),
        (Algorithm::SHA256, 6, Radix(10), 2, "254785"),
        (Algorithm::SHA256, 6, Radix(10), 3, "496144"),
        (Algorithm::SHA256, 6, Radix(16), 1, "687B4E"),
        (Algorithm::SHA256, 6, Radix(24), 1, "N7C1B6"),
        (Algorithm::SHA1, 6, Radix(36), 1, "M16ONI"),
        (Algorithm::SHA256, 8, Radix(10), 100, "93583477"),
        (Algorithm::SHA256, 8, Radix(16), 100, "23615D75"),
        (Algorithm::SHA256, 8, Radix(24), 100, "032D2EKL"),
        (Algorithm::SHA256, 8, Radix(36), 100, "009TEJXX"),
        (Algorithm::SHA256, 4, Radix(36), 1, "6ONI"),
        (Algorithm::SHA256, 4, Radix(36), 2, "KYWX"),
        (Algorithm::SHA256, 4, Radix(36), 3, "ERBK"),
        (Algorithm::SHA256, 4, Radix(36), 4, "ROTO"),
    ];

    data.iter().for_each(|(algorithm, length, radix, counter, otp)| {
        let hotp = match rusotp::HOTP::new(*algorithm, secret, *length, *radix) {
            Ok(hotp) => hotp,
            Err(e) => panic!("{}", e),
        };
        if radix.get() == 10 && length == &6 && algorithm == &Algorithm::SHA1 {
            println!(
                "LENGTH: {}, RADIX: {}, COUNTER: {} \tHOTP : {} \tVERIFIED : {} \tURI : {}",
                length,
                radix.get(),
                counter,
                hotp.generate(*counter).unwrap(),
                hotp.verify(otp, *counter, 0).unwrap().is_some(),
                hotp.provisioning_uri("IAM", *counter).unwrap(),
            );
        } else {
            println!(
                "LENGTH: {}, RADIX: {}, COUNTER: {} \tHOTP : {} \tVERIFIED : {}",
                length,
                radix.get(),
                counter,
                hotp.generate(*counter).unwrap(),
                hotp.verify(otp, *counter, 0).unwrap().is_some(),
            );
        }
    });
}
