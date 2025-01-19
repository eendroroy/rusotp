use rusotp::{Algorithm};

fn main() {
    let secret = "12345678901234567890";

    let data = vec![
        (6, 10, 1, "247374"),
        (6, 10, 2, "254785"),
        (6, 10, 3, "496144"),
        (6, 16, 1, "687B4E"),
        (6, 24, 1, "N7C1B6"),
        (6, 36, 1, "M16ONI"),
        (8, 10, 100, "93583477"),
        (8, 16, 100, "23615D75"),
        (8, 24, 100, "032D2EKL"),
        (8, 36, 100, "009TEJXX"),
        (4, 36, 1, "6ONI"),
        (4, 36, 2, "KYWX"),
        (4, 36, 3, "ERBK"),
        (4, 36, 4, "ROTO"),
    ];

    data.iter().for_each(|(length, radix, counter, otp)| {
        let hotp = match rusotp::HOTP::new(Algorithm::SHA1, secret, *length, *radix) {
            Ok(hotp) => hotp,
            Err(e) => panic!("{}", e),
        };
        if radix == &10 && length == &6 {
            println!(
                "LENGTH: {}, RADIX: {}, COUNTER: {} \tHOTP : {} \tVERIFIED : {} \tURI : {}",
                length,
                radix,
                counter,
                hotp.generate(*counter).unwrap(),
                hotp.verify(otp, *counter, 0).unwrap().is_some(),
                hotp.provisioning_uri("IAM", *counter).unwrap(),
            );
        } else {
            println!(
                "LENGTH: {}, RADIX: {}, COUNTER: {} \tHOTP : {} \tVERIFIED : {}",
                length,
                radix,
                counter,
                hotp.generate(*counter).unwrap(),
                hotp.verify(otp, *counter, 0).unwrap().is_some(),
            );
        }
    });
}
