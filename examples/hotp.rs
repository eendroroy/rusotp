use rusotp::{Algorithm, Radix, Secret};
use std::num::NonZero;

fn main() {
    let secret = Secret::new("12345678901234567890").unwrap();

    let data = vec![
        (Algorithm::SHA1, 6, 10, 1, "247374"),
        (Algorithm::SHA256, 6, 10, 2, "254785"),
        (Algorithm::SHA256, 6, 10, 3, "496144"),
        (Algorithm::SHA256, 6, 16, 1, "687B4E"),
        (Algorithm::SHA256, 6, 24, 1, "N7C1B6"),
        (Algorithm::SHA1, 6, 36, 1, "M16ONI"),
        (Algorithm::SHA256, 8, 10, 100, "93583477"),
        (Algorithm::SHA256, 8, 16, 100, "23615D75"),
        (Algorithm::SHA256, 8, 24, 100, "032D2EKL"),
        (Algorithm::SHA256, 8, 36, 100, "009TEJXX"),
        (Algorithm::SHA256, 4, 36, 1, "6ONI"),
        (Algorithm::SHA256, 4, 36, 2, "KYWX"),
        (Algorithm::SHA256, 4, 36, 3, "ERBK"),
        (Algorithm::SHA256, 4, 36, 4, "ROTO"),
    ];

    data.iter().for_each(|(algorithm, length, radix, counter, otp)| {
        let hotp =
            rusotp::HOTP::new(*algorithm, secret.clone(), NonZero::new(*length).unwrap(), Radix::new(*radix).unwrap());
        if *radix == 10 && *length == 6 && *algorithm == Algorithm::SHA1 {
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
