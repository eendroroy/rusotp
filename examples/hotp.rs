use rusotp::{Algorithm, Radix, Secret};
use std::num::NonZeroU8;

fn main() {
    let secret = Secret::new("12345678901234567890").unwrap();

    let data = vec![
        (Algorithm::SHA1, NonZeroU8::new(6).unwrap(), Radix(10), 1, "247374"),
        (Algorithm::SHA256, NonZeroU8::new(6).unwrap(), Radix(10), 2, "254785"),
        (Algorithm::SHA256, NonZeroU8::new(6).unwrap(), Radix(10), 3, "496144"),
        (Algorithm::SHA256, NonZeroU8::new(6).unwrap(), Radix(16), 1, "687B4E"),
        (Algorithm::SHA256, NonZeroU8::new(6).unwrap(), Radix(24), 1, "N7C1B6"),
        (Algorithm::SHA1, NonZeroU8::new(6).unwrap(), Radix(36), 1, "M16ONI"),
        (Algorithm::SHA256, NonZeroU8::new(8).unwrap(), Radix(10), 100, "93583477"),
        (Algorithm::SHA256, NonZeroU8::new(8).unwrap(), Radix(16), 100, "23615D75"),
        (Algorithm::SHA256, NonZeroU8::new(8).unwrap(), Radix(24), 100, "032D2EKL"),
        (Algorithm::SHA256, NonZeroU8::new(8).unwrap(), Radix(36), 100, "009TEJXX"),
        (Algorithm::SHA256, NonZeroU8::new(4).unwrap(), Radix(36), 1, "6ONI"),
        (Algorithm::SHA256, NonZeroU8::new(4).unwrap(), Radix(36), 2, "KYWX"),
        (Algorithm::SHA256, NonZeroU8::new(4).unwrap(), Radix(36), 3, "ERBK"),
        (Algorithm::SHA256, NonZeroU8::new(4).unwrap(), Radix(36), 4, "ROTO"),
    ];

    data.iter().for_each(|(algorithm, length, radix, counter, otp)| {
        let hotp = rusotp::HOTP::new(*algorithm, secret.clone(), *length, *radix);
        if radix.get() == 10 && length.get() == 6 && algorithm == &Algorithm::SHA1 {
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
