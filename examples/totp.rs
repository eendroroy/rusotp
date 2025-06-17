use rusotp::{Algorithm, Radix, Secret};
use std::num::NonZero;

fn main() {
    let secret = Secret::new("12345678901234567890").unwrap();

    let data = vec![
        (6, Radix(10), 10, 10000, "959738"),
        (6, Radix(10), 20, 10000, "946818"),
        (6, Radix(10), 30, 10000, "474706"),
        (6, Radix(16), 1, 10000, "A4AC65"),
        (6, Radix(24), 2, 10000, "HIH7EE"),
        (6, Radix(10), 30, 300, "586609"),
        (8, Radix(10), 100, 10000, "93583477"),
        (8, Radix(16), 100, 10000, "23615D75"),
        (8, Radix(24), 100, 10000, "032D2EKL"),
        (8, Radix(36), 100, 10000, "009TEJXX"),
        (4, Radix(36), 1, 10000, "D55X"),
        (4, Radix(36), 200, 10000, "GZ11"),
        (4, Radix(36), 31, 10000, "XJTQ"),
        (4, Radix(36), 44, 10000, "8KE5"),
    ];

    data.iter().for_each(|(length, radix, interval, timestamp, otp)| {
        let totp = match rusotp::TOTP::new(
            Algorithm::SHA1,
            secret.clone(),
            NonZero::new(*length).unwrap(),
            *radix,
            NonZero::new(*interval).unwrap(),
        ) {
            Ok(hotp) => hotp,
            Err(e) => panic!("{}", e),
        };
        if *length == 6 && radix.get() == 10 && *interval == 30 {
            println!(
                "LENGTH: {}, RADIX: {}, INTERVAL: {}, TIMESTAMP: {} \tNOW: {} \tTOTP : {} \tVERIFIED : {}\tURI : {}",
                length,
                radix.get(),
                interval,
                timestamp,
                totp.generate().unwrap(),
                totp.generate_at(*timestamp).unwrap(),
                totp.verify_at(otp, *timestamp, Some(0), 0, 0).unwrap().is_some(),
                totp.provisioning_uri("rusotp", "user@email.mail").unwrap()
            );
        } else {
            println!(
                "LENGTH: {}, RADIX: {}, INTERVAL: {}, TIMESTAMP: {} \t NOW: {} \tTOTP : {} \tVERIFIED : {}",
                length,
                radix.get(),
                interval,
                timestamp,
                totp.generate().unwrap(),
                totp.generate_at(*timestamp).unwrap(),
                totp.verify_at(otp, *timestamp, Some(0), 0, 0).unwrap().is_some(),
            );
        }
    });
}
