use rusotp::{generate_totp_at, generate_totp_now, totp_provisioning_uri, verify_totp, Algorithm};

fn main() {
    let secret = "12345678901234567890";

    let data = vec![
        (6, 10, 10, 10000, "959738"),
        (6, 10, 20, 10000, "946818"),
        (6, 10, 30, 10000, "474706"),
        (6, 16, 1, 10000, "A4AC65"),
        (6, 24, 2, 10000, "HIH7EE"),
        (6, 10, 30, 300, "586609"),
        (8, 10, 100, 10000, "93583477"),
        (8, 16, 100, 10000, "23615D75"),
        (8, 24, 100, 10000, "032D2EKL"),
        (8, 36, 100, 10000, "009TEJXX"),
        (4, 36, 1, 10000, "D55X"),
        (4, 36, 200, 10000, "GZ11"),
        (4, 36, 31, 10000, "XJTQ"),
        (4, 36, 44, 10000, "8KE5"),
    ];

    data.iter().for_each(|(length, radix, interval, timestamp, otp)| {
        if *length == 6 && *radix == 10 && *interval == 30 {
            println!(
                "LENGTH: {}, RADIX: {}, INTERVAL: {}, TIMESTAMP: {} \tNOW: {} \tTOTP : {} \tVERIFIED : {}\tURI : {}",
                length,
                radix,
                interval,
                timestamp,
                generate_totp_now(Algorithm::SHA256, secret, *length, *radix, *interval),
                generate_totp_at(Algorithm::SHA256, secret, *length, *radix, *interval, *timestamp),
                verify_totp(
                    Algorithm::SHA256,
                    secret, *length,
                    *radix, *interval,
                    otp, *timestamp,
                    Some(0),
                    0,
                    0
                ).is_some(),
                totp_provisioning_uri(
                    Algorithm::SHA256,
                    secret,
                    *length,
                    *radix,
                    *interval,
                    "rusotp",
                    "user@email.mail"
                )
            );
        } else {
            println!(
                "LENGTH: {}, RADIX: {}, INTERVAL: {}, TIMESTAMP: {} \t NOW: {} \tTOTP : {} \tVERIFIED : {}",
                length,
                radix,
                interval,
                timestamp,
                generate_totp_now(Algorithm::SHA256, secret, *length, *radix, *interval),
                generate_totp_at(Algorithm::SHA256, secret, *length, *radix, *interval, *timestamp),
                verify_totp(
                    Algorithm::SHA256,
                    secret, *length,
                    *radix, *interval,
                    otp,
                    *timestamp,
                    Some(0),
                    0,
                    0
                ).is_some(),
            );
        }
    });
}
