#include <stdio.h>
#include "rusotp.h"

int main() {
    const char* secret = "12345678901234567890";

    struct Data {
        int length;
        int radix;
        int interval;
        int timestamp;
        const char* otp;
    } data[] = {
        {6, 10, 10, 10000, "959738"},
        {6, 10, 20, 10000, "946818"},
        {6, 10, 30, 10000, "474706"},
        {6, 16, 1, 10000, "A4AC65"},
        {6, 24, 2, 10000, "HIH7EE"},
        {6, 10, 30, 300, "586609"},
        {8, 10, 100, 10000, "93583477"},
        {8, 16, 100, 10000, "23615D75"},
        {8, 24, 100, 10000, "032D2EKL"},
        {8, 36, 100, 10000, "009TEJXX"},
        {4, 36, 1, 10000, "D55X"},
        {4, 36, 200, 10000, "GZ11"},
        {4, 36, 31, 10000, "XJTQ"},
        {4, 36, 44, 10000, "8KE5"},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        struct Data d = data[i];
        if (d.length == 6 && d.radix == 10 && d.interval == 30) {
            printf(
                "LENGTH: %d, RADIX: %d, INTERVAL: %d, TIMESTAMP: %d \tNOW: %s \tTOTP : %s \tVERIFIED : %d\tURI : %s\n",
                d.length,
                d.radix,
                d.interval,
                d.timestamp,
                generate_totp_now(secret, d.length, d.radix, d.interval),
                generate_totp_at(secret, d.length, d.radix, d.interval, d.timestamp),
                verify_totp(secret, d.length, d.radix, d.interval, d.otp, d.timestamp, 0, 0, 0),
                totp_provisioning_uri(secret, d.length, d.radix, d.interval, "rusotp", "user@email.mail"));
        } else {
            printf(
                "LENGTH: %d, RADIX: %d, INTERVAL: %d, TIMESTAMP: %d \t NOW: %s \tTOTP : %s \tVERIFIED : %d\n",
                d.length,
                d.radix,
                d.interval,
                d.timestamp,
                generate_totp_now(secret, d.length, d.radix, d.interval),
                generate_totp_at(secret, d.length, d.radix, d.interval, d.timestamp),
                verify_totp(secret, d.length, d.radix, d.interval, d.otp, d.timestamp, 0, 0, 0));
        }
    }

    return 0;
}

