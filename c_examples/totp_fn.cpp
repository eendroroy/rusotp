#include <stdio.h>
#include "rusotp.h"

int main() {
    const char* secret = "12345678901234567890";

    struct Data {
        TotpConfig config;
        unsigned long timestamp;
        const char* otp;
    } data[] = {
        {{"SHA256", secret, 6, 10, 10}, 10000, "959738"},
        {{"SHA256", secret, 6, 10, 20}, 10000, "946818"},
        {{"SHA256", secret, 6, 10, 30}, 10000, "474706"},
        {{"SHA256", secret, 6, 16, 1}, 10000, "A4AC65"},
        {{"SHA256", secret, 6, 24, 2}, 10000, "HIH7EE"},
        {{"SHA256", secret, 6, 10, 30}, 300, "586609"},
        {{"SHA256", secret, 8, 10, 100}, 10000, "93583477"},
        {{"SHA256", secret, 8, 16, 100}, 10000, "23615D75"},
        {{"SHA256", secret, 8, 24, 100}, 10000, "032D2EKL"},
        {{"SHA256", secret, 8, 36, 100}, 10000, "009TEJXX"},
        {{"SHA256", secret, 4, 36, 1}, 10000, "D55X"},
        {{"SHA256", secret, 4, 36, 200}, 10000, "GZ11"},
        {{"SHA256", secret, 4, 36, 31}, 10000, "XJTQ"},
        {{"SHA256", secret, 4, 36, 44}, 10000, "8KE5"},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        TotpConfig config = data[i].config;
        unsigned long timestamp = data[i].timestamp;
        const char* otp = data[i].otp;

        if (config.length == 6 && config.radix == 10 && config.interval == 30 && strcmp(config.algorithm, "SHA1") == 0) {
            printf(
                "LENGTH: %d, RADIX: %d, INTERVAL: %d, TIMESTAMP: %lu \tNOW: %s \tTOTP : %s \tVERIFIED : %s\tURI : %s\n",
                config.length,
                config.radix,
                config.interval,
                timestamp,
                generate_totp_now(config),
                generate_totp_at(config, timestamp),
                verify_totp(config, otp, timestamp, 0, 0, 0) ? "true" : "false",
                totp_provisioning_uri(config, "rusotp", "user@email.mail"));
        } else {
            printf(
                "LENGTH: %d, RADIX: %d, INTERVAL: %d, TIMESTAMP: %lu \t NOW: %s \tTOTP : %s \tVERIFIED : %s\n",
                config.length,
                config.radix,
                config.interval,
                timestamp,
                generate_totp_now(config),
                generate_totp_at(config, timestamp),
                verify_totp(config, otp, timestamp, 0, 0, 0) ? "true" : "false");
        }
    }

    return 0;
}

