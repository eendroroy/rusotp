#include <stdio.h>
#include "rusotp.h"

int main() {
    const char* secret = "12345678901234567890";

    struct Data {
        TotpConfig config;
        unsigned long timestamp;
        const char* otp;
    } data[] = {
        {{"SHA256", secret, 6, 10, 10}, 10000},
        {{"SHA256", secret, 6, 10, 20}, 10000},
        {{"SHA1", secret, 6, 10, 30}, 10000},
        {{"SHA256", secret, 6, 16, 1}, 10000},
        {{"SHA256", secret, 6, 24, 2}, 10000},
        {{"SHA1", secret, 6, 10, 30}, 300},
        {{"SHA256", secret, 8, 10, 100}, 10000},
        {{"SHA256", secret, 8, 16, 100}, 10000},
        {{"SHA256", secret, 8, 24, 100}, 10000},
        {{"SHA256", secret, 8, 36, 100}, 10000},
        {{"SHA256", secret, 4, 36, 1}, 10000},
        {{"SHA256", secret, 4, 36, 200}, 10000},
        {{"SHA256", secret, 4, 36, 31}, 10000},
        {{"SHA256", secret, 4, 36, 44}, 10000},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        TotpConfig config = data[i].config;
        unsigned long timestamp = data[i].timestamp;

        const char *otp_now =  generate_totp_now(config);
        const char *otp_at = generate_totp_at(config, timestamp);
        const char *verified = verify_totp(config, otp_at, timestamp, 0, 0, 0) ? "true" : "false";

        if (config.length == 6 && config.radix == 10 && config.interval == 30 && strcmp(config.algorithm, "SHA1") == 0) {
            printf(
                "LENGTH: %d, RADIX: %d, INTERVAL: %d, TIMESTAMP: %lu \tNOW: %s \tTOTP : %s \tVERIFIED : %s\tURI : %s\n",
                config.length,
                config.radix,
                config.interval,
                timestamp,
                otp_now,
                otp_at,
                verified,
                totp_provisioning_uri(config, "rusotp", "user@email.mail"));
        } else {
            printf(
                "LENGTH: %d, RADIX: %d, INTERVAL: %d, TIMESTAMP: %lu \t NOW: %s \tTOTP : %s \tVERIFIED : %s\n",
                config.length,
                config.radix,
                config.interval,
                timestamp,
                otp_now,
                otp_at,
                verified
            );
        }
    }

    return 0;
}

