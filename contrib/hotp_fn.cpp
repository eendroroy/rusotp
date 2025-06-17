#include <stdio.h>
#include "rusotp.hpp"

int main() {
    const char* secret = "12345678901234567890";

    struct {
        HotpConfig config;
        unsigned long counter;
        const char* otp;
    } data[] = {
        {{"SHA1", secret, 6, 10}, 1},
        {{"SHA256", secret, 6, 10}, 2},
        {{"SHA256", secret, 6, 10}, 3},
        {{"SHA1", secret, 6, 16}, 1},
        {{"SHA256", secret, 6, 24}, 1},
        {{"SHA256", secret, 6, 36}, 1},
        {{"SHA256", secret, 8, 10}, 100},
        {{"SHA256", secret, 8, 16}, 100},
        {{"SHA1", secret, 8, 24}, 100},
        {{"SHA256", secret, 8, 36}, 100},
        {{"SHA256", secret, 4, 36}, 1},
        {{"SHA256", secret, 4, 36}, 2},
        {{"SHA256", secret, 4, 36}, 3},
        {{"SHA256", secret, 4, 36}, 4},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        HotpConfig config = data[i].config;
        unsigned long counter = data[i].counter;

        const char *otp = hotp_generate(config, counter);
        const char *verified = hotp_verify(config, otp, counter, 0) ? "true" : "false";

        if (config.radix == 10 && config.length == 6 && strcmp(config.algorithm, "SHA1") == 0) {
            const char *uri = hotp_provisioning_uri(config, "rusotp", counter);
            printf("LENGTH: %d, RADIX: %d, COUNTER: %lu \tHOTP : %s \tVERIFIED : %s \tURI : %s\n", config.length, config.radix, counter, otp, verified, uri);
        } else {
            printf("LENGTH: %d, RADIX: %d, COUNTER: %lu \tHOTP : %s \tVERIFIED : %s\n", config.length, config.radix, counter, otp, verified);
        }
    }

    return 0;
}