#include <stdio.h>
#include "rusotp.h"

int main() {
    const char* secret = "12345678901234567890";

    struct {
        HotpConfig config;
        unsigned long counter;
        const char* otp;
    } data[] = {
        {{"SHA256", secret, 6, 10}, 1, "247374"},
        {{"SHA256", secret, 6, 10}, 2, "254785"},
        {{"SHA256", secret, 6, 10}, 3, "496144"},
        {{"SHA256", secret, 6, 16}, 1, "687B4E"},
        {{"SHA256", secret, 6, 24}, 1, "N7C1B6"},
        {{"SHA256", secret, 6, 36}, 1, "M16ONI"},
        {{"SHA256", secret, 8, 10}, 100, "93583477"},
        {{"SHA256", secret, 8, 16}, 100, "23615D75"},
        {{"SHA256", secret, 8, 24}, 100, "032D2EKL"},
        {{"SHA256", secret, 8, 36}, 100, "009TEJXX"},
        {{"SHA256", secret, 4, 36}, 1, "6ONI"},
        {{"SHA256", secret, 4, 36}, 2, "KYWX"},
        {{"SHA256", secret, 4, 36}, 3, "ERBK"},
        {{"SHA256", secret, 4, 36}, 4, "ROTO"},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        HotpConfig config = data[i].config;
        unsigned long counter = data[i].counter;
        const char* otp_value = data[i].otp;

        char *otp = generate_hotp(config, counter);
        const char *verified = verify_hotp(config, otp, counter, 0) ? "true" : "false";

        if (config.radix == 10 && config.length == 6 && strcmp(config.algorithm, "SHA1") == 0) {
            char *uri = hotp_provisioning_uri(config, "rusotp", counter);
            printf("LENGTH: %d, RADIX: %d, COUNTER: %lu \tHOTP : %s \tVERIFIED : %s \tURI : %s\n", config.length, config.radix, counter, otp, verified, uri);
        } else {
            printf("LENGTH: %d, RADIX: %d, COUNTER: %lu \tHOTP : %s \tVERIFIED : %s\n", config.length, config.radix, counter, otp, verified);
        }
    }

    return 0;
}