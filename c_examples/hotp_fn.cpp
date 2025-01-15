#include <stdio.h>
#include "rusotp.h"

int main() {
    const char* secret = "12345678901234567890";

    struct {
        const char* algorithm;
        int length;
        int radix;
        int counter;
        const char* otp;
    } data[] = {
        {"SHA256", 6, 10, 1, "247374"},
        {"SHA256", 6, 10, 2, "254785"},
        {"SHA256", 6, 10, 3, "496144"},
        {"SHA256", 6, 16, 1, "687B4E"},
        {"SHA256", 6, 24, 1, "N7C1B6"},
        {"SHA256", 6, 36, 1, "M16ONI"},
        {"SHA256", 8, 10, 100, "93583477"},
        {"SHA256", 8, 16, 100, "23615D75"},
        {"SHA256", 8, 24, 100, "032D2EKL"},
        {"SHA256", 8, 36, 100, "009TEJXX"},
        {"SHA256", 4, 36, 1, "6ONI"},
        {"SHA256", 4, 36, 2, "KYWX"},
        {"SHA256", 4, 36, 3, "ERBK"},
        {"SHA256", 4, 36, 4, "ROTO"},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        const char* algorithm = data[i].algorithm;
        int length = data[i].length;
        int radix = data[i].radix;
        int counter = data[i].counter;
        const char* otp_value = data[i].otp;

        char *otp = generate_hotp(algorithm, secret, length, radix, counter);
        int verified = verify_hotp(algorithm, secret, otp_value, length, radix, counter, 0);

        if (radix == 10 && length == 6) {
            char *uri = hotp_provisioning_uri(algorithm, secret, length, radix, "rusotp", counter);
            printf("LENGTH: %d, RADIX: %d, COUNTER: %d \tHOTP : %s \tVERIFIED : %d \tURI : %s\n",
                   length, radix, counter, otp, verified, uri);
        } else {
            printf("LENGTH: %d, RADIX: %d, COUNTER: %d \tHOTP : %s \tVERIFIED : %d\n",
                   length, radix, counter, otp, verified);
        }
    }

    return 0;
}