#include <stdio.h>
#include "rusotp.h"

int main() {
    const char* secret = "12345678901234567890";

    struct {
        int length;
        int radix;
        int counter;
        const char* otp;
    } data[] = {
        {6, 10, 1, "247374"},
        {6, 10, 2, "254785"},
        {6, 10, 3, "496144"},
        {6, 16, 1, "687B4E"},
        {6, 24, 1, "N7C1B6"},
        {6, 36, 1, "M16ONI"},
        {8, 10, 100, "93583477"},
        {8, 16, 100, "23615D75"},
        {8, 24, 100, "032D2EKL"},
        {8, 36, 100, "009TEJXX"},
        {4, 36, 1, "6ONI"},
        {4, 36, 2, "KYWX"},
        {4, 36, 3, "ERBK"},
        {4, 36, 4, "ROTO"},
    };

    for (int i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
        int length = data[i].length;
        int radix = data[i].radix;
        int counter = data[i].counter;
        const char* otp_value = data[i].otp;

        char *otp = generate_hotp(secret, length, radix, counter);
        int verified = verify_hotp(secret, otp_value, length, radix, counter, 0);

        if (radix == 10 && length == 6) {
            char *uri = hotp_provisioning_uri(secret, length, radix, "rusotp", counter);
            printf("LENGTH: %d, RADIX: %d, COUNTER: %d \tHOTP : %s \tVERIFIED : %d \tURI : %s\n",
                   length, radix, counter, otp, verified, uri);
        } else {
            printf("LENGTH: %d, RADIX: %d, COUNTER: %d \tHOTP : %s \tVERIFIED : %d\n",
                   length, radix, counter, otp, verified);
        }
    }

    return 0;
}