#include <stdio.h>
#include "rusotp.hpp"

int main() {
    HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
    unsigned long counter = 2;

    StringResult otp = hotp_generate(config, counter);
    printf("HOTP : %s\n", otp.data);

    return 0;
}