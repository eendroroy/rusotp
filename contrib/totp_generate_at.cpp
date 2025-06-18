#include <stdio.h>
#include "rusotp.hpp"

int main() {
    TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
    unsigned long timestamp = 10000;

    StringResult otp_at = totp_generate_at(config, timestamp);
    printf("AT: %s\n", otp_at.data);

    return 0;
}
