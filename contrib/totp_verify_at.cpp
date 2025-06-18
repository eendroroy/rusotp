#include <stdio.h>
#include "rusotp.hpp"

int main() {
    TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
    unsigned long timestamp = 10000;

    StringResult otp_at = totp_generate_at(config, timestamp);
    const char *verified = totp_verify_at(config, otp_at.data, timestamp, 0, 0, 0).data ? "true" : "false";
    printf("VERIFIED : %s\n", verified);

    return 0;
}
