#include <stdio.h>
#include "rusotp.hpp"

int main() {
    TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};

    StringResult otp_now =  totp_generate(config);
    printf("NOW: %s\n", otp_now.data);

    return 0;
}
