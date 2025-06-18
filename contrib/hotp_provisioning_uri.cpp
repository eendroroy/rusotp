#include <stdio.h>
#include "rusotp.hpp"

int main() {
    HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
    unsigned long counter = 2;

    StringResult uri = hotp_provisioning_uri(config, "rusotp", counter);
    printf("URI : %s\n", uri.data);

    return 0;
}