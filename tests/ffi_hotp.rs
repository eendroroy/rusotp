use inline_c::assert_cxx;

#[test]
fn test_hotp_generate_success() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            const char *otp = hotp_generate(config, counter);
            printf("%s", otp);

            return 0;
        }
    }
    .success()
    .stdout("359152");
}

#[test]
fn test_hotp_verify() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            const char *otp = hotp_generate(config, counter);
            printf("%s", otp);

            const char *verified = hotp_verify(config, otp, counter, 0) ? "true" : "false";
            printf(":%s", verified);

            return 0;
        }
    }
    .success()
    .stdout("359152:true");
}

#[test]
fn test_hotp_provisioning_uri() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            const char *uri = hotp_provisioning_uri(config, "rusotp", counter);
            printf("%s", uri);

            return 0;
        }
    }
    .success()
    .stdout("otpauth://hotp/rusotp?secret=12345678901234567890&counter=2");
}
