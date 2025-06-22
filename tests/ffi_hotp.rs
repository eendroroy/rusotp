#[cfg(not(any(target_os = "windows")))]
use inline_c::assert_cxx;

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_hotp_generate_success() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            StringResult otp = hotp_generate(config, counter);
            printf("%s", otp.data);

            return 0;
        }
    }
    .success()
    .stdout("359152");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_hotp_verify() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            StringResult otp = hotp_generate(config, counter);
            printf("%s", otp.data);

            const char *verified = hotp_verify(config, otp.data, counter, 0).data ? "true" : "false";
            printf(":%s", verified);

            return 0;
        }
    }
    .success()
    .stdout("359152:true");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_hotp_provisioning_uri() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            StringResult uri = hotp_provisioning_uri(config, "rusotp", counter);
            printf("%s", uri.data);

            return 0;
        }
    }
    .success()
    .stdout("otpauth://hotp/rusotp?secret=12345678901234567890&counter=2");
}
