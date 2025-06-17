use inline_c::assert_cxx;

#[test]
fn test_totp_generate_now_success() {
    assert_cxx! {
         #include <stdio.h>
         #include "contrib/rusotp.hpp"

         int main() {
             TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};

             const char *otp_now =  totp_generate(config);
             printf("%s", otp_now);

             return 0;
         }
    }
    .success();
}

#[test]
fn test_totp_generate_at_success() {
    assert_cxx! {
         #include <stdio.h>
         #include "contrib/rusotp.hpp"

         int main() {
             TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
             unsigned long timestamp = 10000;

             const char *otp =  totp_generate_at(config, timestamp);
             printf("%s", otp);

             return 0;
         }
    }
    .success()
    .stdout("785198");
}

#[test]
fn test_totp_verify() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"
        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            const char *otp_now =  totp_generate(config);
            const char *verified = totp_verify(config, otp_now, 0, 0, 0) ? "true" : "false";
            printf("%s", verified);
            return 0;
        }
    }
    .success()
    .stdout("true");
}

#[test]
fn test_totp_verify_at() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"
        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            unsigned long timestamp = 10000;
            const char *otp =  totp_generate_at(config, timestamp);
            const char *verified = totp_verify_at(config, otp, timestamp, 0, 0, 0) ? "true" : "false";
            printf("%s", verified);
            return 0;
        }
    }
    .success()
    .stdout("true");
}

#[test]
fn test_hotp_provisioning_uri() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"
        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            const char *provisioning_uri = totp_provisioning_uri(config, "rusotp", "user@email.mail");
            printf("%s", provisioning_uri);
            return 0;
        }
    }
    .success()
    .stdout("otpauth://totp/rusotp%3Auser%40email.mail?secret=12345678901234567890&issuer=rusotp");
}
