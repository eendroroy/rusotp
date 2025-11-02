// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

#[cfg(not(any(target_os = "windows")))]
use inline_c::assert_cxx;

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_totp_generate_now_success() {
    assert_cxx! {
         #include <stdio.h>
         #include "contrib/rusotp.hpp"

         int main() {
             TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};

             StringResult otp_now =  totp_generate(config);
             printf("%s", otp_now.data);

             return 0;
         }
    }
    .success();
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_totp_generate_at_success() {
    assert_cxx! {
         #include <stdio.h>
         #include "contrib/rusotp.hpp"

         int main() {
             TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
             unsigned long timestamp = 10000;

             StringResult otp =  totp_generate_at(config, timestamp);
             printf("%s", otp.data);

             return 0;
         }
    }
    .success()
    .stdout("785198");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_totp_verify() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"
        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            StringResult otp_now =  totp_generate(config);
            const char * verified = totp_verify(config, otp_now.data, 0, 0, 0).data ? "true" : "false";
            printf("%s", verified);
            return 0;
        }
    }
    .success()
    .stdout("true");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_totp_verify_at() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"
        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            unsigned long timestamp = 10000;
            StringResult otp =  totp_generate_at(config, timestamp);
            const char *verified = totp_verify_at(config, otp.data, timestamp, 0, 0, 0).data ? "true" : "false";
            printf("%s", verified);
            return 0;
        }
    }
    .success()
    .stdout("true");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_hotp_provisioning_uri() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"
        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            StringResult provisioning_uri = totp_provisioning_uri(config, "rusotp", "user@email.mail");
            printf("%s", provisioning_uri.data);
            return 0;
        }
    }
    .success()
    .stdout("otpauth://totp/rusotp%3Auser%40email.mail?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&issuer=rusotp");
}
