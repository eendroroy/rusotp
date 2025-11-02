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
    .stdout("359152")
    .stderr("");
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
    .stdout("359152:true")
    .stderr("");
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

            StringResult uri = hotp_provisioning_uri(config, "rusotp", "rusotp", counter);
            printf("%s", uri.data);

            return 0;
        }
    }
    .success()
    .stdout("otpauth://hotp/rusotp%3Arusotp?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&counter=2&issuer=rusotp")
    .stderr("");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_hotp_from_uri() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
            unsigned long counter = 2;

            StringResult uri = hotp_provisioning_uri(config, "rusotp", "rusotp", counter);
            HotpConfigResult config_parsed = hotp_from_uri(uri.data);

            printf("%s == %s", config_parsed.data->secret, config.secret);

            return 0;
        }
    }
    .success()
    .stdout("12345678901234567890 == 12345678901234567890")
    .stderr("");
}

#[test]
#[cfg(not(any(target_os = "windows")))]
fn test_hotp_from_uri_fail() {
    assert_cxx! {
        #include <stdio.h>
        #include "contrib/rusotp.hpp"

        int main() {
            char uri[] = "otpauth://hotp/rusotp%3Arusotp?secret=&counter=2&issuer=rusotp";
            HotpConfigResult config_parsed = hotp_from_uri(uri);

            if (!config_parsed.success) {
                fprintf(stderr, "%s", config_parsed.error);
                return 1;
            } else {
                return 0;
            }
        }
    }
    .failure()
    .stdout("")
    .stderr("Invalid secret");
}
