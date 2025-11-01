// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use inline_c::assert_cxx;

fn main() {
    let output = assert_cxx! {
        #include <stdio.h>
        #include "rusotp.hpp"

        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
            unsigned long timestamp = 10000;

            // Generate an OTP
            StringResult otp_now =  totp_generate(config);
            printf("NOW: %s\n", otp_now.data);

            // Verify an OTP
            const char *verified = totp_verify(config, otp_now.data, 0, 0, 0).data ? "true" : "false";
            printf("VERIFIED : %s\n", verified);

            // Generate an OTP at given timestamp
            StringResult otp_at = totp_generate_at(config, timestamp);
            printf("AT: %s\n", otp_at.data);

            // Verify an OTP generated at given timestamp
            const char *verified_at = totp_verify_at(config, otp_at.data, timestamp, 0, 0, 0).data ? "true" : "false";
            printf("VERIFIED : %s\n", verified_at);

            // Generate provisioning URI
            StringResult provisioning_uri = totp_provisioning_uri(config, "rusotp", "user@email.mail");
            printf("URI : %s\n", provisioning_uri.data);

            return 0;
        }
    }
    .success()
    .get_output()
    .clone();

    println!("{:?}", output);
    println!();
    println!("{}", String::from_utf8(output.stdout).unwrap());
}
