use inline_c::assert_cxx;

fn main() {
    let output = assert_cxx! {
        #include <stdio.h>
        #include "rusotp.hpp"

        int main() {
            TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};

            StringResult otp_now =  totp_generate(config);
            printf("NOW: %s\n", otp_now.data);

            const char *verified = totp_verify(config, otp_now.data, 0, 0, 0).data ? "true" : "false";
            printf("VERIFIED : %s\n", verified);

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
