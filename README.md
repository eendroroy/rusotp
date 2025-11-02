<!--
  Copyright (c) Indrajit Roy

  This file is licensed under the Affero General Public License version 3 or
  any later version.

  See the file LICENSE for details.
-->

# rusotp

OTP generation and validation library.

* Implements [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226)
  and [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)
* Supports alphanumeric OTP generation
* Supports `HmacSha1`, `HmacSha256`, and `HmacSha512` digests

**Note:** `HmacSha1` support is provided for RFC compliance.
It is recommended to use `HmacSha256` or `HmacSha512` for better security.

[![asciicast](https://asciinema.org/a/724539.svg)](https://asciinema.org/a/724539)

## installation

Add `rusotp` to your `Cargo.toml`:

```toml
[dependencies]
rusotp = "0.5.0-alpha2"
```

## HOTP Usage

```rust
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::num::NonZeroU8;

const ALGORITHM: Algorithm = Algorithm::SHA1;
const COUNTER: u64 = 1;

fn main() {
    let secret = Secret::new("12345678901234567890").unwrap();
    let radix = Radix::new(10).unwrap();

    // Generate an OTP
    let hotp = HOTP::new(ALGORITHM, secret, NonZeroU8::new(6).unwrap(), radix);
    let otp = hotp.generate(COUNTER).unwrap();
    println!("Generated OTP: {}", otp);

    // Verify an OTP
    let is_valid = hotp.verify("287082", COUNTER, 0).unwrap();
    println!("Is OTP valid? {}", is_valid.is_some());

    // Generate provisioning URI
    const ISSUER: &str = "MyService";
    let uri = hotp.provisioning_uri(ISSUER, COUNTER).unwrap();
    println!("Provisioning URI: {}", uri);
}
```

## TOTP Usage

```rust
use rusotp::{Algorithm, Radix, Secret, TOTP};
use std::num::NonZero;

const ALGORITHM: Algorithm = Algorithm::SHA1;
const LENGTH: u8 = 6;
const INTERVAL: u64 = 30;

fn main() {
    let radix = Radix::new(10).unwrap();
    let secret = Secret::new("12345678901234567890").unwrap();

    // Generate an OTP
    let totp = TOTP::new(ALGORITHM, secret, NonZero::new(LENGTH).unwrap(), radix, NonZero::new(INTERVAL).unwrap());
    let otp = totp.generate().unwrap();
    println!("Generated OTP: {}", otp);

    // Verify an OTP
    let is_valid = totp.verify(&otp, None, 0, 0).unwrap();
    println!("Is OTP valid? {}", is_valid.is_some());

    // Generate provisioning URI
    const ISSUER: &str = "MyService";
    const NAME: &str = "user@example.com";
    let uri = totp.provisioning_uri(ISSUER, NAME).unwrap();
    println!("Provisioning URI: {}", uri);
}
```

## C bindings

#### HOTP

```c
#include <stdio.h>
#include "rusotp.hpp"

int main() {
    HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
    unsigned long counter = 2;
    
    // Generate an OTP
    StringResult otp = hotp_generate(config, counter);
    printf("HOTP : %s\n", otp.data);
    
    // Verify an OTP
    const char *verified = hotp_verify(config, otp.data, counter, 0).data ? "true" : "false";
    printf("VERIFIED : %s\n", verified);
    
    // Generate provisioning URI
    StringResult uri = hotp_provisioning_uri(config, "rusotp", counter);
    printf("URI : %s\n", uri.data);
    
    return 0;
}
```

#### TOTP

```c
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
```

## Documentation

See the [docs.rs/rusotp](https://docs.rs/rusotp) for more examples and API details.

## Contributing

We welcome contributions to the [rusotp](https://github.com/eendroroy/rusotp) project! Here are some ways you can help:

1. **Report Bugs**: If you find a bug, please report it by opening an issue on GitHub.
2. **Suggest Features**: If you have an idea for a new feature, please open an issue to discuss it.
3. **Submit Pull Requests**: If you want to contribute code, follow these steps:
    1. Fork the repository (https://github.com/eendroroy/rusotp/fork)
    2. Create a new branch (`git checkout -b my-new-feature`)
    3. Make your changes and commit them (`git commit -am 'Add some feature'`)
    4. Push to the branch (`git push origin my-new-feature`)
    5. Open a Pull Request

Please make sure your contributions adhere to our [Code of Conduct](http://contributor-covenant.org).

## License

This project is licensed under the [GNU AGPL-3.0 License](https://www.gnu.org/licenses/agpl-3.0.html).
See the [LICENSE](./LICENSE) file for more details.
