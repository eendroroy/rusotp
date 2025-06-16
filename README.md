# rusotp

OTP generation and validation library.

* Implements [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226)
  and [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)
* Supports alphanumeric OTP generation
* Supports `HmacSha1`, `HmacSha256`, and `HmacSha512` digests

**Note:** `HmacSha1` support is provided for RFC compliance.
It is recommended to use `HmacSha256` or `HmacSha512` for better security.

## installation

Add `rusotp` to your `Cargo.toml`:

```toml
[dependencies]
rusotp = "0.3.4"
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

const ALGORITHM: Algorithm = Algorithm::SHA1;
const LENGTH: u8 = 6;
const INTERVAL: u8 = 30;

fn main() {
    let radix = Radix::new(10).unwrap();
    let secret = Secret::new("12345678901234567890").unwrap();

    // Generate an OTP
    let totp = TOTP::new(ALGORITHM, secret, LENGTH, radix, INTERVAL).unwrap();
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
