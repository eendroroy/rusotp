# rusotp

OTP generation and validation library.

* Implements [RFC4226](https://datatracker.ietf.org/doc/html/rfc4226)
  and [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238)
* Supports alphanumeric OTP generation
* Supports `HmacSha1`, `HmacSha256`, and `HmacSha512` digests

**Note:** `HmacSha1` support is provided for RFC compliance. 
It is recommended to use `HmacSha256` or `HmacSha512` for better security.

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