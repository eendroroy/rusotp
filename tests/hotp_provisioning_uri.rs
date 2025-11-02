// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{
    Algorithm, Radix, Secret, UnsupportedAlgorithmError, UnsupportedLengthError, UnsupportedRadixError, HOTP,
};
use std::num::NonZeroU8;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const RADIX: u8 = 10;

#[test]
fn provisioning_uri_should_be_correct() {
    let hotp_tool = HOTP::new(
        Algorithm::SHA1,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(RADIX).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_ok(), "Expected a result");
    assert_eq!(
        result.unwrap(),
        "otpauth://hotp/test%3Atest?secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq&counter=0&issuer=test"
    );
}

#[test]
fn provisioning_uri_should_fail_with_sha256() {
    let hotp_tool = HOTP::new(
        Algorithm::SHA256,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(RADIX).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), UnsupportedAlgorithmError(Algorithm::SHA256).to_string());
}

#[test]
fn provisioning_uri_should_fail_with_sha512() {
    let hotp_tool = HOTP::new(
        Algorithm::SHA512,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(RADIX).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), UnsupportedAlgorithmError(Algorithm::SHA512).to_string());
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_less_than_6() {
    let hotp_tool = HOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(5).unwrap(),
        Radix::new(RADIX).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), UnsupportedLengthError(5).to_string());
}

#[test]
fn provisioning_uri_should_fail_with_otp_length_more_than_6() {
    let hotp_tool = HOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(7).unwrap(),
        Radix::new(RADIX).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), UnsupportedLengthError(7).to_string());
}

#[test]
fn provisioning_uri_should_fail_with_radix_less_than_10() {
    let hotp_tool = HOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(9).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), UnsupportedRadixError(9).to_string());
}

#[test]
fn provisioning_uri_should_fail_with_radix_more_than_10() {
    let hotp_tool = HOTP::new(
        ALGORITHM,
        Secret::new("12345678901234567890").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(11).unwrap(),
    );

    let result = hotp_tool.provisioning_uri("test", "test", 0);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), UnsupportedRadixError(11).to_string());
}
