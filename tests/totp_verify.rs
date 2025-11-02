// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{AfterError, Algorithm, DriftBehindError, Radix, Secret, TOTP};
use std::num::NonZero;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const LENGTH: u8 = 6;
const RADIX: u8 = 10;
const INTERVAL: u64 = 30;
const AFTER: u64 = 0;
const DRIFT_AHEAD: u64 = 0;
const DRIFT_BEHIND: u64 = 0;

#[test]
fn should_fail_with_otp_length_not_matched() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );
    let result = totp.verify_at("12345", 10, Some(AFTER), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(result.is_ok(), "Expected a result");
    assert!(result.unwrap().is_none(), "Expected a failed verification");
}

#[test]
fn should_fail_if_after_is_greater_than_at() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );
    let otp = totp.generate_at(10000).unwrap();
    let result = totp.verify_at(&otp, 10000, Some(10000 + 1), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), AfterError(10000 + 1, 10000).to_string());
}

#[test]
fn should_fail_if_drift_behind_is_greater_than_at() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );
    let otp = totp.generate_at(10000).unwrap();
    let result = totp.verify_at(&otp, 10000, Some(10000), DRIFT_AHEAD, 10000 + 1);

    assert!(result.is_err(), "Expected an error");
    assert_eq!(result.err().unwrap().to_string(), DriftBehindError(10000 + 1, 10000).to_string());
}

#[test]
fn should_verify_within_interval() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate_at(1).unwrap();
    let verify = totp.verify_at(&now, 29, Some(AFTER), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_not_verify_after_interval() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate_at(1).unwrap();
    let verify = totp.verify_at(&now, 30, Some(AFTER), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(verify.unwrap().is_none(), "OTP should not be verified");
}

#[test]
fn should_verify_with_after_less_than_at() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate().unwrap();
    let verify = totp.verify_at(
        &now,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        Some(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() - 100),
        DRIFT_AHEAD,
        DRIFT_BEHIND,
    );

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_verify_with_after_less_than_at_and_drift_behind() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate().unwrap();
    let verify = totp.verify_at(
        &now,
        std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
        Some(std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() - 100),
        DRIFT_AHEAD,
        101,
    );

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_not_verify_with_after_greater_than_at() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate().unwrap();
    let at = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
    let after = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() + 100;
    let verify = totp.verify_at(&now, at, Some(after), DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(verify.is_err(), "OTP should not be verified");
    assert_eq!(verify.err().unwrap().to_string(), AfterError(after, at).to_string());
}

#[test]
fn should_verify_without_after() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate().unwrap();
    let verify =
        totp.verify_at(&now, std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(), None, DRIFT_AHEAD, DRIFT_BEHIND);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_verify_with_drift_behind() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate_at(90).unwrap();
    let verify = totp.verify_at(&now, 91, Some(AFTER), DRIFT_AHEAD, 1);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}

#[test]
fn should_verify_with_drift_ahead() {
    let totp = TOTP::new(
        ALGORITHM,
        Secret::from_str("12345678901234567890").unwrap(),
        NonZero::new(LENGTH).unwrap(),
        Radix::new(RADIX).unwrap(),
        NonZero::new(INTERVAL).unwrap(),
    );

    let now = totp.generate_at(90).unwrap();
    let verify = totp.verify_at(&now, 89, Some(AFTER), 1, DRIFT_BEHIND);

    assert!(verify.unwrap().is_some(), "OTP should be verified");
}
