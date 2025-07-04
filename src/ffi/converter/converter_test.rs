use crate::ffi::{HotpConfig, TotpConfig};
use crate::{Algorithm, Radix, Secret, HOTP};
use std::any::Any;
use std::num::{NonZeroU64, NonZeroU8};

#[test]
fn to_string_should_convert_cstr_to_string() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let ptr = c_str.as_ptr();

    let result = super::to_string(ptr);
    assert_eq!(result, "Hello");
    assert_eq!(result.type_id(), String::from("Hello").type_id());
}

#[test]
fn to_str_should_convert_cstr_to_str() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let ptr = c_str.as_ptr();

    let result = super::to_str(ptr);
    assert_eq!(result, "Hello");
    assert_eq!(result.type_id(), "Hello".type_id());
}

#[test]
fn to_hotp_should_convert_hotp_config_to_hotp() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let secret = c_str.as_ptr();
    let c_str = std::ffi::CString::new("SHA1").unwrap();
    let algorithm = c_str.as_ptr();
    let hotp_config = HotpConfig {
        secret,
        algorithm,
        length: 6,
        radix: 10,
    };

    let hotp = super::to_hotp(hotp_config);
    let hotp_orig =
        HOTP::new(Algorithm::SHA1, Secret::new("Hello").unwrap(), NonZeroU8::new(6).unwrap(), Radix::new(10).unwrap());
    assert_eq!(hotp, hotp_orig);
}

#[test]
fn to_hotp_should_fail_with_empty_secret() {
    let c_str = std::ffi::CString::new("SHA1").unwrap();
    let algorithm = c_str.as_ptr();
    let hotp_config = HotpConfig {
        secret: std::ptr::null(),
        algorithm,
        length: 6,
        radix: 10,
    };

    assert!(std::panic::catch_unwind(|| super::to_hotp(hotp_config)).is_err());
}

#[test]
fn to_hotp_should_fail_with_empty_algorithm() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let secret = c_str.as_ptr();
    let hotp_config = HotpConfig {
        secret,
        algorithm: std::ptr::null(),
        length: 6,
        radix: 10,
    };
    assert!(std::panic::catch_unwind(|| super::to_hotp(hotp_config)).is_err());
}

#[test]
fn to_hotp_should_panic_with_invalid_data() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let secret = c_str.as_ptr();
    let c_str = std::ffi::CString::new("SHA1").unwrap();
    let algorithm = c_str.as_ptr();
    let hotp_config = HotpConfig {
        secret,
        algorithm,
        length: 6,
        radix: 37,
    };
    assert!(std::panic::catch_unwind(|| super::to_hotp(hotp_config)).is_err());
}

#[test]
fn to_totp_should_convert_totp_config_to_totp() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let secret = c_str.as_ptr();
    let c_str = std::ffi::CString::new("SHA1").unwrap();
    let algorithm = c_str.as_ptr();
    let totp_config = TotpConfig {
        secret,
        algorithm,
        length: 6,
        radix: 10,
        interval: 30,
    };
    let totp = super::to_totp(totp_config);
    let totp_orig = crate::TOTP::new(
        Algorithm::SHA1,
        Secret::new("Hello").unwrap(),
        NonZeroU8::new(6).unwrap(),
        Radix::new(10).unwrap(),
        NonZeroU64::new(30).unwrap(),
    );
    assert_eq!(totp, totp_orig);
}

#[test]
fn to_totp_should_fail_with_empty_secret() {
    let c_str = std::ffi::CString::new("SHA1").unwrap();
    let algorithm = c_str.as_ptr();
    let totp_config = TotpConfig {
        secret: std::ptr::null(),
        algorithm,
        length: 6,
        radix: 10,
        interval: 30,
    };
    assert!(std::panic::catch_unwind(|| super::to_totp(totp_config)).is_err());
}

#[test]
fn to_totp_should_fail_with_empty_algorithm() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let secret = c_str.as_ptr();
    let totp_config = TotpConfig {
        secret,
        algorithm: std::ptr::null(),
        length: 6,
        radix: 10,
        interval: 30,
    };
    assert!(std::panic::catch_unwind(|| super::to_totp(totp_config)).is_err());
}

#[test]
fn to_totp_should_panic_with_invalid_data() {
    let c_str = std::ffi::CString::new("Hello").unwrap();
    let secret = c_str.as_ptr();
    let c_str = std::ffi::CString::new("SHA1").unwrap();
    let algorithm = c_str.as_ptr();
    let totp_config = TotpConfig {
        secret,
        algorithm,
        length: 6,
        radix: 37,
        interval: 30,
    };
    assert!(std::panic::catch_unwind(|| super::to_totp(totp_config)).is_err());
}
