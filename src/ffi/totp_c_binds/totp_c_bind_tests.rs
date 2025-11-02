// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use super::*;
use crate::ffi::converter::to_string;
use std::ffi::CString;
use std::ptr::null;

fn make_config() -> TotpConfig {
    TotpConfig {
        algorithm: CString::new("SHA1").unwrap().into_raw(),
        secret: CString::new("JBSWY3DPEHPK3PXP").unwrap().into_raw(),
        length: 6,
        radix: 10,
        interval: 30,
    }
}

#[test]
fn test_totp_generate() {
    let config = make_config();
    let otp_ptr = totp_generate(config);
    assert!(otp_ptr.success);
    assert_eq!(to_str(otp_ptr.data).len(), 6);
}

#[test]
fn test_totp_generate_at() {
    let config = make_config();
    let otp_ptr = totp_generate_at(config, 1000);
    assert!(otp_ptr.success);
    assert!(!otp_ptr.data.is_null());
}

#[test]
fn test_totp_verify() {
    let config = make_config();
    let otp_ptr = totp_generate(config);
    let result = totp_verify(config, otp_ptr.data, 0, 0, 0);
    assert!(result.success);
    assert!(result.data);
}

#[test]
fn test_totp_verify_at() {
    let config = make_config();
    let otp_ptr = totp_generate_at(config, 100);
    let result = totp_verify_at(config, otp_ptr.data, 100, 0, 0, 0);
    assert!(result.success);
    assert!(result.data);
}

#[test]
fn test_totp_provisioning_uri() {
    let config = make_config();
    let issuer = CString::new("TestIssuer").unwrap();
    let name = CString::new("TestUser").unwrap();
    let uri_ptr = totp_provisioning_uri(config, issuer.as_ptr(), name.as_ptr());
    assert!(uri_ptr.success);
    assert!(uri_ptr.error.is_null());
    assert_eq!(
        to_str(uri_ptr.data),
        "otpauth://totp/TestIssuer%3ATestUser?secret=jjbfgv2zgncfarkikbftgucyka======&issuer=TestIssuer"
    );
}

#[test]
fn test_totp_from_uri() {
    let config = make_config();
    let issuer = CString::new("testissuer").unwrap();
    let user = CString::new("testuser").unwrap();
    let uri = totp_provisioning_uri(config, issuer.as_ptr(), user.as_ptr());
    assert!(uri.success);
    assert!(to_string(uri.data).contains("otpauth://totp/"));

    let config_parsed = totp_from_uri(uri.data);

    unsafe {
        assert_eq!(to_string((*config_parsed.data).algorithm), to_string(config.algorithm));
        assert_eq!(to_string((*config_parsed.data).secret), to_string(config.secret));
        assert_eq!((*config_parsed.data).length, config.length);
        assert_eq!((*config_parsed.data).radix, config.radix);
        assert_eq!((*config_parsed.data).interval, config.interval);
    }
}

#[test]
fn test_totp_from_uri_fail() {
    let config = make_config();
    let issuer = CString::new("testissuer").unwrap();
    let user = CString::new("testuser").unwrap();
    let uri = totp_provisioning_uri(config, issuer.as_ptr(), user.as_ptr());
    assert!(uri.success);
    assert!(to_string(uri.data).contains("otpauth://totp/"));

    let config_parsed = totp_from_uri(uri.data);

    unsafe {
        assert_eq!(to_string((*config_parsed.data).algorithm), to_string(config.algorithm));
        assert_eq!(to_string((*config_parsed.data).secret), to_string(config.secret));
        assert_eq!((*config_parsed.data).length, config.length);
        assert_eq!((*config_parsed.data).radix, config.radix);
        assert_eq!((*config_parsed.data).interval, config.interval);
    }

    let fail_result = totp_from_uri(null());
    assert_eq!(to_string(fail_result.error), "URI is null");
}
