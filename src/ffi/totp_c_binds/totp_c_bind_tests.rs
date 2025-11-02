// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use super::*;
use std::ffi::CString;

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
