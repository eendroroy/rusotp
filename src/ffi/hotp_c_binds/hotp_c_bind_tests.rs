use super::*;
use crate::ffi::converter::to_string;
use std::ffi::CString;

fn make_config() -> HotpConfig {
    HotpConfig {
        algorithm: CString::new("SHA1").unwrap().into_raw(),
        secret: CString::new("12345678901234567890").unwrap().into_raw(),
        length: 6,
        radix: 10,
    }
}

#[test]
fn test_hotp_generate() {
    let config = make_config();
    let otp = unsafe { hotp_generate(config, 0) };
    assert!(otp.success);
    assert_eq!(to_string(otp.data).len(), 6);
}

#[test]
fn test_hotp_provisioning_uri() {
    let config = make_config();
    let name = CString::new("testuser").unwrap();
    let uri = unsafe { hotp_provisioning_uri(config, name.as_ptr(), 0) };
    assert!(uri.success);
    assert!(to_string(uri.data).contains("otpauth://hotp/"));
}

#[test]
fn test_hotp_verify() {
    let config = make_config();
    let otp = unsafe { hotp_generate(config, 1) };
    let verified = unsafe { hotp_verify(config, otp.data, 1, 0) };
    assert!(verified.success);
    assert!(verified.data);
}
// TODO
// #[test]
// #[should_panic(expected = "OTP is null")]
// fn test_hotp_verify_null_otp() {
//     let config = make_config();
//     unsafe { hotp_verify(config, std::ptr::null(), 1, 0); }
// }
//
// TODO
// #[test]
// #[should_panic(expected = "Name is null")]
// fn test_hotp_provisioning_uri_null_name() {
//     let config = make_config();
//     unsafe { hotp_provisioning_uri(config, std::ptr::null(), 0); }
// }
