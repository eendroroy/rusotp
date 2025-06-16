use super::*;
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
    let otp_ptr = unsafe { hotp_generate(config, 0) };
    assert!(!otp_ptr.is_null());
    let otp = unsafe { CStr::from_ptr(otp_ptr).to_str().unwrap().to_owned() };
    assert_eq!(otp.len(), 6);
    unsafe {
        let _ = CString::from_raw(otp_ptr as *mut c_char);
    }
}

#[test]
fn test_hotp_provisioning_uri() {
    let config = make_config();
    let name = CString::new("testuser").unwrap();
    let uri_ptr = unsafe { hotp_provisioning_uri(config, name.as_ptr(), 0) };
    assert!(!uri_ptr.is_null());
    let uri = unsafe { CStr::from_ptr(uri_ptr).to_str().unwrap().to_owned() };
    assert!(uri.contains("otpauth://hotp/"));
    unsafe {
        let _ = CString::from_raw(uri_ptr as *mut c_char);
    }
}

#[test]
fn test_hotp_verify() {
    let config = make_config();
    let otp_ptr = unsafe { hotp_generate(config, 1) };
    let otp = unsafe { CStr::from_ptr(otp_ptr).to_str().unwrap().to_owned() };
    let otp_c = CString::new(otp.clone()).unwrap();
    let verified = unsafe { hotp_verify(config, otp_c.as_ptr(), 1, 0) };
    assert!(verified);
    unsafe {
        let _ = CString::from_raw(otp_ptr as *mut c_char);
    }
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
