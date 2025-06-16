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
    let otp_ptr = unsafe { totp_generate(config) };
    assert!(!otp_ptr.is_null());
    unsafe {
        CString::from_raw(otp_ptr as *mut i8);
    }
}

// TODO
// #[test]
// fn test_totp_generate_at() {
//     let config = make_config();
//     let otp_ptr = unsafe { totp_generate_at(config, 0) };
//     assert!(!otp_ptr.is_null());
//     unsafe { CString::from_raw(otp_ptr as *mut i8); }
// }
//
// TODO
// #[test]
// fn test_totp_verify() {
//     let config = make_config();
//     let otp_ptr = unsafe { totp_generate(config) };
//     let result = unsafe { totp_verify(config, otp_ptr, 0, 0, 0) };
//     assert!(result);
//     unsafe { CString::from_raw(otp_ptr as *mut i8); }
// }
//
// TODO
// #[test]
// fn test_totp_verify_at() {
//     let config = make_config();
//     let otp_ptr = unsafe { totp_generate_at(config, 0) };
//     let result = unsafe { totp_verify_at(config, otp_ptr, 0, 0, 0, 0) };
//     assert!(result);
//     unsafe { CString::from_raw(otp_ptr as *mut i8); }
// }

#[test]
fn test_totp_provisioning_uri() {
    let config = make_config();
    let issuer = CString::new("TestIssuer").unwrap();
    let name = CString::new("TestUser").unwrap();
    let uri_ptr = unsafe { totp_provisioning_uri(config, issuer.as_ptr(), name.as_ptr()) };
    assert!(!uri_ptr.is_null());
    unsafe {
        CString::from_raw(uri_ptr as *mut i8);
    }
}
