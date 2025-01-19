use crate::ffi::converter::{to_hotp, to_str};
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong, c_ushort};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HotpConfig {
    pub algorithm: *const c_char,
    pub secret: *const c_char,
    pub length: c_ushort,
    pub radix: c_ushort,
}

#[export_name = "generate_hotp"]
pub unsafe extern "C" fn c_generate_hotp(config: HotpConfig, counter: c_ulong) -> *mut c_char {
    let hotp = to_hotp(config);

    match hotp.generate(counter.into()) {
        Ok(otp) => std::ffi::CString::new(otp).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    }
}

#[export_name = "hotp_provisioning_uri"]
pub unsafe extern "C" fn c_hotp_provisioning_uri(
    config: HotpConfig,
    name: *const c_char,
    counter: c_ulong,
) -> *mut c_char {
    if name.is_null() {
        panic!("Name is null");
    }

    let hotp = to_hotp(config);

    match hotp.provisioning_uri(CStr::from_ptr(name).to_str().unwrap(), counter.into()) {
        Ok(uri) => std::ffi::CString::new(uri).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    }
}

#[export_name = "verify_hotp"]
pub unsafe extern "C" fn c_verify_hotp(
    config: HotpConfig,
    otp: *const c_char,
    counter: c_ulong,
    retries: c_ulong,
) -> bool {
    if otp.is_null() {
        panic!("OTP is null");
    }

    let hotp = to_hotp(config);

    match hotp.verify(to_str(otp), counter.into(), retries.into()) {
        Ok(verified) => verified.is_some(),
        Err(e) => {
            panic!("{}", e)
        }
    }
}
