use crate::ffi::converter::{to_str, to_totp};
use std::os::raw::{c_char, c_ulong, c_ushort};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TotpConfig {
    pub algorithm: *const c_char,
    pub secret: *const c_char,
    pub length: c_ushort,
    pub radix: c_ushort,
    pub interval: c_ushort,
}

#[export_name = "generate_totp_now"]
pub unsafe extern "C" fn c_generate_totp_now(config: TotpConfig) -> *mut c_char {
    let totp = to_totp(config);
    match totp.now() {
        Ok(otp) => std::ffi::CString::new(otp).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    }
}

#[export_name = "generate_totp_at"]
pub unsafe extern "C" fn c_generate_totp_at(config: TotpConfig, timestamp: c_ulong) -> *mut c_char {
    let totp = to_totp(config);
    match totp.at_timestamp(timestamp) {
        Ok(otp) => std::ffi::CString::new(otp).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    };
    match totp.at_timestamp(timestamp) {
        Ok(otp) => std::ffi::CString::new(otp).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    }
}

#[export_name = "verify_totp"]
pub unsafe extern "C" fn c_verify_totp(
    config: TotpConfig,
    otp: *const c_char,
    timestamp: c_ulong,
    after: c_ulong,
    drift_ahead: c_ulong,
    drift_behind: c_ulong,
) -> bool {
    if otp.is_null() {
        panic!("OTP is null");
    }

    let totp = to_totp(config);

    match totp.verify(
        to_str(otp),
        timestamp,
        Some(after as u64),
        drift_ahead as u64,
        drift_behind as u64,
    ) {
        Ok(verified) => verified.is_some(),
        Err(e) => panic!("{}", e),
    }
}

#[export_name = "totp_provisioning_uri"]
pub unsafe extern "C" fn c_totp_provisioning_uri(
    config: TotpConfig,
    issuer: *const c_char,
    name: *const c_char,
) -> *mut c_char {
    if issuer.is_null() {
        panic!("Issuer is null");
    }
    if name.is_null() {
        panic!("Name is null");
    }

    let totp = to_totp(config);

    match totp.provisioning_uri(to_str(issuer), to_str(name)) {
        Ok(uri) => std::ffi::CString::new(uri).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    }
}
