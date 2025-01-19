use crate::otp::algorithm::{Algorithm, AlgorithmTrait};
use crate::{
    generate_hotp, generate_totp_at, generate_totp_now, hotp_provisioning_uri,
    totp_provisioning_uri, verify_hotp, verify_totp,
};
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong, c_ushort};

#[export_name = "generate_hotp"]
pub unsafe extern "C" fn c_generate_hotp(
    algorithm: *const c_char,
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    counter: c_ulong,
) -> *mut c_char {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    let hotp = generate_hotp(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        length as u8,
        radix as u8,
        counter as u64,
    );
    let c_string = std::ffi::CString::new(hotp).unwrap();
    c_string.into_raw()
}

#[export_name = "hotp_provisioning_uri"]
pub unsafe extern "C" fn c_hotp_provisioning_uri(
    algorithm: *const c_char,
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    name: *const c_char,
    counter: c_ulong,
) -> *mut c_char {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if name.is_null() {
        panic!("Name is null");
    }

    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    let uri = hotp_provisioning_uri(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        length as u8,
        radix as u8,
        CStr::from_ptr(name).to_str().unwrap(),
        counter as u64,
    );
    let c_string = std::ffi::CString::new(uri).unwrap();
    c_string.into_raw()
}

#[export_name = "verify_hotp"]
pub unsafe extern "C" fn c_verify_hotp(
    algorithm: *const c_char,
    secret: *const c_char,
    otp: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    counter: c_ulong,
    retries: c_ulong,
) -> bool {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if otp.is_null() {
        panic!("OTP is null");
    }
    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    verify_hotp(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        CStr::from_ptr(otp).to_str().unwrap(),
        length as u8,
        radix as u8,
        counter as u64,
        retries as u64,
    )
}

#[export_name = "generate_totp_now"]
pub unsafe extern "C" fn c_generate_totp_now(
    algorithm: *const c_char,
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
) -> *mut c_char {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    let hotp = generate_totp_now(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        length as u8,
        radix as u8,
        interval as u8,
    );
    let c_string = std::ffi::CString::new(hotp).unwrap();
    c_string.into_raw()
}

#[export_name = "generate_totp_at"]
pub unsafe extern "C" fn c_generate_totp_at(
    algorithm: *const c_char,
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
    timestamp: c_ulong,
) -> *mut c_char {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    let totp = generate_totp_at(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        length as u8,
        radix as u8,
        interval as u8,
        timestamp as u64,
    );
    let c_string = std::ffi::CString::new(totp).unwrap();
    c_string.into_raw()
}

#[export_name = "verify_totp"]
pub unsafe extern "C" fn c_verify_totp(
    algorithm: *const c_char,
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
    otp: *const c_char,
    timestamp: c_ulong,
    after: c_ulong,
    drift_ahead: c_ulong,
    drift_behind: c_ulong,
) -> bool {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if otp.is_null() {
        panic!("OTP is null");
    }
    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    verify_totp(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        length as u8,
        radix as u8,
        interval as u8,
        CStr::from_ptr(otp).to_str().unwrap(),
        timestamp as u64,
        Some(after as u64),
        drift_ahead as u64,
        drift_behind as u64,
    )
}

#[export_name = "totp_provisioning_uri"]
pub unsafe extern "C" fn c_totp_provisioning_uri(
    algorithm: *const c_char,
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
    issuer: *const c_char,
    name: *const c_char,
) -> *mut c_char {
    if secret.is_null() {
        panic!("Secret is null");
    }
    if issuer.is_null() {
        panic!("Issuer is null");
    }
    if name.is_null() {
        panic!("Name is null");
    }
    if algorithm.is_null() {
        panic!("Algorithm is null");
    }
    let uri = totp_provisioning_uri(
        Algorithm::from_string(CStr::from_ptr(algorithm).to_str().unwrap().to_string()),
        CStr::from_ptr(secret).to_str().unwrap(),
        length as u8,
        radix as u8,
        interval as u8,
        CStr::from_ptr(issuer).to_str().unwrap(),
        CStr::from_ptr(name).to_str().unwrap(),
    );
    let c_string = std::ffi::CString::new(uri).unwrap();
    c_string.into_raw()
}
