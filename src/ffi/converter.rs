use crate::{Algorithm, AlgorithmTrait, HOTP, TOTP};
use std::ffi::CStr;
use std::os::raw::c_char;

pub(crate) unsafe fn to_string(ptr: *const c_char) -> String {
    CStr::from_ptr(ptr).to_str().unwrap().to_string()
}

pub(crate) unsafe fn to_str(ptr: *const c_char) -> &'static str {
    CStr::from_ptr(ptr).to_str().unwrap()
}

pub(crate) unsafe fn to_hotp(config: crate::ffi::hotp_c_binds::HotpConfig) -> HOTP {
    if config.secret.is_null() {
        panic!("Secret is null");
    }
    if config.algorithm.is_null() {
        panic!("Algorithm is null");
    }

    match HOTP::new(
        Algorithm::from_string(to_string(config.algorithm)),
        to_str(config.secret),
        config.length as u8,
        config.radix as u8,
    ) {
        Ok(hotp) => hotp,
        Err(e) => panic!("{}", e),
    }
}

pub(crate) unsafe fn to_totp(config: crate::ffi::totp_c_binds::TotpConfig) -> TOTP {
    if config.secret.is_null() {
        panic!("Secret is null");
    }
    if config.algorithm.is_null() {
        panic!("Algorithm is null");
    }

    match TOTP::new(
        Algorithm::from_string(to_string(config.algorithm)),
        to_str(config.secret),
        config.length as u8,
        config.radix as u8,
        config.interval as u8,
    ) {
        Ok(totp) => totp,
        Err(e) => panic!("{}", e),
    }
}

#[cfg(test)]
mod converter_test;
