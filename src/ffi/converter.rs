use crate::{Algorithm, AlgorithmTrait, Radix, Secret, HOTP, TOTP};
use std::ffi::CStr;
use std::num::NonZeroU8;
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

    HOTP::new(
        Algorithm::from_string(to_string(config.algorithm)),
        Secret::new(to_str(config.secret)).unwrap(),  // TODO
        NonZeroU8::new(config.length as u8).unwrap(), // TODO
        Radix::new(config.radix as u8).unwrap(),      // TODO
    )
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
        Secret::new(to_str(config.secret)).unwrap(), // TODO
        config.length as u8,
        Radix::new(config.radix as u8).unwrap(), // TODO
        config.interval as u8,
    ) {
        Ok(totp) => totp,
        Err(e) => panic!("{}", e),
    }
}

#[cfg(test)]
mod converter_test;
