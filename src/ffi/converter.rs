// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::ffi::{HotpConfig, TotpConfig};
use crate::{Algorithm, AlgorithmTrait, Radix, Secret, HOTP, TOTP};
use std::ffi::CStr;
use std::num::{NonZeroU64, NonZeroU8};
use std::os::raw::c_char;

pub(crate) fn to_cstr(str: &str) -> *mut c_char {
    std::ffi::CString::new(str).unwrap().into_raw()
}

pub(crate) fn to_string(ptr: *const c_char) -> String {
    unsafe { CStr::from_ptr(ptr).to_str().unwrap().to_string() }
}

pub(crate) fn to_str(ptr: *const c_char) -> &'static str {
    unsafe { CStr::from_ptr(ptr).to_str().unwrap() }
}

pub(crate) fn to_hotp(config: HotpConfig) -> HOTP {
    if config.secret.is_null() {
        panic!("Secret is null");
    }
    if config.algorithm.is_null() {
        panic!("Algorithm is null");
    }

    HOTP::new(
        Algorithm::from_string(to_string(config.algorithm)).unwrap(),
        Secret::new_from_str(to_str(config.secret)).unwrap(), // TODO
        NonZeroU8::new(config.length as u8).unwrap(),         // TODO
        Radix::new(config.radix as u8).unwrap(),              // TODO
    )
}

pub(crate) fn to_totp(config: TotpConfig) -> TOTP {
    if config.secret.is_null() {
        panic!("Secret is null");
    }
    if config.algorithm.is_null() {
        panic!("Algorithm is null");
    }

    TOTP::new(
        Algorithm::from_string(to_string(config.algorithm)).unwrap(),
        Secret::new_from_str(to_str(config.secret)).unwrap(), // TODO
        NonZeroU8::new(config.length as u8).unwrap(),         // TODO
        Radix::new(config.radix as u8).unwrap(),              // TODO
        NonZeroU64::new(config.interval).unwrap(),            // TODO
    )
}

#[cfg(test)]
mod converter_test;
