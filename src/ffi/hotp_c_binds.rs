use crate::ffi::converter::{to_hotp, to_str};
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong, c_ushort};

/// Configuration for HOTP (HMAC-based One-Time Password).
///
/// # Fields
/// - `algorithm`: A pointer to a C string representing the hashing algorithm (e.g., "SHA1").
/// - `secret`: A pointer to a C string representing the shared secret key.
/// - `length`: The length of the generated OTP.
/// - `radix`: The base (radix) for the OTP (e.g., 10 for decimal).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HotpConfig {
    pub algorithm: *const c_char,
    pub secret: *const c_char,
    pub length: c_ushort,
    pub radix: c_ushort,
}

/// Generates an HOTP (HMAC-based One-Time Password) based on the provided configuration and counter.
///
/// # Arguments
///
/// * `config` - A `HotpConfig` struct containing the configuration for the HOTP generation.
/// * `counter` - A counter value used in the HOTP generation.
///
/// # Returns
///
/// A pointer to a C string containing the generated HOTP. The caller is responsible for freeing the memory.
///
/// # Panics
///
/// This function will panic if the HOTP generation fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and returns a raw pointer.
#[export_name = "generate_hotp"]
pub unsafe extern "C" fn generate_hotp(config: HotpConfig, counter: c_ulong) -> *const c_char {
    std::ffi::CString::new(to_hotp(config).generate(counter.into()).unwrap())
        .unwrap()
        .into_raw()
}

/// Generates a provisioning URI for HOTP (HMAC-based One-Time Password) based on the provided configuration, name, and counter.
///
/// # Arguments
///
/// * `config` - A `HotpConfig` struct containing the configuration for the HOTP generation.
/// * `name` - A pointer to a C string representing the name of the user or account.
/// * `counter` - A counter value used in the HOTP generation.
///
/// # Returns
///
/// A pointer to a C string containing the provisioning URI. The caller is responsible for freeing the memory.
///
/// # Panics
///
/// This function will panic if the name is null or if the URI generation fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and returns a raw pointer.
#[export_name = "hotp_provisioning_uri"]
pub unsafe extern "C" fn hotp_provisioning_uri(
    config: HotpConfig,
    name: *const c_char,
    counter: c_ulong,
) -> *const c_char {
    if name.is_null() {
        panic!("Name is null");
    }

    let hotp = to_hotp(config);

    match hotp.provisioning_uri(CStr::from_ptr(name).to_str().unwrap(), counter.into()) {
        Ok(uri) => std::ffi::CString::new(uri).unwrap().into_raw(),
        Err(e) => panic!("{}", e),
    }
}

/// Verifies an HOTP (HMAC-based One-Time Password) based on the provided configuration, OTP, counter, and retries.
///
/// # Arguments
///
/// * `config` - A `HotpConfig` struct containing the configuration for the HOTP verification.
/// * `otp` - A pointer to a C string representing the OTP to be verified.
/// * `counter` - A counter value used in the HOTP verification.
/// * `retries` - The number of retries allowed for the HOTP verification.
///
/// # Returns
///
/// A boolean value indicating whether the OTP is verified (`true`) or not (`false`).
///
/// # Panics
///
/// This function will panic if the OTP is null or if the HOTP verification fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers.
#[export_name = "verify_hotp"]
pub unsafe extern "C" fn verify_hotp(
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
