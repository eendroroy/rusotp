use crate::ffi::converter::{to_str, to_totp};
use std::ffi::{c_char, c_ulonglong, c_ushort};

/// Configuration for TOTP (Time-based One-Time Password).
///
/// # Fields
/// - `algorithm`: A pointer to a C string representing the hashing algorithm (e.g., "SHA1").
/// - `secret`: A pointer to a C string representing the shared secret key.
/// - `length`: The length of the generated OTP.
/// - `radix`: The base (radix) for the OTP (e.g., 10 for decimal).
/// - `interval`: The time interval in seconds for the TOTP generation.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct TotpConfig {
    pub algorithm: *const c_char,
    pub secret: *const c_char,
    pub length: c_ushort,
    pub radix: c_ushort,
    pub interval: c_ulonglong,
}

/// Generates a TOTP (Time-based One-Time Password) based on the provided configuration for the current time.
///
/// # Arguments
///
/// * `config` - A `TotpConfig` struct containing the configuration for the TOTP generation.
///
/// # Returns
///
/// A pointer to a C string containing the generated TOTP. The caller is responsible for freeing the memory.
///
/// # Panics
///
/// This function will panic if the TOTP generation fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and returns a raw pointer.
#[no_mangle]
pub unsafe extern "C" fn totp_generate(config: TotpConfig) -> *const c_char {
    std::ffi::CString::new(to_totp(config).generate().unwrap())
        .unwrap()
        .into_raw()
}

/// Generates a TOTP (Time-based One-Time Password) based on the provided configuration and timestamp.
///
/// # Arguments
///
/// * `config` - A `TotpConfig` struct containing the configuration for the TOTP generation.
/// * `timestamp` - A timestamp value used in the TOTP generation.
///
/// # Returns
///
/// A pointer to a C string containing the generated TOTP. The caller is responsible for freeing the memory.
///
/// # Panics
///
/// This function will panic if the TOTP generation fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and returns a raw pointer.
#[no_mangle]
pub unsafe extern "C" fn totp_generate_at(config: TotpConfig, timestamp: c_ulonglong) -> *const c_char {
    std::ffi::CString::new(to_totp(config).generate_at(timestamp).unwrap())
        .unwrap()
        .into_raw()
}

/// Verifies a TOTP (Time-based One-Time Password) based on the provided configuration, OTP, and drift parameters.
///
/// # Arguments
///
/// * `config` - A `TotpConfig` struct containing the configuration for the TOTP verification.
/// * `otp` - A pointer to a C string representing the OTP to be verified.
/// * `after` - The number of time steps after the current time to allow for verification.
/// * `drift_ahead` - The number of time steps ahead of the current time to allow for verification.
/// * `drift_behind` - The number of time steps behind the current time to allow for verification.
///
/// # Returns
///
/// A boolean value indicating whether the OTP is verified (`true`) or not (`false`).
///
/// # Panics
///
/// This function will panic if the OTP is null or if the TOTP verification fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
pub unsafe extern "C" fn totp_verify(
    config: TotpConfig,
    otp: *const c_char,
    after: c_ulonglong,
    drift_ahead: c_ulonglong,
    drift_behind: c_ulonglong,
) -> bool {
    if otp.is_null() {
        panic!("OTP is null");
    }

    let totp = to_totp(config);

    match totp.verify(to_str(otp), Some(after), drift_ahead, drift_behind) {
        Ok(verified) => verified.is_some(),
        Err(e) => panic!("{}", e),
    }
}

/// Verifies a TOTP (Time-based One-Time Password) based on the provided configuration, OTP, timestamp, and drift parameters.
///
/// # Arguments
///
/// * `config` - A `TotpConfig` struct containing the configuration for the TOTP verification.
/// * `otp` - A pointer to a C string representing the OTP to be verified.
/// * `timestamp` - A timestamp value used in the TOTP verification.
/// * `after` - The number of time steps after the current time to allow for verification.
/// * `drift_ahead` - The number of time steps ahead of the current time to allow for verification.
/// * `drift_behind` - The number of time steps behind the current time to allow for verification.
///
/// # Returns
///
/// A boolean value indicating whether the OTP is verified (`true`) or not (`false`).
///
/// # Panics
///
/// This function will panic if the OTP is null or if the TOTP verification fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers.
#[no_mangle]
pub unsafe extern "C" fn totp_verify_at(
    config: TotpConfig,
    otp: *const c_char,
    timestamp: c_ulonglong,
    after: c_ulonglong,
    drift_ahead: c_ulonglong,
    drift_behind: c_ulonglong,
) -> bool {
    if otp.is_null() {
        panic!("OTP is null");
    }

    let totp = to_totp(config);

    match totp.verify_at(to_str(otp), timestamp, Some(after), drift_ahead, drift_behind) {
        Ok(verified) => verified.is_some(),
        Err(e) => panic!("{}", e),
    }
}

/// Generates a provisioning URI for TOTP (Time-based One-Time Password) based on the provided configuration, issuer, and name.
///
/// # Arguments
///
/// * `config` - A `TotpConfig` struct containing the configuration for the TOTP generation.
/// * `issuer` - A pointer to a C string representing the issuer of the TOTP.
/// * `name` - A pointer to a C string representing the name of the user or account.
///
/// # Returns
///
/// A pointer to a C string containing the provisioning URI. The caller is responsible for freeing the memory.
///
/// # Panics
///
/// This function will panic if the issuer or name is null or if the URI generation fails.
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers and returns a raw pointer.
#[no_mangle]
pub unsafe extern "C" fn totp_provisioning_uri(
    config: TotpConfig,
    issuer: *const c_char,
    name: *const c_char,
) -> *const c_char {
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

#[cfg(test)]
mod totp_c_bind_tests;
