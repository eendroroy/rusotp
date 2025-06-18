use std::os::raw::{c_char, c_ushort};

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