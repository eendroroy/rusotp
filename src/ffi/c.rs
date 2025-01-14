use crate::{
    generate_hotp, generate_totp_at, generate_totp_now, hotp_provisioning_uri,
    totp_provisioning_uri, verify_hotp, verify_totp,
};
use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong, c_ushort};

/// Generates an HOTP code using the provided secret and counter.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `length`: The length of the OTP to generate.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `counter`: The counter value.
///
/// # Returns
/// A pointer to a C string containing the generated HOTP code.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdlib.h>
///
/// // Declaration of the FFI function
/// extern char* c_generate_hotp(
///     const char* secret,
///     unsigned short length,
///     unsigned short radix,
///     unsigned long counter
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     unsigned long counter = 1;
///
///     // Call the FFI function
///     char* hotp = c_generate_hotp(secret, length, radix, counter);
///
///     // Print the generated HOTP
///     printf("Generated HOTP: %s\n", hotp);
///
///     // Free the allocated memory if necessary
///     free(hotp);
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_generate_hotp(
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    counter: c_ulong,
) -> *mut c_char {
    generate_hotp(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        counter,
    )
    .as_ptr() as *mut c_char
}

/// Generates a provisioning URI for HOTP using the provided secret, length, radix, name, and counter.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `length`: The length of the OTP to generate.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `name`: A pointer to a C string containing the name.
/// - `counter`: The counter value.
///
/// # Returns
/// A pointer to a C string containing the generated provisioning URI.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdlib.h>
///
/// // Declaration of the FFI function
/// extern char* c_hotp_provisioning_uri(
///     const char* secret,
///     unsigned short length,
///     unsigned short radix,
///     const char* name,
///     unsigned long counter
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     const char* name = "your_name";
///     unsigned long counter = 1;
///
///     // Call the FFI function
///     char* uri = c_hotp_provisioning_uri(secret, length, radix, name, counter);
///
///     // Print the generated URI
///     printf("Generated URI: %s\n", uri);
///
///     // Free the allocated memory if necessary
///     free(uri);
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_hotp_provisioning_uri(
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    name: *const c_char,
    counter: c_ulong,
) -> *mut c_char {
    hotp_provisioning_uri(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        CStr::from_ptr(name).to_string_lossy().as_ref(),
        counter,
    )
    .as_ptr() as *mut c_char
}

/// Verifies an HOTP code using the provided secret, OTP, and counter.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `otp`: A pointer to a C string containing the OTP to verify.
/// - `length`: The length of the OTP.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `counter`: The counter value.
/// - `retries`: The number of retries allowed.
///
/// # Returns
/// `true` if the OTP is valid, `false` otherwise.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdbool.h>
///
/// // Declaration of the FFI function
/// extern bool c_verify_hotp(
///     const char* secret,
///     const char* otp,
///     unsigned short length,
///     unsigned short radix,
///     unsigned long counter,
///     unsigned long retries
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     const char* otp = "123456";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     unsigned long counter = 1;
///     unsigned long retries = 3;
///
///     // Call the FFI function
///     bool is_valid = c_verify_hotp(secret, otp, length, radix, counter, retries);
///
///     // Print the verification result
///     printf("OTP is %s\n", is_valid ? "valid" : "invalid");
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_verify_hotp(
    secret: *const c_char,
    otp: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    counter: c_ulong,
    retries: c_ulong,
) -> bool {
    verify_hotp(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        CStr::from_ptr(otp).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        counter,
        retries,
    )
}

/// Generates a TOTP code for the current time using the provided secret.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `length`: The length of the OTP to generate.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `interval`: The time interval in seconds for the TOTP.
///
/// # Returns
/// A pointer to a C string containing the generated TOTP code.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdlib.h>
///
/// // Declaration of the FFI function
/// extern char* c_generate_totp_now(
///     const char* secret,
///     unsigned short length,
///     unsigned short radix,
///     unsigned short interval
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     unsigned short interval = 30;
///
///     // Call the FFI function
///     char* totp = c_generate_totp_now(secret, length, radix, interval);
///
///     // Print the generated TOTP
///     printf("Generated TOTP: %s\n", totp);
///
///     // Free the allocated memory if necessary
///     free(totp);
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_generate_totp_now(
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
) -> *mut c_char {
    generate_totp_now(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        interval as u8,
    )
    .as_ptr() as *mut c_char
}

/// Generates a TOTP code for a specific timestamp using the provided secret.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `length`: The length of the OTP to generate.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `interval`: The time interval in seconds for the TOTP.
/// - `timestamp`: The specific timestamp for which to generate the TOTP.
///
/// # Returns
/// A pointer to a C string containing the generated TOTP code.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdlib.h>
///
/// // Declaration of the FFI function
/// extern char* c_generate_totp_at(
///     const char* secret,
///     unsigned short length,
///     unsigned short radix,
///     unsigned short interval,
///     unsigned long timestamp
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     unsigned short interval = 30;
///     unsigned long timestamp = 1627846261; // Example timestamp
///
///     // Call the FFI function
///     char* totp = c_generate_totp_at(secret, length, radix, interval, timestamp);
///
///     // Print the generated TOTP
///     printf("Generated TOTP: %s\n", totp);
///
///     // Free the allocated memory if necessary
///     free(totp);
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_generate_totp_at(
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
    timestamp: c_ulong,
) -> *mut c_char {
    generate_totp_at(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        interval as u8,
        timestamp as i64,
    )
    .as_ptr() as *mut c_char
}

/// Verifies a TOTP code using the provided secret, OTP, and timestamp.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `length`: The length of the OTP.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `interval`: The time interval in seconds for the TOTP.
/// - `otp`: A pointer to a C string containing the OTP to verify.
/// - `timestamp`: The specific timestamp for which to verify the TOTP.
/// - `after`: The time after the timestamp to allow for verification.
/// - `drift_ahead`: The allowed drift ahead of the timestamp.
/// - `drift_behind`: The allowed drift behind the timestamp.
///
/// # Returns
/// `true` if the OTP is valid, `false` otherwise.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdbool.h>
///
/// // Declaration of the FFI function
/// extern bool c_verify_totp(
///     const char* secret,
///     unsigned short length,
///     unsigned short radix,
///     unsigned short interval,
///     const char* otp,
///     unsigned long timestamp,
///     unsigned long after,
///     unsigned long drift_ahead,
///     unsigned long drift_behind
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     const char* otp = "123456";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     unsigned short interval = 30;
///     unsigned long timestamp = 1627846261; // Example timestamp
///     unsigned long after = 0;
///     unsigned long drift_ahead = 1;
///     unsigned long drift_behind = 1;
///
///     // Call the FFI function
///     bool is_valid = c_verify_totp(secret, length, radix, interval, otp, timestamp, after, drift_ahead, drift_behind);
///
///     // Print the verification result
///     printf("TOTP is %s\n", is_valid ? "valid" : "invalid");
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_verify_totp(
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
    verify_totp(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        interval as u8,
        CStr::from_ptr(otp).to_string_lossy().as_ref(),
        timestamp as i64,
        Some(after as i64),
        drift_ahead as i64,
        drift_behind as i64,
    )
    .is_some()
}

/// Generates a provisioning URI for TOTP using the provided secret, length, radix, interval, issuer, and name.
///
/// # Parameters
/// - `secret`: A pointer to a C string containing the secret key.
/// - `length`: The length of the OTP to generate.
/// - `radix`: The base of the OTP (e.g., 10 for decimal).
/// - `interval`: The time interval in seconds for the TOTP.
/// - `issuer`: A pointer to a C string containing the issuer name.
/// - `name`: A pointer to a C string containing the name.
///
/// # Returns
/// A pointer to a C string containing the generated provisioning URI.
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # C Usage
/// ```c
/// #include <stdio.h>
/// #include <stdlib.h>
///
/// // Declaration of the FFI function
/// extern char* c_totp_provisioning_uri(
///     const char* secret,
///     unsigned short length,
///     unsigned short radix,
///     unsigned short interval,
///     const char* issuer,
///     const char* name
/// );
///
/// int main() {
///     const char* secret = "your_secret_key";
///     unsigned short length = 6;
///     unsigned short radix = 10;
///     unsigned short interval = 30;
///     const char* issuer = "your_issuer";
///     const char* name = "your_name";
///
///     // Call the FFI function
///     char* uri = c_totp_provisioning_uri(secret, length, radix, interval, issuer, name);
///
///     // Print the generated URI
///     printf("Generated URI: %s\n", uri);
///
///     // Free the allocated memory if necessary
///     free(uri);
///
///     return 0;
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn c_totp_provisioning_uri(
    secret: *const c_char,
    length: c_ushort,
    radix: c_ushort,
    interval: c_ushort,
    issuer: *const c_char,
    name: *const c_char,
) -> *mut c_char {
    totp_provisioning_uri(
        CStr::from_ptr(secret).to_string_lossy().as_ref(),
        length as u8,
        radix as u8,
        interval as u8,
        CStr::from_ptr(issuer).to_string_lossy().as_ref(),
        CStr::from_ptr(name).to_string_lossy().as_ref(),
    )
    .as_ptr() as *mut c_char
}
