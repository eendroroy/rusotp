// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::ffi::converter::{to_cstr, to_hotp, to_str};
use crate::ffi::{
    error_bool_result, error_hotp_config_result, error_string_result, success_bool_result, success_hotp_config_result,
    success_string_result, BoolResult, HotpConfig, HotpConfigResult, StringResult,
};
use crate::{AlgorithmTrait, HOTP};
use std::ffi::{c_ulonglong, c_ushort};
use std::os::raw::c_char;

/// Generates an HOTP (HMAC-based One-Time Password) based on the provided configuration and counter.
///
/// # Arguments
///
/// * `config` - A `HotpConfig` struct containing the configuration for the HOTP generation.
/// * `counter` - A counter value used in the HOTP generation.
///
/// # Returns
///
/// A `StringResult` containing success status and data if success.
///
/// # Example
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
///     unsigned long counter = 2;
///
///     StringResult otp = hotp_generate(config, counter);
///     printf("HOTP : %s\n", otp.data);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
/// ```
#[no_mangle]
pub extern "C" fn hotp_generate(config: HotpConfig, counter: c_ulonglong) -> StringResult {
    match to_hotp(config).generate(counter) {
        Ok(c) => success_string_result(c.as_str()),
        Err(e) => error_string_result(e.to_string().as_str()),
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
/// A `BoolResult` containing success status and data if success.
///
/// # Example
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
///     unsigned long counter = 2;
///
///     StringResult otp = hotp_generate(config, counter);
///     printf("HOTP : %s\n", otp.data);
///
///     const char *verified = hotp_verify(config, otp.data, counter, 0).data ? "true" : "false";
///     printf("VERIFIED : %s\n", verified);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
/// ```
#[no_mangle]
pub extern "C" fn hotp_verify(
    config: HotpConfig,
    otp: *const c_char,
    counter: c_ulonglong,
    retries: c_ulonglong,
) -> BoolResult {
    if otp.is_null() {
        error_bool_result("OTP is null")
    } else {
        match to_hotp(config).verify(to_str(otp), counter, retries) {
            Ok(verified) => success_bool_result(verified.is_some()),
            Err(e) => error_bool_result(e.to_string().as_str()),
        }
    }
}

/// Generates a provisioning URI for HOTP (HMAC-based One-Time Password) based on the provided configuration, name, and counter.
///
/// # Arguments
///
/// * `config` - A `HotpConfig` struct containing the configuration for the HOTP generation.
/// * `user` - A pointer to a C string representing the name of the user or account.
/// * `counter` - A counter value used in the HOTP generation.
///
/// # Returns
///
/// A `StringResult` containing success status and data if success.
///
/// # Example
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     HotpConfig config = {"SHA1", "12345678901234567890", 6, 10};
///     unsigned long counter = 2;
///
///     StringResult uri = hotp_provisioning_uri(config, "rusotp", "rusotp", counter);
///     printf("URI : %s\n", uri.data);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
/// ```
#[no_mangle]
pub extern "C" fn hotp_provisioning_uri(
    config: HotpConfig,
    issuer: *const c_char,
    user: *const c_char,
    counter: c_ulonglong,
) -> StringResult {
    if user.is_null() {
        error_string_result("Name is null")
    } else {
        match to_hotp(config).provisioning_uri(to_str(issuer), to_str(user), counter) {
            Ok(uri) => success_string_result(uri.as_str()),
            Err(e) => error_string_result(e.to_string().as_str()),
        }
    }
}

#[no_mangle]
pub extern "C" fn hotp_from_uri(uri: *const c_char) -> HotpConfigResult {
    if uri.is_null() {
        error_hotp_config_result("URI is null")
    } else {
        match HOTP::from_uri(to_str(uri)) {
            Ok(hotp) => success_hotp_config_result(HotpConfig {
                algorithm: to_cstr(hotp.algorithm.to_string().as_str()),
                secret: to_cstr(hotp.secret.string().as_str()),
                length: hotp.length.get() as c_ushort,
                radix: hotp.radix.get() as c_ushort,
            }),
            Err(e) => error_hotp_config_result(e.to_string().as_str()),
        }
    }
}

#[cfg(test)]
mod hotp_c_bind_tests;
