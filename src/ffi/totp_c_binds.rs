// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use crate::ffi::converter::{to_str, to_totp};
use crate::ffi::{
    error_bool_result, error_string_result, success_bool_result, success_string_result, BoolResult, StringResult,
    TotpConfig,
};
use std::ffi::{c_char, c_ulonglong};

/// Generates a TOTP (Time-based One-Time Password) based on the provided configuration for the current time.
///
/// # Arguments
///
/// * `config` - A `TotpConfig` struct containing the configuration for the TOTP generation.
///
/// # Returns
///
/// A `StringResult` containing success status and data if success.
///
/// # Example
///
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
///
///     StringResult otp_now =  totp_generate(config);
///     printf("NOW: %s\n", otp_now.data);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
///```
#[no_mangle]
pub extern "C" fn totp_generate(config: TotpConfig) -> StringResult {
    match to_totp(config).generate() {
        Ok(otp) => success_string_result(&otp),
        Err(e) => error_string_result(&e.to_string()),
    }
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
/// A `StringResult` containing success status and data if success.
///
/// # Example
///
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
///     unsigned long timestamp = 10000;
///
///     StringResult otp_at = totp_generate_at(config, timestamp);
///     printf("AT: %s\n", otp_at.data);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
///```
#[no_mangle]
pub extern "C" fn totp_generate_at(config: TotpConfig, timestamp: c_ulonglong) -> StringResult {
    match to_totp(config).generate_at(timestamp) {
        Ok(otp) => success_string_result(&otp),
        Err(e) => error_string_result(&e.to_string()),
    }
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
/// A `BoolResult` containing success status and data if success.
///
/// # Example
///
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
///
///     StringResult otp_now =  totp_generate(config);
///     printf("NOW: %s\n", otp_now.data);
///
///     const char *verified = totp_verify(config, otp_now.data, 0, 0, 0).data ? "true" : "false";
///     printf("VERIFIED : %s\n", verified);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
///```
#[no_mangle]
pub extern "C" fn totp_verify(
    config: TotpConfig,
    otp: *const c_char,
    after: c_ulonglong,
    drift_ahead: c_ulonglong,
    drift_behind: c_ulonglong,
) -> BoolResult {
    if otp.is_null() {
        error_bool_result("OTP is null");
    }

    let totp = to_totp(config);

    match totp.verify(to_str(otp), Some(after), drift_ahead, drift_behind) {
        Ok(verified) => success_bool_result(verified.is_some()),
        Err(e) => error_bool_result(e.to_string().as_str()),
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
/// A `BoolResult` containing success status and data if success.
///
/// # Example
///
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
///     unsigned long timestamp = 10000;
///
///     StringResult otp_at = totp_generate_at(config, timestamp);
///     const char *verified = totp_verify_at(config, otp_at.data, timestamp, 0, 0, 0).data ? "true" : "false";
///     printf("VERIFIED : %s\n", verified);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
///```
#[no_mangle]
pub extern "C" fn totp_verify_at(
    config: TotpConfig,
    otp: *const c_char,
    timestamp: c_ulonglong,
    after: c_ulonglong,
    drift_ahead: c_ulonglong,
    drift_behind: c_ulonglong,
) -> BoolResult {
    if otp.is_null() {
        error_bool_result("OTP is null")
    } else {
        match to_totp(config).verify_at(to_str(otp), timestamp, Some(after), drift_ahead, drift_behind) {
            Ok(verified) => success_bool_result(verified.is_some()),
            Err(e) => error_bool_result(e.to_string().as_str()),
        }
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
/// A `StringResult` containing success status and data if success.
///
/// # Example
///
/// ```
/// # use inline_c::assert_cxx;
/// #
/// # fn main() {
/// #     (assert_cxx! {
/// #include <stdio.h>
/// #include "rusotp.hpp"
///
/// int main() {
///     TotpConfig config = {"SHA1", "12345678901234567890", 6, 10, 30};
///
///     StringResult provisioning_uri = totp_provisioning_uri(config, "rusotp", "user@email.mail");
///     printf("URI : %s\n", provisioning_uri.data);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
///```
#[no_mangle]
pub extern "C" fn totp_provisioning_uri(
    config: TotpConfig,
    issuer: *const c_char,
    name: *const c_char,
) -> StringResult {
    if issuer.is_null() {
        error_string_result("Issuer is null")
    } else if name.is_null() {
        error_string_result("Name is null")
    } else {
        match to_totp(config).provisioning_uri(to_str(issuer), to_str(name)) {
            Ok(uri) => success_string_result(uri.as_str()),
            Err(e) => error_string_result(e.to_string().as_str()),
        }
    }
}

#[cfg(test)]
mod totp_c_bind_tests;
