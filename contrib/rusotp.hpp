#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

/// FFI-safe result type for operations returning a string.
///
/// # Fields
/// - `success`: Indicates if the operation was successful.
/// - `data`: Pointer to a C string containing the result data (valid if `success` is true).
/// - `error`: Pointer to a C string containing the error message (valid if `success` is false).
struct StringResult {
  bool success;
  const char *data;
  const char *error;
};

/// Configuration for HOTP (HMAC-based One-Time Password).
///
/// # Fields
/// - `algorithm`: A pointer to a C string representing the hashing algorithm (e.g., "SHA1").
/// - `secret`: A pointer to a C string representing the shared secret key.
/// - `length`: The length of the generated OTP.
/// - `radix`: The base (radix) for the OTP (e.g., 10 for decimal).
struct HotpConfig {
  const char *algorithm;
  const char *secret;
  unsigned short length;
  unsigned short radix;
};

/// FFI-safe result type for operations returning a boolean value.
///
/// # Fields
/// - `success`: Indicates if the operation was successful.
/// - `data`: The boolean result (valid if `success` is true).
/// - `error`: Pointer to a C string containing the error message (valid if `success` is false).
struct BoolResult {
  bool success;
  bool data;
  const char *error;
};

/// Configuration for TOTP (Time-based One-Time Password).
///
/// # Fields
/// - `algorithm`: A pointer to a C string representing the hashing algorithm (e.g., "SHA1").
/// - `secret`: A pointer to a C string representing the shared secret key.
/// - `length`: The length of the generated OTP.
/// - `radix`: The base (radix) for the OTP (e.g., 10 for decimal).
/// - `interval`: The time interval in seconds for the TOTP generation.
struct TotpConfig {
  const char *algorithm;
  const char *secret;
  unsigned short length;
  unsigned short radix;
  unsigned long long interval;
};

extern "C" {

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
StringResult hotp_generate(HotpConfig config,
                           unsigned long long counter);

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
BoolResult hotp_verify(HotpConfig config,
                       const char *otp,
                       unsigned long long counter,
                       unsigned long long retries);

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
///     StringResult uri = hotp_provisioning_uri(config, "rusotp", counter);
///     printf("URI : %s\n", uri.data);
///
///     return 0;
/// }
/// #    })
/// #    .success();
/// # }
/// ```
StringResult hotp_provisioning_uri(HotpConfig config,
                                   const char *name,
                                   unsigned long long counter);

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
StringResult totp_generate(TotpConfig config);

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
StringResult totp_generate_at(TotpConfig config,
                              unsigned long long timestamp);

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
BoolResult totp_verify(TotpConfig config,
                       const char *otp,
                       unsigned long long after,
                       unsigned long long drift_ahead,
                       unsigned long long drift_behind);

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
BoolResult totp_verify_at(TotpConfig config,
                          const char *otp,
                          unsigned long long timestamp,
                          unsigned long long after,
                          unsigned long long drift_ahead,
                          unsigned long long drift_behind);

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
StringResult totp_provisioning_uri(TotpConfig config,
                                   const char *issuer,
                                   const char *name);

}  // extern "C"
