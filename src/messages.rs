pub const SECRET_EMPTY: &str = "Secret must not be empty";
pub const OTP_LENGTH_INVALID: &str = "OTP length must be greater than or equal to 4";
pub const RADIX_INVALID: &str = "Radix must be between 2 and 36 inclusive";
pub const COUNTER_INVALID: &str = "Counter must be greater than or equal to 1";
pub const TIMESTAMP_INVALID: &str = "Timestamp must be greater than or equal to 1";
pub const DRIFT_BEHIND_INVALID: &str = "Drift behind must be less than timestamp";
pub const DRIFT_AHEAD_INVALID: &str = "Drift ahead must be greater than or equal to 0";
pub const OTP_LENGTH_NOT_MATCHED: &str =
    "OTP length does not match the length of the configuration";
pub const INTERVAL_INVALID: &str = "Interval must be greater than or equal to 30";
pub const PROV_OTP_LENGTH_INVALID: &str = "HOTP length must be 6";
pub const PROV_OTP_RADIX_INVALID: &str = "HOTP radix must be 10";
pub const MAC_CREATE_ERROR: &str = "Failed to create HMAC";
