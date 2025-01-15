mod ffi;
mod messages;
mod otp;

pub use crate::otp::hotp::HOTP;
pub use crate::otp::totp::TOTP;

pub use crate::otp::hotp::generate_hotp;
pub use crate::otp::hotp::hotp_provisioning_uri;
pub use crate::otp::hotp::verify_hotp;

pub use crate::otp::totp::generate_totp_at;
pub use crate::otp::totp::generate_totp_now;
pub use crate::otp::totp::totp_provisioning_uri;
pub use crate::otp::totp::verify_totp;

pub use crate::ffi::c_binds::c_generate_hotp;
pub use crate::ffi::c_binds::c_hotp_provisioning_uri;
pub use crate::ffi::c_binds::c_verify_hotp;

pub use crate::ffi::c_binds::c_generate_totp_at;
pub use crate::ffi::c_binds::c_generate_totp_now;
pub use crate::ffi::c_binds::c_totp_provisioning_uri;
pub use crate::ffi::c_binds::c_verify_totp;
