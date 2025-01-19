mod ffi;
mod messages;
mod otp;

pub use crate::otp::algorithm::Algorithm;
pub use crate::otp::algorithm::AlgorithmTrait;

pub use crate::otp::hotp::HOTP;
pub use crate::otp::totp::TOTP;

pub use crate::ffi::hotp_c_binds::generate_hotp;
pub use crate::ffi::hotp_c_binds::hotp_provisioning_uri;
pub use crate::ffi::hotp_c_binds::verify_hotp;

pub use crate::ffi::totp_c_binds::c_generate_totp_at;
pub use crate::ffi::totp_c_binds::c_generate_totp_now;
pub use crate::ffi::totp_c_binds::c_totp_provisioning_uri;
pub use crate::ffi::totp_c_binds::c_verify_totp;
