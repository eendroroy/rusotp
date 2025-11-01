// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

//! Error types and result alias for OTP (One-Time Password) operations.

use crate::{Algorithm, AlgorithmTrait};
use std::fmt::{Debug, Display};

/// Trait for all OTP-related errors.
///
/// Implementors must also implement `Display` and `Debug`.
pub trait OtpError: Display + Debug {}

/// Result type alias for OTP operations.
pub type OtpResult<T> = Result<T, Box<dyn OtpError>>;

/// Generic OTP error with a message.
#[derive(Debug, Clone, PartialEq)]
pub struct OtpGenericError(pub String);

impl OtpError for OtpGenericError {}

impl Display for OtpGenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error indicating that a value exceeds the allowed drift.
#[derive(Debug, Clone, PartialEq)]
pub struct DriftBehindError(pub u64, pub u64);

impl OtpError for DriftBehindError {}

impl Display for DriftBehindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be less than `at` ({})", self.0, self.1)
    }
}

/// Error indicating that a value exceeds allowed point.
#[derive(Debug, Clone, PartialEq)]
pub struct AfterError(pub u64, pub u64);

impl OtpError for AfterError {}

impl Display for AfterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be less than or equal to `at` ({})", self.0, self.1)
    }
}

/// Error for unsupported OTP code length.
#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedLengthError(pub u8);

impl OtpError for UnsupportedLengthError {}

impl Display for UnsupportedLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be 6", self.0)
    }
}

/// Error for unsupported OTP interval.
#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedIntervalError(pub u64);

impl OtpError for UnsupportedIntervalError {}

impl Display for UnsupportedIntervalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be greater than or equal to 30", self.0)
    }
}

/// Error for unsupported radix in OTP.
#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedRadixError(pub u8);

impl OtpError for UnsupportedRadixError {}

impl Display for UnsupportedRadixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be 10", self.0)
    }
}

/// Error for unsupported algorithm in OTP.
#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedAlgorithmError(pub Algorithm);

impl OtpError for UnsupportedAlgorithmError {}

impl Display for UnsupportedAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be {}", self.0.to_string(), Algorithm::SHA1.to_string())
    }
}
