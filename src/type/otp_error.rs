use crate::{Algorithm, AlgorithmTrait};
use std::fmt::{Debug, Display};

pub trait OtpError: Display + Debug {}

pub type OtpResult<T> = Result<T, Box<dyn OtpError>>;

#[derive(Debug, Clone, PartialEq)]
pub struct OtpGenericError(pub String);

impl OtpError for OtpGenericError {}

impl Display for OtpGenericError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DriftBehindError(pub u64, pub u64);

impl OtpError for DriftBehindError {}

impl Display for DriftBehindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be less than `at` ({})", self.0, self.1)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AfterError(pub u64, pub u64);

impl OtpError for AfterError {}

impl Display for AfterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be less than or equal to `at` ({})", self.0, self.1)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedLengthError(pub u8);

impl OtpError for UnsupportedLengthError {}

impl Display for UnsupportedLengthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be 6", self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedIntervalError(pub u8);

impl OtpError for UnsupportedIntervalError {}

impl Display for UnsupportedIntervalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be greater than or equal to 30", self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedRadixError(pub u8);

impl OtpError for UnsupportedRadixError {}

impl Display for UnsupportedRadixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be 10", self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnsupportedAlgorithmError(pub Algorithm);

impl OtpError for UnsupportedAlgorithmError {}

impl Display for UnsupportedAlgorithmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be {}", self.0.to_string(), Algorithm::SHA1.to_string())
    }
}
