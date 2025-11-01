// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

/// Error for invalid radix values (must be 2..=36).
#[derive(Debug, Clone, PartialEq)]
pub struct RadixError(pub u8);

impl std::fmt::Display for RadixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} must be between 2 and 36", self.0)
    }
}

/// A specialized `Result` type for operations that may return a `RadixError`.
pub type RadixResult<T> = Result<T, RadixError>;

/// Numeric radix (base) between 2 and 36.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Radix(u8);

impl Default for Radix {
    fn default() -> Self {
        Self(10)
    }
}

impl Radix {
    /// Creates a new `Radix` if value is between 2 and 36 inclusive.
    pub fn new(radix: u8) -> RadixResult<Self> {
        match radix {
            2..=36 => Ok(Self(radix)),
            _ => Err(RadixError(radix)),
        }
    }

    /// Returns the radix value.
    pub fn get(self) -> u8 {
        self.0
    }
}
