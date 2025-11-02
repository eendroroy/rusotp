// Copyright (c) Indrajit Roy
//
// This file is licensed under the Affero General Public License version 3 or
// any later version.
//
// See the file LICENSE for details.

use rusotp::{Secret, SecretError};

#[test]
fn should_create_secret() {
    assert!(Secret::from_str("123").is_ok());
    assert_eq!(Secret::from_str("123").unwrap().get(), "123".as_bytes());
}

#[test]
fn should_fail_to_create_secret() {
    assert!(Secret::from_str("").is_err());
    assert_eq!(Secret::from_str("").err().unwrap().to_string(), SecretError.to_string());
}
