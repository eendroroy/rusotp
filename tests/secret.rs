use rusotp::{Secret, SecretError};

#[test]
fn should_create_secret() {
    assert_eq!(Secret::new("123").is_ok(), true);
    assert_eq!(Secret::new("123").unwrap().get(), "123".as_bytes());
}

#[test]
fn should_fail_to_create_secret() {
    assert_eq!(Secret::new("").is_ok(), false);
    assert_eq!(Secret::new("").err().unwrap(), SecretError);
}
