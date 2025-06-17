use rusotp::{Radix, RadixError};

#[test]
fn should_create_default_radix() {
    assert_eq!(Radix::default().get(), 10);
}

#[test]
fn should_create_radix() {
    (2..=36).for_each(|value| {
        assert!(Radix::new(value).is_ok());
        assert_eq!(Radix::new(value).unwrap().get(), value);
    })
}

#[test]
fn should_fail_to_create_radix() {
    [1, 37, 100].iter().for_each(|value| {
        assert!(Radix::new(*value).is_err());
        assert_eq!(Radix::new(*value).err().unwrap().to_string(), RadixError(*value).to_string());
    })
}
