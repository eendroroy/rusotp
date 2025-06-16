use rusotp::{Radix, RadixError};

#[test]
fn should_create_radix() {
    (2..=36).for_each(|value| {
        assert_eq!(Radix::new(value).is_ok(), true);
        assert_eq!(Radix::new(value).unwrap().get(), value);
    })
}

#[test]
fn should_fail_to_create_radix() {
    vec![1, 37, 100].iter().for_each(|value| {
        assert_eq!(Radix::new(*value).is_ok(), false);
        assert_eq!(Radix::new(*value).err().unwrap(), RadixError(*value));
    })
}
