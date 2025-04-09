use crate::{Algorithm, AlgorithmTrait};
use hmac::Mac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::any::Any;

#[test]
fn to_string_should_properly_convert_algorithm_to_string() {
    assert_eq!(Algorithm::SHA1.to_string(), "SHA1");
    assert_eq!(Algorithm::SHA1.to_string().type_id(), String::from("SHA1").type_id());
    assert_eq!(Algorithm::SHA256.to_string(), "SHA256");
    assert_eq!(Algorithm::SHA256.to_string().type_id(), String::from("SHA256").type_id());
    assert_eq!(Algorithm::SHA512.to_string(), "SHA512");
    assert_eq!(Algorithm::SHA512.to_string().type_id(), String::from("SHA512").type_id());
}

#[test]
fn from_string_should_properly_convert_algorithm_from_string() {
    assert_eq!(Algorithm::from_string("SHA1".to_string()), Algorithm::SHA1);
    assert_eq!(Algorithm::from_string("SHA256".to_string()), Algorithm::SHA256);
    assert_eq!(Algorithm::from_string("SHA512".to_string()), Algorithm::SHA512);
}

#[test]
#[should_panic(expected = "Unsupported algorithm")]
fn from_string_should_panic_with_invalid_algorithm_name() {
    Algorithm::from_string("INVALID".to_string());
}

#[test]
fn hash_should_be_generated_using_sha1() {
    let secret = b"mysecret".to_vec();
    let data = 12345u64;
    let result = Algorithm::SHA1.hash(secret.clone(), data).unwrap();
    let mut mac = hmac::Hmac::<Sha1>::new_from_slice(&secret).unwrap();
    mac.update(&data.to_be_bytes());
    assert_eq!(result, mac.finalize().into_bytes().to_vec());
}

#[test]
fn hash_should_be_generated_using_sha256() {
    let secret = b"mysecret".to_vec();
    let data = 12345u64;
    let result = Algorithm::SHA256.hash(secret.clone(), data).unwrap();
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(&secret).unwrap();
    mac.update(&data.to_be_bytes());
    assert_eq!(result, mac.finalize().into_bytes().to_vec());
}

#[test]
fn hash_should_be_generated_using_sha512() {
    let secret = b"mysecret".to_vec();
    let data = 12345u64;
    let result = Algorithm::SHA512.hash(secret.clone(), data).unwrap();
    let mut mac = hmac::Hmac::<Sha512>::new_from_slice(&secret).unwrap();
    mac.update(&data.to_be_bytes());
    assert_eq!(result, mac.finalize().into_bytes().to_vec());
}
