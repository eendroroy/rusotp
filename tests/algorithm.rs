use rusotp::Algorithm;
use rusotp::AlgorithmTrait;

#[test]
fn algorithms_should_be_get_converted_to_string() {
    assert_eq!(Algorithm::SHA1.to_string(), "SHA1");
    assert_eq!(Algorithm::SHA256.to_string(), "SHA256");
    assert_eq!(Algorithm::SHA512.to_string(), "SHA512");
}

#[test]
fn algorithms_should_be_get_converted_from_string() {
    assert_eq!(Algorithm::from_string("SHA1".to_string()), Algorithm::SHA1);
    assert_eq!(Algorithm::from_string("SHA256".to_string()), Algorithm::SHA256);
    assert_eq!(Algorithm::from_string("SHA512".to_string()), Algorithm::SHA512);
}

#[test]
#[should_panic="Unsupported algorithm"]
fn algorithms_should_should_panic_with_unsupported_name() {
    Algorithm::from_string("SHA110".to_string());
}

#[test]
fn sha1_should_should_generate_hash() {
    let result = Algorithm::SHA1.hash(vec![0; 20], 0);
    assert_eq!(result.is_ok(), true);
    assert_ne!(result.unwrap().len(), 0, "SHA1 hash should not be empty");
}

#[test]
fn sha256_should_should_generate_hash() {
    let result = Algorithm::SHA256.hash(vec![0; 20], 0);
    assert_eq!(result.is_ok(), true);
    assert_ne!(result.unwrap().len(), 0, "SHA256 hash should not be empty");
}

#[test]
fn sha512_should_should_generate_hash() {
    let result = Algorithm::SHA512.hash(vec![0; 20], 0);
    assert_eq!(result.is_ok(), true);
    assert_ne!(result.unwrap().len(), 0, "SHA512 hash should not be empty");
}