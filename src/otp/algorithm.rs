use crate::messages::UNSUPPORTED_ALGORITHM;

use hmac::Mac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub trait AlgorithmTrait {
    fn to_string(&self) -> String;
    fn from_string(s: String) -> Self;
    fn hash(&self, secret: Vec<u8>, data: u64) -> Result<Vec<u8>, String>;
}

#[derive(Copy, Clone)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }

    fn ne(&self, other: &Self) -> bool {
        self.to_string() != other.to_string()
    }
}

impl AlgorithmTrait for Algorithm {
    fn to_string(&self) -> String {
        match self {
            Algorithm::SHA1 => "SHA1".to_string(),
            Algorithm::SHA256 => "SHA256".to_string(),
            Algorithm::SHA512 => "SHA512".to_string(),
        }
    }

    fn from_string(s: String) -> Self {
        match s.as_str() {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => panic!("{}", UNSUPPORTED_ALGORITHM),
        }
    }

    fn hash(&self, secret: Vec<u8>, data: u64) -> Result<Vec<u8>, String> {
        match self {
            Algorithm::SHA1 => match hmac::Hmac::<Sha1>::new_from_slice(secret.as_ref()) {
                Ok(mut mac) => {
                    mac.update(&data.to_be_bytes());
                    Ok(mac.finalize().into_bytes().to_vec())
                }
                Err(e) => Err(e.to_string()),
            },
            Algorithm::SHA256 => match hmac::Hmac::<Sha256>::new_from_slice(secret.as_ref()) {
                Ok(mut mac) => {
                    mac.update(&data.to_be_bytes());
                    Ok(mac.finalize().into_bytes().to_vec())
                }
                Err(e) => Err(e.to_string()),
            },
            Algorithm::SHA512 => match hmac::Hmac::<Sha512>::new_from_slice(secret.as_ref()) {
                Ok(mut mac) => {
                    mac.update(&data.to_be_bytes());
                    Ok(mac.finalize().into_bytes().to_vec())
                }
                Err(e) => Err(e.to_string()),
            },
        }
    }
}
