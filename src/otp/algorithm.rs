use crate::messages::{MAC_CREATE_ERROR, UNSUPPORTED_ALGORITHM};

use hmac::Mac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

pub trait AlgorithmTrait {
    fn to_str(&self) -> &str;
    fn from_str(s: &str) -> Self;
    fn hash(&self, secret: Vec<u8>, data: u64) -> Vec<u8>;
}

pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        self.to_str() == other.to_str()
    }

    fn ne(&self, other: &Self) -> bool {
        self.to_str() != other.to_str()
    }
}

impl AlgorithmTrait for Algorithm {
    fn to_str(&self) -> &str {
        match self {
            Algorithm::SHA1 => "SHA1",
            Algorithm::SHA256 => "SHA256",
            Algorithm::SHA512 => "SHA512",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => panic!("{}", UNSUPPORTED_ALGORITHM),
        }
    }

    fn hash(&self, secret: Vec<u8>, data: u64) -> Vec<u8> {
        match self {
            Algorithm::SHA1 => {
                let mut mac =
                    hmac::Hmac::<Sha1>::new_from_slice(secret.as_ref()).expect(MAC_CREATE_ERROR);
                mac.update(&data.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA256 => {
                let mut mac =
                    hmac::Hmac::<Sha256>::new_from_slice(secret.as_ref()).expect(MAC_CREATE_ERROR);
                mac.update(&data.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }
            Algorithm::SHA512 => {
                let mut mac =
                    hmac::Hmac::<Sha512>::new_from_slice(secret.as_ref()).expect(MAC_CREATE_ERROR);
                mac.update(&data.to_be_bytes());
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}
