use crate::messages::MAC_CREATE_ERROR;

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;
use std::ops::Rem;

pub(crate) fn otp(secret: Vec<u8>, length: u8, radix: u8, counter: u64) -> String {
    format!(
        "{:0>width$}",
        BigUint::to_str_radix(
            &BigUint::from(otp_bin_code(secret, counter).rem((radix as u64).pow(length as u32))),
            radix as u32,
        ),
        width = length as usize
    )
    .to_uppercase()
}

fn otp_bin_code(secret: Vec<u8>, counter: u64) -> u64 {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_ref()).expect(MAC_CREATE_ERROR);
    mac.update(&counter.to_be_bytes());
    let hmac_result = mac.finalize().into_bytes();

    let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

    ((hmac_result[offset] as u64 & 0x7f) << 24)
        | ((hmac_result[offset + 1] as u64 & 0xff) << 16)
        | ((hmac_result[offset + 2] as u64 & 0xff) << 8)
        | (hmac_result[offset + 3] as u64 & 0xff)
}
