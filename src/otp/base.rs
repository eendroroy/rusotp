use crate::otp::algorithm::{Algorithm, AlgorithmTrait};
use crate::{OtpGenericError, OtpResult};
use num_bigint::BigUint;
use std::ops::Rem;

pub(crate) fn otp(algorithm: &Algorithm, secret: Vec<u8>, length: u8, radix: u8, counter: u64) -> OtpResult<String> {
    match otp_bin_code(algorithm, secret, counter) {
        Ok(otp_bin_code) => {
            let value = BigUint::to_str_radix(
                &BigUint::from(otp_bin_code).rem(BigUint::from(radix as u64).pow(length as u32)),
                radix as u32,
            );
            Ok(format!("{:0>width$}", value, width = length as usize).to_uppercase())
        }
        Err(e) => Err(Box::new(OtpGenericError(e.to_string()))),
    }
}

fn otp_bin_code(algorithm: &Algorithm, secret: Vec<u8>, counter: u64) -> Result<u64, String> {
    match algorithm.hash(secret, counter) {
        Ok(hmac_result) => {
            let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

            Ok(((hmac_result[offset] as u64 & 0x7f) << 24)
                | ((hmac_result[offset + 1] as u64 & 0xff) << 16)
                | ((hmac_result[offset + 2] as u64 & 0xff) << 8)
                | (hmac_result[offset + 3] as u64 & 0xff))
        }
        Err(e) => Err(e),
    }
}
