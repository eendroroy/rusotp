use hmac::{Hmac, Mac};
use sha2::{Sha256};
use num_bigint::BigUint;

fn generate_otp(input: u64, secret: &[u8], length: usize, radix: u32) -> String {
    type HmacSha1 = Hmac<Sha256>;
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&input.to_be_bytes());
    let hmac_result = mac.finalize().into_bytes();

    let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

    let binary_code = ((hmac_result[offset] as u32 & 0x7f) << 24)
        | ((hmac_result[offset + 1] as u32 & 0xff) << 16)
        | ((hmac_result[offset + 2] as u32 & 0xff) << 8)
        | (hmac_result[offset + 3] as u32 & 0xff);

    let otp_value = binary_code % radix.pow(length as u32);

    let otp = format!("{:0>width$}", BigUint::to_str_radix(&BigUint::from(otp_value), radix), width = length);

    otp.to_uppercase()
}