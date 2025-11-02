use qrcode::QrCode;
use image::Luma;

pub fn generate_qr_code_string(data: String) -> String {
    let code = QrCode::new(data.as_bytes());
    code.unwrap().to_debug_str('█', ' ')
}

pub fn generate_qr_code_image(data: String, path: String) {
    let code = QrCode::new(data.as_bytes()).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image.save(path).unwrap();
}
