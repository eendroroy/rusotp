use std::env;
use std::path::PathBuf;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let include_dir = env!("CARGO_MANIFEST_DIR");
    let package = env!("CARGO_PKG_NAME");
    let lib_name = match target_os.as_str() {
        "linux" => format!("lib{}.so", package),
        "macos" => format!("lib{}.dylib", package),
        "windows" => format!("{}.dll", package),
        _ => panic!("Unknown target: {}", target_os.as_str()),
    };
    let header_path = PathBuf::from("contrib").join("rusotp.hpp");

    // Generate C++ header
    cbindgen::Builder::new()
        .with_crate(include_dir)
        .with_language(cbindgen::Language::Cxx)
        .generate()
        .unwrap_or_else(|e| panic!("Failed to generate bindings: {}", e))
        .write_to_file(header_path.clone());

    // Construct shared object path
    let mut shared_object_dir = PathBuf::from(include_dir);
    shared_object_dir.push("target");
    shared_object_dir.push(env::var("PROFILE").unwrap());
    let shared_object_dir = shared_object_dir.as_path().to_string_lossy();

    // * `-I`, add `include_dir` to include search path,
    // * `-L`, add `shared_object_dir` to library search path,
    // * `-D_DEBUG`, enable debug mode to enable `assert.h`.
    println!("cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{} -L{} -D_DEBUG", include_dir, shared_object_dir);

    // Here, we pass the full path to the shared object with
    // `LDFLAGS`.
    println!("cargo:rustc-env=INLINE_C_RS_LDFLAGS={}/{}", shared_object_dir, lib_name);

    // Optional debug info
    println!("cargo:warning=Generated C++ header at {:?}", header_path);
    println!("cargo:warning=Shared object dir: {}", shared_object_dir);
    println!("cargo:warning=Library name: {}", lib_name);
    println!("cargo:warning=Target OS: {}", target_os.as_str());
}
