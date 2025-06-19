use std::env;
use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};
use std::path::PathBuf;

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let package = env!("CARGO_PKG_NAME");

    // Generate C++ header
    cbindgen::Builder::new()
        .with_crate(manifest_dir)
        .with_language(cbindgen::Language::Cxx)
        .generate()
        .unwrap_or_else(|e| panic!("Failed to generate bindings: {}", e))
        .write_to_file("contrib/rusotp.hpp");

    // Construct shared object path
    let mut shared_object_dir = PathBuf::from(manifest_dir);
    shared_object_dir.push("target");
    shared_object_dir.push(env::var("PROFILE").unwrap());
    let shared_object_dir = shared_object_dir.as_path().to_string_lossy().replace('\\', "/"); // Prevent backslash issues on Windows

    // Emit INLINE_C_RS_CFLAGS based on platform
    #[cfg(target_os = "linux")]
    println!(
        "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG -D_GNU_SOURCE",
        I = manifest_dir,
        L = shared_object_dir,
    );

    #[cfg(target_os = "macos")]
    println!(
        "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG -D_DARWIN",
        I = manifest_dir,
        L = shared_object_dir,
    );

    #[cfg(target_os = "windows")]
    println!(
        "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG -D_CRT_SECURE_NO_WARNINGS -DWIN32",
        I = manifest_dir,
        L = shared_object_dir,
    );

    // Linker flags
    let lib_name = format!("{}{}{}", DLL_PREFIX, package, DLL_SUFFIX);
    println!("cargo:rustc-env=INLINE_C_RS_LDFLAGS={}/{}", shared_object_dir, lib_name);
}
