use std::env;
use std::env::consts::{DLL_PREFIX, DLL_SUFFIX};
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let package = env!("CARGO_PKG_NAME");

    // Emit rerun hint if lib.rs changes (optional, but improves build efficiency)
    println!("cargo:rerun-if-changed=src/lib.rs");

    // Generate C++ header using cbindgen
    let header_path = PathBuf::from("contrib").join("rusotp.hpp");
    fs::create_dir_all("contrib").expect("Failed to create contrib directory");

    cbindgen::Builder::new()
        .with_crate(manifest_dir)
        .with_language(cbindgen::Language::Cxx)
        .generate()
        .unwrap_or_else(|e| panic!("Failed to generate bindings: {}", e))
        .write_to_file(&header_path);

    // Construct normalized shared object directory path
    let mut shared_object_dir = PathBuf::from(manifest_dir);
    shared_object_dir.push("target");
    shared_object_dir.push(env::var("PROFILE").unwrap());
    let shared_object_dir = shared_object_dir.as_path().to_string_lossy();

    // Detect and print target_os
    if cfg!(target_os = "linux") {
        println!("cargo:warning=Detected target_os: linux");
        println!(
            "cargo:rustc-env=INLINE_C_RS_CFLAGS=-std=c++11 -I{I} -L{L} -D_DEBUG",
            I = manifest_dir,
            L = shared_object_dir,
        );
    } else if cfg!(target_os = "macos") {
        println!("cargo:warning=Detected target_os: macos");
        println!(
            "cargo:rustc-env=INLINE_C_RS_CFLAGS=-std=c++11 -I{I} -L{L} -D_DEBUG",
            I = manifest_dir,
            L = shared_object_dir,
        );
    } else if cfg!(target_os = "windows") {
        println!("cargo:warning=Detected target_os: windows");
        println!(
            "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG -D_CRT_SECURE_NO_WARNINGS",
            I = manifest_dir,
            L = shared_object_dir,
        );
    } else {
        println!("cargo:warning=Unsupported target_os");
    }

    // Emit linker flags for INLINE_C_RS
    let lib_name = format!("{}{}{}", DLL_PREFIX, package, DLL_SUFFIX);
    println!("cargo:rustc-env=INLINE_C_RS_LDFLAGS={}/{}", shared_object_dir, lib_name);

    // Optional debug info
    println!("cargo:warning=Generated C++ header at {:?}", header_path);
    println!("cargo:warning=Shared object dir: {}", shared_object_dir);
    println!("cargo:warning=Library name: {}", lib_name);
}
