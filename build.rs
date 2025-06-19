use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Step 1, let's generate the `rusotp.hpp` file automatically.
    cbindgen::Builder::new()
        .with_crate(&manifest_dir)
        .with_language(cbindgen::Language::Cxx)
        .generate()
        .unwrap()
        .write_to_file("contrib/rusotp.hpp");

    // Step 2, let's set the `CFLAGS` and the `LDFLAGS` variables.
    let include_dir = manifest_dir.clone();
    let mut shared_object_dir = PathBuf::from(manifest_dir);
    shared_object_dir.push("target");
    shared_object_dir.push(env::var("PROFILE").unwrap());
    let shared_object_dir = shared_object_dir.as_path().to_string_lossy();

    println!(
        "cargo:rustc-env=INLINE_C_RS_CFLAGS=-I{I} -L{L} -D_DEBUG -D_CRT_SECURE_NO_WARNINGS",
        I = include_dir,
        L = shared_object_dir,
    );

    let lib_name = if cfg!(target_os = "macos") {
        "librusotp.dylib"
    } else if cfg!(target_os = "linux") {
        "librusotp.so"
    } else if cfg!(target_os = "windows") {
        "rusotp.dll"
    } else {
        panic!("Unsupported platform");
    };

    println!(
        "cargo:rustc-env=INLINE_C_RS_LDFLAGS={shared_object_dir}/{libname}",
        shared_object_dir = shared_object_dir,
        libname = lib_name,
    );
}
