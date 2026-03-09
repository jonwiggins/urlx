//! Build script for liburlx-ffi.
//!
//! Regenerates the C header file using cbindgen when the source changes.

fn main() {
    // Only regenerate when lib.rs changes
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Try to run cbindgen if available
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    if let Ok(bindings) = cbindgen::generate(&crate_dir) {
        let out_path = std::path::Path::new(&crate_dir).join("include").join("urlx.h");
        let _ = bindings.write_to_file(out_path);
    }
}
