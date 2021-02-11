use std::env;
use std::path::PathBuf;
extern crate protobuf_codegen_pure;

fn main() {
    protobuf_codegen_pure::Codegen::new()
        .out_dir("src")
        .input("src/struct.proto")
        .include("src")
        .run()
        .expect("protoc");

    if cfg!(target_os = "linux") {
        let src_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

        println!(
            "cargo:rustc-link-search=native={}",
            src_dir.join("..").join("libprobe").to_str().unwrap()
        );
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-search=native=/lib");
        println!("cargo:rustc-link-lib=static=probe");
        println!("cargo:rustc-link-lib=static=bpf");
        println!("cargo:rustc-link-lib=static=elf");
        println!("cargo:rustc-link-lib=static=z");
    }
}
