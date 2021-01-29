use std::env;
use std::path::PathBuf;
use std::process::Command;
extern crate protobuf_codegen_pure;

fn main() {
    protobuf_codegen_pure::Args::new()
        .out_dir("src")
        .inputs(&["struct.proto"])
        .run()
        .expect("protoc");

    if cfg!(target_os = "linux") {
        let src_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("src");
        let status = Command::new("make")
            .current_dir(src_dir.clone())
            .status()
            .unwrap();

        assert!(status.success());

        println!(
            "cargo:rustc-link-search=native={}",
            src_dir.join(".output").to_str().unwrap()
        );
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-search=native=/lib");
        println!("cargo:rustc-link-lib=static=probe");
        println!("cargo:rustc-link-lib=static=bpf");
        println!("cargo:rustc-link-lib=static=elf");
        println!("cargo:rustc-link-lib=static=z");
    }
}
