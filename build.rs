use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "bpf/kukri.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("kukri.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I", "bpf"])
        .build_and_generate(&out)
        .expect("bpf compilation failed");

    println!("cargo:rerun-if-changed={SRC}");
    println!("cargo:rerun-if-changed=bpf/vmlinux.h");
}
