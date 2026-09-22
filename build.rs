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

    // `SRC` #includes other files under `bpf/` (per-direction hooks, shared
    // headers), so watching just `SRC` misses edits to those — Cargo would
    // silently keep using a stale skeleton. Watch the whole directory
    // instead: any file added or changed under `bpf/` triggers a rebuild.
    println!("cargo:rerun-if-changed=bpf");
}
