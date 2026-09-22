use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "bpf/kukri.bpf.c";
const CONSTS: &str = "src/consts.rs";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("kukri.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I", "bpf"])
        .build_and_generate(&out)
        .expect("bpf compilation failed");

    verify_consts_match_skeleton(&out);

    // `SRC` #includes other files under `bpf/` (per-direction hooks, shared
    // headers), so watching just `SRC` misses edits to those — Cargo would
    // silently keep using a stale skeleton. Watch the whole directory
    // instead: any file added or changed under `bpf/` triggers a rebuild.
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-changed={CONSTS}");
}

/// `src/consts.rs` names BPF programs that Rust code looks up by name
/// (`INGRESS_PROGRAM`, `ENGRESS_PROGRAM`, ...) instead of through generic
/// discovery. If one of those names stops matching anything actually
/// compiled into the object — a `.bpf.c` rename, a typo, a deleted
/// function — that lookup fails silently at runtime ("no BPF program named
/// X loaded") instead of at build time. Catch it here instead: read the
/// generated skeleton as text and confirm every name in `consts.rs` shows
/// up in it.
fn verify_consts_match_skeleton(skel_path: &Path) {
    let skel_src = fs::read_to_string(skel_path)
        .unwrap_or_else(|err| panic!("failed to read generated skeleton {}: {err}", skel_path.display()));
    let consts_src =
        fs::read_to_string(CONSTS).unwrap_or_else(|err| panic!("failed to read {CONSTS}: {err}"));

    let mut missing = Vec::new();
    for (const_name, prog_name) in program_name_consts(&consts_src) {
        let needle = format!("\"{prog_name}\"");
        if !skel_src.contains(&needle) {
            missing.push(format!("{CONSTS}::{const_name} = \"{prog_name}\""));
        }
    }

    if !missing.is_empty() {
        panic!(
            "{CONSTS} is out of sync with the compiled BPF object ({}): the following \
             constant(s) don't match any program actually in it:\n  {}\n\
             Either a bpf/*.bpf.c SEC(...) function was renamed/removed, or {CONSTS} is stale \
             — fix whichever one is wrong.",
            skel_path.display(),
            missing.join("\n  ")
        );
    }
}

/// Crude but sufficient for this file's shape: pulls `(CONST_NAME, "value")`
/// out of every `pub const CONST_NAME: &str = "value";` line.
fn program_name_consts(src: &str) -> Vec<(String, String)> {
    src.lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("pub const ")?;
            let (const_name, rest) = rest.split_once(':')?;
            if !rest.contains("&str") {
                return None;
            }
            let quote_start = rest.find('"')? + 1;
            let quote_rest = &rest[quote_start..];
            let quote_end = quote_rest.find('"')?;
            Some((const_name.trim().to_string(), quote_rest[..quote_end].to_string()))
        })
        .collect()
}
