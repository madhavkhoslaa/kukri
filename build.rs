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
/// (`PROGRAM_NAMES`, a `Direction -> program name` map) instead of through
/// generic discovery. If one of those names stops matching anything
/// actually compiled into the object — a `.bpf.c` rename, a typo, a
/// deleted function — that lookup fails silently at runtime ("no BPF
/// program named X loaded") instead of at build time. Catch it here
/// instead: read the generated skeleton as text and confirm every quoted
/// program name in `consts.rs` shows up in it.
fn verify_consts_match_skeleton(skel_path: &Path) {
    let skel_src = fs::read_to_string(skel_path)
        .unwrap_or_else(|err| panic!("failed to read generated skeleton {}: {err}", skel_path.display()));
    let consts_src =
        fs::read_to_string(CONSTS).unwrap_or_else(|err| panic!("failed to read {CONSTS}: {err}"));

    let mut missing = Vec::new();
    for prog_name in quoted_string_literals(&consts_src) {
        let needle = format!("\"{prog_name}\"");
        if !skel_src.contains(&needle) {
            missing.push(prog_name);
        }
    }

    if !missing.is_empty() {
        panic!(
            "{CONSTS} is out of sync with the compiled BPF object ({}): the following program \
             name(s) don't match anything actually in it:\n  {}\n\
             Either a bpf/*.bpf.c SEC(...) function was renamed/removed, or {CONSTS} is stale \
             — fix whichever one is wrong.",
            skel_path.display(),
            missing.join("\n  ")
        );
    }
}

/// Every string literal appearing on a non-comment line of `src`. Skips
/// `//`/`///`/`//!` lines so doc comments that happen to mention a quoted
/// example (e.g. `` `SEC("xdp")` ``) don't get treated as claimed program
/// names — only literals that appear in actual code (map keys, values,
/// whatever shape `consts.rs` takes) count.
fn quoted_string_literals(src: &str) -> Vec<String> {
    let mut literals = Vec::new();
    for line in src.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut in_string = false;
        let mut current = String::new();
        for ch in line.chars() {
            if ch == '"' {
                if in_string {
                    literals.push(std::mem::take(&mut current));
                }
                in_string = !in_string;
            } else if in_string {
                current.push(ch);
            }
        }
    }
    literals
}
