use std::collections::HashSet;
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

    // SRC #includes other files under bpf/, so watching just SRC misses
    // edits to those.
    println!("cargo:rerun-if-changed=bpf");
    println!("cargo:rerun-if-changed={CONSTS}");
}

fn verify_consts_match_skeleton(skel_path: &Path) {
    let skel_src = fs::read_to_string(skel_path)
        .unwrap_or_else(|err| panic!("failed to read generated skeleton {}: {err}", skel_path.display()));
    let consts_src =
        fs::read_to_string(CONSTS).unwrap_or_else(|err| panic!("failed to read {CONSTS}: {err}"));

    let actual: HashSet<String> = compiled_program_names(&skel_src);
    let declared: HashSet<String> = quoted_string_literals(&consts_src).into_iter().collect();

    let mut missing: Vec<&String> = actual.difference(&declared).collect();
    missing.sort();
    let mut stale: Vec<&String> = declared.difference(&actual).collect();
    stale.sort();

    if missing.is_empty() && stale.is_empty() {
        return;
    }

    let mut message = format!("{CONSTS} is out of sync with the compiled BPF object ({}):\n", skel_path.display());
    if !missing.is_empty() {
        message += &format!(
            "  compiled but not declared in {CONSTS} (add to the right AttachType, or Ignore):\n    {}\n",
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n    ")
        );
    }
    if !stale.is_empty() {
        message += &format!(
            "  declared in {CONSTS} but not compiled (stale name):\n    {}\n",
            stale.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n    ")
        );
    }
    panic!("{message}");
}

// one .prog("name") call per compiled program in the generated builder chain
fn compiled_program_names(skel_src: &str) -> HashSet<String> {
    const PATTERN: &str = ".prog(\"";
    let mut names = HashSet::new();
    let mut rest = skel_src;
    while let Some(start) = rest.find(PATTERN) {
        rest = &rest[start + PATTERN.len()..];
        let Some(end) = rest.find('"') else { break };
        names.insert(rest[..end].to_string());
        rest = &rest[end..];
    }
    names
}

// skips comment lines so a doc comment mentioning e.g. SEC("xdp") as prose
// doesn't get picked up as a claimed program name
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
