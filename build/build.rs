use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "bpf/kukri.bpf.c";
const BPF_DIR: &str = "bpf";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("kukri.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I", "bpf", "-I", "bpf/common", "-I", "bpf/maps"])
        .build_and_generate(&out)
        .expect("bpf compilation failed");

    verify_programs_match_skeleton(&out);

    // SRC #includes other files under bpf/, so watching just SRC misses
    // edits to those. We watch the whole directory instead.
    println!("cargo:rerun-if-changed=bpf");
}

fn verify_programs_match_skeleton(skel_path: &Path) {
    let skel_src = fs::read_to_string(skel_path).unwrap_or_else(|err| {
        panic!(
            "failed to read generated skeleton {}: {err}",
            skel_path.display()
        )
    });

    let actual: HashSet<String> = compiled_program_names(&skel_src);
    let declared = declared_program_names();

    let mut missing: Vec<&String> = actual.difference(&declared).collect();
    missing.sort();
    let mut stale: Vec<&String> = declared.difference(&actual).collect();
    stale.sort();

    if missing.is_empty() && stale.is_empty() {
        return;
    }

    let mut message = format!(
        "{BPF_DIR}/*.bpf.c is out of sync with the compiled BPF object ({}):\n",
        skel_path.display()
    );
    if !missing.is_empty() {
        message += &format!(
            "  compiled but not declared in {BPF_DIR}/*.bpf.c:\n    {}\n",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n    ")
        );
    }
    if !stale.is_empty() {
        message += &format!(
            "  declared in {BPF_DIR}/*.bpf.c but not compiled (stale name):\n    {}\n",
            stale
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n    ")
        );
    }
    panic!("{message}");
}

// Each compiled program is one .prog("name") call in the generated builder chain
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

// A SEC declaration only counts if a C function immediatley follows it.
fn declared_program_names() -> HashSet<String> {
    let mut names = HashSet::new();
    collect_declared_program_names(Path::new(BPF_DIR), &mut names);
    names
}

fn collect_declared_program_names(dir: &Path, names: &mut HashSet<String>) {
    for entry in fs::read_dir(dir).expect("failed to read bpf sources") {
        let path = entry.expect("failed to read bpf source entry").path();
        if path.is_dir() {
            collect_declared_program_names(&path, names);
            continue;
        }
        if !path.to_string_lossy().ends_with(".bpf.c") {
            continue;
        }
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let mut lines = src.lines();
        while let Some(line) = lines.next() {
            let Some(section) = line.trim_start().strip_prefix("SEC(\"") else {
                continue;
            };
            let Some((section, after)) = section.split_once("\")") else {
                continue;
            };
            if section != "xdp" && section != "tc" && !section.starts_with("tracepoint/") {
                continue;
            }
            let signature = if after.trim().is_empty() {
                lines.next().unwrap_or("")
            } else {
                after
            };
            if let Some(rest) = signature.trim_start().strip_prefix("int ") {
                let name = rest.trim_start().split('(').next().unwrap_or("").trim();
                if !name.is_empty()
                    && rest.contains('(')
                    && name
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                {
                    names.insert(name.to_string());
                }
            }
        }
    }
}
