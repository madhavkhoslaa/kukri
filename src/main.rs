use std::fs;
use std::path::PathBuf;

use clap::Parser;
use kukri::dto::config::ACLConfig;

mod bpf;
#[path = "../build-support/consts.rs"]
mod consts;
mod settings;
mod tui;

#[derive(Parser)]
#[command(name = "kukri", about = "eBPF-backed firewall")]
struct Cli {
    /// Path to the ACL config JSON file
    config: PathBuf,
}

fn load_config(path: &PathBuf) -> anyhow::Result<ACLConfig> {
    let raw = fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read config file {}: {err}", path.display()))?;
    let config: ACLConfig = serde_json::from_str(&raw)
        .map_err(|err| anyhow::anyhow!("failed to parse config file {}: {err}", path.display()))?;
    Ok(config)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = load_config(&cli.config)?;
    config.validate()?;

    let skel = bpf::load()?;
    let programs = bpf::programs(&skel);
    let interfaces = config.interfaces.names.clone();

    tui::run(&skel, programs, config, interfaces)
}
