use std::fs;
use std::path::PathBuf;

use clap::Parser;
use kukri::dto::config::ACLConfig;

mod bpf;
#[path = "../build/consts.rs"]
mod consts;
mod events;
mod nic;
mod settings;
mod stages;
mod tui;

#[derive(Parser)]
#[command(name = "kukri", about = "eBPF-backed firewall")]
struct Cli {
    /// Where the ACL config JSON file lives
    config: PathBuf,
    /// Run without the interative terminal UI, handy for integration tests
    #[arg(long)]
    headless: bool,
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

    let skel: &'static bpf::KukriSkel<'static> = Box::leak(Box::new(bpf::load()?));
    let programs = bpf::programs(skel);
    bpf::wire_protocol_routes(skel, &programs)?;
    let interfaces = config.interfaces.names.clone();

    if cli.headless {
        tui::run_headless(skel, programs, config, interfaces, cli.config)
    } else {
        tui::run(skel, programs, config, interfaces, cli.config)
    }
}
