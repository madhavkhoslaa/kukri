use std::mem::MaybeUninit;

use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;

// Generated at build time by `build.rs` via `libbpf_cargo::SkeletonBuilder`
// from bpf/kukri.bpf.c.
mod skel {
    include!(concat!(env!("OUT_DIR"), "/kukri.skel.rs"));
}

pub use skel::KukriSkel;
use skel::KukriSkelBuilder;

/// Opens, loads and attaches the BPF skeleton. Leaks the skeleton's backing
/// storage once so the returned handle is `'static` and can live in shared
/// state for the lifetime of the process.
pub fn load() -> anyhow::Result<KukriSkel<'static>> {
    let skel_builder = KukriSkelBuilder::default();
    let open_object: &'static mut MaybeUninit<_> = Box::leak(Box::new(MaybeUninit::uninit()));
    let open_skel = skel_builder.open(open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    Ok(skel)
}

pub fn exec_count(skel: &KukriSkel<'static>) -> u64 {
    let key = 0u32.to_ne_bytes();
    skel.maps
        .exec_count
        .lookup(&key, MapFlags::ANY)
        .ok()
        .flatten()
        .and_then(|bytes| bytes.get(0..8).map(|b| u64::from_ne_bytes(b.try_into().unwrap())))
        .unwrap_or(0)
}
