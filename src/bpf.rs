use std::collections::HashMap;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use anyhow::bail;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::Link;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::ProgramMut;
use libbpf_rs::ProgramType;
use libbpf_rs::TcHook;
use libbpf_rs::TcHookBuilder;
use libbpf_rs::TC_EGRESS;

// Generated at build time by `build.rs` via `libbpf_cargo::SkeletonBuilder`
// from bpf/kukri.bpf.c.
mod skel {
    include!(concat!(env!("OUT_DIR"), "/kukri.skel.rs"));
}

pub use skel::KukriSkel;
use skel::KukriSkelBuilder;

/// Opens and loads the BPF skeleton, but does not attach anything. Leaks the
/// skeleton's backing storage once so the returned handle is `'static` and
/// can live in shared state for the lifetime of the process. Attaching is
/// left to the caller, program by program (see [`programs`]).
pub fn load() -> anyhow::Result<KukriSkel<'static>> {
    let skel_builder = KukriSkelBuilder::default();
    let open_object: &'static mut MaybeUninit<_> = Box::leak(Box::new(MaybeUninit::uninit()));
    let open_skel = skel_builder.open(open_object)?;
    let skel = open_skel.load()?;
    Ok(skel)
}

/// How a program needs to be attached. Driven by the program's real
/// `bpf_prog_type` (reported by the kernel/libbpf via [`ProgramMut::prog_type`]),
/// which is reliable metadata we get for free — no guessing required for the
/// common case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// Needs a network interface (ifindex) to attach to, via a BPF link.
    Xdp,
    /// Needs a network interface (ifindex) to attach to, via the classic
    /// qdisc-based TC hook (`SEC("tc")`/`SEC("classifier")`).
    Tc,
    /// Everything libbpf can auto-attach from the section name alone
    /// (tracepoints, kprobes, etc).
    Generic,
}

/// Fallback name -> kind table, consulted ONLY when `prog_type()` comes back
/// `Unknown` (i.e. libbpf itself couldn't tell us) and we have to guess from
/// the program's name instead. In the normal case this table is never
/// touched, since the kernel reports XDP and TC (`SchedCls`) programs
/// reliably.
fn fallback_overrides() -> HashMap<&'static str, &'static [&'static str]> {
    HashMap::from([
        ("xdp", ["ingress_hook"].as_slice()),
        ("tc", ["engress_hook"].as_slice()),
        ("syscall", ["handle_execve"].as_slice()),
    ])
}

fn attach_kind(prog: &ProgramMut) -> AttachKind {
    match prog.prog_type() {
        ProgramType::Xdp => AttachKind::Xdp,
        ProgramType::SchedCls | ProgramType::SchedAct => AttachKind::Tc,
        ProgramType::Unknown => {
            let name = prog.name().to_string_lossy().into_owned();
            let overrides = fallback_overrides();
            if overrides.get("xdp").is_some_and(|names| names.contains(&name.as_str())) {
                AttachKind::Xdp
            } else if overrides.get("tc").is_some_and(|names| names.contains(&name.as_str())) {
                AttachKind::Tc
            } else {
                AttachKind::Generic
            }
        }
        _ => AttachKind::Generic,
    }
}

fn resolve_ifindex(name: &str) -> anyhow::Result<u32> {
    let c_name =
        CString::new(name).map_err(|_| anyhow::anyhow!("interface name \"{name}\" contains a NUL byte"))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        bail!("no such network interface: \"{name}\"");
    }
    Ok(index)
}

/// A single BPF program from the loaded skeleton, with the ability to
/// attach/detach it independently of the others.
pub struct BpfProgram<'obj> {
    pub name: String,
    pub fd: RawFd,
    pub kind: AttachKind,
    prog: ProgramMut<'obj>,
    links: Vec<Link>,
    /// `Tc` only: unlike `Link`, a `TcHook` isn't detached on drop, so we
    /// have to track it and call `detach()` ourselves.
    tc_hooks: Vec<TcHook>,
    /// For `Xdp`/`Tc` programs: which configured interfaces this program is
    /// currently attached to. Always empty for `Generic` programs.
    pub attached_interfaces: Vec<String>,
}

impl<'obj> BpfProgram<'obj> {
    pub fn is_running(&self) -> bool {
        !self.links.is_empty() || !self.tc_hooks.is_empty()
    }

    /// Attaches the program. `Generic` programs auto-attach once; `Xdp`/`Tc`
    /// programs attach to every interface in `interfaces` that isn't already
    /// attached. Already-attached interfaces are skipped (idempotent), and
    /// per-interface failures are collected rather than aborting the whole
    /// call, so a bad interface name doesn't prevent attaching to the good
    /// ones.
    pub fn enable(&mut self, interfaces: &[String]) -> anyhow::Result<()> {
        match self.kind {
            AttachKind::Generic => {
                if self.links.is_empty() {
                    self.links.push(self.prog.attach()?);
                }
                Ok(())
            }
            AttachKind::Xdp => {
                if interfaces.is_empty() {
                    bail!("no interfaces configured for XDP program \"{}\"", self.name);
                }

                let mut errors = Vec::new();
                for name in interfaces {
                    if self.attached_interfaces.contains(name) {
                        continue;
                    }
                    let attached = resolve_ifindex(name)
                        .and_then(|ifindex| self.prog.attach_xdp(ifindex as i32).map_err(anyhow::Error::from));
                    match attached {
                        Ok(link) => {
                            self.links.push(link);
                            self.attached_interfaces.push(name.clone());
                        }
                        Err(err) => errors.push(format!("{name}: {err}")),
                    }
                }

                if errors.is_empty() {
                    Ok(())
                } else {
                    bail!("failed on interface(s): {}", errors.join(", "))
                }
            }
            AttachKind::Tc => {
                if interfaces.is_empty() {
                    bail!("no interfaces configured for TC program \"{}\"", self.name);
                }

                let mut errors = Vec::new();
                for name in interfaces {
                    if self.attached_interfaces.contains(name) {
                        continue;
                    }
                    let attached = resolve_ifindex(name).and_then(|ifindex| {
                        // `replace(true)` makes this idempotent against a
                        // filter left over from a previous run that exited
                        // without detaching (TC hooks outlive the process
                        // that attached them).
                        let mut hook = TcHookBuilder::new(self.prog.as_fd())
                            .ifindex(ifindex as i32)
                            .replace(true)
                            .hook(TC_EGRESS);
                        hook.create().map_err(anyhow::Error::from)?;
                        hook.attach().map_err(anyhow::Error::from)
                    });
                    match attached {
                        Ok(hook) => {
                            self.tc_hooks.push(hook);
                            self.attached_interfaces.push(name.clone());
                        }
                        Err(err) => errors.push(format!("{name}: {err}")),
                    }
                }

                if errors.is_empty() {
                    Ok(())
                } else {
                    bail!("failed on interface(s): {}", errors.join(", "))
                }
            }
        }
    }

    /// Detaches from everything. Dropping the `Link`s handles XDP/Generic;
    /// TC hooks need an explicit `detach()` call first, since dropping a
    /// `TcHook` does not detach it.
    pub fn disable(&mut self) -> anyhow::Result<()> {
        self.links.clear();

        let mut errors = Vec::new();
        for hook in &mut self.tc_hooks {
            if let Err(err) = hook.detach() {
                errors.push(err.to_string());
            }
        }
        self.tc_hooks.clear();
        self.attached_interfaces.clear();

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("failed to detach TC hook(s): {}", errors.join(", "))
        }
    }
}

/// Lists every BPF program present in the loaded skeleton — i.e. exactly
/// what's compiled into `kukri.skel.rs` from `bpf/kukri.bpf.c` and its
/// includes — with none of them attached yet. Adding a new `SEC(...)`
/// program anywhere that ends up in that compiled object makes it show up
/// here automatically, with no changes needed on the Rust side.
pub fn programs<'a>(skel: &'a KukriSkel<'static>) -> Vec<BpfProgram<'a>> {
    skel.object()
        .progs_mut()
        .map(|prog| {
            let name = prog.name().to_string_lossy().into_owned();
            let fd = prog.as_fd().as_raw_fd();
            let kind = attach_kind(&prog);
            BpfProgram {
                name,
                fd,
                kind,
                prog,
                links: Vec::new(),
                tc_hooks: Vec::new(),
                attached_interfaces: Vec::new(),
            }
        })
        .collect()
}

fn clear_map(map: &impl MapCore) -> anyhow::Result<()> {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        map.delete(&key)?;
    }
    Ok(())
}

/// `BPF_MAP_TYPE_ARRAY` entries always exist (every index in
/// `0..max_entries`) and reject `delete()` outright — "clearing" one means
/// overwriting every slot back to `0`, not removing keys.
fn clear_array_map(map: &impl MapCore) -> anyhow::Result<()> {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        map.update(&key, &[0u8], MapFlags::ANY)?;
    }
    Ok(())
}

/// `ingress_{tcp,udp}_src_ports` / `engress_{tcp,udp}_dst_ports` are
/// `BPF_MAP_TYPE_ARRAY`s indexed directly by port number (`__u32` key, per
/// the kernel's array-map convention) rather than hashed — the key space is
/// dense and fully bounded (every `u16` value), so direct indexing beats
/// hashing.
fn sync_ports(map: &impl MapCore, ports: &[u16], ranges: &[kukri::dto::config::Range]) -> anyhow::Result<()> {
    clear_array_map(map)?;
    for &port in ports {
        map.update(&(port as u32).to_ne_bytes(), &[1u8], MapFlags::ANY)?;
    }
    for range in ranges {
        for port in range.start..=range.end {
            map.update(&(port as u32).to_ne_bytes(), &[1u8], MapFlags::ANY)?;
        }
    }
    Ok(())
}

fn sync_ips(map: &impl MapCore, ips: &[u32]) -> anyhow::Result<()> {
    clear_map(map)?;
    for &ip in ips {
        map.update(&ip.to_ne_bytes(), &[1u8], MapFlags::ANY)?;
    }
    Ok(())
}

fn sync_ranges(map: &impl MapCore, cidrs: &[String]) -> anyhow::Result<()> {
    clear_map(map)?;
    for cidr in cidrs {
        let (addr, prefix) =
            kukri::dto::config::parse_ipv4_cidr(cidr).map_err(|err| anyhow::anyhow!(err))?;
        // `prefixlen` is read as a native-endian u32 by the kernel's LPM
        // trie code; `data` is matched byte-by-byte in true octet order, so
        // it must NOT be endian-swapped like the other native integers here.
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&(prefix as u32).to_ne_bytes());
        key[4..8].copy_from_slice(&addr.octets());
        map.update(&key, &[1u8], MapFlags::ANY)?;
    }
    Ok(())
}

/// Pushes every blocked port/IP/CIDR range in `config` into the
/// corresponding BPF maps, replacing whatever was there before. This is
/// pure data plumbing: `ingress_hook`/`engress_hook` don't consult these
/// maps yet, so nothing is actually enforced until that's wired up
/// separately.
pub fn sync_acl(skel: &KukriSkel<'static>, config: &kukri::dto::config::ACLConfig) -> anyhow::Result<()> {
    sync_ports(
        &skel.maps.ingress_tcp_src_ports,
        &config.ingress.tcp_rules.blocked_source_ports,
        &config.ingress.tcp_rules.blocked_source_ranges,
    )?;
    sync_ports(
        &skel.maps.ingress_udp_src_ports,
        &config.ingress.udp_rules.blocked_source_ports,
        &config.ingress.udp_rules.blocked_source_ranges,
    )?;
    sync_ips(&skel.maps.ingress_src_ips, &config.ingress.ipv4_rules.blocked_source_ips)?;
    sync_ranges(&skel.maps.ingress_src_ranges, &config.ingress.ipv4_rules.blocked_source_ranges)?;

    sync_ports(
        &skel.maps.engress_tcp_dst_ports,
        &config.engress.tcp_rules.blocked_destination_ports,
        &config.engress.tcp_rules.blocked_destination_ranges,
    )?;
    sync_ports(
        &skel.maps.engress_udp_dst_ports,
        &config.engress.udp_rules.blocked_destination_ports,
        &config.engress.udp_rules.blocked_destination_ranges,
    )?;
    sync_ips(&skel.maps.engress_dst_ips, &config.engress.ipv4_rules.blocked_destination_ips)?;
    sync_ranges(&skel.maps.engress_dst_ranges, &config.engress.ipv4_rules.blocked_destination_ranges)?;
    Ok(())
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
