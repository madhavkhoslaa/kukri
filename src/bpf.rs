use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

use anyhow::bail;
use libbpf_rs::libbpf_sys;
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

// Generated at build time by `build.rs` through `libbpf_cargo::SkeletonBuilder`,
// straight from bpf/kukri.bpf.c.
mod skel {
    include!(concat!(env!("OUT_DIR"), "/kukri.skel.rs"));
}

pub use skel::types;
pub use skel::KukriSkel;
use skel::KukriSkelBuilder;

/// Opens and loads the BPF skeleton, but doesnt attach a thing. We leak the
/// skeleton's backing storage once so the handle is `'static` and can sit in
/// shared state for the whole lifetime of the process. Attaching gets left
/// to the caller, one program at a time (see [`programs`]).
pub fn load() -> anyhow::Result<KukriSkel<'static>> {
    let skel_builder = KukriSkelBuilder::default();
    let open_object: &'static mut MaybeUninit<_> = Box::leak(Box::new(MaybeUninit::uninit()));
    let open_skel = skel_builder.open(open_object)?;
    let skel = open_skel.load()?;
    Ok(skel)
}

/// How a program wants to get attached. Driven by the program's actual
/// `bpf_prog_type` (the kernel/libbpf reports it via [`ProgramMut::prog_type`]),
/// which is reliable metadata we basically get for free. No guessing needed
/// in the common case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// Needs a network interface (ifindex), attached through a BPF link.
    Xdp,
    /// Needs a network interface (ifindex) too, but goes through the
    /// classic qdisc-based TC hook (`SEC("tc")`/`SEC("classifier")`).
    Tc,
    /// Whatever libbpf can auto-attach from the section name alone,
    /// so tracepoints, kprobes, etc.
    Generic,
}

fn attach_kind(prog: &ProgramMut) -> AttachKind {
    match prog.prog_type() {
        ProgramType::Xdp => AttachKind::Xdp,
        ProgramType::SchedCls | ProgramType::SchedAct => AttachKind::Tc,
        _ => AttachKind::Generic,
    }
}

fn resolve_ifindex(name: &str) -> anyhow::Result<u32> {
    let c_name = CString::new(name)
        .map_err(|_| anyhow::anyhow!("interface name \"{name}\" contains a NUL byte"))?;
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        bail!("no such network interface: \"{name}\"");
    }
    Ok(index)
}

/// A generic-mode (SKB) XDP attachment, made through `bpf_xdp_attach` (the
/// legacy netlink/`IFLA_XDP` path). Unlike `Link`s, these are owned by the
/// netdev and not the process, so closing the program fd does *not* detach
/// them. They have to be removed with `bpf_xdp_detach` (tracked here), and
/// a crashed run can leave a stale hook behind untill the next attach
/// clears it. Same outlives-the-process behavior as the TC hooks.
#[derive(Debug)]
pub struct GenericXdp {
    ifindex: i32,
    pub interface: String,
}

/// One BPF program out of the loaded skeleton, able to attach/detach
/// independently of the others.
pub struct BpfProgram<'obj> {
    pub name: String,
    pub fd: RawFd,
    pub kind: AttachKind,
    prog: ProgramMut<'obj>,
    links: Vec<Link>,
    /// `Tc` only. Unlike a `Link`, a `TcHook` doesn't detach on drop, so
    /// we track them and call `detach()` ourselves.
    tc_hooks: Vec<TcHook>,
    /// `Xdp` only, generic (SKB) mode. Netlink-based attachments, so they
    /// need `bpf_xdp_detach` to remove instead of just dropping a `Link`.
    pub generic_xdp: Vec<GenericXdp>,
    /// For `Xdp`/`Tc` programs: which configured interfaces this program
    /// is attached to right now. Always empty for `Generic` programs.
    pub attached_interfaces: Vec<String>,
}

impl<'obj> BpfProgram<'obj> {
    /// Whether this program has any attachment at all right now, be that a
    /// BPF link, a TC hook, or netlink-based generic-XDP, on any interface.
    pub fn is_running(&self) -> bool {
        !self.links.is_empty() || !self.tc_hooks.is_empty() || !self.generic_xdp.is_empty()
    }

    /// Attaches the program. `Generic` programs auto-attach once, while
    /// `Xdp`/`Tc` programs attach to every interface in `interfaces` that
    /// isnt attached yet. Already-attached interfaces get skipped anyway, so
    /// it's idempotent, and per-interface failures get collected instead of
    /// aborting the whole call. A bad interface name won't stop us attaching
    /// to the good ones.
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
                    let attached =
                        resolve_ifindex(name).and_then(|ifindex| self.attach_xdp(name, ifindex));
                    match attached {
                        Ok(()) => {}
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
                        // `replace(true)` keeps this idempotent against a
                        // filter left over from a run that exited without
                        // detaching. TC hooks outlive the process that
                        // attached them, after all.
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

    /// Attaches this XDP program to one interface, preferring native
    /// (link) mode and falling back to generic (SKB) mode when the driver
    /// has no native XDP support, like rtw89 WiFi adapters or e1000e.
    fn attach_xdp(&mut self, name: &str, ifindex: u32) -> anyhow::Result<()> {
        match self.prog.attach_xdp(ifindex as i32) {
            Ok(link) => self.links.push(link),
            Err(native_err) => {
                self.attach_xdp_generic(name, ifindex as i32)
                    .map_err(|generic_err| {
                        anyhow::anyhow!(
                            "native XDP attach failed ({native_err}); \
                         generic (SKB) attach failed ({generic_err})"
                        )
                    })?;
            }
        }
        self.attached_interfaces.push(name.to_string());
        Ok(())
    }

    /// Attaches in generic (SKB) mode through `bpf_xdp_attach` (the legacy
    /// netlink/`IFLA_XDP` path). `libbpf`'s `bpf_program__attach_xdp` only
    /// ever does native mode, which just fails outright on drivers without
    /// XDP support, so this is the only way to get the ingress hook onto
    /// them. Netlink attachments outlive the process, same as the TC hooks,
    /// so a stale one left by a crashed run gets cleared (detach + retry)
    /// instead of being rejected with EBUSY.
    fn attach_xdp_generic(&mut self, name: &str, ifindex: i32) -> anyhow::Result<()> {
        let prog_fd = self.prog.as_fd().as_raw_fd();
        let flags = libbpf_sys::XDP_FLAGS_SKB_MODE | libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST;
        let attach = |flags| unsafe {
            libbpf_sys::bpf_xdp_attach(ifindex, prog_fd, flags, std::ptr::null())
        };
        let ret = attach(flags);
        if ret < 0 {
            let first = std::io::Error::from_raw_os_error(-ret);
            // A generic-XDP program already occupies this netdev's SKB
            // slot, usually our own from a run that died before detaching.
            // Clear the slot and retry. This is basically the generic-mode
            // counterpart of the TC hook's `replace(true)`.
            let _ = unsafe {
                libbpf_sys::bpf_xdp_detach(
                    ifindex,
                    libbpf_sys::XDP_FLAGS_SKB_MODE,
                    std::ptr::null(),
                )
            };
            let ret2 = attach(flags);
            if ret2 < 0 {
                bail!(
                    "generic XDP attach on \"{name}\" failed: {first}; \
                     after clearing the slot: {}",
                    std::io::Error::from_raw_os_error(-ret2)
                );
            }
        }
        self.generic_xdp.push(GenericXdp {
            ifindex,
            interface: name.to_string(),
        });
        Ok(())
    }

    /// Detaches from everything. Dropping the `Link`s handles native
    /// XDP/Generic, but TC hooks and netlink-based generic-XDP attachments
    /// need an explicit detach call first, since neither detaches on drop.
    pub fn disable(&mut self) -> anyhow::Result<()> {
        self.links.clear();

        let mut errors = Vec::new();
        for hook in &mut self.tc_hooks {
            if let Err(err) = hook.detach() {
                errors.push(err.to_string());
            }
        }
        for xdp in &self.generic_xdp {
            let ret = unsafe {
                libbpf_sys::bpf_xdp_detach(
                    xdp.ifindex,
                    libbpf_sys::XDP_FLAGS_SKB_MODE,
                    std::ptr::null(),
                )
            };
            if ret < 0 {
                errors.push(format!(
                    "{}: {}",
                    xdp.interface,
                    std::io::Error::from_raw_os_error(-ret)
                ));
            }
        }
        self.tc_hooks.clear();
        self.generic_xdp.clear();
        self.attached_interfaces.clear();

        if errors.is_empty() {
            Ok(())
        } else {
            bail!(
                "failed to detach TC/generic-XDP hook(s): {}",
                errors.join(", ")
            )
        }
    }
}

/// Lists every BPF program in the loaded skeleton, i.e. exactly what got
/// compiled into `kukri.skel.rs` from `bpf/kukri.bpf.c` and its includes,
/// with none of them attached yet. Add a new `SEC(...)` program anywhere
/// that ends up in that compiled object and it shows up here automatically,
/// with no changes needed on the Rust side.
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
                generic_xdp: Vec::new(),
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

/// `BPF_MAP_TYPE_ARRAY` entries always exist, every index in
/// `0..max_entries`, and they reject `delete()` outright. So "clearing" one
/// means overwriting every slot back to `0`, not removing keys.
fn clear_array_map(map: &impl MapCore) -> anyhow::Result<()> {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        map.update(&key, &[0u8], MapFlags::ANY)?;
    }
    Ok(())
}

/// `ingress_{tcp,udp}_src_ports` / `engress_{tcp,udp}_dst_ports` are
/// `BPF_MAP_TYPE_ARRAY`s indexed directly by port number (`__u32` key, per
/// the kernel's array-map convention) rather than hashed. The key space is
/// dense and fully bounded (every `u16` value), so direct indexing beats
/// hashing anyway.
fn sync_ports(
    map: &impl MapCore,
    ports: &[u16],
    ranges: &[kukri::dto::config::Range],
) -> anyhow::Result<()> {
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

/// `ingress_blocked_mac` / `engress_blocked_mac` are keyed by the raw 8
/// bytes of a zero-extended `__u64` (see eth.ingress.bpf.c /
/// eth.engress.bpf.c). That's the 6 MAC octets followed by two zero bytes,
/// and no endian conversion on either side, becuase both sides just copy
/// raw bytes.
fn mac_key(mac: [u8; 6]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0..6].copy_from_slice(&mac);
    key
}

fn sync_macs(map: &impl MapCore, macs: &[String]) -> anyhow::Result<()> {
    clear_map(map)?;
    for mac in macs {
        let bytes =
            kukri::dto::config::parse_mac_address(mac).map_err(|err| anyhow::anyhow!(err))?;
        map.update(&mac_key(bytes), &[1u8], MapFlags::ANY)?;
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

fn sync_ips6(map: &impl MapCore, ips: &[String]) -> anyhow::Result<()> {
    clear_map(map)?;
    for ip in ips {
        let addr =
            kukri::dto::config::parse_ipv6_address(ip).map_err(|err| anyhow::anyhow!(err))?;
        map.update(&addr.octets(), &[1u8], MapFlags::ANY)?;
    }
    Ok(())
}

fn sync_ranges(map: &impl MapCore, cidrs: &[String]) -> anyhow::Result<()> {
    clear_map(map)?;
    for cidr in cidrs {
        let (addr, prefix) =
            kukri::dto::config::parse_ipv4_cidr(cidr).map_err(|err| anyhow::anyhow!(err))?;
        // The kernel's LPM trie code reads `prefixlen` as a native-endian
        // u32. `data` is matched byte-by-byte in true octet order though,
        // so it must NOT be endian-swapped like the other native integers
        // here.
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&(prefix as u32).to_ne_bytes());
        key[4..8].copy_from_slice(&addr.octets());
        map.update(&key, &[1u8], MapFlags::ANY)?;
    }
    Ok(())
}

fn sync_ranges6(map: &impl MapCore, cidrs: &[String]) -> anyhow::Result<()> {
    clear_map(map)?;
    for cidr in cidrs {
        let (addr, prefix) =
            kukri::dto::config::parse_ipv6_cidr(cidr).map_err(|err| anyhow::anyhow!(err))?;
        let mut key = [0u8; 20];
        key[0..4].copy_from_slice(&(prefix as u32).to_ne_bytes());
        key[4..20].copy_from_slice(&addr.octets());
        map.update(&key, &[1u8], MapFlags::ANY)?;
    }
    Ok(())
}

fn sync_rate_pps(map: &impl MapCore, pps: u32) -> anyhow::Result<()> {
    map.update(&0u32.to_ne_bytes(), &pps.to_ne_bytes(), MapFlags::ANY)?;
    Ok(())
}

/// `disable_loopback` doesn't get a BPF program of its own. Instead it's
/// implemented by folding `127.0.0.0/8` into the same CIDR range list the
/// IP-ACL stage already enforces, so it only takes effect while that
/// direction's `enable_ip_rules` stage is actually attached, just like
/// every other rule in that list.
fn ranges_with_loopback(ranges: &[String], disable_loopback: bool) -> Vec<String> {
    let mut ranges = ranges.to_vec();
    if disable_loopback {
        ranges.push("127.0.0.0/8".to_string());
    }
    ranges
}

fn ranges_with_loopback6(ranges: &[String], disable_loopback: bool) -> Vec<String> {
    let mut ranges = ranges.to_vec();
    if disable_loopback {
        ranges.push("::1/128".to_string());
    }
    ranges
}

/// Pushes every blocked port/IP/CIDR range in `config` into the
/// corresponding BPF maps, replacing whatever was there before. It's pure
/// data plumbing for now, though. `ingress_hook`/`engress_hook` dont
/// consult these maps yet, so nothing is actually enforced until that's
/// wired up separately.
pub fn sync_acl(
    skel: &KukriSkel<'static>,
    config: &kukri::dto::config::ACLConfig,
) -> anyhow::Result<()> {
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
    sync_ips(
        &skel.maps.ingress_src_ips,
        &config.ingress.ipv4_rules.blocked_source_ips,
    )?;
    sync_ranges(
        &skel.maps.ingress_src_ranges,
        &ranges_with_loopback(
            &config.ingress.ipv4_rules.blocked_source_ranges,
            config.ingress.ipv4_rules.disable_loopback,
        ),
    )?;
    sync_ips6(
        &skel.maps.ingress_src_ips6,
        &config.ingress.ipv6_rules.blocked_source_ips,
    )?;
    sync_ranges6(
        &skel.maps.ingress_src_ranges6,
        &ranges_with_loopback6(
            &config.ingress.ipv6_rules.blocked_source_ranges,
            config.ingress.ipv6_rules.disable_loopback,
        ),
    )?;
    sync_macs(
        &skel.maps.ingress_blocked_mac,
        &config.ingress.mac_rules.blocked_source_macs,
    )?;
    sync_rate_pps(
        &skel.maps.ingress_ip_rate_limit_pps,
        config.ingress.rate_limit.ip_rate_limit_pps,
    )?;
    sync_rate_pps(
        &skel.maps.ingress_port_rate_limit_pps,
        config.ingress.rate_limit.port_rate_limit_pps,
    )?;

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
    sync_ips(
        &skel.maps.engress_dst_ips,
        &config.engress.ipv4_rules.blocked_destination_ips,
    )?;
    sync_ranges(
        &skel.maps.engress_dst_ranges,
        &ranges_with_loopback(
            &config.engress.ipv4_rules.blocked_destination_ranges,
            config.engress.ipv4_rules.disable_loopback,
        ),
    )?;
    sync_ips6(
        &skel.maps.engress_dst_ips6,
        &config.engress.ipv6_rules.blocked_destination_ips,
    )?;
    sync_ranges6(
        &skel.maps.engress_dst_ranges6,
        &ranges_with_loopback6(
            &config.engress.ipv6_rules.blocked_destination_ranges,
            config.engress.ipv6_rules.disable_loopback,
        ),
    )?;
    sync_macs(
        &skel.maps.engress_blocked_mac,
        &config.engress.mac_rules.blocked_destination_macs,
    )?;
    sync_rate_pps(
        &skel.maps.engress_ip_rate_limit_pps,
        config.engress.rate_limit.ip_rate_limit_pps,
    )?;
    sync_rate_pps(
        &skel.maps.engress_port_rate_limit_pps,
        config.engress.rate_limit.port_rate_limit_pps,
    )?;
    Ok(())
}

/// Wires the permanent (non-toggleable) protocol-dispatch targets into
/// `protocol_redirecters`. Without this, the tail call from
/// `ingress_hook`/`eth_firewall` into `ipv4handler`/`ipv6handler` always
/// fails and every packet passes through untouched, no matter what rule
/// stages are enabled. Called once at startup, and the GUI never touches
/// these slots.
pub fn wire_protocol_routes(
    skel: &KukriSkel<'static>,
    programs: &[BpfProgram],
) -> anyhow::Result<()> {
    let fd_of = |name: &str| programs.iter().find(|p| p.name == name).map(|p| p.fd);
    set_stage(
        &skel.maps.protocol_redirecters,
        crate::consts::PROTOCOL_IDX_IPV4,
        fd_of(crate::consts::IPV4_HANDLER_PROGRAM),
    )?;
    set_stage(
        &skel.maps.protocol_redirecters,
        crate::consts::PROTOCOL_IDX_IPV6,
        fd_of(crate::consts::IPV6_HANDLER_PROGRAM),
    )?;
    Ok(())
}

/// Sets or clears a rule stage's slot in a prog-array (tail-call) map, and
/// this *is* the enable/disable mechanism for MAC/IP/port blocking. A stage
/// only runs when its program's fd occupies its slot, and does nothing at
/// all when the slot is empty, the `bpf_tail_call()` into it just fails and
/// falls through. There is no seperate boolean flag map to keep in sync.
pub fn set_stage(map: &impl MapCore, index: u32, fd: Option<RawFd>) -> anyhow::Result<()> {
    let key = index.to_ne_bytes();
    match fd {
        Some(fd) => map.update(&key, &(fd as u32).to_ne_bytes(), MapFlags::ANY)?,
        None => match map.delete(&key) {
            Ok(()) => {}
            // Already absent. Disabling an already-disabled stage is a no-op.
            Err(err) if err.kind() == libbpf_rs::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        },
    }
    Ok(())
}

pub fn packets_processed(skel: &KukriSkel<'static>) -> u64 {
    let key = 0u32.to_ne_bytes();
    skel.maps
        .packets_processed
        .lookup(&key, MapFlags::ANY)
        .ok()
        .flatten()
        .and_then(|bytes| {
            bytes
                .get(0..8)
                .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_with_loopback_appends_only_when_enabled() {
        let configured = vec!["10.0.0.0/8".to_string()];
        assert_eq!(ranges_with_loopback(&configured, false), configured);
        assert_eq!(
            ranges_with_loopback(&configured, true),
            vec!["10.0.0.0/8".to_string(), "127.0.0.0/8".to_string()]
        );
        assert_eq!(
            ranges_with_loopback(&[], true),
            vec!["127.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn ranges_with_loopback6_appends_only_when_enabled() {
        let configured = vec!["2001:db8::/32".to_string()];
        assert_eq!(ranges_with_loopback6(&configured, false), configured);
        assert_eq!(
            ranges_with_loopback6(&configured, true),
            vec!["2001:db8::/32".to_string(), "::1/128".to_string()]
        );
    }
}
