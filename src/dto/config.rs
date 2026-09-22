use std::ffi::CString;
use std::net::Ipv4Addr;

use anyhow::bail;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ACLConfig {
    pub ingress: Ingress,
    pub engress: Engress,
    pub interfaces: Interfaces,
}

/// Network interfaces XDP programs may be attached to.
#[derive(Debug, Deserialize)]
pub struct Interfaces {
    pub names: Vec<String>,
}

/// Incoming traffic. Blocked ports/IPs here mean "block traffic coming
/// FROM these" (source-based) — matching the peer that initiated the
/// connection towards us.
#[derive(Debug, Deserialize)]
pub struct Ingress {
    pub enable_rules: bool,
    pub tcp_rules: IngressPortRules,
    pub udp_rules: IngressPortRules,
    pub ipv4_rules: IngressIPv4Rules,
}

/// Outgoing traffic. Blocked ports/IPs here mean "block traffic going TO
/// these" (destination-based) — matching the peer we're trying to reach.
#[derive(Debug, Deserialize)]
pub struct Engress {
    pub enable_rules: bool,
    pub tcp_rules: EngressPortRules,
    pub udp_rules: EngressPortRules,
    pub ipv4_rules: EngressIPv4Rules,
}

#[derive(Debug, Deserialize)]
pub struct Range {
    // An inclusive end range
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Deserialize)]
pub struct IngressPortRules {
    pub enable_port_rules: bool,
    pub blocked_source_ranges: Vec<Range>,
    pub blocked_source_ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
pub struct EngressPortRules {
    pub enable_port_rules: bool,
    pub blocked_destination_ranges: Vec<Range>,
    pub blocked_destination_ports: Vec<u16>,
}

#[derive(Debug, Deserialize)]
pub struct IngressIPv4Rules {
    pub enable_ip_rules: bool,
    pub disable_loopback: bool,
    // CIDR strings, e.g. "10.0.0.0/8"
    pub blocked_source_ranges: Vec<String>,
    pub blocked_source_ips: Vec<u32>,
}

#[derive(Debug, Deserialize)]
pub struct EngressIPv4Rules {
    pub enable_ip_rules: bool,
    pub disable_loopback: bool,
    pub blocked_destination_ranges: Vec<String>,
    pub blocked_destination_ips: Vec<u32>,
}

impl ACLConfig {
    /// Validates the config, collecting every problem found rather than
    /// bailing on the first one, since this runs once at startup against
    /// user-authored JSON.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        validate_port_ranges("ingress.tcp_rules", &self.ingress.tcp_rules.blocked_source_ranges, &mut errors);
        validate_port_ranges("ingress.udp_rules", &self.ingress.udp_rules.blocked_source_ranges, &mut errors);
        validate_cidr_ranges("ingress.ipv4_rules", &self.ingress.ipv4_rules.blocked_source_ranges, &mut errors);
        validate_port_ranges(
            "engress.tcp_rules",
            &self.engress.tcp_rules.blocked_destination_ranges,
            &mut errors,
        );
        validate_port_ranges(
            "engress.udp_rules",
            &self.engress.udp_rules.blocked_destination_ranges,
            &mut errors,
        );
        validate_cidr_ranges(
            "engress.ipv4_rules",
            &self.engress.ipv4_rules.blocked_destination_ranges,
            &mut errors,
        );
        validate_interfaces(&self.interfaces, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            bail!("invalid config:\n  {}", errors.join("\n  "));
        }
    }
}

fn validate_port_ranges(path: &str, ranges: &[Range], errors: &mut Vec<String>) {
    for range in ranges {
        if range.start > range.end {
            errors.push(format!(
                "{path}: blocked range {}..={} has start > end",
                range.start, range.end
            ));
        }
    }
}

fn validate_cidr_ranges(path: &str, ranges: &[String], errors: &mut Vec<String>) {
    for cidr in ranges {
        if let Err(err) = parse_ipv4_cidr(cidr) {
            errors.push(format!("{path}: blocked range \"{cidr}\" {err}"));
        }
    }
}

fn validate_interfaces(interfaces: &Interfaces, errors: &mut Vec<String>) {
    for name in &interfaces.names {
        if name.is_empty() {
            errors.push("interfaces: contains an empty interface name".to_string());
            continue;
        }
        let Ok(c_name) = CString::new(name.as_str()) else {
            errors.push(format!("interfaces: \"{name}\" contains a NUL byte"));
            continue;
        };
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            errors.push(format!("interfaces: no such network interface \"{name}\""));
        }
    }
}

/// Parses a CIDR string like `"10.0.0.0/8"`. Public so the BPF-map sync code
/// can reuse the exact same parsing/validation as config loading.
pub fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| "is not in CIDR form \"a.b.c.d/prefix\"".to_string())?;

    let addr: Ipv4Addr = addr.parse().map_err(|_| format!("has an invalid address \"{addr}\""))?;
    let prefix: u8 = prefix.parse().map_err(|_| format!("has a non-numeric prefix \"{prefix}\""))?;
    if prefix > 32 {
        return Err(format!("has a prefix out of range (0-32): {prefix}"));
    }

    Ok((addr, prefix))
}
