use std::ffi::CString;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use anyhow::bail;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ACLConfig {
    pub ingress: Ingress,
    pub engress: Engress,
    pub interfaces: Interfaces,
}

/// Network interfaces XDP programs can be attached to.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Interfaces {
    pub names: Vec<String>,
}

/// Incoming traffic. Blocked ports/IPs here mean "block traffic coming
/// FROM these", so it's source-based, matching the peer that initiated
/// the connection towards us.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Ingress {
    pub enable_rules: bool,
    pub tcp_rules: IngressPortRules,
    pub udp_rules: IngressPortRules,
    pub ipv4_rules: IngressIPv4Rules,
    #[serde(default)]
    pub ipv6_rules: IngressIPv6Rules,
    pub mac_rules: IngressMacRules,
    #[serde(default)]
    pub rate_limit: RateLimitRules,
}

/// Outgoing traffic. Blocked ports/IPs here mean "block traffic going TO
/// these", destination-based this time, so it's the peer we're trying to
/// reach.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Engress {
    pub enable_rules: bool,
    pub tcp_rules: EngressPortRules,
    pub udp_rules: EngressPortRules,
    pub ipv4_rules: EngressIPv4Rules,
    #[serde(default)]
    pub ipv6_rules: EngressIPv6Rules,
    pub mac_rules: EngressMacRules,
    #[serde(default)]
    pub rate_limit: RateLimitRules,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RateLimitRules {
    pub enable_ip_rate_limit: bool,
    pub ip_rate_limit_pps: u32,
    pub enable_port_rate_limit: bool,
    pub port_rate_limit_pps: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Range {
    // the range is inclusive, the end value counts too
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngressPortRules {
    pub enable_port_rules: bool,
    pub blocked_source_ranges: Vec<Range>,
    pub blocked_source_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngressPortRules {
    pub enable_port_rules: bool,
    pub blocked_destination_ranges: Vec<Range>,
    pub blocked_destination_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngressIPv4Rules {
    pub enable_ip_rules: bool,
    pub disable_loopback: bool,
    // just CIDR strings, e.g. "10.0.0.0/8"
    pub blocked_source_ranges: Vec<String>,
    pub blocked_source_ips: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngressIPv4Rules {
    pub enable_ip_rules: bool,
    pub disable_loopback: bool,
    pub blocked_destination_ranges: Vec<String>,
    pub blocked_destination_ips: Vec<u32>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IngressIPv6Rules {
    pub enable_ip_rules: bool,
    pub disable_loopback: bool,
    pub blocked_source_ranges: Vec<String>,
    pub blocked_source_ips: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EngressIPv6Rules {
    pub enable_ip_rules: bool,
    pub disable_loopback: bool,
    pub blocked_destination_ranges: Vec<String>,
    pub blocked_destination_ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngressMacRules {
    pub enable_mac_rules: bool,
    // MAC adress strings, e.g. "aa:bb:cc:dd:ee:ff"
    pub blocked_source_macs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EngressMacRules {
    pub enable_mac_rules: bool,
    pub blocked_destination_macs: Vec<String>,
}

impl ACLConfig {
    /// Validates the config, collecting every problem it finds instead of
    /// bailing on the first one. Runs once at startup against user-authored
    /// JSON, so theres no point stopping early.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        validate_port_ranges(
            "ingress.tcp_rules",
            &self.ingress.tcp_rules.blocked_source_ranges,
            &mut errors,
        );
        validate_port_ranges(
            "ingress.udp_rules",
            &self.ingress.udp_rules.blocked_source_ranges,
            &mut errors,
        );
        validate_cidr_ranges(
            "ingress.ipv4_rules",
            &self.ingress.ipv4_rules.blocked_source_ranges,
            &mut errors,
        );
        validate_ipv6_cidr_ranges(
            "ingress.ipv6_rules",
            &self.ingress.ipv6_rules.blocked_source_ranges,
            &mut errors,
        );
        validate_ipv6_addresses(
            "ingress.ipv6_rules",
            &self.ingress.ipv6_rules.blocked_source_ips,
            &mut errors,
        );
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
        validate_ipv6_cidr_ranges(
            "engress.ipv6_rules",
            &self.engress.ipv6_rules.blocked_destination_ranges,
            &mut errors,
        );
        validate_ipv6_addresses(
            "engress.ipv6_rules",
            &self.engress.ipv6_rules.blocked_destination_ips,
            &mut errors,
        );
        validate_mac_addresses(
            "ingress.mac_rules",
            &self.ingress.mac_rules.blocked_source_macs,
            &mut errors,
        );
        validate_mac_addresses(
            "engress.mac_rules",
            &self.engress.mac_rules.blocked_destination_macs,
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

fn validate_ipv6_cidr_ranges(path: &str, ranges: &[String], errors: &mut Vec<String>) {
    for cidr in ranges {
        if let Err(err) = parse_ipv6_cidr(cidr) {
            errors.push(format!("{path}: blocked range \"{cidr}\" {err}"));
        }
    }
}

fn validate_ipv6_addresses(path: &str, addresses: &[String], errors: &mut Vec<String>) {
    for address in addresses {
        if let Err(err) = parse_ipv6_address(address) {
            errors.push(format!("{path}: blocked IP \"{address}\" {err}"));
        }
    }
}

fn validate_mac_addresses(path: &str, macs: &[String], errors: &mut Vec<String>) {
    for mac in macs {
        if let Err(err) = parse_mac_address(mac) {
            errors.push(format!("{path}: blocked MAC \"{mac}\" {err}"));
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

/// Parses a CIDR string like `"10.0.0.0/8"`. Public so the BPF-map sync
/// code can reuse the exact same parsing and validation as config loading.
pub fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| "is not in CIDR form \"a.b.c.d/prefix\"".to_string())?;

    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| format!("has an invalid address \"{addr}\""))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("has a non-numeric prefix \"{prefix}\""))?;
    if prefix > 32 {
        return Err(format!("has a prefix out of range (0-32): {prefix}"));
    }

    Ok((addr, prefix))
}

pub fn parse_ipv6_address(addr: &str) -> Result<Ipv6Addr, String> {
    addr.parse()
        .map_err(|_| format!("\"{addr}\" is not a valid IPv6 address"))
}

pub fn parse_ipv6_cidr(cidr: &str) -> Result<(Ipv6Addr, u8), String> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| "is not in CIDR form \"ipv6-address/prefix\"".to_string())?;

    let addr: Ipv6Addr = addr
        .parse()
        .map_err(|_| format!("has an invalid address \"{addr}\""))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("has a non-numeric prefix \"{prefix}\""))?;
    if prefix > 128 {
        return Err(format!("has a prefix out of range (0-128): {prefix}"));
    }

    Ok((addr, prefix))
}

/// Parses a colon-separated MAC address like `"aa:bb:cc:dd:ee:ff"` into
/// its 6 raw bytes. It's public for the same reason `parse_ipv4_cidr` is.
pub fn parse_mac_address(mac: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac.split(':').collect();
    let [p0, p1, p2, p3, p4, p5] = parts[..] else {
        return Err("is not in the form \"aa:bb:cc:dd:ee:ff\"".to_string());
    };
    let mut bytes = [0u8; 6];
    for (i, part) in [p0, p1, p2, p3, p4, p5].into_iter().enumerate() {
        bytes[i] =
            u8::from_str_radix(part, 16).map_err(|_| format!("has an invalid byte \"{part}\""))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips the checked-in example config through serde. The TUI's
    /// save feature (Serialize) has to emit JSON that this same config's
    /// own loader (Deserialize) can read back, otherwise a save+restart
    /// would silently lose the user's rules.
    #[test]
    fn acl_config_round_trips_through_serde() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/kukri.config.json"
        ))
        .expect("examples/kukri.config.json must exist");
        let config: ACLConfig = serde_json::from_str(&raw).expect("example config must parse");
        let reserialized = serde_json::to_string_pretty(&config).expect("must serialize");
        let round_tripped: ACLConfig =
            serde_json::from_str(&reserialized).expect("reserialized JSON must parse");

        assert_eq!(
            config.ingress.enable_rules,
            round_tripped.ingress.enable_rules
        );
        assert_eq!(
            config.ingress.tcp_rules.blocked_source_ports,
            round_tripped.ingress.tcp_rules.blocked_source_ports
        );
        assert_eq!(
            config.ingress.ipv4_rules.blocked_source_ips,
            round_tripped.ingress.ipv4_rules.blocked_source_ips
        );
        assert_eq!(config.interfaces.names, round_tripped.interfaces.names);
        assert_eq!(
            config.ingress.ipv6_rules.blocked_source_ips,
            round_tripped.ingress.ipv6_rules.blocked_source_ips
        );
    }

    #[test]
    fn parse_ipv4_cidr_valid() {
        assert_eq!(
            parse_ipv4_cidr("10.0.0.0/8").unwrap(),
            (Ipv4Addr::new(10, 0, 0, 0), 8)
        );
        assert_eq!(
            parse_ipv4_cidr("192.168.1.0/24").unwrap(),
            (Ipv4Addr::new(192, 168, 1, 0), 24)
        );
        // 32 is a valid (host) prefix, it isn't out of range. Exercise the
        // upper boundary as a passing case here, not an error case.
        assert_eq!(
            parse_ipv4_cidr("255.255.255.255/32").unwrap(),
            (Ipv4Addr::new(255, 255, 255, 255), 32)
        );
        assert_eq!(
            parse_ipv4_cidr("0.0.0.0/0").unwrap(),
            (Ipv4Addr::new(0, 0, 0, 0), 0)
        );
    }

    #[test]
    fn parse_ipv4_cidr_invalid() {
        assert!(
            parse_ipv4_cidr("192.168.1.1/33").is_err(),
            "prefix over 32 must be rejected"
        );
        assert!(
            parse_ipv4_cidr("192.168.1.1").is_err(),
            "missing slash must be rejected"
        );
        assert!(
            parse_ipv4_cidr("10.0.0.0/abc").is_err(),
            "non-numeric prefix must be rejected"
        );
        assert!(
            parse_ipv4_cidr("not-an-ip/24").is_err(),
            "garbage address must be rejected"
        );
    }

    #[test]
    fn parse_ipv6_cidr_valid() {
        assert_eq!(
            parse_ipv6_cidr("2001:db8::/32").unwrap(),
            ("2001:db8::".parse::<Ipv6Addr>().unwrap(), 32)
        );
        assert_eq!(
            parse_ipv6_cidr("fe80::/64").unwrap(),
            ("fe80::".parse::<Ipv6Addr>().unwrap(), 64)
        );
        assert_eq!(
            parse_ipv6_cidr("::1/128").unwrap(),
            (Ipv6Addr::LOCALHOST, 128)
        );
        assert_eq!(parse_ipv6_cidr("::/0").unwrap(), (Ipv6Addr::UNSPECIFIED, 0));
    }

    #[test]
    fn parse_ipv6_cidr_invalid() {
        assert!(
            parse_ipv6_cidr("::1/129").is_err(),
            "prefix over 128 must be rejected"
        );
        assert!(
            parse_ipv6_cidr("::1").is_err(),
            "missing slash must be rejected"
        );
        assert!(
            parse_ipv6_cidr("::/abc").is_err(),
            "non-numeric prefix must be rejected"
        );
        assert!(
            parse_ipv6_cidr("not-an-ip/64").is_err(),
            "garbage address must be rejected"
        );
    }

    #[test]
    fn ipv6_rules_default_and_validate() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/scenario-disabled.json"
        ))
        .unwrap();
        let mut config: ACLConfig = serde_json::from_str(&raw).unwrap();
        assert!(!config.ingress.ipv6_rules.enable_ip_rules);
        assert!(config.engress.ipv6_rules.blocked_destination_ips.is_empty());
        config
            .ingress
            .ipv6_rules
            .blocked_source_ips
            .push("bad-ip".into());
        config
            .engress
            .ipv6_rules
            .blocked_destination_ranges
            .push("::/129".into());
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("ingress.ipv6_rules: blocked IP"));
        assert!(err.contains("engress.ipv6_rules: blocked range"));
    }

    #[test]
    fn scenario_configs_parse_without_ipv6_rules() {
        for name in [
            "scenario-all-enabled.json",
            "scenario-disabled.json",
            "scenario-egress.json",
            "scenario-ipv4-only.json",
            "scenario-loopback.json",
            "scenario-mac-only.json",
            "scenario-ports-only.json",
        ] {
            let path = format!("{}/examples/{name}", env!("CARGO_MANIFEST_DIR"));
            let raw = std::fs::read_to_string(path).unwrap();
            let config: ACLConfig = serde_json::from_str(&raw).unwrap();
            assert!(!config.ingress.ipv6_rules.enable_ip_rules, "{name}");
            assert!(!config.engress.ipv6_rules.enable_ip_rules, "{name}");
        }
    }

    #[test]
    fn parse_mac_address_valid() {
        assert_eq!(
            parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(parse_mac_address("00:00:00:00:00:00").unwrap(), [0u8; 6]);
        assert_eq!(parse_mac_address("FF:FF:FF:FF:FF:FF").unwrap(), [0xff; 6]);
    }

    #[test]
    fn parse_mac_address_invalid() {
        assert!(
            parse_mac_address("aa:bb:cc:dd:ee").is_err(),
            "too few octets must be rejected"
        );
        assert!(
            parse_mac_address("aa:bb:cc:dd:ee:ff:00").is_err(),
            "too many octets must be rejected"
        );
        assert!(
            parse_mac_address("aa:bb:cc:dd:ee:zz").is_err(),
            "non-hex byte must be rejected"
        );
        assert!(
            parse_mac_address("aabbccddeeff").is_err(),
            "missing colons must be rejected"
        );
    }
}
