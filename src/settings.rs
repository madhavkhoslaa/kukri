//! In-memory mutation of the loaded `ACLConfig`, driven by the Settings
//! section of the TUI. It's pure data logic, no BPF/rendering in here.

use std::net::Ipv4Addr;

use kukri::dto::config::parse_ipv4_cidr;
use kukri::dto::config::parse_ipv6_address;
use kukri::dto::config::parse_ipv6_cidr;
use kukri::dto::config::parse_mac_address;
use kukri::dto::config::ACLConfig;
use kukri::dto::config::Range;

#[derive(Debug, Clone, Default)]
pub struct InterfaceSelection {
    pub available: Vec<String>,
    pub selected: Vec<String>,
}

impl InterfaceSelection {
    pub const MAX_SELECTED: usize = 2;

    pub fn toggle(&mut self, name: &str) -> Result<(), String> {
        if let Some(pos) = self.selected.iter().position(|s| s == name) {
            self.selected.remove(pos);
            return Ok(());
        }
        if self.selected.len() >= Self::MAX_SELECTED {
            return Err(format!(
                "at most {} interfaces can be selected at once",
                Self::MAX_SELECTED
            ));
        }
        self.selected.push(name.to_string());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Ingress,
    Engress,
}

impl Direction {
    pub const ALL: [Direction; 2] = [Direction::Ingress, Direction::Engress];

    pub fn label(self) -> &'static str {
        match self {
            Direction::Ingress => "Ingress",
            Direction::Engress => "Engress",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolField {
    EnableRules(Direction),
    EnablePortRules(Direction, Proto),
    EnableIpRules(Direction),
    EnableIpv6Rules(Direction),
    DisableLoopback(Direction),
    DisableLoopback6(Direction),
    EnableMacRules(Direction),
    EnableIpRateLimit(Direction),
    EnablePortRateLimit(Direction),
}

impl BoolField {
    pub fn get(self, config: &ACLConfig) -> bool {
        match self {
            BoolField::EnableRules(Direction::Ingress) => config.ingress.enable_rules,
            BoolField::EnableRules(Direction::Engress) => config.engress.enable_rules,
            BoolField::EnablePortRules(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.enable_port_rules
            }
            BoolField::EnablePortRules(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.enable_port_rules
            }
            BoolField::EnablePortRules(Direction::Engress, Proto::Tcp) => {
                config.engress.tcp_rules.enable_port_rules
            }
            BoolField::EnablePortRules(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.enable_port_rules
            }
            BoolField::EnableIpRules(Direction::Ingress) => {
                config.ingress.ipv4_rules.enable_ip_rules
            }
            BoolField::EnableIpRules(Direction::Engress) => {
                config.engress.ipv4_rules.enable_ip_rules
            }
            BoolField::EnableIpv6Rules(Direction::Ingress) => {
                config.ingress.ipv6_rules.enable_ip_rules
            }
            BoolField::EnableIpv6Rules(Direction::Engress) => {
                config.engress.ipv6_rules.enable_ip_rules
            }
            BoolField::DisableLoopback(Direction::Ingress) => {
                config.ingress.ipv4_rules.disable_loopback
            }
            BoolField::DisableLoopback(Direction::Engress) => {
                config.engress.ipv4_rules.disable_loopback
            }
            BoolField::DisableLoopback6(Direction::Ingress) => {
                config.ingress.ipv6_rules.disable_loopback
            }
            BoolField::DisableLoopback6(Direction::Engress) => {
                config.engress.ipv6_rules.disable_loopback
            }
            BoolField::EnableMacRules(Direction::Ingress) => {
                config.ingress.mac_rules.enable_mac_rules
            }
            BoolField::EnableMacRules(Direction::Engress) => {
                config.engress.mac_rules.enable_mac_rules
            }
            BoolField::EnableIpRateLimit(Direction::Ingress) => {
                config.ingress.rate_limit.enable_ip_rate_limit
            }
            BoolField::EnableIpRateLimit(Direction::Engress) => {
                config.engress.rate_limit.enable_ip_rate_limit
            }
            BoolField::EnablePortRateLimit(Direction::Ingress) => {
                config.ingress.rate_limit.enable_port_rate_limit
            }
            BoolField::EnablePortRateLimit(Direction::Engress) => {
                config.engress.rate_limit.enable_port_rate_limit
            }
        }
    }

    pub fn toggle(self, config: &mut ACLConfig) {
        match self {
            BoolField::EnableRules(Direction::Ingress) => config.ingress.enable_rules ^= true,
            BoolField::EnableRules(Direction::Engress) => config.engress.enable_rules ^= true,
            BoolField::EnablePortRules(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.enable_port_rules ^= true
            }
            BoolField::EnablePortRules(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.enable_port_rules ^= true
            }
            BoolField::EnablePortRules(Direction::Engress, Proto::Tcp) => {
                config.engress.tcp_rules.enable_port_rules ^= true
            }
            BoolField::EnablePortRules(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.enable_port_rules ^= true
            }
            BoolField::EnableIpRules(Direction::Ingress) => {
                config.ingress.ipv4_rules.enable_ip_rules ^= true
            }
            BoolField::EnableIpRules(Direction::Engress) => {
                config.engress.ipv4_rules.enable_ip_rules ^= true
            }
            BoolField::EnableIpv6Rules(Direction::Ingress) => {
                config.ingress.ipv6_rules.enable_ip_rules ^= true
            }
            BoolField::EnableIpv6Rules(Direction::Engress) => {
                config.engress.ipv6_rules.enable_ip_rules ^= true
            }
            BoolField::DisableLoopback(Direction::Ingress) => {
                config.ingress.ipv4_rules.disable_loopback ^= true
            }
            BoolField::DisableLoopback(Direction::Engress) => {
                config.engress.ipv4_rules.disable_loopback ^= true
            }
            BoolField::DisableLoopback6(Direction::Ingress) => {
                config.ingress.ipv6_rules.disable_loopback ^= true
            }
            BoolField::DisableLoopback6(Direction::Engress) => {
                config.engress.ipv6_rules.disable_loopback ^= true
            }
            BoolField::EnableMacRules(Direction::Ingress) => {
                config.ingress.mac_rules.enable_mac_rules ^= true
            }
            BoolField::EnableMacRules(Direction::Engress) => {
                config.engress.mac_rules.enable_mac_rules ^= true
            }
            BoolField::EnableIpRateLimit(Direction::Ingress) => {
                config.ingress.rate_limit.enable_ip_rate_limit ^= true
            }
            BoolField::EnableIpRateLimit(Direction::Engress) => {
                config.engress.rate_limit.enable_ip_rate_limit ^= true
            }
            BoolField::EnablePortRateLimit(Direction::Ingress) => {
                config.ingress.rate_limit.enable_port_rate_limit ^= true
            }
            BoolField::EnablePortRateLimit(Direction::Engress) => {
                config.engress.rate_limit.enable_port_rate_limit ^= true
            }
        }
    }
}

// Every variant blocks something, hence the shared prefix. Renaming them
// away from that would make the TUI-facing meaning less clear, not more.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListField {
    BlockedPorts(Direction, Proto),
    BlockedPortRanges(Direction, Proto),
    BlockedIps(Direction),
    BlockedIps6(Direction),
    BlockedCidrRanges(Direction),
    BlockedCidrRanges6(Direction),
    BlockedMacs(Direction),
}

impl ListField {
    pub fn len(self, config: &ACLConfig) -> usize {
        match self {
            ListField::BlockedPorts(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.blocked_source_ports.len()
            }
            ListField::BlockedPorts(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.blocked_source_ports.len()
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Tcp) => {
                config.engress.tcp_rules.blocked_destination_ports.len()
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.blocked_destination_ports.len()
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.blocked_source_ranges.len()
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.blocked_source_ranges.len()
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Tcp) => {
                config.engress.tcp_rules.blocked_destination_ranges.len()
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.blocked_destination_ranges.len()
            }
            ListField::BlockedIps(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ips.len()
            }
            ListField::BlockedIps(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ips.len()
            }
            ListField::BlockedIps6(Direction::Ingress) => {
                config.ingress.ipv6_rules.blocked_source_ips.len()
            }
            ListField::BlockedIps6(Direction::Engress) => {
                config.engress.ipv6_rules.blocked_destination_ips.len()
            }
            ListField::BlockedCidrRanges(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ranges.len()
            }
            ListField::BlockedCidrRanges(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ranges.len()
            }
            ListField::BlockedCidrRanges6(Direction::Ingress) => {
                config.ingress.ipv6_rules.blocked_source_ranges.len()
            }
            ListField::BlockedCidrRanges6(Direction::Engress) => {
                config.engress.ipv6_rules.blocked_destination_ranges.len()
            }
            ListField::BlockedMacs(Direction::Ingress) => {
                config.ingress.mac_rules.blocked_source_macs.len()
            }
            ListField::BlockedMacs(Direction::Engress) => {
                config.engress.mac_rules.blocked_destination_macs.len()
            }
        }
    }

    pub fn item_label(self, config: &ACLConfig, index: usize) -> String {
        match self {
            ListField::BlockedPorts(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.blocked_source_ports[index].to_string()
            }
            ListField::BlockedPorts(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.blocked_source_ports[index].to_string()
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Tcp) => {
                config.engress.tcp_rules.blocked_destination_ports[index].to_string()
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.blocked_destination_ports[index].to_string()
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Tcp) => {
                range_label(&config.ingress.tcp_rules.blocked_source_ranges[index])
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Udp) => {
                range_label(&config.ingress.udp_rules.blocked_source_ranges[index])
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Tcp) => {
                range_label(&config.engress.tcp_rules.blocked_destination_ranges[index])
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Udp) => {
                range_label(&config.engress.udp_rules.blocked_destination_ranges[index])
            }
            ListField::BlockedIps(Direction::Ingress) => {
                Ipv4Addr::from(config.ingress.ipv4_rules.blocked_source_ips[index]).to_string()
            }
            ListField::BlockedIps(Direction::Engress) => {
                Ipv4Addr::from(config.engress.ipv4_rules.blocked_destination_ips[index]).to_string()
            }
            ListField::BlockedIps6(Direction::Ingress) => {
                config.ingress.ipv6_rules.blocked_source_ips[index].clone()
            }
            ListField::BlockedIps6(Direction::Engress) => {
                config.engress.ipv6_rules.blocked_destination_ips[index].clone()
            }
            ListField::BlockedCidrRanges(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ranges[index].clone()
            }
            ListField::BlockedCidrRanges(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ranges[index].clone()
            }
            ListField::BlockedCidrRanges6(Direction::Ingress) => {
                config.ingress.ipv6_rules.blocked_source_ranges[index].clone()
            }
            ListField::BlockedCidrRanges6(Direction::Engress) => {
                config.engress.ipv6_rules.blocked_destination_ranges[index].clone()
            }
            ListField::BlockedMacs(Direction::Ingress) => {
                config.ingress.mac_rules.blocked_source_macs[index].clone()
            }
            ListField::BlockedMacs(Direction::Engress) => {
                config.engress.mac_rules.blocked_destination_macs[index].clone()
            }
        }
    }

    pub fn remove(self, config: &mut ACLConfig, index: usize) {
        match self {
            ListField::BlockedPorts(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.blocked_source_ports.remove(index);
            }
            ListField::BlockedPorts(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.blocked_source_ports.remove(index);
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Tcp) => {
                config
                    .engress
                    .tcp_rules
                    .blocked_destination_ports
                    .remove(index);
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Udp) => {
                config
                    .engress
                    .udp_rules
                    .blocked_destination_ports
                    .remove(index);
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.blocked_source_ranges.remove(index);
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.blocked_source_ranges.remove(index);
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Tcp) => {
                config
                    .engress
                    .tcp_rules
                    .blocked_destination_ranges
                    .remove(index);
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Udp) => {
                config
                    .engress
                    .udp_rules
                    .blocked_destination_ranges
                    .remove(index);
            }
            ListField::BlockedIps(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ips.remove(index);
            }
            ListField::BlockedIps(Direction::Engress) => {
                config
                    .engress
                    .ipv4_rules
                    .blocked_destination_ips
                    .remove(index);
            }
            ListField::BlockedIps6(Direction::Ingress) => {
                config.ingress.ipv6_rules.blocked_source_ips.remove(index);
            }
            ListField::BlockedIps6(Direction::Engress) => {
                config
                    .engress
                    .ipv6_rules
                    .blocked_destination_ips
                    .remove(index);
            }
            ListField::BlockedCidrRanges(Direction::Ingress) => {
                config
                    .ingress
                    .ipv4_rules
                    .blocked_source_ranges
                    .remove(index);
            }
            ListField::BlockedCidrRanges(Direction::Engress) => {
                config
                    .engress
                    .ipv4_rules
                    .blocked_destination_ranges
                    .remove(index);
            }
            ListField::BlockedCidrRanges6(Direction::Ingress) => {
                config
                    .ingress
                    .ipv6_rules
                    .blocked_source_ranges
                    .remove(index);
            }
            ListField::BlockedCidrRanges6(Direction::Engress) => {
                config
                    .engress
                    .ipv6_rules
                    .blocked_destination_ranges
                    .remove(index);
            }
            ListField::BlockedMacs(Direction::Ingress) => {
                config.ingress.mac_rules.blocked_source_macs.remove(index);
            }
            ListField::BlockedMacs(Direction::Engress) => {
                config
                    .engress
                    .mac_rules
                    .blocked_destination_macs
                    .remove(index);
            }
        }
    }

    /// Parses `input` for this field's kind and appends it. Returns a
    /// human-readable message on bad input rather than panicing, since this
    /// is fed straight from what the user typed into the TUI.
    pub fn add(self, config: &mut ACLConfig, input: &str) -> Result<(), String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("value cannot be empty".to_string());
        }

        match self {
            ListField::BlockedPorts(dir, proto) => {
                let port = parse_port(input)?;
                match (dir, proto) {
                    (Direction::Ingress, Proto::Tcp) => {
                        config.ingress.tcp_rules.blocked_source_ports.push(port)
                    }
                    (Direction::Ingress, Proto::Udp) => {
                        config.ingress.udp_rules.blocked_source_ports.push(port)
                    }
                    (Direction::Engress, Proto::Tcp) => config
                        .engress
                        .tcp_rules
                        .blocked_destination_ports
                        .push(port),
                    (Direction::Engress, Proto::Udp) => config
                        .engress
                        .udp_rules
                        .blocked_destination_ports
                        .push(port),
                }
            }
            ListField::BlockedPortRanges(dir, proto) => {
                let range = parse_port_range(input)?;
                match (dir, proto) {
                    (Direction::Ingress, Proto::Tcp) => {
                        config.ingress.tcp_rules.blocked_source_ranges.push(range)
                    }
                    (Direction::Ingress, Proto::Udp) => {
                        config.ingress.udp_rules.blocked_source_ranges.push(range)
                    }
                    (Direction::Engress, Proto::Tcp) => config
                        .engress
                        .tcp_rules
                        .blocked_destination_ranges
                        .push(range),
                    (Direction::Engress, Proto::Udp) => config
                        .engress
                        .udp_rules
                        .blocked_destination_ranges
                        .push(range),
                }
            }
            ListField::BlockedIps(dir) => {
                let addr: Ipv4Addr = input
                    .parse()
                    .map_err(|_| format!("\"{input}\" is not a valid IPv4 address"))?;
                let ip = u32::from(addr);
                match dir {
                    Direction::Ingress => config.ingress.ipv4_rules.blocked_source_ips.push(ip),
                    Direction::Engress => {
                        config.engress.ipv4_rules.blocked_destination_ips.push(ip)
                    }
                }
            }
            ListField::BlockedIps6(dir) => {
                parse_ipv6_address(input)?;
                match dir {
                    Direction::Ingress => config
                        .ingress
                        .ipv6_rules
                        .blocked_source_ips
                        .push(input.to_string()),
                    Direction::Engress => config
                        .engress
                        .ipv6_rules
                        .blocked_destination_ips
                        .push(input.to_string()),
                }
            }
            ListField::BlockedCidrRanges(dir) => {
                parse_ipv4_cidr(input)?;
                match dir {
                    Direction::Ingress => config
                        .ingress
                        .ipv4_rules
                        .blocked_source_ranges
                        .push(input.to_string()),
                    Direction::Engress => config
                        .engress
                        .ipv4_rules
                        .blocked_destination_ranges
                        .push(input.to_string()),
                }
            }
            ListField::BlockedCidrRanges6(dir) => {
                parse_ipv6_cidr(input)?;
                match dir {
                    Direction::Ingress => config
                        .ingress
                        .ipv6_rules
                        .blocked_source_ranges
                        .push(input.to_string()),
                    Direction::Engress => config
                        .engress
                        .ipv6_rules
                        .blocked_destination_ranges
                        .push(input.to_string()),
                }
            }
            ListField::BlockedMacs(dir) => {
                parse_mac_address(input)?;
                match dir {
                    Direction::Ingress => config
                        .ingress
                        .mac_rules
                        .blocked_source_macs
                        .push(input.to_string()),
                    Direction::Engress => config
                        .engress
                        .mac_rules
                        .blocked_destination_macs
                        .push(input.to_string()),
                }
            }
        }
        Ok(())
    }
}

pub fn range_label(range: &Range) -> String {
    format!("{}-{}", range.start, range.end)
}

fn parse_port(input: &str) -> Result<u16, String> {
    input
        .parse()
        .map_err(|_| format!("\"{input}\" is not a valid port (0-65535)"))
}

fn parse_port_range(input: &str) -> Result<Range, String> {
    let (start_raw, end_raw) = input
        .split_once('-')
        .ok_or_else(|| "expected \"start-end\", e.g. \"0-1023\"".to_string())?;
    let start = parse_port(start_raw.trim())?;
    let end = parse_port(end_raw.trim())?;
    if start > end {
        return Err(format!("start ({start}) must be <= end ({end})"));
    }
    Ok(Range { start, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_fields_edit_independently_of_ipv4() {
        let raw = include_str!("../examples/kukri.config.json");
        let mut config: ACLConfig = serde_json::from_str(raw).unwrap();
        BoolField::EnableIpv6Rules(Direction::Ingress).toggle(&mut config);
        BoolField::DisableLoopback6(Direction::Ingress).toggle(&mut config);
        assert!(BoolField::EnableIpv6Rules(Direction::Ingress).get(&config));
        assert!(BoolField::DisableLoopback6(Direction::Ingress).get(&config));
        assert!(BoolField::DisableLoopback(Direction::Ingress).get(&config));

        let ip = ListField::BlockedIps6(Direction::Ingress);
        let range = ListField::BlockedCidrRanges6(Direction::Engress);
        assert!(ip.add(&mut config, "bad-ip").is_err());
        assert!(range.add(&mut config, "::/129").is_err());
        ip.add(&mut config, "2001:db8::1").unwrap();
        range.add(&mut config, "::1/128").unwrap();
        assert_eq!(ip.len(&config), 1);
        assert_eq!(ip.item_label(&config, 0), "2001:db8::1");
        assert_eq!(range.item_label(&config, 0), "::1/128");
        ip.remove(&mut config, 0);
        range.remove(&mut config, 0);
        assert_eq!(ip.len(&config), 0);
        assert_eq!(range.len(&config), 0);
    }

    #[test]
    fn interface_selection_caps_at_two_and_allows_replacement() {
        let mut selection = InterfaceSelection::default();
        selection.toggle("eth0").unwrap();
        selection.toggle("wlan0").unwrap();
        assert_eq!(
            selection.toggle("tun0"),
            Err("at most 2 interfaces can be selected at once".to_string())
        );
        assert_eq!(selection.selected, ["eth0", "wlan0"]);

        selection.toggle("eth0").unwrap();
        selection.toggle("tun0").unwrap();
        assert_eq!(selection.selected, ["wlan0", "tun0"]);
    }

    #[test]
    fn parse_port_valid() {
        assert_eq!(parse_port("0").unwrap(), 0);
        assert_eq!(parse_port("8080").unwrap(), 8080);
        assert_eq!(parse_port("65535").unwrap(), 65535);
    }

    #[test]
    fn parse_port_invalid() {
        assert!(
            parse_port("65536").is_err(),
            "out of u16 range must be rejected"
        );
        assert!(parse_port("-1").is_err(), "negative must be rejected");
        assert!(parse_port("abc").is_err(), "non-numeric must be rejected");
        assert!(parse_port("").is_err(), "empty must be rejected");
    }

    #[test]
    fn parse_port_range_valid() {
        let range = parse_port_range("0-1023").unwrap();
        assert_eq!((range.start, range.end), (0, 1023));
        let range = parse_port_range(" 1024 - 2048 ").unwrap();
        assert_eq!((range.start, range.end), (1024, 2048));
    }

    #[test]
    fn parse_port_range_invalid() {
        assert!(
            parse_port_range("1023-0").is_err(),
            "start > end must be rejected"
        );
        assert!(
            parse_port_range("1024-").is_err(),
            "missing end must be rejected"
        );
        assert!(
            parse_port_range("1024").is_err(),
            "missing dash must be rejected"
        );
    }
}
