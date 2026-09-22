//! In-memory mutation of the loaded `ACLConfig`, driven by the Settings
//! section of the TUI. Pure data logic — no BPF/rendering concerns here.

use std::net::Ipv4Addr;

use kukri::dto::config::parse_ipv4_cidr;
use kukri::dto::config::parse_mac_address;
use kukri::dto::config::ACLConfig;
use kukri::dto::config::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolField {
    EnableRules(Direction),
    EnablePortRules(Direction, Proto),
    EnableIpRules(Direction),
    DisableLoopback(Direction),
    EnableMacRules(Direction),
}

impl BoolField {
    pub fn get(self, config: &ACLConfig) -> bool {
        match self {
            BoolField::EnableRules(Direction::Ingress) => config.ingress.enable_rules,
            BoolField::EnableRules(Direction::Engress) => config.engress.enable_rules,
            BoolField::EnablePortRules(Direction::Ingress, Proto::Tcp) => config.ingress.tcp_rules.enable_port_rules,
            BoolField::EnablePortRules(Direction::Ingress, Proto::Udp) => config.ingress.udp_rules.enable_port_rules,
            BoolField::EnablePortRules(Direction::Engress, Proto::Tcp) => config.engress.tcp_rules.enable_port_rules,
            BoolField::EnablePortRules(Direction::Engress, Proto::Udp) => config.engress.udp_rules.enable_port_rules,
            BoolField::EnableIpRules(Direction::Ingress) => config.ingress.ipv4_rules.enable_ip_rules,
            BoolField::EnableIpRules(Direction::Engress) => config.engress.ipv4_rules.enable_ip_rules,
            BoolField::DisableLoopback(Direction::Ingress) => config.ingress.ipv4_rules.disable_loopback,
            BoolField::DisableLoopback(Direction::Engress) => config.engress.ipv4_rules.disable_loopback,
            BoolField::EnableMacRules(Direction::Ingress) => config.ingress.mac_rules.enable_mac_rules,
            BoolField::EnableMacRules(Direction::Engress) => config.engress.mac_rules.enable_mac_rules,
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
            BoolField::EnableIpRules(Direction::Ingress) => config.ingress.ipv4_rules.enable_ip_rules ^= true,
            BoolField::EnableIpRules(Direction::Engress) => config.engress.ipv4_rules.enable_ip_rules ^= true,
            BoolField::DisableLoopback(Direction::Ingress) => config.ingress.ipv4_rules.disable_loopback ^= true,
            BoolField::DisableLoopback(Direction::Engress) => config.engress.ipv4_rules.disable_loopback ^= true,
            BoolField::EnableMacRules(Direction::Ingress) => config.ingress.mac_rules.enable_mac_rules ^= true,
            BoolField::EnableMacRules(Direction::Engress) => config.engress.mac_rules.enable_mac_rules ^= true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListField {
    BlockedPorts(Direction, Proto),
    BlockedPortRanges(Direction, Proto),
    BlockedIps(Direction),
    BlockedCidrRanges(Direction),
    BlockedMacs(Direction),
}

impl ListField {
    pub fn len(self, config: &ACLConfig) -> usize {
        match self {
            ListField::BlockedPorts(Direction::Ingress, Proto::Tcp) => config.ingress.tcp_rules.blocked_source_ports.len(),
            ListField::BlockedPorts(Direction::Ingress, Proto::Udp) => config.ingress.udp_rules.blocked_source_ports.len(),
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
            ListField::BlockedIps(Direction::Ingress) => config.ingress.ipv4_rules.blocked_source_ips.len(),
            ListField::BlockedIps(Direction::Engress) => config.engress.ipv4_rules.blocked_destination_ips.len(),
            ListField::BlockedCidrRanges(Direction::Ingress) => config.ingress.ipv4_rules.blocked_source_ranges.len(),
            ListField::BlockedCidrRanges(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ranges.len()
            }
            ListField::BlockedMacs(Direction::Ingress) => config.ingress.mac_rules.blocked_source_macs.len(),
            ListField::BlockedMacs(Direction::Engress) => config.engress.mac_rules.blocked_destination_macs.len(),
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
            ListField::BlockedCidrRanges(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ranges[index].clone()
            }
            ListField::BlockedCidrRanges(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ranges[index].clone()
            }
            ListField::BlockedMacs(Direction::Ingress) => config.ingress.mac_rules.blocked_source_macs[index].clone(),
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
                config.engress.tcp_rules.blocked_destination_ports.remove(index);
            }
            ListField::BlockedPorts(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.blocked_destination_ports.remove(index);
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Tcp) => {
                config.ingress.tcp_rules.blocked_source_ranges.remove(index);
            }
            ListField::BlockedPortRanges(Direction::Ingress, Proto::Udp) => {
                config.ingress.udp_rules.blocked_source_ranges.remove(index);
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Tcp) => {
                config.engress.tcp_rules.blocked_destination_ranges.remove(index);
            }
            ListField::BlockedPortRanges(Direction::Engress, Proto::Udp) => {
                config.engress.udp_rules.blocked_destination_ranges.remove(index);
            }
            ListField::BlockedIps(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ips.remove(index);
            }
            ListField::BlockedIps(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ips.remove(index);
            }
            ListField::BlockedCidrRanges(Direction::Ingress) => {
                config.ingress.ipv4_rules.blocked_source_ranges.remove(index);
            }
            ListField::BlockedCidrRanges(Direction::Engress) => {
                config.engress.ipv4_rules.blocked_destination_ranges.remove(index);
            }
            ListField::BlockedMacs(Direction::Ingress) => {
                config.ingress.mac_rules.blocked_source_macs.remove(index);
            }
            ListField::BlockedMacs(Direction::Engress) => {
                config.engress.mac_rules.blocked_destination_macs.remove(index);
            }
        }
    }

    /// Parses `input` for this field's kind and appends it. Returns a
    /// human-readable message on bad input rather than panicking, since
    /// this is fed straight from what the user typed into the TUI.
    pub fn add(self, config: &mut ACLConfig, input: &str) -> Result<(), String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("value cannot be empty".to_string());
        }

        match self {
            ListField::BlockedPorts(dir, proto) => {
                let port = parse_port(input)?;
                match (dir, proto) {
                    (Direction::Ingress, Proto::Tcp) => config.ingress.tcp_rules.blocked_source_ports.push(port),
                    (Direction::Ingress, Proto::Udp) => config.ingress.udp_rules.blocked_source_ports.push(port),
                    (Direction::Engress, Proto::Tcp) => {
                        config.engress.tcp_rules.blocked_destination_ports.push(port)
                    }
                    (Direction::Engress, Proto::Udp) => {
                        config.engress.udp_rules.blocked_destination_ports.push(port)
                    }
                }
            }
            ListField::BlockedPortRanges(dir, proto) => {
                let range = parse_port_range(input)?;
                match (dir, proto) {
                    (Direction::Ingress, Proto::Tcp) => config.ingress.tcp_rules.blocked_source_ranges.push(range),
                    (Direction::Ingress, Proto::Udp) => config.ingress.udp_rules.blocked_source_ranges.push(range),
                    (Direction::Engress, Proto::Tcp) => {
                        config.engress.tcp_rules.blocked_destination_ranges.push(range)
                    }
                    (Direction::Engress, Proto::Udp) => {
                        config.engress.udp_rules.blocked_destination_ranges.push(range)
                    }
                }
            }
            ListField::BlockedIps(dir) => {
                let addr: Ipv4Addr = input.parse().map_err(|_| format!("\"{input}\" is not a valid IPv4 address"))?;
                let ip = u32::from(addr);
                match dir {
                    Direction::Ingress => config.ingress.ipv4_rules.blocked_source_ips.push(ip),
                    Direction::Engress => config.engress.ipv4_rules.blocked_destination_ips.push(ip),
                }
            }
            ListField::BlockedCidrRanges(dir) => {
                parse_ipv4_cidr(input)?;
                match dir {
                    Direction::Ingress => config.ingress.ipv4_rules.blocked_source_ranges.push(input.to_string()),
                    Direction::Engress => {
                        config.engress.ipv4_rules.blocked_destination_ranges.push(input.to_string())
                    }
                }
            }
            ListField::BlockedMacs(dir) => {
                parse_mac_address(input)?;
                match dir {
                    Direction::Ingress => config.ingress.mac_rules.blocked_source_macs.push(input.to_string()),
                    Direction::Engress => {
                        config.engress.mac_rules.blocked_destination_macs.push(input.to_string())
                    }
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
    input.parse().map_err(|_| format!("\"{input}\" is not a valid port (0-65535)"))
}

fn parse_port_range(input: &str) -> Result<Range, String> {
    let (start_raw, end_raw) = input.split_once('-').ok_or_else(|| "expected \"start-end\", e.g. \"0-1023\"".to_string())?;
    let start = parse_port(start_raw.trim())?;
    let end = parse_port(end_raw.trim())?;
    if start > end {
        return Err(format!("start ({start}) must be <= end ({end})"));
    }
    Ok(Range { start, end })
}
