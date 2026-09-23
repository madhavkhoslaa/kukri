use std::collections::HashMap;
use std::os::fd::RawFd;

use anyhow::{anyhow, Context};

use crate::bpf::{types, BpfProgram, KukriSkel};
use crate::settings::{Direction, Proto};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Feature {
    Mac,
    Ipv4Acl,
    Ipv6Acl,
    IpRateLimit,
    PortRateLimit,
    Port(Proto),
}

#[derive(Debug, Clone, Copy)]
pub struct StageSlot {
    pub index: u32,
    pub fd: RawFd,
}

pub fn classify_stage(name: &str) -> Option<(Direction, Feature)> {
    if name == "eth_firewall" {
        return Some((Direction::Ingress, Feature::Mac));
    }
    if name == "engress_eth_firewall" {
        return Some((Direction::Engress, Feature::Mac));
    }

    let (direction, stage) = if let Some(stage) = name.strip_prefix("engress_") {
        (Direction::Engress, stage)
    } else {
        (Direction::Ingress, name.strip_prefix("ingress_")?)
    };
    let feature = match stage {
        "ipv4_acl_stage" => Feature::Ipv4Acl,
        "ipv6_acl_stage" => Feature::Ipv6Acl,
        "ip_rate_limit_stage" => Feature::IpRateLimit,
        "port_rate_limit_stage" => Feature::PortRateLimit,
        "tcp_port_stage" => Feature::Port(Proto::Tcp),
        "udp_port_stage" => Feature::Port(Proto::Udp),
        _ => return None,
    };
    Some((direction, feature))
}

fn slot_index(name: &str, rodata: &types::rodata) -> Option<u32> {
    Some(match name {
        "eth_firewall" => rodata.ETH_FIREWALL_SLOT,
        "ingress_ipv4_acl_stage" => rodata.INGRESS_IPV4_ACL_STAGE_SLOT,
        "ingress_ipv6_acl_stage" => rodata.INGRESS_IPV6_ACL_STAGE_SLOT,
        "ingress_ip_rate_limit_stage" => rodata.INGRESS_IP_RATE_LIMIT_STAGE_SLOT,
        "ingress_port_rate_limit_stage" => rodata.INGRESS_PORT_RATE_LIMIT_STAGE_SLOT,
        "ingress_tcp_port_stage" => rodata.INGRESS_TCP_PORT_STAGE_SLOT,
        "ingress_udp_port_stage" => rodata.INGRESS_UDP_PORT_STAGE_SLOT,
        "engress_eth_firewall" => rodata.ENGRESS_ETH_FIREWALL_SLOT,
        "engress_ipv4_acl_stage" => rodata.ENGRESS_IPV4_ACL_STAGE_SLOT,
        "engress_ipv6_acl_stage" => rodata.ENGRESS_IPV6_ACL_STAGE_SLOT,
        "engress_ip_rate_limit_stage" => rodata.ENGRESS_IP_RATE_LIMIT_STAGE_SLOT,
        "engress_port_rate_limit_stage" => rodata.ENGRESS_PORT_RATE_LIMIT_STAGE_SLOT,
        "engress_tcp_port_stage" => rodata.ENGRESS_TCP_PORT_STAGE_SLOT,
        "engress_udp_port_stage" => rodata.ENGRESS_UDP_PORT_STAGE_SLOT,
        _ => return None,
    })
}

pub fn discover_stage_slots(
    skel: &KukriSkel<'static>,
    programs: &[BpfProgram],
) -> anyhow::Result<HashMap<(Direction, Feature), StageSlot>> {
    let rodata = skel
        .maps
        .rodata_data
        .context("BPF skeleton has no rodata for optional stage slots")?;
    let mut slots = HashMap::new();
    for program in programs {
        if let Some(key) = classify_stage(&program.name) {
            let index = slot_index(&program.name, rodata)
                .ok_or_else(|| anyhow!("{}: no matching BPF rodata slot field", program.name))?;
            slots.insert(
                key,
                StageSlot {
                    index,
                    fd: program.fd,
                },
            );
        }
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_stage_mac_special_cases() {
        assert_eq!(
            classify_stage("eth_firewall"),
            Some((Direction::Ingress, Feature::Mac))
        );
        assert_eq!(
            classify_stage("engress_eth_firewall"),
            Some((Direction::Engress, Feature::Mac))
        );
    }

    #[test]
    fn classify_stage_ipv4_acl() {
        assert_eq!(
            classify_stage("ingress_ipv4_acl_stage"),
            Some((Direction::Ingress, Feature::Ipv4Acl))
        );
        assert_eq!(
            classify_stage("engress_ipv4_acl_stage"),
            Some((Direction::Engress, Feature::Ipv4Acl))
        );
    }

    #[test]
    fn classify_stage_ipv6_acl() {
        assert_eq!(
            classify_stage("ingress_ipv6_acl_stage"),
            Some((Direction::Ingress, Feature::Ipv6Acl))
        );
        assert_eq!(
            classify_stage("engress_ipv6_acl_stage"),
            Some((Direction::Engress, Feature::Ipv6Acl))
        );
    }

    #[test]
    fn classify_stage_rate_limit() {
        assert_eq!(
            classify_stage("ingress_ip_rate_limit_stage"),
            Some((Direction::Ingress, Feature::IpRateLimit))
        );
        assert_eq!(
            classify_stage("ingress_port_rate_limit_stage"),
            Some((Direction::Ingress, Feature::PortRateLimit))
        );
        assert_eq!(
            classify_stage("engress_ip_rate_limit_stage"),
            Some((Direction::Engress, Feature::IpRateLimit))
        );
        assert_eq!(
            classify_stage("engress_port_rate_limit_stage"),
            Some((Direction::Engress, Feature::PortRateLimit))
        );
    }

    #[test]
    fn classify_stage_ports() {
        assert_eq!(
            classify_stage("ingress_tcp_port_stage"),
            Some((Direction::Ingress, Feature::Port(Proto::Tcp)))
        );
        assert_eq!(
            classify_stage("ingress_udp_port_stage"),
            Some((Direction::Ingress, Feature::Port(Proto::Udp)))
        );
        assert_eq!(
            classify_stage("engress_tcp_port_stage"),
            Some((Direction::Engress, Feature::Port(Proto::Tcp)))
        );
        assert_eq!(
            classify_stage("engress_udp_port_stage"),
            Some((Direction::Engress, Feature::Port(Proto::Udp)))
        );
    }

    #[test]
    fn classify_stage_ignores_non_stage_programs() {
        // Permanent routing targets, entry hooks, and unrelated tracepoints
        // are not optional rule stages, so dont misclassify them.
        for name in [
            "ingress_hook",
            "engress_hook",
            "ipv4handler",
            "ipv6handler",
            "",
            "ingress_",
            "engress_",
            "ingress_unknown_stage",
            "engress_unknown_stage",
            "not_a_stage_at_all",
        ] {
            assert_eq!(
                classify_stage(name),
                None,
                "unexpectedly classified \"{name}\""
            );
        }
    }
}
