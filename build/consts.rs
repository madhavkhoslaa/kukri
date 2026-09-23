// which program each direcion's master switch in Settings attaches or detaches
pub const INGRESS_PROGRAM: &str = "ingress_hook";
pub const ENGRESS_PROGRAM: &str = "engress_hook";

/// Permanent (non-toggleable) protocol-routing slots in
/// `protocol_redirecters`, matching `enum PROTOCOL_HANDLER` in
/// bpf/inline.bpf.h. Unlike the rule stages above, these get wired up once
/// at load time and the GUI never touches them. They're how packets reach
/// the IPv4/IPv6 handlers at all, not an optional feature.
pub const PROTOCOL_IDX_IPV4: u32 = 1;
pub const PROTOCOL_IDX_IPV6: u32 = 2;
pub const IPV4_HANDLER_PROGRAM: &str = "ipv4handler";
pub const IPV6_HANDLER_PROGRAM: &str = "ipv6handler";
