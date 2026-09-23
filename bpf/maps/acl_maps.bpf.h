// SPDX-License-Identifier: GPL-3.0-only

#include "vmlinux.h"
#include "license.bpf.h"
#include <bpf/bpf_helpers.h>
#pragma once


/* Key for an IPv4 CIDR entry in a BPF_MAP_TYPE_LPM_TRIE map. Follows the
 * kernel's `struct bpf_lpm_trie_key` convention: prefix length in bits,
 * then the value the trie matches most-significant-byte first. */
struct ipv4_lpm_key {
  __u32 prefixlen;
  __u32 data;
};

/* IPv6 version of `ipv4_lpm_key` — same `struct bpf_lpm_trie_key`
 * convention, only the address is 16 bytes now instead of 4. */
struct ipv6_lpm_key {
  __u32 prefixlen;
  __u8 data[16];
};

/* Exact-match IPv6 address key. A bare `__u8[16]` array cant be used
 * directly as a BTF-described map key type, so we wrap it in a struct,
 * same trick the MAC key comment in `eth.ingress.bpf.c` describes for its
 * 8-byte key: there's no native 16-byte integer type, so the wrapper
 * struct stands in for one. */
struct ipv6_addr_key {
  __u8 addr[16];
};


/**
Tail-call dispatch table for the ingress (XDP) pipeline. Two kinds of
entries live here, on disjoint indices:

  - Permanent routing targets (`enum PROTOCOL_HANDLER` in inline.bpf.h,
    indices 0-6): pick which per-ethertype handler runs after `ingress_hook`.
    Userspace always keeps these populated; they're not a toggleable feature.
  - Optional rule stages (`enum ingress_stage` below): one BPF program per
    blocking feature (MAC / IP / TCP port / UDP port). A feature being "on"
    is purely a matter of whether its program occupies its slot in this map.
    There is no seperate enabled/disabled flag map: the GUI turns a feature
    on by writing the program's fd into its slot, and off by deleting that
    slot. A `bpf_tail_call()` into a missing slot simply falls through to
    the next instruction, so a disabled stage costs one failed tail call
    and nothing else.
**/
struct {
  __type(key, __u32);
  __type(value, __u32);
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 100);
} protocol_redirecters SEC(".maps");

/** Same idea as `protocol_redirecters`, but for the egress (TC) pipeline.
There's no per-ethertype routing table on this side (egress only ever sees
IPv4 today), so every slot here is an optional rule stage. **/
struct {
  __type(key, __u32);
  __type(value, __u32);
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 100);
} engress_redirecters SEC(".maps");

/* Ingress (XDP) rule-stage slots in `protocol_redirecters`. Stays well away
 * from the protocol-routing indices (0-6, see `enum PROTOCOL_HANDLER`) so
 * the two index spaces can never collide. */
enum ingress_stage {
  INGRESS_STAGE_MAC = 20,
  INGRESS_STAGE_IPV4_ACL = 21,
  INGRESS_STAGE_TCP_PORT = 22,
  INGRESS_STAGE_UDP_PORT = 23,
  INGRESS_STAGE_IP_RATE_LIMIT = 24,
  INGRESS_STAGE_PORT_RATE_LIMIT = 25,
  INGRESS_STAGE_IPV6_ACL = 26,
};

/* Egress (TC) rule-stage slots in `engress_redirecters`, same deal. */
enum engress_stage {
  ENGRESS_STAGE_MAC = 0,
  ENGRESS_STAGE_IPV4_ACL = 1,
  ENGRESS_STAGE_TCP_PORT = 2,
  ENGRESS_STAGE_UDP_PORT = 3,
  ENGRESS_STAGE_IP_RATE_LIMIT = 4,
  ENGRESS_STAGE_PORT_RATE_LIMIT = 5,
  ENGRESS_STAGE_IPV6_ACL = 6,
};

/* Fixed one-second windows, keyed with the same host-order IP/port
 * convetions as the ACL maps. Spin locks force a HASH (not LRU_HASH) map;
 * capacity bounds memory use, and an absent key fails open if we're full. */
struct rate_entry {
  __u64 window_start_ns;
  __u32 count;
  struct bpf_spin_lock lock;
};

#define RATE_COUNTER_MAP(name) \
struct { \
  __uint(type, BPF_MAP_TYPE_HASH); \
  __uint(max_entries, 4096); \
  __type(key, __u32); \
  __type(value, struct rate_entry); \
} name SEC(".maps")

#define RATE_PPS_MAP(name) \
struct { \
  __uint(type, BPF_MAP_TYPE_ARRAY); \
  __uint(max_entries, 1); \
  __type(key, __u32); \
  __type(value, __u32); \
} name SEC(".maps")

RATE_COUNTER_MAP(ingress_ip_rate_limit);
RATE_COUNTER_MAP(ingress_port_rate_limit);
RATE_COUNTER_MAP(engress_ip_rate_limit);
RATE_COUNTER_MAP(engress_port_rate_limit);
RATE_PPS_MAP(ingress_ip_rate_limit_pps);
RATE_PPS_MAP(ingress_port_rate_limit_pps);
RATE_PPS_MAP(engress_ip_rate_limit_pps);
RATE_PPS_MAP(engress_port_rate_limit_pps);

#undef RATE_COUNTER_MAP
#undef RATE_PPS_MAP

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u8);
} ingress_tcp_src_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u8);
} ingress_udp_src_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} ingress_src_ips SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 1024);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u8);
} ingress_src_ranges SEC(".maps");

/**
Egress counterparts of the four maps above — same byte-order contract (the
comment on `ingress_{tcp,udp}_src_ports`/`ingress_src_ips`/`ingress_src_ranges`
applies here too), just matching on destination instead of source.
**/

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u8);
} engress_tcp_dst_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u8);
} engress_udp_dst_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} engress_dst_ips SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 1024);
  __type(key, struct ipv4_lpm_key);
  __type(value, __u8);
} engress_dst_ranges SEC(".maps");

/**
IPv6 counterparts of `ingress_src_ips`/`ingress_src_ranges` and
`engress_dst_ips`/`engress_dst_ranges` — same exact-match-then-CIDR-trie
shape, just 16-byte addresses in place of 4.
**/

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct ipv6_addr_key);
  __type(value, __u8);
} ingress_src_ips6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 1024);
  __type(key, struct ipv6_lpm_key);
  __type(value, __u8);
} ingress_src_ranges6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct ipv6_addr_key);
  __type(value, __u8);
} engress_dst_ips6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 1024);
  __type(key, struct ipv6_lpm_key);
  __type(value, __u8);
} engress_dst_ranges6 SEC(".maps");

/**
Continues the ingress pipeline past an IPv4-ACL stage (whether that stage
is actually installed or not — both `ipv4handler`'s disabled-ACL fallback
path and `ingress_ipv4_acl_stage`'s not-blocked path end up here) by
tail-calling into the TCP/UDP port stage macthing the packet's IP protocol.
A non-TCP/UDP packet, or a missing/disabled port stage, just falls through
to the caller's own XDP_PASS.
**/
static __always_inline void ingress_route_by_ip_proto(struct xdp_md *ctx, __u8 proto) {
  if (proto == IPPROTO_TCP) {
    bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_TCP_PORT);
  } else if (proto == IPPROTO_UDP) {
    bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_UDP_PORT);
  }
}

/** Egress version of `ingress_route_by_ip_proto`. **/
static __always_inline void engress_route_by_ip_proto(struct __sk_buff *ctx, __u8 proto) {
  if (proto == IPPROTO_TCP) {
    bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_TCP_PORT);
  } else if (proto == IPPROTO_UDP) {
    bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_UDP_PORT);
  }
}
