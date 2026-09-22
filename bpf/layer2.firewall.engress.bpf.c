// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
/**
This is for completely rejecting engress packets based off rules
1. Outgoing IP Addr
2. Outgoing IP range
3. Outgoing Port
 **/

#include "tc_actions.bpf.h"
#include "vmlinux.h"
#include "acl_maps.bpf.h"
#include <bpf/bpf_helpers.h>

/**
Data-plumbing maps for the userspace ACL config (ports/IPs/CIDR ranges to
block on egress). `engress_hook` below does not consult these yet — they
are populated from userspace so the wiring exists, but enforcement is a
separate step.

Byte-order contract for whoever writes that consumer:
- `engress_{tcp,udp}_dst_ports`: keyed directly by port number (as a plain
  array index), so a lookup needs the host-native port value — convert wire
  fields with `bpf_ntohs()` first.
- `engress_dst_ips`: exact-match hash, host-native `__u32`. Convert with
  `bpf_ntohl()` before lookup.
- `engress_dst_ranges`: LPM trie. `data` must stay in raw wire/octet order
  (do NOT `bpf_ntohl()` it) since the trie matches bytes MSB-first;
  `prefixlen` is a plain host-native `__u32`.
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

SEC("tc")
int engress_hook(struct __sk_buff *ctx) { return TC_ACT_OK; }
