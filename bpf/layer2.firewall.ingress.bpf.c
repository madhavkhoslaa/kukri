// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
/**
This is for completely rejecting ingress packets based off rules
1. Incoming IP Addr
2. Incoming IP range
3. Incoming Port
 **/

#include "acl_maps.bpf.h"
#include "inline.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/// Tail-call dispatch table for ingress sub-programs. Populated from
/// userspace via `bpf_prog_update()`/skeleton prog-array fixups; nothing
/// calls `bpf_tail_call()` into it yet.
struct {
  __type(key, __u32);
  __type(value, __u32);
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 100);
} layer_2_prog_map SEC(".maps");

/**
Data-plumbing maps for the userspace ACL config (ports/IPs/CIDR ranges to
block on ingress). `ingress_hook` below does not consult these yet — they
are populated from userspace so the wiring exists, but enforcement is a
separate step.

Byte-order contract for whoever writes that consumer:
- `ingress_{tcp,udp}_src_ports`: keyed directly by port number (as a plain
  array index), so a lookup needs the host-native port value — convert wire
  fields with `bpf_ntohs()` first.
- `ingress_src_ips`: exact-match hash, host-native `__u32`. Convert with
  `bpf_ntohl()` before lookup.
- `ingress_src_ranges`: LPM trie. `data` must stay in raw wire/octet order
  (do NOT `bpf_ntohl()` it) since the trie matches bytes MSB-first;
  `prefixlen` is a plain host-native `__u32`.
**/

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
Whether each rule category is enabled, indexed by `enum rule_flag` rather
than a name string — BPF map keys are fixed-size blobs compared byte for
byte, so a `char *` key (a pointer value, not string contents) never did
what the old design implied.
**/

enum rule_flag {
  RULE_MAC_PORT_INBOUND = 0,
  RULE_MAC_PORT_OUTBOUND,
  RULE_IP_INBOUND,
  RULE_IP_OUTBOUND,
  RULE_FLAG_COUNT,
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, RULE_FLAG_COUNT);
  __type(key, __u32);
  __type(value, __u8);
} enabled_rules SEC(".maps");

SEC("xdp")
int ingress_hook(struct xdp_md *ctx) {
  if (!layer_2_check((void *)(long)ctx->data, (void *)(long)ctx->data_end)) {
    return XDP_PASS;
  }
  struct ethhdr *ethAddr = (void *)(long)ctx->data;
  if (ethAddr->h_proto == 0x0800) {
    // TODO: And IPv4 handler is enabled
    // If this is an IPv4 header
  }
  if (ethAddr->h_proto == 0x86DD) {
    // TODO: And IPv6 handler is enabled
    // If this is an IPv6 header
  }
  return XDP_PASS;
}
