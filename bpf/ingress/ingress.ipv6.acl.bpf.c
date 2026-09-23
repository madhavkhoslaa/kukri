// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 INGRESS_IPV6_ACL_STAGE_SLOT = 26;

/**
Optional rule stage (`INGRESS_STAGE_IPV6_ACL`): blocks packets whose source
IPv6 address matches an exact-match entry in `ingress_src_ips6` or a CIDR
range in `ingress_src_ranges6`. If not blocked, continues to whichever
TCP/UDP port stage is enabled — mirrors `ingress_ipv4_acl_stage`'s
fallback behavior exactley.
**/
SEC("xdp")
int ingress_ipv6_acl_stage(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6hdr *ip6 = parse_ipv6(data, data_end);
  if (!ip6) {
    return XDP_PASS;
  }

  struct ipv6_addr_key addr_key;
  __builtin_memcpy(addr_key.addr, &ip6->saddr, 16);
  if (bpf_map_lookup_elem(&ingress_src_ips6, &addr_key)) {
    submit_drop_event(0, KUKRI_REASON_IPV6_ACL, 0, 0, 0);
    return XDP_DROP;
  }

  struct ipv6_lpm_key key = {
    .prefixlen = 128,
  };
  __builtin_memcpy(key.data, &ip6->saddr, 16); // wire order — the LPM trie wants raw octets
  if (bpf_map_lookup_elem(&ingress_src_ranges6, &key)) {
    submit_drop_event(0, KUKRI_REASON_IPV6_ACL, 0, 0, 0);
    return XDP_DROP;
  }

  ingress_route_by_ip_proto(ctx, ip6->nexthdr);
  return XDP_PASS;
}
