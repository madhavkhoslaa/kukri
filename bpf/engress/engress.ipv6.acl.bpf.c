// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include "tc_actions.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 ENGRESS_IPV6_ACL_STAGE_SLOT = 6;

/**
Optional rule stage (`ENGRESS_STAGE_IPV6_ACL`): blocks a packet whose
destination IPv6 address matches an exact-match entry in
`engress_dst_ips6` or a CIDR range in `engress_dst_ranges6`. If not
blocked, carries on to whichever TCP/UDP port stage is enabled.
**/
SEC("tc")
int engress_ipv6_acl_stage(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6hdr *ip6 = parse_ipv6(data, data_end);
  if (!ip6) {
    return TC_ACT_OK;
  }

  struct ipv6_addr_key addr_key;
  __builtin_memcpy(addr_key.addr, &ip6->daddr, 16);
  if (bpf_map_lookup_elem(&engress_dst_ips6, &addr_key)) {
    submit_drop_event(1, KUKRI_REASON_IPV6_ACL, 0, 0, 0);
    return TC_ACT_SHOT;
  }

  struct ipv6_lpm_key key = {
    .prefixlen = 128,
  };
  __builtin_memcpy(key.data, &ip6->daddr, 16); // wire order — the LPM trie wants raw octets
  if (bpf_map_lookup_elem(&engress_dst_ranges6, &key)) {
    submit_drop_event(1, KUKRI_REASON_IPV6_ACL, 0, 0, 0);
    return TC_ACT_SHOT;
  }

  engress_route_by_ip_proto(ctx, ip6->nexthdr);
  return TC_ACT_OK;
}
