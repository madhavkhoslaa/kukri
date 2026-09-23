// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include "tc_actions.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 ENGRESS_IPV4_ACL_STAGE_SLOT = 1;

/**
Optional rule stage (`ENGRESS_STAGE_IPV4_ACL`): blocks a packet whose
destination IPv4 adress matches an exact-match entry in `engress_dst_ips`
or a CIDR range in `engress_dst_ranges`. If not blocked, it carries on to
whichever TCP/UDP port stage is enabled.
**/
SEC("tc")
int engress_ipv4_acl_stage(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *ip = parse_ipv4(data, data_end);
  if (!ip) {
    return TC_ACT_OK;
  }

  __u32 dst_ip = bpf_ntohl(ip->daddr);
  if (bpf_map_lookup_elem(&engress_dst_ips, &dst_ip)) {
    submit_drop_event(1, KUKRI_REASON_IPV4_ACL, dst_ip, 0, 0);
    return TC_ACT_SHOT;
  }

  struct ipv4_lpm_key key = {
    .prefixlen = 32,
    .data = ip->daddr, // wire order — the LPM trie wants raw octets
  };
  if (bpf_map_lookup_elem(&engress_dst_ranges, &key)) {
    submit_drop_event(1, KUKRI_REASON_IPV4_ACL, dst_ip, 0, 0);
    return TC_ACT_SHOT;
  }

  engress_route_by_ip_proto(ctx, ip->protocol);
  return TC_ACT_OK;
}
