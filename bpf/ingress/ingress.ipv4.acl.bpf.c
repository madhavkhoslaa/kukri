// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 INGRESS_IPV4_ACL_STAGE_SLOT = 21;

/**
Optional rule stage (`INGRESS_STAGE_IPV4_ACL`): blocks packets whose source
IPv4 address matches an exact-match entry in `ingress_src_ips` or a CIDR
range in `ingress_src_ranges`. If not blocked, continues to whichever
TCP/UDP port stage is enabled — same as `ipv4handler`'s fallback when this
stage is disabled, so toggling it never affects wether port rules run.
**/
SEC("xdp")
int ingress_ipv4_acl_stage(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *ip = parse_ipv4(data, data_end);
  if (!ip) {
    return XDP_PASS;
  }

  __u32 src_ip = bpf_ntohl(ip->saddr);
  if (bpf_map_lookup_elem(&ingress_src_ips, &src_ip)) {
    submit_drop_event(0, KUKRI_REASON_IPV4_ACL, src_ip, 0, 0);
    return XDP_DROP;
  }

  struct ipv4_lpm_key key = {
    .prefixlen = 32,
    .data = ip->saddr, // wire order — the LPM trie wants raw octets
  };
  if (bpf_map_lookup_elem(&ingress_src_ranges, &key)) {
    submit_drop_event(0, KUKRI_REASON_IPV4_ACL, src_ip, 0, 0);
    return XDP_DROP;
  }

  ingress_route_by_ip_proto(ctx, ip->protocol);
  return XDP_PASS;
}
