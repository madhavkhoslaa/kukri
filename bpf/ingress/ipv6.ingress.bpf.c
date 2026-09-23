// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include <bpf/bpf_helpers.h>

/**
Permanent tail-call target for IPv6 frames (registerd at
`protocol_redirecters[IPv6]`, like `ipv4handler`). Hands off to the IPv6
ACL stage if one is currently enabled; otherwise routes straight to
whichever TCP/UDP port stage is enabled — mirrors `ipv4handler` exactly.
**/
SEC("xdp")
int ipv6handler(struct xdp_md* ctx){
  bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_IPV6_ACL);

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ipv6hdr *ip6 = parse_ipv6(data, data_end);
  if (!ip6) {
    return XDP_PASS;
  }
  ingress_route_by_ip_proto(ctx, ip6->nexthdr);
  return XDP_PASS;
}
