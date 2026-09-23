// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include <bpf/bpf_helpers.h>

/**
Permanent tail-call target for IPv4 frames (registered at
`protocol_redirecters[IPv4]` by userspace at load time, unlike the rule
stages — this is routing, not a toggleable feature). Hands off to the
IP-ACL stage if one is currently enabled; otherwise it routes straight to
whichever TCP/UDP port stage is enabled, since that stage still needs to
run even when IP-address blocking doesnt.
**/
SEC("xdp")
int ipv4handler(struct xdp_md* ctx){
  bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_IPV4_ACL);

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct iphdr *ip = parse_ipv4(data, data_end);
  if (!ip) {
    return XDP_PASS;
  }
  ingress_route_by_ip_proto(ctx, ip->protocol);
  return XDP_PASS;
}
