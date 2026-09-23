// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
/**
Rejects egress packets completely, based on the rules below:
1. Outgoing MAC Addr
2. Outgoing IP Addr / range
3. Outgoing Port
 **/

#include "tc_actions.bpf.h"
#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "rate_limit.bpf.h"
#include "events.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/**
Egress entry point, mirroring `ingress_hook`: tries the optional MAC-block
stage first (falls through if disabled), then, for IPv4 traffic, hands off
to the optional IPv4-ACL stage. There's no per-ethertype routing table
here like `protocol_redirecters` has on the ingress side — egress only
ever seperates IPv4 from everything else, so that one check lives inline.
**/
SEC("tc")
int engress_hook(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return TC_ACT_OK;
  }
  bump_packets_processed();
  // Reused (not re-derived from `ctx->data`) below — see `ingress_hook`'s
  // comment on why reloading fresh after a tail call would lose the proof.
  struct ethhdr *eth_header = data;

  bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_IP_RATE_LIMIT);
  engress_after_ip_rate(ctx, bpf_ntohs(eth_header->h_proto));
  return TC_ACT_OK;
}
