// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
/**
Rejects ingress packets completely, based on the rules below:
1. Incoming IP Addr
2. Incoming IP range
3. Incoming Port
 **/

#include "acl_maps.bpf.h"
#include "inline.bpf.h"
#include "rate_limit.bpf.h"
#include "events.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



SEC("xdp")
int ingress_hook(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return XDP_PASS;
  }
  bump_packets_processed();
  // `eth_header` has to be reused below, never re-derived from `ctx->data`:
  // a fresh reload after `bpf_tail_call()` becomes an unverified pointer
  // again as far as the verifier cares, even though nothing about the
  // packet actully changed on the fallthrough (disabled-stage) path.
  struct ethhdr *eth_header = data;

  // Each absent rate stage is one failed tail call; the same MAC/protocol
  // dispatch happens whether a rate stage is present or not.
  bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_IP_RATE_LIMIT);
  ingress_after_ip_rate(ctx, bpf_ntohs(eth_header->h_proto));
  return XDP_PASS;
}
