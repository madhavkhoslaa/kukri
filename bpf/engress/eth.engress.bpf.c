// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include "tc_actions.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* Egress (destination-MAC) block list. Same key scheme as
 * `ingress_blocked_mac` in eth.ingress.bpf.c — see the comment there. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, __u8);
} engress_blocked_mac SEC(".maps");

const volatile __u32 ENGRESS_ETH_FIREWALL_SLOT = 0;

/**
Optional rule stage (`ENGRESS_STAGE_MAC`): drops frames whose destination
MAC is blocked; otherwise it continues the pipeline exactly like
`engress_hook` would have (IPv4 check + ACL-stage tail call).
**/
SEC("tc")
int engress_eth_firewall(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return TC_ACT_OK;
  }

  struct ethhdr *eth_header = data;
  __u64 dst_mac = 0;
  __builtin_memcpy(&dst_mac, eth_header->h_dest, ETH_ALEN);
  if (bpf_map_lookup_elem(&engress_blocked_mac, &dst_mac)) {
    submit_drop_event(1, KUKRI_REASON_MAC, 0, 0, eth_header->h_dest);
    return TC_ACT_SHOT;
  }

  __u16 ethertype = bpf_ntohs(eth_header->h_proto);
  if (ethertype == 0x0800) {
    bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_IPV4_ACL);
  } else if (ethertype == 0x86DD) {
    bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_IPV6_ACL);
  }
  return TC_ACT_OK;
}
