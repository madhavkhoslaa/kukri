// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * `<linux/if_ether.h>` (which we'd want for `ETH_ALEN`) redefines types
 * vmlinux.h already pulled in from kernel BTF — same class of clash that
 * `tc_actions.bpf.h` documents for `<linux/pkt_cls.h>` — so it can't sit
 * alongside vmlinux.h. `struct ethhdr` already comes from vmlinux.h, and
 * `ETH_ALEN` is just the constant 6 anyway.
 */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

/* Ingress (source-MAC) block list. Keyed by the raw 8 bytes of a
 * zero-extended `__u64` holding the 6 MAC octets (see the memcpy below).
 * The key is 8 bytes becuase there's no native 6-byte integer type, not
 * because the top 2 bytes carry anything. Userspace (`sync_acl` in
 * src/bpf.rs) must build keys the exact same way: MAC bytes then two zero
 * bytes, with no endian conversion, since both sides just copy raw bytes
 * into a buffer. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, __u8);
} ingress_blocked_mac SEC(".maps");

const volatile __u32 ETH_FIREWALL_SLOT = 20;

/**
Optional rule stage (`INGRESS_STAGE_MAC`): only runs when userspace
inserted this program into `protocol_redirecters`. Drops the frame if the
source MAC is blocked; otherwise it continues the pipeline exactly like
`ingress_hook` would have (protocol-based tail call), so dissabling the
stage never affects anything downstream.
**/
SEC("xdp")
int eth_firewall(struct xdp_md* ctx){
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if(!eth_check(data, data_end)){
    return XDP_DROP;
  }
  struct ethhdr* eth_header = data;
  __u64 src_mac = 0;
  __builtin_memcpy(&src_mac, eth_header->h_source, ETH_ALEN);
  void* is_present = bpf_map_lookup_elem(&ingress_blocked_mac, &src_mac);
  if(is_present){
    submit_drop_event(0, KUKRI_REASON_MAC, 0, 0, eth_header->h_source);
    return XDP_DROP;
  }
  bpf_tail_call(ctx, &protocol_redirecters, protocol_to_array_idx(bpf_ntohs(eth_header->h_proto)));
  return XDP_PASS;
}
