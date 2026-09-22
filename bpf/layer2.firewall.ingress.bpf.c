// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
/**
This is for completely rejecting ingress packets based off rules
1. Incoming IP Addr
2. Incoming IP range
3. Incoming Port
 **/

#include "vmlinux.h"
#include "inline.bpf.h"
#include <bpf/bpf_helpers.h>

struct {
  __type(key, __u32);
  __type(value, __u32);
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 100);
} layer_2_prog_map SEC(".maps");


/**
Map that enables if rules are enabled or not.
This is done because I do not want to load progmaps
dynamically from the userspace.
TODO: Not sure if this is performant over just having prog maps. Do a comparison later
**/

struct {
 __type(key, char*);
 __type(value, bool);
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, 20);
} enabled_rules SEC(".maps");


/**
Example entries[Include both directions for packets]
mac_port_inbound_block_rule = true/false;
mac_port_outbound_block_rule = true/false
ip_inbound_block_rule = true/false;
in_outbound_block_rule = true/false
**/

SEC("xdp")
int ingress_hook(struct xdp_md* ctx){
 if(!layer_2_check((void*)(long)ctx->data, (void* )(long)ctx->data_end)){
  return XDP_PASS;
 }
 struct ethhdr* ethAddr = (void*)(long)ctx->data;
 // bpf_printk("srcmac=%x and destmac=%x", ethAddr->h_source,ethAddr->h_dest);
 if(ethAddr->h_proto == 0x0800){
  // TODO: And IPv4 handler is enabled
  // If this is an IPv4 header
 }
 if(ethAddr->h_proto == 0x86DD){
  // TODO: And IPv6 handler is enabled
  // If this is an IPv6 header
 }
 return XDP_PASS;
}
