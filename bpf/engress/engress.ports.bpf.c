// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include "tc_actions.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 ENGRESS_TCP_PORT_STAGE_SLOT = 2;
const volatile __u32 ENGRESS_UDP_PORT_STAGE_SLOT = 3;

/** Egress version of `ingress_port_stage_payload` — same idea, finds the
 * L4 payload for either IP version so the TCP/UDP-port maps stay shared
 * across both. **/
__always_inline void *engress_port_stage_payload(void *data, void *data_end) {
  if (!eth_check(data, data_end)) {
    return 0;
  }
  struct ethhdr *eth_header = data;
  __u16 ethertype = bpf_ntohs(eth_header->h_proto);
  if (ethertype == 0x0800) {
    struct iphdr *ip = parse_ipv4(data, data_end);
    return ip ? ipv4_payload(ip, data_end) : 0;
  }
  if (ethertype == 0x86DD) {
    struct ipv6hdr *ip6 = parse_ipv6(data, data_end);
    return ip6 ? ipv6_payload(ip6, data_end) : 0;
  }
  return 0;
}

/**
Optional rule stage (`ENGRESS_STAGE_TCP_PORT`): drops a TCP packet (IPv4 or
IPv6) whose destnation port is in `engress_tcp_dst_ports`. Terminal stage.
**/
SEC("tc")
int engress_tcp_port_stage(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *payload = engress_port_stage_payload(data, data_end);
  if (!payload || !tcp_check(payload, data_end)) {
    return TC_ACT_OK;
  }

  struct tcphdr *tcp = payload;
  __u32 port = bpf_ntohs(tcp->dest);
  __u8 *blocked = bpf_map_lookup_elem(&engress_tcp_dst_ports, &port);
  if (blocked && *blocked) {
    submit_drop_event(1, KUKRI_REASON_TCP_PORT, 0, port, 0);
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;
}

/** UDP version of `engress_tcp_port_stage` (`ENGRESS_STAGE_UDP_PORT`). **/
SEC("tc")
int engress_udp_port_stage(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *payload = engress_port_stage_payload(data, data_end);
  if (!payload || !udp_check(payload, data_end)) {
    return TC_ACT_OK;
  }

  struct udphdr *udp = payload;
  __u32 port = bpf_ntohs(udp->dest);
  __u8 *blocked = bpf_map_lookup_elem(&engress_udp_dst_ports, &port);
  if (blocked && *blocked) {
    submit_drop_event(1, KUKRI_REASON_UDP_PORT, 0, port, 0);
    return TC_ACT_SHOT;
  }
  return TC_ACT_OK;
}
