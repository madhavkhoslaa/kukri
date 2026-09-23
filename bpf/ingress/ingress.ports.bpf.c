// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "acl_maps.bpf.h"
#include "events.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 INGRESS_TCP_PORT_STAGE_SLOT = 22;
const volatile __u32 INGRESS_UDP_PORT_STAGE_SLOT = 23;

/* Finds the L4 payload for either IP version, sharing the same TCP/UDP
 * port maps no matter which one the packet actully used — the port-block
 * lists aren't IP-version-specific. Returns NULL (and the caller should
 * XDP_PASS/TC_ACT_OK) for anything that isn't IPv4 or IPv6, or that trips
 * either version's own bounds checks. */
__always_inline void *ingress_port_stage_payload(void *data, void *data_end) {
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
Optional rule stage (`INGRESS_STAGE_TCP_PORT`): drops a TCP packet (IPv4 or
IPv6) whose source port is listed in `ingress_tcp_src_ports`. It's the
terminal stage — nothing left to tail-call into after a port check, so it
just falls back to XDP_PASS either way.
**/
SEC("xdp")
int ingress_tcp_port_stage(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *payload = ingress_port_stage_payload(data, data_end);
  if (!payload || !tcp_check(payload, data_end)) {
    return XDP_PASS;
  }

  struct tcphdr *tcp = payload;
  __u32 port = bpf_ntohs(tcp->source);
  __u8 *blocked = bpf_map_lookup_elem(&ingress_tcp_src_ports, &port);
  if (blocked && *blocked) {
    submit_drop_event(0, KUKRI_REASON_TCP_PORT, 0, port, 0);
    return XDP_DROP;
  }
  return XDP_PASS;
}

/** UDP version of `ingress_tcp_port_stage` (`INGRESS_STAGE_UDP_PORT`). **/
SEC("xdp")
int ingress_udp_port_stage(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  void *payload = ingress_port_stage_payload(data, data_end);
  if (!payload || !udp_check(payload, data_end)) {
    return XDP_PASS;
  }

  struct udphdr *udp = payload;
  __u32 port = bpf_ntohs(udp->source);
  __u8 *blocked = bpf_map_lookup_elem(&ingress_udp_src_ports, &port);
  if (blocked && *blocked) {
    submit_drop_event(0, KUKRI_REASON_UDP_PORT, 0, port, 0);
    return XDP_DROP;
  }
  return XDP_PASS;
}
