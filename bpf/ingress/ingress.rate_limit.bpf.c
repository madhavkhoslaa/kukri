// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "rate_limit.bpf.h"
#include "events.bpf.h"
#include <bpf/bpf_endian.h>

const volatile __u32 INGRESS_IP_RATE_LIMIT_STAGE_SLOT = 24;
const volatile __u32 INGRESS_PORT_RATE_LIMIT_STAGE_SLOT = 25;

SEC("xdp")
int ingress_ip_rate_limit_stage(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return XDP_PASS;
  }
  struct ethhdr *eth = data;
  __u16 ethertype = bpf_ntohs(eth->h_proto);
  if (ethertype == 0x0800) {
    struct iphdr *ip = parse_ipv4(data, data_end);
    if (ip) {
      __u32 src_ip = bpf_ntohl(ip->saddr);
      if (rate_exceeded(&ingress_ip_rate_limit, &ingress_ip_rate_limit_pps, src_ip)) {
        submit_drop_event(0, KUKRI_REASON_IP_RATE_LIMIT, src_ip, 0, 0);
        return XDP_DROP;
      }
    }
  }
  ingress_after_ip_rate(ctx, ethertype);
  return XDP_PASS;
}

SEC("xdp")
int ingress_port_rate_limit_stage(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return XDP_PASS;
  }
  struct ethhdr *eth = data;
  __u16 ethertype = bpf_ntohs(eth->h_proto);
  if (ethertype == 0x0800) {
    struct iphdr *ip = parse_ipv4(data, data_end);
    if (ip) {
      void *payload = ipv4_payload(ip, data_end);
      __u32 port;
      if (ip->protocol == IPPROTO_TCP && payload && tcp_check(payload, data_end)) {
        struct tcphdr *tcp = payload;
        port = bpf_ntohs(tcp->dest);
      } else if (ip->protocol == IPPROTO_UDP && payload && udp_check(payload, data_end)) {
        struct udphdr *udp = payload;
        port = bpf_ntohs(udp->dest);
      } else {
        goto next;
      }
      if (rate_exceeded(&ingress_port_rate_limit, &ingress_port_rate_limit_pps, port)) {
        submit_drop_event(0, KUKRI_REASON_PORT_RATE_LIMIT, 0, port, 0);
        return XDP_DROP;
      }
    }
  }
next:
  ingress_after_port_rate(ctx, ethertype);
  return XDP_PASS;
}
