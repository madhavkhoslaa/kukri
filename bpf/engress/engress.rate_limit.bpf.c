// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include "rate_limit.bpf.h"
#include "events.bpf.h"
#include "tc_actions.bpf.h"
#include <bpf/bpf_endian.h>

const volatile __u32 ENGRESS_IP_RATE_LIMIT_STAGE_SLOT = 4;
const volatile __u32 ENGRESS_PORT_RATE_LIMIT_STAGE_SLOT = 5;

SEC("tc")
int engress_ip_rate_limit_stage(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return TC_ACT_OK;
  }
  struct ethhdr *eth = data;
  __u16 ethertype = bpf_ntohs(eth->h_proto);
  if (ethertype == 0x0800) {
    struct iphdr *ip = parse_ipv4(data, data_end);
    if (ip) {
      __u32 dst_ip = bpf_ntohl(ip->daddr);
      if (rate_exceeded(&engress_ip_rate_limit, &engress_ip_rate_limit_pps, dst_ip)) {
        submit_drop_event(1, KUKRI_REASON_IP_RATE_LIMIT, dst_ip, 0, 0);
        return TC_ACT_SHOT;
      }
    }
  }
  engress_after_ip_rate(ctx, ethertype);
  return TC_ACT_OK;
}

SEC("tc")
int engress_port_rate_limit_stage(struct __sk_buff *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (!eth_check(data, data_end)) {
    return TC_ACT_OK;
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
      if (rate_exceeded(&engress_port_rate_limit, &engress_port_rate_limit_pps, port)) {
        submit_drop_event(1, KUKRI_REASON_PORT_RATE_LIMIT, 0, port, 0);
        return TC_ACT_SHOT;
      }
    }
  }
next:
  engress_after_port_rate(ctx, ethertype);
  return TC_ACT_OK;
}
