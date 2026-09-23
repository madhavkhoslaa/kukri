// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include "vmlinux.h"
#include "license.bpf.h"
#include <bpf/bpf_helpers.h>



__always_inline bool eth_check(void* start, void* end){
  if((char*)(long)start + sizeof(struct ethhdr) > (char*)(long)end){
    return false;
  }
  return true;
}

__always_inline bool tcp_check(void* start, void* end){
  if((char*)(long)start + sizeof(struct tcphdr) > (char*)(long)end){
    return false;
  }
  return true;
}

__always_inline bool udp_check(void* start, void* end){
  if((char*)(long)start + sizeof(struct udphdr) > (char*)(long)end){
    return false;
  }
  return true;
}

/* Bounds-checked cast of an Ethernet frame at `data` to its IPv4 header.
 * Trusts the caller to already know this is IPv4 (routing here only ever
 * happens after an ethertype check); we dont re-derive the type, we just
 * make sure the header actually fits in the packet. */
__always_inline struct iphdr *parse_ipv4(void *data, void *data_end) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return 0;
  }
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return 0;
  }
  return ip;
}

/* Start of the IPv4 payload (i.e. the L4 header), honoring a variable-length
 * IP header (options) via IHL. The caller has to apply the protocol-specific
 * tcp_check()/udp_check() bounds check before dereferencing the result. */
__always_inline void *ipv4_payload(struct iphdr *ip, void *data_end) {
  (void)data_end;
  __u8 ihl = ip->ihl;
  if (ihl < 5) {
    ihl = 5;
  }
  return (char *)ip + (ihl * 4);
}

/* Bounds-checked cast of an Ethernet frame at `data` to its IPv6 header.
 * Same trust contract as `parse_ipv4`: the caller knows from the ethertype
 * that this is IPv6, we only double-check that the fixed-size (40 byte,
 * no options) header actually fits. */
__always_inline struct ipv6hdr *parse_ipv6(void *data, void *data_end) {
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return 0;
  }
  struct ipv6hdr *ip6 = (void *)(eth + 1);
  if ((void *)(ip6 + 1) > data_end) {
    return 0;
  }
  return ip6;
}

/* Start of the IPv6 payload (the L4 header). Unlike IPv4's IHL, the IPv6
 * header is always exactly 40 bytes, so there's no variable length to
 * account for here. This does NOT walk IPv6 extension headers (hop-by-hop,
 * routing, fragment, etc.) if present; `ip6->nexthdr` is trusted as the L4
 * protocol directly, matching this project's existing IPv4 path, which
 * likewise doesnt handle IP options beyond IHL. */
__always_inline void *ipv6_payload(struct ipv6hdr *ip6, void *data_end) {
  (void)data_end;
  return (char *)ip6 + sizeof(struct ipv6hdr);
}

enum PROTOCOL_HANDLER{
  ETH = 0,
  IPv4,
  IPv6,
  ARP,
  ICMP,
  TCP,
  UDP
};

__always_inline enum PROTOCOL_HANDLER protocol_to_array_idx(int protocol){
  switch (protocol ){
  case 0:
    return ETH;
  case 0x0800:
    return IPv4;
  case 0x86DD:
    return IPv6;
  case 0x806:
    return ARP;
  case 1:
    return ICMP;
  case 6:
    return TCP;
  case 17:
    return UDP;
  default:
    return IPv4;
}
}
