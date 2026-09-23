// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
#pragma once

enum kukri_drop_reason {
  KUKRI_REASON_MAC = 0,
  KUKRI_REASON_IPV4_ACL = 1,
  KUKRI_REASON_TCP_PORT = 2,
  KUKRI_REASON_UDP_PORT = 3,
  KUKRI_REASON_IP_RATE_LIMIT = 4,
  KUKRI_REASON_PORT_RATE_LIMIT = 5,
  // `struct kukri_event` only has a 4-byte `ip` field (IPv4), so IPv6 ACL
  // drops get counted under this reason with no address attached. The
  // Summary tally still shows how many IPv6 drops happened, just not
  // which address, unlike IPv4.
  KUKRI_REASON_IPV6_ACL = 6
};

struct kukri_event {
  __u64 ts_ns;
  __u8 direction;
  __u8 reason;
  __u32 ip;
  __u16 port;
  __u8 mac[6];
  __u8 _pad[1];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, (1 << 16));
} kukri_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} packets_processed SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} packets_rejected SEC(".maps");

static __always_inline void bump_packets_rejected(void) {
  __u32 key = 0;
  __u64 *count = bpf_map_lookup_elem(&packets_rejected, &key);

  if (count)
    __sync_fetch_and_add(count, 1);
}

static __always_inline void submit_drop_event(__u8 direction, __u8 reason,
                                              __u32 ip, __u16 port,
                                              const __u8 *mac) {
  // A rejected packet is a rejected packet whether or not this event ever
  // makes it into the ring buffer, so count it before reserving.
  bump_packets_rejected();

  struct kukri_event *event = bpf_ringbuf_reserve(&kukri_events, sizeof(struct kukri_event), 0);
  if (!event)
    return;

  __builtin_memset(event, 0, sizeof(*event));
  event->ts_ns = bpf_ktime_get_ns();
  event->direction = direction;
  event->reason = reason;
  event->ip = ip;
  event->port = port;
  if (mac)
    __builtin_memcpy(event->mac, mac, 6);
  bpf_ringbuf_submit(event, 0);
}

static __always_inline void bump_packets_processed(void) {
  __u32 key = 0;
  __u64 *count = bpf_map_lookup_elem(&packets_processed, &key);

  if (count)
    __sync_fetch_and_add(count, 1);
}
