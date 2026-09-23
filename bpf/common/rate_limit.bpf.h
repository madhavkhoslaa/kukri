// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
#pragma once

#include "acl_maps.bpf.h"
#include "inline.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Insert a zeroed value only when the key is absent. Once published, the
 * lock-bearing value is changed in place, including across window
 * boundaries.
 */
static __always_inline bool rate_exceeded(void *counters, void *limit_map, __u32 key) {
  __u32 zero = 0;
  __u32 *limit = bpf_map_lookup_elem(limit_map, &zero);
  if (!limit || !*limit) {
    return false;
  }
  __u32 pps = *limit;
  __u64 now = bpf_ktime_get_ns();
  struct rate_entry *entry = bpf_map_lookup_elem(counters, &key);
  if (!entry) {
    struct rate_entry initial = {};
    bpf_map_update_elem(counters, &key, &initial, BPF_NOEXIST);
    entry = bpf_map_lookup_elem(counters, &key);
    if (!entry) {
      return false; // Map full or allocation failed: fail open.
    }
  }

  __u32 count;
  bpf_spin_lock(&entry->lock);
  if (entry->window_start_ns == 0 ||
      (now >= entry->window_start_ns && now - entry->window_start_ns >= 1000000000ULL)) {
    entry->window_start_ns = now;
    entry->count = 1;
  } else if (entry->count != (__u32)-1) {
    // A stale now from before another CPU's new window: don't rewind the window with it.
    entry->count++;
  }
  count = entry->count;
  bpf_spin_unlock(&entry->lock);
  return count > pps;
}

static __always_inline void ingress_after_port_rate(struct xdp_md *ctx, __u16 ethertype) {
  bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_MAC);
  bpf_tail_call(ctx, &protocol_redirecters, protocol_to_array_idx(ethertype));
}

static __always_inline void ingress_after_ip_rate(struct xdp_md *ctx, __u16 ethertype) {
  bpf_tail_call(ctx, &protocol_redirecters, INGRESS_STAGE_PORT_RATE_LIMIT);
  ingress_after_port_rate(ctx, ethertype);
}

static __always_inline void engress_after_port_rate(struct __sk_buff *ctx, __u16 ethertype) {
  bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_MAC);
  if (ethertype == 0x0800) {
    bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_IPV4_ACL);
  } else if (ethertype == 0x86DD) {
    bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_IPV6_ACL);
  }
}

static __always_inline void engress_after_ip_rate(struct __sk_buff *ctx, __u16 ethertype) {
  bpf_tail_call(ctx, &engress_redirecters, ENGRESS_STAGE_PORT_RATE_LIMIT);
  engress_after_port_rate(ctx, ethertype);
}
