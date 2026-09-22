// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
#pragma once

#include "vmlinux.h"

/* Key for an IPv4 CIDR entry in a BPF_MAP_TYPE_LPM_TRIE map, matching the
 * kernel's `struct bpf_lpm_trie_key` convention: a prefix length in bits,
 * followed by the value the trie matches against most-significant-byte
 * first. */
struct ipv4_lpm_key {
  __u32 prefixlen;
  __u32 data;
};
