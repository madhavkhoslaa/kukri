// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"

#include "vmlinux.h"
#include "inline.bpf.h"
#include <bpf/bpf_helpers.h>

struct {
  __type(key, __u32);
  __type(value, __u32);
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 10);
} layer_2_prog_map SEC(".maps");


struct {
  __type(key, __u32);
  __type(value, __u32);
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 10);
} layer_1_prog_map SEC(".maps");


/**
Map that enables if rules are enabled or not.
This is done because I do not want to load progmaps
dynamically from the userspace.
TODO: Not sure if this is performant over just having prog maps. Do a comparison later
**/
/**
Example entries[Include both directions for packets]
mac_port_inbound_block_rule = true/false;
mac_port_outbound_block_rule = true/false
**/
struct {
 __type(key, char*);
 __type(value, bool);
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, 20);
} layer_1_enabled_rules SEC(".maps");


/**
Example entries[Include both directions for packets]
ip_inbound_block_rule = true/false;
in_outbound_block_rule = true/false
**/
struct {
 __type(key, char*);
 __type(value, bool);
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, 20);
} layer_2_enabled_rules SEC(".maps");
