// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
/**
This is for completely rejecting engress packets based off rules
1. Outgoing IP Addr
2. Outgoing IP range
3. Outgoing Port
 **/

#include "vmlinux.h"
#include "inline.bpf.h"
#include "tc_actions.bpf.h"
#include <bpf/bpf_helpers.h>
SEC("tc")
int engress_hook(struct __sk_buff* ctx){
  return TC_ACT_OK;
}
