// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


__always_inline bool layer_2_check(void* start, void* end){
  if((char*)(long)start >= (char*)(long)end){
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

