#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


__always_inline bool layer_2_check(void* start, void* end){
  if((char*)(long)start >= (char*)(long)end){
    return false;
  }
  return true;
}

