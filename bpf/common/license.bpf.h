// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * The kernel's BPF loader only unlocks GPL-only helpers for a fixed set of
 * literal SEC("license") strings (see license_is_gpl_compatible() in
 * kernel/bpf/syscall.c): "GPL", "GPL v2", "GPL and additional rights",
 * "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL". Anything else, say
 * "GPL-3.0", isn't recognized and you just silently end up with GPL-only
 * helpers blocked. So "GPL" is the right value regardless of which GPL
 * version actully covers the surrounding source (this project is
 * GPL-3.0-only, see /LICENSE).
 */
char LICENSE[] SEC("license") = "GPL";
