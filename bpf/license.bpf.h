// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <bpf/bpf_helpers.h>

/*
 * The kernel's BPF loader only unlocks GPL-only helpers for a fixed set of
 * literal SEC("license") strings (see license_is_gpl_compatible() in
 * kernel/bpf/syscall.c): "GPL", "GPL v2", "GPL and additional rights",
 * "Dual BSD/GPL", "Dual MIT/GPL", "Dual MPL/GPL". A string like "GPL-3.0"
 * is NOT recognized and would silently fall back to GPL-only helpers being
 * blocked. "GPL" is the correct value here regardless of which GPL version
 * covers the surrounding source (this project uses GPL-3.0-only, see
 * /LICENSE).
 */
char LICENSE[] SEC("license") = "GPL";
