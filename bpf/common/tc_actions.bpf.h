// SPDX-License-Identifier: GPL-3.0-only
#include "license.bpf.h"
#pragma once

/*
 * TC_ACT_* are plain #define constants in <linux/pkt_cls.h>, not BTF-backed
 * kernel types, so bpftool's BTF dump never puts them in vmlinux.h. XDP_PASS
 * and XDP_DROP are different: they're enumerators of the real `enum xdp_action`
 * type, so those do get dumped. The trouble with pulling <linux/pkt_cls.h> in
 * directly is that it also declares the TCA_ACT_*, TCA_EMATCH_TREE_*, and
 * TCA_FLOWER_KEY_CT_FLAGS_* enums, which vmlinux.h already has from kernel
 * BTF; haveing both headers at once then fails with "redefinition of
 * enumerator". Defining just the constants we need sidesteps the whole
 * collision.
 */
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
