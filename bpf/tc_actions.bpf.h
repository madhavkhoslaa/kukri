// SPDX-License-Identifier: GPL-3.0-only
#pragma once

/*
 * TC_ACT_* are plain #define constants in <linux/pkt_cls.h>, not BTF-backed
 * kernel types, so bpftool's BTF dump never puts them in vmlinux.h (unlike
 * XDP_PASS/XDP_DROP, which are enumerators of the real `enum xdp_action`
 * type and do get dumped). Pulling in <linux/pkt_cls.h> directly to get
 * these clashes with vmlinux.h: that header also declares TCA_ACT_*,
 * TCA_EMATCH_TREE_*, and TCA_FLOWER_KEY_CT_FLAGS_* enums, which vmlinux.h
 * already carries from kernel BTF, so both headers together fail with
 * "redefinition of enumerator". Defining just the constants we need avoids
 * the collision entirely.
 */
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
