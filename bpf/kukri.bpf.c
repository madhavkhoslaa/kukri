// SPDX-License-Identifier: GPL-3.0-only

#include "license.bpf.h"
#include "vmlinux.h"

// Ingress (XDP) pipeline: entry point, then the permanent protocol-routing
// targets, then the optional rule stages the entry point (or a routing
// target's fallback) tail-calls into.
#include "ingress/ingress.hook.bpf.c"
#include "ingress/eth.ingress.bpf.c"
#include "ingress/ipv4.ingress.bpf.c"
#include "ingress/ipv6.ingress.bpf.c"
#include "ingress/ingress.ipv4.acl.bpf.c"
#include "ingress/ingress.ipv6.acl.bpf.c"
#include "ingress/ingress.ports.bpf.c"
#include "ingress/ingress.rate_limit.bpf.c"

// Egress (TC) pipeline: entry point, then its optional rule stages, same deal.
#include "engress/engress.hook.bpf.c"
#include "engress/eth.engress.bpf.c"
#include "engress/engress.ipv4.acl.bpf.c"
#include "engress/engress.ipv6.acl.bpf.c"
#include "engress/engress.ports.bpf.c"
#include "engress/engress.rate_limit.bpf.c"
