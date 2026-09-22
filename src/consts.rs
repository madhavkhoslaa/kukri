//! Names of BPF programs that Rust code looks up *by name* rather than
//! through generic discovery (see `bpf::programs()`), so a rename in the
//! `.bpf.c` `SEC(...)` function has one Rust-side place to update instead of
//! a string literal buried at each use site.
//!
//! `build.rs` reads this file as text and checks every value below actually
//! appears in the generated BPF skeleton (`kukri.skel.rs`) — if a name here
//! doesn't match anything actually compiled into the object (typo, rename on
//! either side, function deleted), the build fails with a clear message
//! instead of this drifting silently until something fails to attach at
//! runtime.

/// The `SEC("xdp")` program handling ingress traffic.
pub const INGRESS_PROGRAM: &str = "ingress_hook";

/// The `SEC("tc")` program handling egress traffic.
pub const ENGRESS_PROGRAM: &str = "engress_hook";
