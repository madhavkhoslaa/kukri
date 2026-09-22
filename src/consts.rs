//! Names of BPF programs that Rust code looks up *by name* rather than
//! through generic discovery (see `bpf::programs()`), so a rename in the
//! `.bpf.c` SEC(...) function has one Rust-side place to update instead of
//! a string literal buried at each use site.
//!
//! `build.rs` reads this file as text and checks every quoted program-name
//! value below actually appears in the generated BPF skeleton
//! (`kukri.skel.rs`) — if a name here doesn't match anything actually
//! compiled into the object (typo, rename on either side, function
//! deleted), the build fails with a clear message instead of this drifting
//! silently until something fails to attach at runtime.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Which side of the firewall a BPF program handles. Kept local to this
/// module (rather than reusing the TUI's own direction type) so this file
/// has no dependency on anything above the BPF-wiring layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Ingress,
    Engress,
}

/// Maps each direction to the BPF program that direction's master switch
/// attaches/detaches.
pub static PROGRAM_NAMES: LazyLock<HashMap<Direction, &'static str>> = LazyLock::new(|| {
    HashMap::from([(Direction::Ingress, "ingress_hook"), (Direction::Engress, "engress_hook")])
});
