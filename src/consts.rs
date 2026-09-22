use std::collections::HashMap;
use std::sync::LazyLock;

// build.rs checks this against the compiled skeleton both ways: every name
// here must exist in the object, and every program in the object must be
// listed here somewhere, even if just under Ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttachType {
    Xdp,
    Tc,
    Kprobe,
    Kretprobe,
    Fentry,
    Fexit,
    Ignore, // already self-attaches via its own SEC(), no mount step needed
}

pub static PROGRAMS: LazyLock<HashMap<AttachType, Vec<&'static str>>> = LazyLock::new(|| {
    HashMap::from([
        (AttachType::Xdp, vec!["ingress_hook"]),
        (AttachType::Tc, vec!["engress_hook"]),
        (AttachType::Kprobe, vec![]),
        (AttachType::Kretprobe, vec![]),
        (AttachType::Fentry, vec![]),
        (AttachType::Fexit, vec![]),
        (AttachType::Ignore, vec!["handle_execve"]),
    ])
});

// which program each direction's master switch in Settings attaches/detaches
pub const INGRESS_PROGRAM: &str = "ingress_hook";
pub const ENGRESS_PROGRAM: &str = "engress_hook";
