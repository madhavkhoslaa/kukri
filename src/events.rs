use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use libbpf_rs::RingBufferBuilder;

use crate::bpf::KukriSkel;
use crate::settings::Direction;

#[repr(C)]
struct RawKukriEvent {
    ts_ns: u64,
    direction: u8,
    reason: u8,
    ip: u32,
    port: u16,
    mac: [u8; 6],
    _pad: [u8; 1],
}

fn parse_event(bytes: &[u8]) -> Option<RawKukriEvent> {
    if bytes.len() != std::mem::size_of::<RawKukriEvent>() {
        return None;
    }
    Some(RawKukriEvent {
        ts_ns: u64::from_ne_bytes(bytes.get(0..8)?.try_into().ok()?),
        direction: *bytes.get(8)?,
        reason: *bytes.get(9)?,
        ip: u32::from_ne_bytes(bytes.get(12..16)?.try_into().ok()?),
        port: u16::from_ne_bytes(bytes.get(16..18)?.try_into().ok()?),
        mac: bytes.get(18..24)?.try_into().ok()?,
        _pad: bytes.get(24..25)?.try_into().ok()?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropReason {
    Mac,
    Ipv4Acl,
    TcpPort,
    UdpPort,
    IpRateLimit,
    PortRateLimit,
}

impl TryFrom<u8> for DropReason {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Mac),
            1 => Ok(Self::Ipv4Acl),
            2 => Ok(Self::TcpPort),
            3 => Ok(Self::UdpPort),
            4 => Ok(Self::IpRateLimit),
            5 => Ok(Self::PortRateLimit),
            _ => Err(()),
        }
    }
}

impl DropReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::Mac => "MAC",
            Self::Ipv4Acl => "IPv4 ACL",
            Self::TcpPort => "TCP port",
            Self::UdpPort => "UDP port",
            Self::IpRateLimit => "IP rate limit",
            Self::PortRateLimit => "port rate limit",
        }
    }
}

#[allow(dead_code)]
pub struct KukriEvent {
    pub ts_ns: u64,
    pub direction: Direction,
    pub reason: DropReason,
    pub ip: Option<Ipv4Addr>,
    pub port: Option<u16>,
    pub mac: Option<[u8; 6]>,
}

impl TryFrom<RawKukriEvent> for KukriEvent {
    type Error = ();

    fn try_from(raw: RawKukriEvent) -> Result<Self, Self::Error> {
        let direction = match raw.direction {
            0 => Direction::Ingress,
            1 => Direction::Engress,
            _ => return Err(()),
        };
        Ok(Self {
            ts_ns: raw.ts_ns,
            direction,
            reason: raw.reason.try_into()?,
            ip: (raw.ip != 0).then(|| Ipv4Addr::from(raw.ip)),
            port: (raw.port != 0).then_some(raw.port),
            mac: (raw.mac != [0; 6]).then_some(raw.mac),
        })
    }
}

pub struct EventLog {
    events: VecDeque<KukriEvent>,
    cap: usize,
}

impl EventLog {
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            cap: 1000,
        }
    }

    pub fn push(&mut self, event: KukriEvent) {
        if self.events.len() == self.cap {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn iter(&self) -> impl Iterator<Item = &KukriEvent> {
        self.events.iter()
    }
}

pub fn spawn_poller(
    skel: &'static KukriSkel<'static>,
    log: Arc<Mutex<EventLog>>,
) -> anyhow::Result<JoinHandle<()>> {
    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.kukri_events, move |bytes| {
        if let Some(event) = parse_event(bytes).and_then(|raw| KukriEvent::try_from(raw).ok()) {
            if let Ok(mut log) = log.lock() {
                log.push(event);
            }
        }
        0
    })?;
    let ring_buffer = builder.build()?;
    Ok(std::thread::spawn(move || loop {
        if let Err(err) = ring_buffer.poll(Duration::from_millis(200)) {
            eprintln!("event ring buffer poll: {err}");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_c_layout_and_rejects_wrong_size() {
        assert_eq!(std::mem::size_of::<RawKukriEvent>(), 32);
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&42u64.to_ne_bytes());
        bytes[8] = 1;
        bytes[9] = 4;
        bytes[12..16].copy_from_slice(&u32::from(Ipv4Addr::new(10, 0, 0, 1)).to_ne_bytes());
        let event = KukriEvent::try_from(parse_event(&bytes).unwrap()).unwrap();
        assert_eq!(event.ts_ns, 42);
        assert_eq!(event.direction, Direction::Engress);
        assert_eq!(event.reason, DropReason::IpRateLimit);
        assert_eq!(event.ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(parse_event(&bytes[..31]).is_none());
    }

    #[test]
    fn log_evicts_oldest() {
        let mut log = EventLog::new();
        for ts_ns in 0..1001 {
            log.push(KukriEvent {
                ts_ns,
                direction: Direction::Ingress,
                reason: DropReason::Mac,
                ip: None,
                port: None,
                mac: None,
            });
        }
        assert_eq!(log.iter().count(), 1000);
        assert_eq!(log.iter().next().unwrap().ts_ns, 1);
    }
}
