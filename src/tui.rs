use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kukri::dto::config::ACLConfig;
use kukri::dto::config::Range;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::bpf;
use crate::bpf::BpfProgram;
use crate::bpf::KukriSkel;
use crate::events::{self, DropReason, EventLog};
use crate::settings::range_label;
use crate::settings::BoolField;
use crate::settings::Direction;
use crate::settings::InterfaceSelection;
use crate::settings::ListField;
use crate::settings::Proto;
use crate::stages::{self, Feature, StageSlot};

const BANNER: &str = include_str!("../assets/kukri.ascii.art.txt");

static HEADLESS_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_headless_stop(_: libc::c_int) {
    HEADLESS_STOP.store(true, Ordering::Relaxed);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    /// Read-only: whatever's actually attached right now.
    Summary,
    /// Editable ACL rules. Flipping a direction's "Enable rules" master
    /// switch here is what actually attaches/detaches that direction's BPF
    /// program, since there's no seperate program-list UI to do it from.
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsSection {
    Ip,
    Tcp,
    Udp,
    Mac,
    Interfaces,
}

impl SettingsSection {
    const ALL: [SettingsSection; 5] = [
        SettingsSection::Ip,
        SettingsSection::Tcp,
        SettingsSection::Udp,
        SettingsSection::Mac,
        SettingsSection::Interfaces,
    ];

    fn label(self) -> &'static str {
        match self {
            SettingsSection::Ip => "IP",
            SettingsSection::Tcp => "TCP",
            SettingsSection::Udp => "UDP",
            SettingsSection::Mac => "MAC",
            SettingsSection::Interfaces => "Interfaces",
        }
    }

    fn next(self) -> SettingsSection {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap();
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    fn prev(self) -> SettingsSection {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap();
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// One line in the section we're showing right now. Rebuilt from
/// `programs`/`config` after every mutation and every section/tab switch.
enum Row {
    Header(String),
    /// Summary tab only: a plain read-only summary line, e.g. a blocked-port list.
    Info(String),
    Bool(BoolField, String),
    Item(ListField, usize, String),
    AddNew(ListField, String),
    Iface(String, bool),
}

fn is_selectable(row: &Row) -> bool {
    matches!(
        row,
        Row::Bool(..) | Row::Item(..) | Row::AddNew(..) | Row::Iface(..)
    )
}

struct App<'a> {
    skel: &'a KukriSkel<'static>,
    event_log: Arc<Mutex<EventLog>>,
    programs: Vec<BpfProgram<'a>>,
    stage_slots: HashMap<(Direction, Feature), StageSlot>,
    config: ACLConfig,
    config_path: PathBuf,
    interfaces: Vec<String>,
    iface_selection: InterfaceSelection,
    tab: Tab,
    section: SettingsSection,
    rows: Vec<Row>,
    selected: Option<usize>,
    /// The pending "add new" text prompt for this list field.
    input_target: Option<ListField>,
    input_buffer: String,
    status: Option<String>,
}

impl<'a> App<'a> {
    fn new(
        skel: &'static KukriSkel<'static>,
        programs: Vec<BpfProgram<'a>>,
        config: ACLConfig,
        interfaces: Vec<String>,
        config_path: PathBuf,
    ) -> anyhow::Result<Self> {
        let stage_slots = stages::discover_stage_slots(skel, &programs)?;
        let event_log = Arc::new(Mutex::new(EventLog::new()));
        events::spawn_poller(skel, Arc::clone(&event_log))?;
        let iface_selection = InterfaceSelection {
            available: crate::nic::list_interfaces().unwrap_or_default(),
            selected: interfaces.clone(),
        };
        let mut app = App {
            skel,
            event_log,
            programs,
            stage_slots,
            config,
            config_path,
            interfaces,
            iface_selection,
            tab: Tab::Summary,
            section: SettingsSection::Ip,
            rows: Vec::new(),
            selected: None,
            input_target: None,
            input_buffer: String::new(),
            status: None,
        };
        app.rebuild_rows();
        Ok(app)
    }

    /// Explicit save only, no autosave. Writing on every toggle would
    /// silently rewrite the user's config file alot more often than they'd
    /// expect. We write to a temp file in the same directory and rename
    /// over the original, so a crash mid-write can't leave a half-written
    /// corrupt config on disk.
    fn save_config(&mut self) {
        let result = (|| -> anyhow::Result<()> {
            let json = serde_json::to_string_pretty(&self.config)?;
            let tmp_path = self.config_path.with_extension("json.tmp");
            std::fs::write(&tmp_path, json)?;
            std::fs::rename(&tmp_path, &self.config_path)?;
            Ok(())
        })();
        self.status = Some(match result {
            Ok(()) => format!("saved to {}", self.config_path.display()),
            Err(err) => format!("failed to save {}: {err}", self.config_path.display()),
        });
    }

    fn rebuild_rows(&mut self) {
        self.rows = match self.tab {
            Tab::Summary => summary_rows(
                &self.config,
                &self.programs,
                bpf::packets_processed(self.skel),
                &self.event_log,
            ),
            Tab::Settings => match self.section {
                SettingsSection::Ip => ip_rows(&self.config),
                SettingsSection::Tcp => port_section_rows(&self.config, Proto::Tcp),
                SettingsSection::Udp => port_section_rows(&self.config, Proto::Udp),
                SettingsSection::Mac => mac_rows(&self.config),
                SettingsSection::Interfaces => interface_rows(&self.iface_selection),
            },
        };
        self.selected = self.rows.iter().position(is_selectable);
    }

    fn sync(&mut self) {
        if let Err(err) = bpf::sync_acl(self.skel, &self.config) {
            self.status = Some(format!("failed to sync BPF maps: {err}"));
        }
    }

    fn program_for_direction(&mut self, dir: Direction) -> Option<&mut BpfProgram<'a>> {
        let name = match dir {
            Direction::Ingress => crate::consts::INGRESS_PROGRAM,
            Direction::Engress => crate::consts::ENGRESS_PROGRAM,
        };
        self.programs.iter_mut().find(|p| p.name == name)
    }

    /// Called right after one of the finer-grained enable flags
    /// (`EnableMacRules`/`EnableIpRules`/`EnablePortRules`) gets toggled.
    /// Inserts or removes that feature's BPF program from the relevant
    /// prog-array slot so the slot matches the new config state. Honestly,
    /// that's the whole enable/disable mechanism for these features. There
    /// is no BPF map tracking "is this rule category on" separately from
    /// whether its program occupies its slot.
    fn apply_stage_toggle(&mut self, field: BoolField) {
        let (dir, feature) = match field {
            BoolField::EnableMacRules(dir) => (dir, Feature::Mac),
            BoolField::EnableIpRules(dir) => (dir, Feature::Ipv4Acl),
            BoolField::EnableIpv6Rules(dir) => (dir, Feature::Ipv6Acl),
            BoolField::EnablePortRules(dir, proto) => (dir, Feature::Port(proto)),
            BoolField::EnableIpRateLimit(dir) => (dir, Feature::IpRateLimit),
            BoolField::EnablePortRateLimit(dir) => (dir, Feature::PortRateLimit),
            BoolField::EnableRules(_)
            | BoolField::DisableLoopback(_)
            | BoolField::DisableLoopback6(_) => return,
        };
        let enabled = field.get(&self.config);
        let Some(slot) = self.stage_slots.get(&(dir, feature)) else {
            self.status = Some(format!(
                "{} {feature:?}: no matching BPF program loaded",
                dir.label()
            ));
            return;
        };
        let target_fd = if enabled { Some(slot.fd) } else { None };
        let result = match dir {
            Direction::Ingress => {
                bpf::set_stage(&self.skel.maps.protocol_redirecters, slot.index, target_fd)
            }
            Direction::Engress => {
                bpf::set_stage(&self.skel.maps.engress_redirecters, slot.index, target_fd)
            }
        };
        self.status = Some(match result {
            Ok(()) if enabled => format!("{} {feature:?} enabled", dir.label()),
            Ok(()) => format!("{} {feature:?} disabled", dir.label()),
            Err(err) => format!("failed to toggle {} {feature:?}: {err}", dir.label()),
        });
    }

    /// Pushes every stage toggle's current config state into the prog arrays.
    /// Called once at startup, so a config file loaded with e.g.
    /// `enable_mac_rules: true` takes effect immediately instead of waiting
    /// for the next manual toggle.
    fn apply_all_stage_toggles(&mut self) {
        for dir in Direction::ALL {
            self.apply_stage_toggle(BoolField::EnableMacRules(dir));
            self.apply_stage_toggle(BoolField::EnableIpRules(dir));
            self.apply_stage_toggle(BoolField::EnableIpv6Rules(dir));
            self.apply_stage_toggle(BoolField::EnableIpRateLimit(dir));
            self.apply_stage_toggle(BoolField::EnablePortRateLimit(dir));
            self.apply_stage_toggle(BoolField::EnablePortRules(dir, Proto::Tcp));
            self.apply_stage_toggle(BoolField::EnablePortRules(dir, Proto::Udp));
        }
    }

    /// Called right after `BoolField::EnableRules(dir)` gets toggled.
    /// Attaches or detaches that direction's program so it matches the new
    /// config state.
    fn apply_master_switch(&mut self, dir: Direction) {
        let enabled = BoolField::EnableRules(dir).get(&self.config);
        let interfaces = self.interfaces.clone();
        let Some(program) = self.program_for_direction(dir) else {
            self.status = Some(format!("{}: no matching BPF program loaded", dir.label()));
            return;
        };
        let name = program.name.clone();
        let result = if enabled {
            program.enable(&interfaces)
        } else {
            program.disable().map(|_| ())
        };
        self.status = Some(match (enabled, result) {
            (true, Ok(())) => format!("{name} attached"),
            (true, Err(err)) => format!("failed to attach {name}: {err}"),
            (false, Ok(())) => format!("{name} stopped"),
            (false, Err(err)) => format!("{name} stopped with errors: {err}"),
        });
    }

    /// Re-syncs the running hooks after the interface selection changes.
    /// For every direction whose master switch is on, we detach and
    /// re-attach to teh current interface list. Toggling an interface has
    /// to be a *hot* change, otherwise it's just a config edit and the
    /// hooks stay on the old interface set until the app is restarted or
    /// the master switch is flipped.
    fn reapply_attachments(&mut self) {
        let interfaces = self.interfaces.clone();
        for dir in Direction::ALL {
            if !BoolField::EnableRules(dir).get(&self.config) {
                continue;
            }
            let status = {
                let Some(program) = self.program_for_direction(dir) else {
                    continue;
                };
                let name = program.name.clone();
                match (|| -> anyhow::Result<()> {
                    program.disable()?;
                    program.enable(&interfaces)
                })() {
                    Ok(()) => format!("{name} re-attached to {}", interfaces.join(", ")),
                    Err(err) => format!("failed to re-attach {name}: {err}"),
                }
            };
            self.status = Some(status);
        }
    }
}

fn direction_header(dir: Direction) -> String {
    format!("── {} ──", dir.label())
}

fn push_list_rows(
    rows: &mut Vec<Row>,
    config: &ACLConfig,
    field: ListField,
    header: &str,
    add_label: &str,
) {
    rows.push(Row::Header(header.to_string()));
    for index in 0..field.len(config) {
        rows.push(Row::Item(field, index, field.item_label(config, index)));
    }
    rows.push(Row::AddNew(field, add_label.to_string()));
}

fn port_items(ports: &[u16], ranges: &[Range]) -> Vec<String> {
    let mut items: Vec<String> = ports.iter().map(u16::to_string).collect();
    items.extend(ranges.iter().map(range_label));
    items
}

fn summary_line(label: &str, items: &[String]) -> Row {
    if items.is_empty() {
        Row::Info(format!("{label}: none blocked"))
    } else {
        Row::Info(format!("{label}: blocking {}", items.join(", ")))
    }
}

/// Ethernet/MAC rows.
fn layer2_rows(config: &ACLConfig) -> Vec<Row> {
    let mut rows = vec![Row::Header("Layer 2 Summary".to_string())];
    rows.push(summary_line(
        "Ingress MAC (source)",
        &config.ingress.mac_rules.blocked_source_macs,
    ));
    rows.push(summary_line(
        "Engress MAC (destination)",
        &config.engress.mac_rules.blocked_destination_macs,
    ));
    rows
}

/// IPv4 and IPv6 rows.
fn layer3_rows(config: &ACLConfig) -> Vec<Row> {
    let mut rows = vec![Row::Header("Layer 3 Summary".to_string())];
    let ingress: Vec<String> = config
        .ingress
        .ipv4_rules
        .blocked_source_ips
        .iter()
        .map(|&ip| Ipv4Addr::from(ip).to_string())
        .chain(
            config
                .ingress
                .ipv4_rules
                .blocked_source_ranges
                .iter()
                .cloned(),
        )
        .collect();
    rows.push(summary_line("Ingress IPv4 (source)", &ingress));
    let ingress6: Vec<String> = config
        .ingress
        .ipv6_rules
        .blocked_source_ips
        .iter()
        .cloned()
        .chain(
            config
                .ingress
                .ipv6_rules
                .blocked_source_ranges
                .iter()
                .cloned(),
        )
        .collect();
    rows.push(summary_line("Ingress IPv6 (source)", &ingress6));
    let engress: Vec<String> = config
        .engress
        .ipv4_rules
        .blocked_destination_ips
        .iter()
        .map(|&ip| Ipv4Addr::from(ip).to_string())
        .chain(
            config
                .engress
                .ipv4_rules
                .blocked_destination_ranges
                .iter()
                .cloned(),
        )
        .collect();
    rows.push(summary_line("Engress IPv4 (destination)", &engress));
    let engress6: Vec<String> = config
        .engress
        .ipv6_rules
        .blocked_destination_ips
        .iter()
        .cloned()
        .chain(
            config
                .engress
                .ipv6_rules
                .blocked_destination_ranges
                .iter()
                .cloned(),
        )
        .collect();
    rows.push(summary_line("Engress IPv6 (destination)", &engress6));
    rows
}

/// TCP + UDP rows.
fn layer4_rows(config: &ACLConfig) -> Vec<Row> {
    let mut rows = vec![Row::Header("Layer 4 Summary".to_string())];
    rows.push(summary_line(
        "Ingress TCP (source)",
        &port_items(
            &config.ingress.tcp_rules.blocked_source_ports,
            &config.ingress.tcp_rules.blocked_source_ranges,
        ),
    ));
    rows.push(summary_line(
        "Ingress UDP (source)",
        &port_items(
            &config.ingress.udp_rules.blocked_source_ports,
            &config.ingress.udp_rules.blocked_source_ranges,
        ),
    ));
    rows.push(summary_line(
        "Engress TCP (destination)",
        &port_items(
            &config.engress.tcp_rules.blocked_destination_ports,
            &config.engress.tcp_rules.blocked_destination_ranges,
        ),
    ));
    rows.push(summary_line(
        "Engress UDP (destination)",
        &port_items(
            &config.engress.udp_rules.blocked_destination_ports,
            &config.engress.udp_rules.blocked_destination_ranges,
        ),
    ));
    rows
}

/// Live attach state of the two direction hooks, so the Summary tab can
/// show whether filtering is actually running, on which interfaces, and in
/// which XDP mode. Rebuilt every frame, which makes it double as the "did
/// my toggle take effect" indicator.
fn attachment_rows(programs: &[BpfProgram<'_>]) -> Vec<Row> {
    let mut rows = vec![Row::Header("Attachment".to_string())];
    for name in [
        crate::consts::INGRESS_PROGRAM,
        crate::consts::ENGRESS_PROGRAM,
    ] {
        let Some(prog) = programs.iter().find(|p| p.name == name) else {
            rows.push(Row::Info(format!("{name}: program not loaded")));
            continue;
        };
        if !prog.is_running() {
            rows.push(Row::Info(format!("{name}: NOT attached")));
            continue;
        }
        let generic: Vec<&String> = prog.generic_xdp.iter().map(|g| &g.interface).collect();
        let parts: Vec<String> = prog
            .attached_interfaces
            .iter()
            .map(|iface| {
                if generic.contains(&iface) {
                    format!("{iface} (generic XDP)")
                } else {
                    iface.clone()
                }
            })
            .collect();
        rows.push(Row::Info(format!(
            "{name}: attached to {}",
            parts.join(", ")
        )));
    }
    rows
}

fn summary_rows(
    config: &ACLConfig,
    programs: &[BpfProgram<'_>],
    packets: u64,
    log: &Mutex<EventLog>,
) -> Vec<Row> {
    let mut rows = attachment_rows(programs);
    rows.extend(layer2_rows(config));
    rows.extend(layer3_rows(config));
    rows.extend(layer4_rows(config));
    rows.push(Row::Header("Event stream".to_string()));
    rows.push(Row::Info(format!("packets processed: {packets}")));

    let mut reasons = BTreeMap::<DropReason, usize>::new();
    let mut blocked_ips = BTreeMap::<Ipv4Addr, usize>::new();
    let mut limited_ips = BTreeMap::<Ipv4Addr, usize>::new();
    let mut limited_ports = BTreeMap::<u16, usize>::new();
    if let Ok(log) = log.lock() {
        for event in log.iter() {
            *reasons.entry(event.reason).or_default() += 1;
            match event.reason {
                DropReason::Ipv4Acl => {
                    if let Some(ip) = event.ip {
                        *blocked_ips.entry(ip).or_default() += 1;
                    }
                }
                DropReason::IpRateLimit => {
                    if let Some(ip) = event.ip {
                        *limited_ips.entry(ip).or_default() += 1;
                    }
                }
                DropReason::PortRateLimit => {
                    if let Some(port) = event.port {
                        *limited_ports.entry(port).or_default() += 1;
                    }
                }
                _ => {}
            }
        }
    }
    for (reason, count) in reasons {
        rows.push(Row::Info(format!(
            "{} dropped events: {count}",
            reason.label()
        )));
    }
    for (ip, count) in blocked_ips {
        rows.push(Row::Info(format!("blocked IP {ip}: {count}")));
    }
    for (ip, count) in limited_ips {
        rows.push(Row::Info(format!("rate-limited IP {ip}: {count}")));
    }
    for (port, count) in limited_ports {
        rows.push(Row::Info(format!("rate-limited port {port}: {count}")));
    }
    rows
}

/// Ingress blocks by source, aka who it's coming from. Egress blocks by
/// destination, where it's going. Label text spells that out rather than
/// using some direction-agnostic "blocked" wording.
fn peer_word(dir: Direction) -> &'static str {
    match dir {
        Direction::Ingress => "source",
        Direction::Engress => "destination",
    }
}

fn ip_rows(config: &ACLConfig) -> Vec<Row> {
    let mut rows = Vec::new();
    for dir in Direction::ALL {
        let peer = peer_word(dir);
        rows.push(Row::Header(direction_header(dir)));
        rows.push(Row::Bool(
            BoolField::EnableRules(dir),
            "Enable rules (master switch — attaches/detaches the BPF program)".to_string(),
        ));
        rows.push(Row::Bool(
            BoolField::EnableIpRules(dir),
            "Enable IPv4 rules".to_string(),
        ));
        rows.push(Row::Bool(
            BoolField::DisableLoopback(dir),
            "Disable IPv4 loopback".to_string(),
        ));
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedIps(dir),
            &format!("Blocked {peer} IPv4 IPs"),
            &format!("+ add {peer} IPv4 IP"),
        );
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedCidrRanges(dir),
            &format!("Blocked {peer} IPv4 CIDR ranges"),
            &format!("+ add {peer} CIDR range (a.b.c.d/prefix)"),
        );
        rows.push(Row::Bool(
            BoolField::EnableIpv6Rules(dir),
            "Enable IPv6 rules".to_string(),
        ));
        rows.push(Row::Bool(
            BoolField::DisableLoopback6(dir),
            "Disable IPv6 loopback".to_string(),
        ));
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedIps6(dir),
            &format!("Blocked {peer} IPv6 IPs"),
            &format!("+ add {peer} IPv6 IP"),
        );
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedCidrRanges6(dir),
            &format!("Blocked {peer} IPv6 CIDR ranges"),
            &format!("+ add {peer} CIDR range (ipv6-address/prefix)"),
        );
        let rate = match dir {
            Direction::Ingress => &config.ingress.rate_limit,
            Direction::Engress => &config.engress.rate_limit,
        };
        rows.push(Row::Header("Rate limit".to_string()));
        rows.push(Row::Bool(
            BoolField::EnableIpRateLimit(dir),
            format!("Enable per-{peer}-IP rate limit"),
        ));
        rows.push(Row::Info(format!(
            "IP limit: {} packets/s (0 = unlimited)",
            rate.ip_rate_limit_pps
        )));
        rows.push(Row::Bool(
            BoolField::EnablePortRateLimit(dir),
            "Enable per-destination-port rate limit".to_string(),
        ));
        rows.push(Row::Info(format!(
            "Port limit: {} packets/s (0 = unlimited)",
            rate.port_rate_limit_pps
        )));
    }
    rows
}

fn port_section_rows(config: &ACLConfig, proto: Proto) -> Vec<Row> {
    let mut rows = Vec::new();
    for dir in Direction::ALL {
        let peer = peer_word(dir);
        rows.push(Row::Header(direction_header(dir)));
        rows.push(Row::Bool(
            BoolField::EnablePortRules(dir, proto),
            "Enable rules".to_string(),
        ));
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedPorts(dir, proto),
            &format!("Blocked {peer} ports"),
            &format!("+ add {peer} port"),
        );
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedPortRanges(dir, proto),
            &format!("Blocked {peer} port ranges"),
            &format!("+ add {peer} port range (start-end)"),
        );
    }
    rows
}

fn mac_rows(config: &ACLConfig) -> Vec<Row> {
    let mut rows = Vec::new();
    for dir in Direction::ALL {
        let peer = peer_word(dir);
        rows.push(Row::Header(direction_header(dir)));
        rows.push(Row::Bool(
            BoolField::EnableMacRules(dir),
            "Enable MAC rules".to_string(),
        ));
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedMacs(dir),
            &format!("Blocked {peer} MACs"),
            &format!("+ add {peer} MAC (aa:bb:cc:dd:ee:ff)"),
        );
    }
    rows
}

fn interface_rows(selection: &InterfaceSelection) -> Vec<Row> {
    selection
        .available
        .iter()
        .map(|name| Row::Iface(name.clone(), selection.selected.contains(name)))
        .collect()
}

fn select_next(app: &mut App) {
    let Some(current) = app.selected else { return };
    if let Some(next) = ((current + 1)..app.rows.len()).find(|&i| is_selectable(&app.rows[i])) {
        app.selected = Some(next);
    }
}

fn select_previous(app: &mut App) {
    let Some(current) = app.selected else { return };
    if let Some(prev) = (0..current).rev().find(|&i| is_selectable(&app.rows[i])) {
        app.selected = Some(prev);
    }
}

fn handle_space(app: &mut App) {
    let Some(index) = app.selected else { return };
    if let Row::Iface(name, _) = &app.rows[index] {
        let name = name.clone();
        match app.iface_selection.toggle(&name) {
            Ok(()) => {
                app.interfaces = app.iface_selection.selected.clone();
                // Persist into the config, so a save + restart keeps the
                // selection (and `validate()` on next launch can check
                // it).
                app.config.interfaces.names = app.interfaces.clone();
                // Interface toggles are hot, so move the running hooks
                // onto the new interface set for any direction that's
                // currently on.
                app.status = None;
                app.reapply_attachments();
                app.rebuild_rows();
            }
            Err(err) => app.status = Some(err),
        }
        return;
    }
    if let Row::Bool(field, _) = &app.rows[index] {
        let field = *field;
        field.toggle(&mut app.config);
        app.sync();
        if let BoolField::EnableRules(dir) = field {
            app.apply_master_switch(dir);
        } else {
            app.apply_stage_toggle(field);
        }
        app.rebuild_rows();
    }
}

fn handle_delete(app: &mut App) {
    let Some(index) = app.selected else { return };
    if let Row::Item(field, item_index, label) = &app.rows[index] {
        let (field, item_index, label) = (*field, *item_index, label.clone());
        field.remove(&mut app.config, item_index);
        app.status = Some(format!("removed {label}"));
        app.rebuild_rows();
        app.sync();
    }
}

fn handle_enter(app: &mut App) {
    let Some(index) = app.selected else { return };
    if matches!(app.rows[index], Row::Iface(..)) {
        handle_space(app);
        return;
    }
    if let Row::AddNew(field, _) = &app.rows[index] {
        app.input_target = Some(*field);
        app.input_buffer.clear();
    }
}

fn submit_input(app: &mut App) {
    let Some(field) = app.input_target else {
        return;
    };
    match field.add(&mut app.config, &app.input_buffer) {
        Ok(()) => {
            app.status = Some(format!("added \"{}\"", app.input_buffer.trim()));
            app.input_target = None;
            app.input_buffer.clear();
            app.rebuild_rows();
            app.sync();
        }
        Err(err) => app.status = Some(err),
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width, height)
}

fn row_line(row: &Row, config: &ACLConfig) -> Line<'static> {
    match row {
        Row::Header(text) => Line::styled(
            text.clone(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Row::Bool(field, label) => {
            let marker = if field.get(config) { "[x]" } else { "[ ]" };
            Line::from(format!("{marker} {label}"))
        }
        Row::Iface(name, selected) => {
            let marker = if *selected { "[x]" } else { "[ ]" };
            Line::from(format!("{marker} {name}"))
        }
        Row::Info(text) => Line::from(format!("  {text}")),
        Row::Item(_, _, label) => Line::from(format!("    - {label}  (d to remove)")),
        Row::AddNew(_, label) => Line::styled(label.clone(), Style::default().fg(Color::Yellow)),
    }
}

fn draw(app: &mut App, frame: &mut Frame) {
    let area = frame.area();
    let banner_height = BANNER.lines().count() as u16;
    let layout = Layout::vertical([
        Constraint::Length(banner_height),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .split(area);

    frame.render_widget(Paragraph::new(BANNER), layout[0]);

    let tab_line = Line::from(vec![
        tab_span("Summary", app.tab == Tab::Summary),
        Span::raw("   "),
        tab_span("Settings", app.tab == Tab::Settings),
    ]);
    frame.render_widget(Paragraph::new(tab_line), layout[1]);

    match app.tab {
        Tab::Summary => {
            frame.render_widget(Paragraph::new(""), layout[2]);
            let items: Vec<ListItem> = app
                .rows
                .iter()
                .map(|row| ListItem::new(row_line(row, &app.config)))
                .collect();
            let list = List::new(items).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("What's running"),
            );
            frame.render_widget(list, layout[3]);
        }
        Tab::Settings => {
            let section_line = Line::from(
                SettingsSection::ALL
                    .iter()
                    .flat_map(|section| {
                        vec![
                            Span::raw(" "),
                            tab_span(section.label(), *section == app.section),
                        ]
                    })
                    .collect::<Vec<_>>(),
            );
            frame.render_widget(Paragraph::new(section_line), layout[2]);

            let items: Vec<ListItem> = app
                .rows
                .iter()
                .map(|row| ListItem::new(row_line(row, &app.config)))
                .collect();
            let mut list_state = ListState::default().with_selected(app.selected);
            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(app.section.label()),
                )
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_stateful_widget(list, layout[3], &mut list_state);
        }
    }

    let footer_text = app
        .status
        .clone()
        .unwrap_or_else(|| default_footer_hint(app.tab));
    frame.render_widget(Paragraph::new(footer_text), layout[4]);

    if app.input_target.is_some() {
        let popup_area = centered_rect(60, 5, area);
        frame.render_widget(Clear, popup_area);
        let lines = vec![
            Line::from(format!("{}_", app.input_buffer)),
            Line::from(""),
            Line::from("[Enter] add    [Esc] cancel"),
        ];
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("New value")),
            popup_area,
        );
    }
}

fn tab_span(label: &str, active: bool) -> Span<'static> {
    let style = if active {
        Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    } else {
        Style::default()
    };
    Span::styled(format!(" {label} "), style)
}

fn default_footer_hint(tab: Tab) -> String {
    match tab {
        Tab::Summary => "Tab switch page   s save config   q quit".to_string(),
        Tab::Settings => {
            "Tab switch page   \u{2190}/\u{2192} section   \u{2191}/\u{2193} move   space toggle   d delete   enter toggle/add   s save config   q quit".to_string()
        }
    }
}

fn handle_key(app: &mut App, code: KeyCode) -> bool {
    if app.input_target.is_some() {
        match code {
            KeyCode::Enter => submit_input(app),
            KeyCode::Esc => {
                app.input_target = None;
                app.input_buffer.clear();
            }
            KeyCode::Backspace => {
                app.input_buffer.pop();
            }
            KeyCode::Char(c) => app.input_buffer.push(c),
            _ => {}
        }
        return false;
    }

    match code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('s') => app.save_config(),
        KeyCode::Tab => {
            app.tab = match app.tab {
                Tab::Summary => Tab::Settings,
                Tab::Settings => Tab::Summary,
            };
            app.status = None;
            app.rebuild_rows();
        }
        KeyCode::Left if app.tab == Tab::Settings => {
            app.section = app.section.prev();
            app.rebuild_rows();
        }
        KeyCode::Right if app.tab == Tab::Settings => {
            app.section = app.section.next();
            app.rebuild_rows();
        }
        KeyCode::Down if app.tab == Tab::Settings => select_next(app),
        KeyCode::Up if app.tab == Tab::Settings => select_previous(app),
        KeyCode::Char(' ') if app.tab == Tab::Settings => handle_space(app),
        KeyCode::Char('d') if app.tab == Tab::Settings => handle_delete(app),
        KeyCode::Enter if app.tab == Tab::Settings => handle_enter(app),
        _ => {}
    }
    false
}

/// Just runs the TUI until the user quits.
pub fn run(
    skel: &'static KukriSkel<'static>,
    programs: Vec<BpfProgram<'_>>,
    config: ACLConfig,
    interfaces: Vec<String>,
    config_path: PathBuf,
) -> anyhow::Result<()> {
    // BPF setup runs before we grab the terminal, so a failure here just
    // prints a normal error to stderr instead of getting lost somewhere in
    // unrendered TUI status-bar state.
    let mut app = App::new(skel, programs, config, interfaces, config_path)?;
    app.sync();
    app.apply_all_stage_toggles();
    // The master switch is what actually attaches the hooks to the
    // configured interfaces, so apply it at startup too and not just on
    // the first manual toggle. Otherwise a config with
    // `enable_rules: true` would sit loaded-but-unattached untill the user
    // touched the switch by hand.
    for dir in Direction::ALL {
        app.apply_master_switch(dir);
    }

    let mut terminal = ratatui::try_init()?;
    let result = (|| -> anyhow::Result<()> {
        loop {
            if app.tab == Tab::Summary {
                app.rebuild_rows();
            }
            terminal.draw(|frame| draw(&mut app, frame))?;

            if !event::poll(Duration::from_millis(200))? {
                continue;
            }
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if handle_key(&mut app, key.code) {
                    return Ok(());
                }
            }
        }
    })();

    ratatui::restore();
    result
}

/// Runs the same BPF setup as the interactive UI, but keeps the process
/// alive without needing a terminal. Intended for privileged integration
/// tests and containerized network tests.
pub fn run_headless(
    skel: &'static KukriSkel<'static>,
    programs: Vec<BpfProgram<'_>>,
    config: ACLConfig,
    interfaces: Vec<String>,
    config_path: PathBuf,
) -> anyhow::Result<()> {
    HEADLESS_STOP.store(false, Ordering::Relaxed);
    unsafe {
        libc::signal(
            libc::SIGINT,
            request_headless_stop as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            request_headless_stop as *const () as libc::sighandler_t,
        );
    }
    let mut app = App::new(skel, programs, config, interfaces, config_path)?;
    app.sync();
    app.apply_all_stage_toggles();
    for dir in Direction::ALL {
        app.apply_master_switch(dir);
    }
    while !HEADLESS_STOP.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));
    }

    for program in &mut app.programs {
        let _ = program.disable();
    }
    Ok(())
}
