use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use kukri::dto::config::ACLConfig;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

use crate::bpf;
use crate::bpf::AttachKind;
use crate::bpf::BpfProgram;
use crate::bpf::KukriSkel;
use crate::settings::BoolField;
use crate::settings::Direction;
use crate::settings::ListField;
use crate::settings::Proto;

const BANNER: &str = include_str!("../assets/kukri.ascii.art.txt");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    /// Read-only: what's actually attached right now.
    Summary,
    /// Editable ACL rules. Flipping a direction's "Enable rules" master
    /// switch here is what actually attaches/detaches that direction's BPF
    /// program — there's no separate program-list UI to do it from.
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsSection {
    Ip,
    Tcp,
    Udp,
}

impl SettingsSection {
    const ALL: [SettingsSection; 3] = [SettingsSection::Ip, SettingsSection::Tcp, SettingsSection::Udp];

    fn label(self) -> &'static str {
        match self {
            SettingsSection::Ip => "IP",
            SettingsSection::Tcp => "TCP",
            SettingsSection::Udp => "UDP",
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

/// One line in the currently-shown section. Rebuilt from `programs`/`config`
/// after every mutation and every section/tab switch.
enum Row {
    Header(String),
    /// Summary tab only — informational, not selectable/interactive.
    Program(usize),
    Bool(BoolField, String),
    Item(ListField, usize, String),
    AddNew(ListField, String),
}

fn is_selectable(row: &Row) -> bool {
    matches!(row, Row::Bool(..) | Row::Item(..) | Row::AddNew(..))
}

struct App<'a> {
    skel: &'a KukriSkel<'static>,
    programs: Vec<BpfProgram<'a>>,
    config: ACLConfig,
    interfaces: Vec<String>,
    tab: Tab,
    section: SettingsSection,
    rows: Vec<Row>,
    selected: Option<usize>,
    /// A pending "add new" text prompt for this list field.
    input_target: Option<ListField>,
    input_buffer: String,
    status: Option<String>,
}

impl<'a> App<'a> {
    fn new(
        skel: &'a KukriSkel<'static>,
        programs: Vec<BpfProgram<'a>>,
        config: ACLConfig,
        interfaces: Vec<String>,
    ) -> Self {
        let mut app = App {
            skel,
            programs,
            config,
            interfaces,
            tab: Tab::Summary,
            section: SettingsSection::Ip,
            rows: Vec::new(),
            selected: None,
            input_target: None,
            input_buffer: String::new(),
            status: None,
        };
        app.rebuild_rows();
        app
    }

    fn rebuild_rows(&mut self) {
        self.rows = match self.tab {
            Tab::Summary => summary_rows(&self.programs),
            Tab::Settings => match self.section {
                SettingsSection::Ip => ip_rows(&self.config),
                SettingsSection::Tcp => port_section_rows(&self.config, Proto::Tcp),
                SettingsSection::Udp => port_section_rows(&self.config, Proto::Udp),
            },
        };
        self.selected = self.rows.iter().position(is_selectable);
    }

    fn sync(&mut self) {
        if let Err(err) = bpf::sync_acl(self.skel, &self.config) {
            self.status = Some(format!("failed to sync BPF maps: {err}"));
        }
    }

    /// The BPF program a direction's master switch controls. `ingress_hook`
    /// and `engress_hook` are the only two programs Settings ever touches
    /// directly — anything else in the object (e.g. the exec tracepoint)
    /// only shows up read-only on the Summary tab.
    fn program_for_direction(&mut self, dir: Direction) -> Option<&mut BpfProgram<'a>> {
        let name = match dir {
            Direction::Ingress => crate::consts::INGRESS_PROGRAM,
            Direction::Engress => crate::consts::ENGRESS_PROGRAM,
        };
        self.programs.iter_mut().find(|p| p.name == name)
    }

    /// Called right after `BoolField::EnableRules(dir)` gets toggled:
    /// attaches or detaches that direction's program to match the new
    /// config state.
    fn apply_master_switch(&mut self, dir: Direction) {
        let enabled = BoolField::EnableRules(dir).get(&self.config);
        let interfaces = self.interfaces.clone();
        let Some(program) = self.program_for_direction(dir) else {
            self.status = Some(format!("{}: no matching BPF program loaded", dir.label()));
            return;
        };
        let name = program.name.clone();
        let result = if enabled { program.enable(&interfaces) } else { program.disable().map(|_| ()) };
        self.status = Some(match (enabled, result) {
            (true, Ok(())) => format!("{name} attached"),
            (true, Err(err)) => format!("failed to attach {name}: {err}"),
            (false, Ok(())) => format!("{name} stopped"),
            (false, Err(err)) => format!("{name} stopped with errors: {err}"),
        });
    }
}

fn direction_header(dir: Direction) -> String {
    format!("── {} ──", dir.label())
}

fn push_list_rows(rows: &mut Vec<Row>, config: &ACLConfig, field: ListField, header: &str, add_label: &str) {
    rows.push(Row::Header(header.to_string()));
    for index in 0..field.len(config) {
        rows.push(Row::Item(field, index, field.item_label(config, index)));
    }
    rows.push(Row::AddNew(field, add_label.to_string()));
}

fn summary_rows(programs: &[BpfProgram]) -> Vec<Row> {
    (0..programs.len()).map(Row::Program).collect()
}

/// Ingress blocks by source (who it's coming from); egress blocks by
/// destination (where it's going). Label text makes that explicit rather
/// than using a direction-agnostic "blocked" wording.
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
        rows.push(Row::Bool(BoolField::EnableRules(dir), "Enable rules (master switch — attaches/detaches the BPF program)".to_string()));
        rows.push(Row::Bool(BoolField::EnableIpRules(dir), "Enable IP rules".to_string()));
        rows.push(Row::Bool(BoolField::DisableLoopback(dir), "Disable loopback".to_string()));
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedIps(dir),
            &format!("Blocked {peer} IPs"),
            &format!("+ add {peer} IP"),
        );
        push_list_rows(
            &mut rows,
            config,
            ListField::BlockedCidrRanges(dir),
            &format!("Blocked {peer} CIDR ranges"),
            &format!("+ add {peer} CIDR range (a.b.c.d/prefix)"),
        );
    }
    rows
}

fn port_section_rows(config: &ACLConfig, proto: Proto) -> Vec<Row> {
    let mut rows = Vec::new();
    for dir in Direction::ALL {
        let peer = peer_word(dir);
        rows.push(Row::Header(direction_header(dir)));
        rows.push(Row::Bool(BoolField::EnablePortRules(dir, proto), "Enable rules".to_string()));
        push_list_rows(&mut rows, config, ListField::BlockedPorts(dir, proto), &format!("Blocked {peer} ports"), &format!("+ add {peer} port"));
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
    if let Row::Bool(field, _) = &app.rows[index] {
        let field = *field;
        field.toggle(&mut app.config);
        app.sync();
        if let BoolField::EnableRules(dir) = field {
            app.apply_master_switch(dir);
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
    if let Row::AddNew(field, _) = &app.rows[index] {
        app.input_target = Some(*field);
        app.input_buffer.clear();
    }
}

fn submit_input(app: &mut App) {
    let Some(field) = app.input_target else { return };
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

fn program_status_text(program: &BpfProgram) -> (String, Style) {
    if !program.is_running() {
        return ("STOPPED".to_string(), Style::default().fg(Color::DarkGray));
    }
    match program.kind {
        AttachKind::Xdp | AttachKind::Tc => (
            format!("RUNNING ({})", program.attached_interfaces.join(",")),
            Style::default().fg(Color::Green),
        ),
        AttachKind::Generic => ("RUNNING".to_string(), Style::default().fg(Color::Green)),
    }
}

fn kind_text(kind: AttachKind) -> &'static str {
    match kind {
        AttachKind::Xdp => "XDP",
        AttachKind::Tc => "TC",
        AttachKind::Generic => "GENERIC",
    }
}

fn row_line(row: &Row, programs: &[BpfProgram], config: &ACLConfig) -> Line<'static> {
    match row {
        Row::Header(text) => {
            Line::styled(text.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        }
        Row::Program(index) => {
            let program = &programs[*index];
            let (status, style) = program_status_text(program);
            Line::from(vec![
                Span::raw(format!(
                    "{:<20} {:<8} fd={:<5} ",
                    program.name,
                    kind_text(program.kind),
                    program.fd
                )),
                Span::styled(status, style),
            ])
        }
        Row::Bool(field, label) => {
            let marker = if field.get(config) { "[x]" } else { "[ ]" };
            Line::from(format!("{marker} {label}"))
        }
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
            let items: Vec<ListItem> = app.rows.iter().map(|row| ListItem::new(row_line(row, &app.programs, &app.config))).collect();
            let list = List::new(items).block(Block::default().borders(Borders::ALL).title("What's running"));
            frame.render_widget(list, layout[3]);
        }
        Tab::Settings => {
            let section_line = Line::from(
                SettingsSection::ALL
                    .iter()
                    .flat_map(|section| vec![Span::raw(" "), tab_span(section.label(), *section == app.section)])
                    .collect::<Vec<_>>(),
            );
            frame.render_widget(Paragraph::new(section_line), layout[2]);

            let items: Vec<ListItem> = app.rows.iter().map(|row| ListItem::new(row_line(row, &app.programs, &app.config))).collect();
            let mut list_state = ListState::default().with_selected(app.selected);
            let list = List::new(items)
                .block(Block::default().borders(Borders::ALL).title(app.section.label()))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_stateful_widget(list, layout[3], &mut list_state);
        }
    }

    let footer_text = app.status.clone().unwrap_or_else(|| default_footer_hint(app.tab));
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
        Tab::Summary => "Tab switch page   q quit".to_string(),
        Tab::Settings => {
            "Tab switch page   \u{2190}/\u{2192} section   \u{2191}/\u{2193} move   space toggle   d delete   enter add   q quit".to_string()
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

/// Runs the TUI until the user quits.
pub fn run(
    skel: &KukriSkel<'static>,
    programs: Vec<BpfProgram<'_>>,
    config: ACLConfig,
    interfaces: Vec<String>,
) -> anyhow::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let mut app = App::new(skel, programs, config, interfaces);
    app.sync();

    let result = (|| -> anyhow::Result<()> {
        loop {
            terminal.draw(|frame| draw(&mut app, frame))?;

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
