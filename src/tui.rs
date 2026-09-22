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
    Main,
    Analytics,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MainSection {
    Eth,
    Ip,
    Tcp,
    Udp,
}

impl MainSection {
    const ALL: [MainSection; 4] = [MainSection::Eth, MainSection::Ip, MainSection::Tcp, MainSection::Udp];

    fn label(self) -> &'static str {
        match self {
            MainSection::Eth => "ETH",
            MainSection::Ip => "IP",
            MainSection::Tcp => "TCP",
            MainSection::Udp => "UDP",
        }
    }

    fn next(self) -> MainSection {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap();
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    fn prev(self) -> MainSection {
        let idx = Self::ALL.iter().position(|s| *s == self).unwrap();
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// One line in the currently-shown section. Rebuilt from `programs`/`config`
/// after every mutation and every section/tab switch.
enum Row {
    Header(String),
    Program(usize),
    Bool(BoolField, String),
    Item(ListField, usize, String),
    AddNew(ListField, String),
}

fn is_selectable(row: &Row) -> bool {
    !matches!(row, Row::Header(_))
}

struct App<'a> {
    skel: &'a KukriSkel<'static>,
    programs: Vec<BpfProgram<'a>>,
    config: ACLConfig,
    interfaces: Vec<String>,
    tab: Tab,
    section: MainSection,
    rows: Vec<Row>,
    selected: Option<usize>,
    /// Row index into `programs` (via `Row::Program`) awaiting confirmation.
    confirm_enable: Option<usize>,
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
            tab: Tab::Main,
            section: MainSection::Eth,
            rows: Vec::new(),
            selected: None,
            confirm_enable: None,
            input_target: None,
            input_buffer: String::new(),
            status: None,
        };
        app.rebuild_rows();
        app
    }

    fn rebuild_rows(&mut self) {
        self.rows = match self.section {
            MainSection::Eth => eth_rows(&self.programs),
            MainSection::Ip => ip_rows(&self.config),
            MainSection::Tcp => port_section_rows(&self.config, Proto::Tcp),
            MainSection::Udp => port_section_rows(&self.config, Proto::Udp),
        };
        self.selected = self.rows.iter().position(is_selectable);
    }

    fn sync(&mut self) {
        if let Err(err) = bpf::sync_acl(self.skel, &self.config) {
            self.status = Some(format!("failed to sync BPF maps: {err}"));
        }
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

fn eth_rows(programs: &[BpfProgram]) -> Vec<Row> {
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
        rows.push(Row::Bool(BoolField::EnableRules(dir), "Enable rules (master switch)".to_string()));
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
    match &app.rows[index] {
        Row::Program(program_index) => {
            let program_index = *program_index;
            let Some(program) = app.programs.get_mut(program_index) else { return };
            if program.is_running() {
                let name = program.name.clone();
                match program.disable() {
                    Ok(()) => app.status = Some(format!("{name} stopped")),
                    Err(err) => app.status = Some(format!("{name} stopped with errors: {err}")),
                }
            } else {
                app.confirm_enable = Some(program_index);
            }
        }
        Row::Bool(field, _) => {
            let field = *field;
            field.toggle(&mut app.config);
            app.rebuild_rows();
            app.sync();
        }
        _ => {}
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

fn confirm_enable(app: &mut App) {
    let Some(program_index) = app.confirm_enable.take() else { return };
    let Some(program) = app.programs.get_mut(program_index) else { return };
    match program.enable(&app.interfaces) {
        Ok(()) => app.status = Some(format!("{} attached", program.name)),
        Err(err) => app.status = Some(format!("failed to attach {}: {err}", program.name)),
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
        tab_span("Main", app.tab == Tab::Main),
        Span::raw("   "),
        tab_span("Analytics", app.tab == Tab::Analytics),
    ]);
    frame.render_widget(Paragraph::new(tab_line), layout[1]);

    match app.tab {
        Tab::Main => {
            let section_line = Line::from(
                MainSection::ALL
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
        Tab::Analytics => {
            frame.render_widget(Paragraph::new(""), layout[2]);
            frame.render_widget(
                Paragraph::new("Analytics — coming soon").block(Block::default().borders(Borders::ALL).title("Analytics")),
                layout[3],
            );
        }
    }

    let footer_text = app.status.clone().unwrap_or_else(default_footer_hint);
    frame.render_widget(Paragraph::new(footer_text), layout[4]);

    if let Some(program_index) = app.confirm_enable {
        if let Some(program) = app.programs.get(program_index) {
            let popup_area = centered_rect(60, 6, area);
            frame.render_widget(Clear, popup_area);
            let mut lines = vec![Line::from(format!("Attach \"{}\" (fd {})?", program.name, program.fd))];
            if matches!(program.kind, AttachKind::Xdp | AttachKind::Tc) {
                lines.push(Line::from(format!("Interfaces: {}", app.interfaces.join(", "))));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("[Enter] confirm    [Esc] cancel"));
            frame.render_widget(
                Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Confirm")),
                popup_area,
            );
        }
    }

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

fn default_footer_hint() -> String {
    "Tab switch page   \u{2190}/\u{2192} section   \u{2191}/\u{2193} move   space toggle   d delete   enter add   q quit".to_string()
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

    if app.confirm_enable.is_some() {
        match code {
            KeyCode::Enter => confirm_enable(app),
            KeyCode::Esc => app.confirm_enable = None,
            _ => {}
        }
        return false;
    }

    match code {
        KeyCode::Char('q') => return true,
        KeyCode::Tab => {
            app.tab = match app.tab {
                Tab::Main => Tab::Analytics,
                Tab::Analytics => Tab::Main,
            };
            app.status = None;
        }
        KeyCode::Left if app.tab == Tab::Main => {
            app.section = app.section.prev();
            app.rebuild_rows();
        }
        KeyCode::Right if app.tab == Tab::Main => {
            app.section = app.section.next();
            app.rebuild_rows();
        }
        KeyCode::Down if app.tab == Tab::Main => select_next(app),
        KeyCode::Up if app.tab == Tab::Main => select_previous(app),
        KeyCode::Char(' ') if app.tab == Tab::Main => handle_space(app),
        KeyCode::Char('d') if app.tab == Tab::Main => handle_delete(app),
        KeyCode::Enter if app.tab == Tab::Main => handle_enter(app),
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
