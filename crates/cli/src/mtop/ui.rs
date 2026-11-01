use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use macluster_protocol::types::{DiskCapacity, JobRecord, JobState};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Cell, HighlightSpacing, Paragraph, Row, Table, TableState},
};
use unicode_width::UnicodeWidthStr;

use super::model::{
    DisplayNodeIdentity, MetricView, NodeRole, ResourceValues, SortDirection, SortKey, SortRow,
    aggregate_cpu, aggregate_cpu_temperature, aggregate_disk, aggregate_memory, aggregate_network,
    aggregate_power, sort_rows,
};
use super::processes::{ProcessInfo, ProcessSort, ProcessView, sort_processes};

const POWER_STALE_AFTER: Duration = Duration::from_secs(15);
const POWER_CACHE_TTL: Duration =
    Duration::from_millis(macluster_protocol::types::POWER_SAMPLE_CACHE_TTL_MS);
const DETAIL_BASE_ROWS: u16 = 5;
const DETAIL_MIN_PROCESS_ROWS: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutMode {
    TooSmall,
    Compact,
    Medium,
    Wide,
}

pub fn layout_mode(area: Rect) -> LayoutMode {
    if area.height <= 8 {
        LayoutMode::TooSmall
    } else if area.width >= 140 {
        LayoutMode::Wide
    } else if area.width >= 100 {
        LayoutMode::Medium
    } else {
        LayoutMode::Compact
    }
}

#[derive(Clone, Debug)]
pub struct UiNode {
    pub identity: DisplayNodeIdentity,
    pub metrics: MetricView,
    pub jobs: Vec<JobRecord>,
    pub cpu_history: Vec<Option<f64>>,
    pub last_error: Option<String>,
    pub processes: ProcessView,
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub queue_name: String,
    pub nodes: Vec<UiNode>,
    pub jobs: Vec<JobRecord>,
    pub selected_id: Option<String>,
    pub sort_key: SortKey,
    pub sort_direction: SortDirection,
    pub process_sort: ProcessSort,
    pub expanded: bool,
    pub show_help: bool,
    pub refresh_requested: bool,
    pub no_color: bool,
    pub updated_at: Option<Instant>,
    pub sample_latency: HashMap<String, Duration>,
    pub jobs_updated_at: Option<Instant>,
    pub job_store_error: Option<String>,
    pub status_message: Option<String>,
}

impl AppState {
    pub fn empty(queue_name: impl Into<String>) -> Self {
        Self {
            queue_name: queue_name.into(),
            nodes: Vec::new(),
            jobs: Vec::new(),
            selected_id: None,
            sort_key: SortKey::Id,
            sort_direction: SortDirection::Ascending,
            process_sort: ProcessSort::Cpu,
            expanded: false,
            show_help: false,
            refresh_requested: false,
            no_color: false,
            updated_at: None,
            sample_latency: HashMap::new(),
            jobs_updated_at: None,
            job_store_error: None,
            status_message: None,
        }
    }

    pub fn select_delta(&mut self, delta: isize) {
        if self.nodes.is_empty() {
            self.selected_id = None;
            return;
        }
        let index = self
            .selected_id
            .as_ref()
            .and_then(|id| self.nodes.iter().position(|node| &node.identity.id == id))
            .unwrap_or(0);
        let count = self.nodes.len() as isize;
        let next = (index as isize + delta).clamp(0, count - 1) as usize;
        self.selected_id = Some(self.nodes[next].identity.id.clone());
    }

    pub fn select_first(&mut self) {
        self.selected_id = self.nodes.first().map(|node| node.identity.id.clone());
    }

    pub fn select_last(&mut self) {
        self.selected_id = self.nodes.last().map(|node| node.identity.id.clone());
    }

    pub fn sort(&mut self, key: SortKey) {
        if self.sort_key == key {
            self.sort_direction = match self.sort_direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            self.sort_key = key;
            self.sort_direction = SortDirection::Descending;
        }
        self.sort_nodes();
    }

    pub fn sort_by_id(&mut self) {
        self.sort_key = SortKey::Id;
        self.sort_direction = SortDirection::Ascending;
        self.sort_nodes();
    }

    pub fn sort_nodes(&mut self) {
        let selected = self.selected_id.clone();
        let mut rows: Vec<_> = self
            .nodes
            .iter()
            .map(|node| SortRow::new(node.identity.id.clone(), resources(&node.metrics)))
            .collect();
        sort_rows(&mut rows, self.sort_key, self.sort_direction);
        let order: HashMap<_, _> = rows
            .into_iter()
            .enumerate()
            .map(|(index, row)| (row.id, index))
            .collect();
        self.nodes.sort_by_key(|node| order[&node.identity.id]);
        self.selected_id =
            selected.or_else(|| self.nodes.first().map(|node| node.identity.id.clone()));
    }

    pub fn selected(&self) -> Option<&UiNode> {
        let id = self.selected_id.as_ref()?;
        self.nodes.iter().find(|node| &node.identity.id == id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAction {
    Continue,
    Quit,
}

pub fn handle_key(state: &mut AppState, key: KeyEvent) -> InputAction {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL)
        || key.code == KeyCode::Char('q')
    {
        return InputAction::Quit;
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => state.select_delta(-1),
        KeyCode::Down | KeyCode::Char('j') => state.select_delta(1),
        KeyCode::PageUp => state.select_delta(-10),
        KeyCode::PageDown => state.select_delta(10),
        KeyCode::Home => state.select_first(),
        KeyCode::End => state.select_last(),
        KeyCode::Enter => {
            if state.show_help {
                state.show_help = false;
            } else {
                state.expanded = !state.expanded;
            }
        }
        KeyCode::Esc => {
            if state.show_help {
                state.show_help = false;
            } else {
                state.expanded = false;
            }
        }
        KeyCode::Char('c') => {
            if state.expanded {
                state.process_sort = ProcessSort::Cpu;
            } else {
                state.sort(SortKey::Cpu);
            }
        }
        KeyCode::Char('m') => {
            if state.expanded {
                state.process_sort = ProcessSort::Memory;
            } else {
                state.sort(SortKey::Memory);
            }
        }
        KeyCode::Char('n') => state.sort(SortKey::Network),
        KeyCode::Char('p') => state.sort(SortKey::Power),
        KeyCode::Char('i') => state.sort_by_id(),
        KeyCode::Char('r') => state.refresh_requested = true,
        KeyCode::Char('?') => state.show_help = !state.show_help,
        _ => {}
    }
    InputAction::Continue
}

pub(super) fn resources(view: &MetricView) -> ResourceValues {
    let MetricView::Available {
        snapshot,
        age,
        stale,
    } = view
    else {
        return ResourceValues::default();
    };
    let is_fresh = !stale;
    let power_age = snapshot
        .power_age_ms
        .map(Duration::from_millis)
        .map(|source_age| source_age.saturating_add(*age));
    let power_fresh =
        snapshot.power_watts.is_some() && power_age.is_some_and(|age| age <= POWER_CACHE_TTL);
    let gpu_age = snapshot
        .gpu_age_ms
        .map(Duration::from_millis)
        .map(|source_age| source_age.saturating_add(*age));
    let gpu_fresh = !stale
        && snapshot.gpu_percent.is_some()
        && gpu_age.is_some_and(|age| age < Duration::from_secs(8));
    ResourceValues {
        fresh: is_fresh,
        cpu_percent: snapshot.cpu_percent,
        cpu_max_percent: snapshot.cpu_max_percent,
        cpu_temp_celsius: snapshot.cpu_temp_celsius,
        memory_used_bytes: snapshot.memory_used_bytes,
        memory_total_bytes: snapshot.memory_total_bytes,
        disk_read_bytes_per_sec: snapshot.disk_read_bytes_per_sec,
        disk_write_bytes_per_sec: snapshot.disk_write_bytes_per_sec,
        network_rx_bytes_per_sec: snapshot.network_rx_bytes_per_sec,
        network_tx_bytes_per_sec: snapshot.network_tx_bytes_per_sec,
        power_watts: snapshot.power_watts,
        power_scope: snapshot.power_scope.clone(),
        fan_speed_rpm: snapshot.fan_speed_rpm,
        power_fresh,
        gpu_percent: snapshot.gpu_percent,
        gpu_fresh,
    }
}

pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    let area = frame.area();
    match layout_mode(area) {
        LayoutMode::TooSmall => render_too_small(frame, area),
        mode => render_dashboard(frame, area, state, mode),
    }
    if state.show_help && area.width >= 28 && area.height >= 10 {
        render_help(
            frame,
            centered(area, area.width.min(72), area.height.min(18)),
            state,
        );
    }
}

fn render_dashboard(frame: &mut Frame<'_>, area: Rect, state: &AppState, mode: LayoutMode) {
    let has_detail = area.height >= if mode == LayoutMode::Compact { 24 } else { 20 };
    let detail_height = if state.expanded && area.height >= 32 {
        18
    } else if state.expanded && area.height >= 26 {
        14
    } else if state.expanded && area.height >= 24 {
        12
    } else {
        8
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if has_detail {
            [
                Constraint::Length(5),
                Constraint::Min(5),
                Constraint::Length(detail_height),
                Constraint::Length(1),
            ]
        } else {
            [
                Constraint::Length(5),
                Constraint::Min(2),
                Constraint::Length(1),
                Constraint::Length(1),
            ]
        })
        .split(area);
    let task_counts = task_counts_by_node(&state.nodes, &state.jobs);
    render_summary(frame, chunks[0], state);
    render_nodes(frame, chunks[1], state, &task_counts);
    if has_detail {
        render_detail(frame, chunks[2], state, &task_counts);
    }
    render_footer(frame, chunks[3], state);
}

fn render_summary(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let scope_rows: Vec<_> = state
        .nodes
        .iter()
        .filter(|node| node.identity.compute_member)
        .map(|node| resources(&node.metrics))
        .collect();
    let cpu = aggregate_cpu(&scope_rows);
    let cpu_temperature = aggregate_cpu_temperature(&scope_rows);
    let memory = aggregate_memory(&scope_rows);
    let disk = aggregate_disk(&scope_rows);
    let network = aggregate_network(&scope_rows);
    let power = aggregate_power(&scope_rows);
    let online = state
        .nodes
        .iter()
        .filter(|node| {
            node.identity.compute_member
                && matches!(node.metrics, MetricView::Available { stale: false, .. })
        })
        .count();
    let compute_nodes = state
        .nodes
        .iter()
        .filter(|node| node.identity.compute_member)
        .count();
    let pending = state
        .jobs
        .iter()
        .filter(|job| job.state == JobState::Pending)
        .count();
    let active = state
        .jobs
        .iter()
        .filter(|job| {
            matches!(
                job.state,
                JobState::Starting | JobState::Running | JobState::Cancelling
            )
        })
        .count();
    let job_summary = if state.job_store_error.is_some() {
        "Jobs N/A".into()
    } else {
        format!("{active} active · {pending} pending")
    };
    let timestamp = state
        .updated_at
        .map_or_else(|| "waiting".into(), |instant| format_age(instant.elapsed()));
    let title_style = if state.no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    let summary = vec![Line::from(Span::styled(
        format!(
            " {}  ·  {}/{} compute nodes online   {}   Updated {}",
            state.queue_name, online, compute_nodes, job_summary, timestamp
        ),
        title_style,
    ))];
    let cpu_text = aggregate_cpu_text(
        cpu.cpu_percent,
        cpu.cpu_max_percent,
        cpu.valid_nodes,
        cpu.total_nodes,
    );
    let memory_text = match (memory.used_bytes, memory.total_bytes) {
        (Some(used), Some(total)) => format!(
            "MEM(GiB) {:.1} / {:.1}{}",
            gib(used),
            gib(total),
            coverage(memory.valid_nodes, memory.total_nodes)
        ),
        _ => format!(
            "MEM(GiB) N/A{}",
            coverage(memory.valid_nodes, memory.total_nodes)
        ),
    };
    let power_text = if power.is_empty() {
        format!("Power N/A{}", coverage(0, scope_rows.len()))
    } else {
        format!(
            "Power {}",
            power
                .iter()
                .map(|(scope, aggregate)| format!(
                    "{:.1} W {scope}{}",
                    aggregate.watts,
                    coverage(aggregate.valid_nodes, aggregate.total_nodes)
                ))
                .collect::<Vec<_>>()
                .join(" · ")
        )
    };
    let disk_text = format!(
        "DISK(R/W) {}",
        match (disk.read_bytes_per_sec, disk.write_bytes_per_sec) {
            (Some(read), Some(write)) => format!(
                "{:.2}/{:.2} MB/s{}",
                read / 1_000_000.0,
                write / 1_000_000.0,
                coverage(disk.valid_nodes, disk.total_nodes)
            ),
            _ => format!("N/A{}", coverage(disk.valid_nodes, disk.total_nodes)),
        }
    );
    let network_text = format!(
        "NET(down/up) {}",
        match (network.rx_bytes_per_sec, network.tx_bytes_per_sec) {
            (Some(rx), Some(tx)) => format!(
                "{:.2}/{:.2} MB/s{}",
                rx / 1_000_000.0,
                tx / 1_000_000.0,
                coverage(network.valid_nodes, network.total_nodes)
            ),
            _ => format!("N/A{}", coverage(network.valid_nodes, network.total_nodes)),
        }
    );
    let mut summary = summary;
    let temperature_text = match cpu_temperature.max_celsius {
        Some(value) => format!(
            "TEMP max {value:.1}°C · {}/{}",
            cpu_temperature.valid_nodes, cpu_temperature.total_nodes
        ),
        None => format!(
            "TEMP max N/A · {}/{}",
            cpu_temperature.valid_nodes, cpu_temperature.total_nodes
        ),
    };
    if area.width < 100 {
        let compact_cpu = match (cpu.cpu_percent, cpu.cpu_max_percent) {
            (Some(value), Some(max)) => format!(
                "CPU% {value:.0}/{max:.0}{}",
                compact_coverage(cpu.valid_nodes, cpu.total_nodes)
            ),
            _ => format!(
                "CPU% N/A{}",
                compact_coverage(cpu.valid_nodes, cpu.total_nodes)
            ),
        };
        let compact_memory = match (memory.used_bytes, memory.total_bytes) {
            (Some(used), Some(total)) => format!(
                "MEM(GiB) {:.1}/{:.1}{}",
                gib(used),
                gib(total),
                compact_coverage(memory.valid_nodes, memory.total_nodes)
            ),
            _ => format!(
                "MEM(GiB) N/A{}",
                compact_coverage(memory.valid_nodes, memory.total_nodes)
            ),
        };
        let compact_temperature = match cpu_temperature.max_celsius {
            Some(value) => format!(
                "TEMP max {value:.1}°C {}/{}",
                cpu_temperature.valid_nodes, cpu_temperature.total_nodes
            ),
            None => format!(
                "TEMP max N/A {}/{}",
                cpu_temperature.valid_nodes, cpu_temperature.total_nodes
            ),
        };
        summary.push(Line::from(format!(
            " {compact_cpu}    {compact_memory}    {compact_temperature}"
        )));
        summary.push(Line::from(format!(
            " {disk_text}    {network_text}    {power_text}"
        )));
    } else {
        summary.push(Line::from(format!(
            " {cpu_text}    {memory_text}    {temperature_text}"
        )));
        summary.push(Line::from(format!(
            " {disk_text}    {network_text}    {power_text}"
        )));
    }
    let mut block = Block::bordered().border_type(ratatui::widgets::BorderType::Rounded);
    if !state.no_color {
        block = block.border_style(Style::default().fg(Color::DarkGray));
    }
    frame.render_widget(Paragraph::new(summary).block(block), area);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeColumn {
    Node,
    Task,
    Cpu,
    Memory,
    Gpu,
    Disk,
    Network,
    Power,
    CpuTemp,
    Queues,
    Age,
}

impl NodeColumn {
    const PRIORITY: [Self; 11] = [
        Self::Node,
        Self::Task,
        Self::Cpu,
        Self::Memory,
        Self::Gpu,
        Self::Disk,
        Self::Network,
        Self::Power,
        Self::CpuTemp,
        Self::Queues,
        Self::Age,
    ];

    fn header(self) -> &'static str {
        match self {
            Self::Node => "NODE",
            Self::Task => "RUN/WAIT",
            Self::Cpu => "CPU%",
            Self::Memory => "MEM(GiB)",
            Self::Gpu => "GPU%",
            Self::Disk => "DISK(R/W)",
            Self::Network => "NET(down/up)",
            Self::Power => "POWER",
            Self::CpuTemp => "TEMP",
            Self::Queues => "QUEUES",
            Self::Age => "AGE",
        }
    }

    fn min_width(self) -> u16 {
        match self {
            Self::Node => 8,
            Self::Task => 8,
            Self::Cpu => 7,
            Self::Memory => 8,
            Self::Gpu => 5,
            Self::Disk | Self::Network => 13,
            Self::Power => 6,
            Self::CpuTemp => 6,
            Self::Queues => 6,
            Self::Age => 3,
        }
    }

    fn is_name(self) -> bool {
        matches!(self, Self::Node | Self::Queues)
    }

    fn preferred_width(self) -> u16 {
        match self {
            Self::Node => 12,
            Self::Task => 8,
            Self::Cpu => 8,
            Self::Memory => 11,
            Self::Gpu => 6,
            Self::Disk | Self::Network => 14,
            Self::Power => 8,
            Self::CpuTemp => 7,
            Self::Queues => 12,
            Self::Age => 5,
        }
    }

    fn max_width(self) -> u16 {
        match self {
            Self::Node | Self::Queues => 32,
            Self::Task => 8,
            Self::Cpu => 11,
            Self::Memory => 16,
            Self::Gpu => 7,
            Self::Disk | Self::Network => 20,
            Self::Power => 12,
            Self::CpuTemp => 8,
            Self::Age => 5,
        }
    }
}

fn visible_node_columns(
    width: u16,
    nodes: &[UiNode],
    task_counts: &HashMap<String, TaskCounts>,
) -> Vec<(NodeColumn, u16)> {
    // Reserve the table border and the two-cell row selection marker.
    let available = width.saturating_sub(4) as usize;
    let mut used = 0_usize;
    let mut columns = Vec::new();
    for column in NodeColumn::PRIORITY {
        let content_width = nodes
            .iter()
            .map(|node| UnicodeWidthStr::width(node_cell_value(node, column, task_counts).as_str()))
            .max()
            .unwrap_or(0)
            .min(usize::from(u16::MAX)) as u16;
        // Numeric cells must fit in full, including units and freshness markers.
        // Names have a stable compact width until every column is visible.
        let content_width = if column.is_name() {
            content_width.min(column.preferred_width())
        } else {
            content_width
        };
        let cell_width = column.min_width().max(content_width);
        let spacing = usize::from(!columns.is_empty());
        let required = usize::from(cell_width) + spacing;
        if used + required > available {
            break;
        }
        used += required;
        columns.push((column, cell_width));
    }

    // Keep these widths stable when admitting another column. Spending spare
    // space before the full set fits would make earlier columns shrink again.
    if columns.len() < NodeColumn::PRIORITY.len() {
        return columns;
    }

    let mut remaining = available.saturating_sub(used) as u16;
    for (column, allocated) in &mut columns {
        let content_width = nodes
            .iter()
            .map(|node| {
                UnicodeWidthStr::width(node_cell_value(node, *column, task_counts).as_str())
            })
            .max()
            .unwrap_or(0)
            .min(usize::from(column.max_width())) as u16;
        let wanted = column
            .preferred_width()
            .max(content_width)
            .min(column.max_width());
        let extra = wanted.saturating_sub(*allocated).min(remaining);
        *allocated += extra;
        remaining -= extra;
    }

    // If there is still room, grow flexible columns evenly so wide terminals
    // use the available space without allowing a single long name to dominate.
    const STRETCH_ORDER: [NodeColumn; 8] = [
        NodeColumn::Node,
        NodeColumn::Queues,
        NodeColumn::Disk,
        NodeColumn::Network,
        NodeColumn::Memory,
        NodeColumn::Power,
        NodeColumn::Cpu,
        NodeColumn::CpuTemp,
    ];
    while remaining > 0 {
        let mut grew = false;
        for stretch in STRETCH_ORDER {
            let Some((_, allocated)) = columns.iter_mut().find(|(column, _)| *column == stretch)
            else {
                continue;
            };
            if *allocated < stretch.max_width() && remaining > 0 {
                *allocated += 1;
                remaining -= 1;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    columns
}

fn render_nodes(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    task_counts: &HashMap<String, TaskCounts>,
) {
    let columns = visible_node_columns(area.width, &state.nodes, task_counts);
    let header = Row::new(columns.iter().map(|(column, width)| {
        Cell::from(truncate(column.header(), usize::from(*width)))
            .style(Style::default().add_modifier(Modifier::BOLD))
    }));
    let selected = state.selected_id.as_deref();
    let rows = state.nodes.iter().map(|node| {
        let cells = node_cells(node, &columns, task_counts);
        let id_style = if state.no_color {
            Style::default()
        } else {
            link_style(&node.metrics)
        };
        let cells = cells.into_iter().enumerate().map(|(index, value)| {
            let cell = Cell::from(value);
            if index == 0 {
                cell.style(id_style)
            } else {
                cell
            }
        });
        let style = if selected == Some(node.identity.id.as_str()) && !state.no_color {
            Style::default().bg(Color::Rgb(40, 55, 72))
        } else if state.no_color {
            Style::default()
        } else {
            link_style(&node.metrics)
        };
        Row::new(cells).style(style)
    });
    let constraints = columns
        .iter()
        .map(|(_, width)| Constraint::Length(*width))
        .collect::<Vec<_>>();
    let sort_label = match state.sort_key {
        SortKey::Id => "node ID",
        SortKey::Cpu => "CPU load",
        SortKey::Memory => "memory",
        SortKey::Network => "network",
        SortKey::Power => "power by scope",
    };
    let sort_arrow = if state.sort_direction == SortDirection::Descending {
        "↓"
    } else {
        "↑"
    };
    let table = Table::new(rows, constraints)
        .column_spacing(1)
        .header(header)
        .block(
            Block::bordered()
                .border_type(ratatui::widgets::BorderType::Rounded)
                .title(format!(" Nodes · {sort_label} {sort_arrow} ")),
        )
        .highlight_symbol("› ")
        .highlight_spacing(HighlightSpacing::Always)
        .row_highlight_style(if state.no_color {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().bg(Color::Blue)
        });
    let selected_index = state
        .selected_id
        .as_ref()
        .and_then(|id| state.nodes.iter().position(|node| &node.identity.id == id));
    let visible_rows = area.height.saturating_sub(3) as usize;
    let offset = selected_index
        .filter(|index| visible_rows > 0 && *index >= visible_rows)
        .map_or(0, |index| index + 1 - visible_rows);
    let mut table_state = TableState::default()
        .with_offset(offset)
        .with_selected(selected_index);
    frame.render_stateful_widget(table, area, &mut table_state);
}

fn node_cells(
    node: &UiNode,
    columns: &[(NodeColumn, u16)],
    task_counts: &HashMap<String, TaskCounts>,
) -> Vec<String> {
    columns
        .iter()
        .map(|(column, width)| {
            let value = node_cell_value(node, *column, task_counts);
            if column.is_name() {
                truncate(&value, usize::from(*width))
            } else {
                value
            }
        })
        .collect()
}

fn node_cell_value(
    node: &UiNode,
    column: NodeColumn,
    task_counts: &HashMap<String, TaskCounts>,
) -> String {
    let res = resources(&node.metrics);
    let age = match &node.metrics {
        MetricView::Loading | MetricView::Unavailable { .. } => "—".to_owned(),
        MetricView::Available { age, .. } => format_age(*age),
    };
    let cpu = pair_percent(res.cpu_percent, res.cpu_max_percent);
    let cpu_temperature = cpu_temperature_text(res.cpu_temp_celsius);
    let memory = memory_text(&res);
    let disk = pair_rate(res.disk_read_bytes_per_sec, res.disk_write_bytes_per_sec);
    let network = pair_rate(res.network_rx_bytes_per_sec, res.network_tx_bytes_per_sec);
    let power = power_cell(&node.metrics);
    let gpu = gpu_cell(&res);
    let queues = node.identity.queues.join(",");
    let display_id = if node.identity.role == NodeRole::Login {
        "login"
    } else {
        &node.identity.id
    };
    let tasks = task_counts
        .get(&node.identity.id)
        .copied()
        .unwrap_or_default();
    match column {
        NodeColumn::Node => display_id.to_owned(),
        NodeColumn::Task => format!("{}/{}", tasks.running, tasks.waiting),
        NodeColumn::Cpu => cpu.clone(),
        NodeColumn::Memory => memory.clone(),
        NodeColumn::Gpu => gpu.clone(),
        NodeColumn::Disk => disk.clone(),
        NodeColumn::Network => network.clone(),
        NodeColumn::Power => power.clone(),
        NodeColumn::CpuTemp => cpu_temperature.clone(),
        NodeColumn::Queues => queues,
        NodeColumn::Age => age.clone(),
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TaskCounts {
    running: usize,
    waiting: usize,
}

fn task_counts_by_node(nodes: &[UiNode], all_jobs: &[JobRecord]) -> HashMap<String, TaskCounts> {
    let mut counts: HashMap<_, _> = nodes
        .iter()
        .map(|node| {
            let running = node
                .jobs
                .iter()
                .filter(|job| {
                    matches!(
                        job.state,
                        JobState::Starting | JobState::Running | JobState::Cancelling
                    )
                })
                .count();
            (
                node.identity.id.clone(),
                TaskCounts {
                    running,
                    waiting: 0,
                },
            )
        })
        .collect();
    let mut pending_by_node = HashMap::<String, usize>::new();
    let mut pending_by_queue = HashMap::<String, usize>::new();
    for job in all_jobs.iter().filter(|job| job.state == JobState::Pending) {
        if let Some(node) = job.spec.node.as_ref() {
            *pending_by_node.entry(node.to_string()).or_default() += 1;
        } else {
            *pending_by_queue
                .entry(job.spec.queue.to_string())
                .or_default() += 1;
        }
    }
    for node in nodes {
        let Some(task_count) = counts.get_mut(&node.identity.id) else {
            continue;
        };
        task_count.waiting = pending_by_node
            .get(&node.identity.id)
            .copied()
            .unwrap_or_default();
        if node.identity.compute_member {
            for queue in &node.identity.queues {
                task_count.waiting += pending_by_queue.get(queue).copied().unwrap_or_default();
            }
        }
    }
    counts
}

fn render_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &AppState,
    task_counts: &HashMap<String, TaskCounts>,
) {
    let Some(node) = state.selected() else {
        frame.render_widget(
            Paragraph::new("No nodes configured").block(Block::bordered().title(" Selected node ")),
            area,
        );
        return;
    };
    let tasks = task_counts
        .get(&node.identity.id)
        .copied()
        .unwrap_or_default();
    let request_latency = state.sample_latency.get(&node.identity.id).map_or_else(
        || "N/A".to_owned(),
        |latency| format!("{}ms", latency.as_millis()),
    );
    if state.expanded {
        render_expanded_detail(
            frame,
            area,
            node,
            tasks,
            state.process_sort,
            state.no_color,
            &request_latency,
        );
        return;
    }
    let selected_age = match &node.metrics {
        MetricView::Available { age, .. } => format_age(*age),
        _ => "N/A".into(),
    };
    let latest = node
        .cpu_history
        .iter()
        .map(|point| match point {
            None => '·',
            Some(value) if *value < 10.0 => '▁',
            Some(value) if *value < 25.0 => '▂',
            Some(value) if *value < 40.0 => '▃',
            Some(value) if *value < 55.0 => '▄',
            Some(value) if *value < 70.0 => '▅',
            Some(value) if *value < 85.0 => '▆',
            Some(value) if *value < 100.0 => '▇',
            Some(_) => '█',
        })
        .collect::<String>();
    let resources = resources(&node.metrics);
    let system_disk = disk_capacities(&node.metrics)
        .0
        .map(disk_capacity_value)
        .unwrap_or_else(|| "N/A".into());
    let display_id = if node.identity.role == NodeRole::Login {
        "login"
    } else {
        &node.identity.id
    };
    let info = vec![
        Line::from(vec![
            Span::styled(
                display_id,
                if state.no_color {
                    Style::default()
                } else {
                    link_style(&node.metrics)
                },
            ),
            Span::raw(format!(
                " · {} · sample age {selected_age} · request {request_latency}",
                node.identity.host
            )),
        ]),
        Line::from(format!(
            "Queues: {}",
            if node.identity.queues.is_empty() {
                "none".into()
            } else {
                node.identity.queues.join(", ")
            }
        )),
        Line::from(format!(
            "CPU% {}   MEM(GiB) {}   GPU% {}   POWER {}",
            pair_percent(resources.cpu_percent, resources.cpu_max_percent),
            memory_text(&resources),
            gpu_cell(&resources),
            power_text(&node.metrics)
        )),
        Line::from(format!(
            "DISK(R/W) {}   NET(down/up) {}   FAN {}",
            pair_rate(
                resources.disk_read_bytes_per_sec,
                resources.disk_write_bytes_per_sec
            ),
            pair_rate(
                resources.network_rx_bytes_per_sec,
                resources.network_tx_bytes_per_sec
            ),
            fan_speed_detail_text(&node.metrics, resources.fan_speed_rpm)
        )),
        Line::from(format!(
            "TEMP {}   SYS DISK {system_disk}",
            cpu_temperature_text(resources.cpu_temp_celsius)
        )),
        Line::from(format!("CPU · last 60s  {latest}")),
        Line::from(format!(
            "Jobs: {} · RUN/WAIT {}/{} · database read {}",
            job_label(&node.jobs),
            tasks.running,
            tasks.waiting,
            state
                .jobs_updated_at
                .map_or_else(|| "N/A".into(), |at| format_age(at.elapsed()))
        )),
    ];
    let mut info = info;
    if node.jobs.len() > 1 {
        for job in &node.jobs {
            info.push(Line::from(format!(
                "Job {} {:?} · node {}",
                job.id,
                job.state,
                job.node.as_ref().map_or("unknown", |node| node.as_str())
            )));
        }
    }
    if let Some(error) = node.last_error.as_deref() {
        info.push(Line::from(format!("Last request error: {error}")));
    }
    if let MetricView::Available { snapshot, .. } = &node.metrics {
        for (metric, error) in &snapshot.errors {
            info.push(Line::from(format!("{metric}: {error}")));
        }
    }
    if let MetricView::Unavailable { reason } = &node.metrics {
        info.push(Line::from(format!("Unavailable: {reason}")));
    }
    frame.render_widget(
        Paragraph::new(info)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .block(
                Block::bordered()
                    .border_type(ratatui::widgets::BorderType::Rounded)
                    .title(if state.expanded {
                        " Details · Esc to close "
                    } else {
                        " Selected node · Enter for details "
                    }),
            ),
        area,
    );
}

fn render_expanded_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    node: &UiNode,
    tasks: TaskCounts,
    process_sort: ProcessSort,
    no_color: bool,
    request_latency: &str,
) {
    let selected_age = match &node.metrics {
        MetricView::Available { age, .. } => format_age(*age),
        _ => "N/A".into(),
    };
    let resources = resources(&node.metrics);
    let display_id = if node.identity.role == NodeRole::Login {
        "login"
    } else {
        &node.identity.id
    };
    let queues = if node.identity.queues.is_empty() {
        "none".to_owned()
    } else {
        node.identity.queues.join(", ")
    };
    let block = Block::bordered()
        .border_type(ratatui::widgets::BorderType::Rounded)
        .title(" Details · c CPU ↓ · m Memory ↓ · Esc to close ");
    let inner = block.inner(area);
    let (system_disk, external_disks) = disk_capacities(&node.metrics);
    let external_disk_line = (inner.height > DETAIL_BASE_ROWS + DETAIL_MIN_PROCESS_ROWS)
        .then(|| external_disk_capacity_line(external_disks, inner.width as usize))
        .flatten();
    let external_disk_rows = usize::from(external_disk_line.is_some());
    frame.render_widget(block, area);
    let mut constraints =
        vec![Constraint::Length(1); DETAIL_BASE_ROWS as usize + external_disk_rows];
    constraints.push(Constraint::Min(1));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                display_id,
                if no_color {
                    Style::default()
                } else {
                    link_style(&node.metrics)
                },
            ),
            Span::raw(format!(
                " · {} · sample age {selected_age} · request {request_latency} · queues {queues}",
                node.identity.host
            )),
        ])),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "CPU% {}   MEM(GiB) {}   GPU% {}   TEMP {}",
            pair_percent(resources.cpu_percent, resources.cpu_max_percent),
            memory_text(&resources),
            gpu_cell(&resources),
            cpu_temperature_text(resources.cpu_temp_celsius)
        )),
        chunks[1],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "DISK(R/W) {}   NET(down/up) {}",
            pair_rate(
                resources.disk_read_bytes_per_sec,
                resources.disk_write_bytes_per_sec
            ),
            pair_rate(
                resources.network_rx_bytes_per_sec,
                resources.network_tx_bytes_per_sec
            ),
        )),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "POWER {}   FAN {}   {}",
            power_text(&node.metrics),
            fan_speed_detail_text(&node.metrics, resources.fan_speed_rpm),
            system_disk.map_or_else(
                || "SYS DISK N/A".into(),
                |disk| disk_capacity_line("SYS DISK", disk)
            )
        )),
        chunks[3],
    );
    if let Some(line) = external_disk_line {
        frame.render_widget(Paragraph::new(line), chunks[4]);
    }
    frame.render_widget(
        Paragraph::new(format!(
            "Jobs {} · RUN/WAIT {}/{} · {}",
            job_label(&node.jobs),
            tasks.running,
            tasks.waiting,
            process_status(&node.processes, process_sort)
        )),
        chunks[4 + external_disk_rows],
    );

    let preview_cpu = matches!(
        &node.processes,
        ProcessView::Available {
            warning: Some(warning),
            ..
        } if warning.starts_with("Preview: ps average CPU%")
    );
    let mut rows = match &node.processes {
        ProcessView::Available { rows, .. } => rows.clone(),
        ProcessView::Loading | ProcessView::Unavailable { .. } => Vec::new(),
    };
    sort_processes(&mut rows, process_sort);
    let table_rows = rows.iter().map(process_row);
    let table = Table::new(
        table_rows,
        [
            Constraint::Length(7),
            Constraint::Length(if preview_cpu { 10 } else { 8 }),
            Constraint::Length(9),
            Constraint::Length(12),
            Constraint::Min(8),
        ],
    )
    .header(
        Row::new([
            "PID",
            if preview_cpu { "CPU(avg)%" } else { "CPU%" },
            "MEM",
            "TIME",
            "COMMAND",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(table, chunks[5 + external_disk_rows]);
}

fn disk_capacities(view: &MetricView) -> (Option<&DiskCapacity>, &[DiskCapacity]) {
    match view {
        MetricView::Available { snapshot, .. } => (
            snapshot.system_disk_capacity.as_ref(),
            &snapshot.external_disk_capacities,
        ),
        MetricView::Loading | MetricView::Unavailable { .. } => (None, &[]),
    }
}

fn disk_capacity_line(label: &str, disk: &DiskCapacity) -> String {
    format!("{label} {}", disk_capacity_value(disk))
}

fn external_disk_capacity_line(disks: &[DiskCapacity], max_width: usize) -> Option<String> {
    let entries = disks
        .iter()
        .filter(|disk| !is_recovery_volume(disk))
        .map(|disk| {
            let name = disk
                .mount_point
                .strip_prefix("/Volumes/")
                .unwrap_or(&disk.mount_point)
                .split('/')
                .next()
                .filter(|name| !name.is_empty())
                .unwrap_or("volume");
            format!("{name} {}", disk_capacity_value(disk))
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return None;
    }
    Some(truncate(&format!("EXT {}", entries.join(" · ")), max_width))
}

fn is_recovery_volume(disk: &DiskCapacity) -> bool {
    disk.mount_point
        .strip_prefix("/Volumes/")
        .is_some_and(|name| name.eq_ignore_ascii_case("Recovery"))
}

fn disk_capacity_value(disk: &DiskCapacity) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = GIB * 1024.0;
    let (unit, divisor) = if disk.total_bytes as f64 >= TIB {
        ("TiB", TIB)
    } else {
        ("GiB", GIB)
    };
    format!(
        "{:.1}/{:.1} {unit}",
        disk.used_bytes.min(disk.total_bytes) as f64 / divisor,
        disk.total_bytes as f64 / divisor
    )
}

fn process_status(view: &ProcessView, sort: ProcessSort) -> String {
    let sort_label = match sort {
        ProcessSort::Cpu => "CPU ↓",
        ProcessSort::Memory => "Memory ↓",
    };
    match view {
        ProcessView::Loading => {
            format!("Processes · sorted {sort_label} · sampling selected node…")
        }
        ProcessView::Unavailable { reason } => {
            format!("Processes · sorted {sort_label} · unavailable: {reason}")
        }
        ProcessView::Available {
            rows,
            age,
            stale,
            warning,
        } => {
            let freshness = if *stale { " · STALE" } else { "" };
            let no_processes = if rows.is_empty() {
                " · no processes reported"
            } else {
                ""
            };
            let warning = warning
                .as_deref()
                .map(|warning| {
                    if warning.starts_with("Preview:") {
                        format!(" · {warning}")
                    } else {
                        format!(" · refresh failed: {warning}")
                    }
                })
                .unwrap_or_default();
            format!(
                "Processes · sorted {sort_label} · updated {} ago{freshness}{no_processes}{warning}",
                format_age(*age)
            )
        }
    }
}

fn process_row(process: &ProcessInfo) -> Row<'static> {
    Row::new([
        process.pid.to_string(),
        format!("{:.1}", process.cpu_percent),
        process.memory.clone(),
        process.cpu_time.clone(),
        process.command.clone(),
    ])
}

pub(super) fn job_label(jobs: &[JobRecord]) -> String {
    match jobs {
        [] => "—".into(),
        [job] => format!("{} {:?}", job.id, job.state),
        _ => "CONFLICT".into(),
    }
}

fn power_cell(view: &MetricView) -> String {
    let Some((watts, scope, age)) = power_reading(view) else {
        return "N/A".into();
    };
    let scope = if scope.eq_ignore_ascii_case("soc") || scope.eq_ignore_ascii_case("system") {
        String::new()
    } else {
        format!(" {scope}")
    };
    let age = match age {
        Some(age) if age < POWER_STALE_AFTER => "",
        Some(_) => "*",
        None => "?",
    };
    format!("{watts:.1}W{scope}{age}")
}

pub(super) fn power_text(view: &MetricView) -> String {
    match power_reading(view) {
        Some((watts, scope, Some(age))) => {
            let scope = detail_power_scope(scope);
            let freshness = if age >= POWER_STALE_AFTER { "*" } else { "" };
            format!("{watts:.1} W{scope}{freshness}")
        }
        Some((watts, scope, None)) => {
            format!("{watts:.1} W{}?", detail_power_scope(scope))
        }
        None => "N/A".into(),
    }
}

fn detail_power_scope(scope: &str) -> String {
    if scope.eq_ignore_ascii_case("soc") || scope.eq_ignore_ascii_case("system") {
        String::new()
    } else {
        format!(" {scope}")
    }
}

fn power_reading(view: &MetricView) -> Option<(f64, &str, Option<Duration>)> {
    let MetricView::Available { snapshot, age, .. } = view else {
        return None;
    };
    let (Some(watts), Some(scope)) = (snapshot.power_watts, snapshot.power_scope.as_deref()) else {
        return None;
    };
    let age = snapshot
        .power_age_ms
        .map(Duration::from_millis)
        .map(|source_age| source_age.saturating_add(*age));
    if age.is_some_and(|age| age > POWER_CACHE_TTL) {
        return None;
    }
    Some((watts, scope, age))
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let hint = if state.show_help {
        "? Close help"
    } else if state.expanded {
        "q Quit   ↑↓/jk Select   c CPU process ↓   m Memory process ↓   n Network nodes   p Power nodes   Enter Collapse   ? Help"
    } else {
        "q Quit   ↑↓/jk Select   Enter Details   c CPU   m Memory   n Network   p Power   r Refresh   ? Help"
    };
    let status = state
        .status_message
        .as_deref()
        .or(state.job_store_error.as_deref())
        .unwrap_or(hint);
    let color = if !state.no_color && state.status_message.is_some() {
        Color::Yellow
    } else {
        Color::DarkGray
    };
    frame.render_widget(
        Paragraph::new(truncate(status, area.width as usize))
            .style(Style::default().fg(if state.no_color { Color::Reset } else { color })),
        area,
    );
}

fn render_too_small(frame: &mut Frame<'_>, area: Rect) {
    let text = if area.width >= 12 {
        "mtop · q quits"
    } else {
        "q quits"
    };
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);
}

fn render_help(frame: &mut Frame<'_>, area: Rect, state: &AppState) {
    let sort_help = if state.expanded {
        " c / m            Sort processes by CPU↓ / memory↓"
    } else {
        " c / m            Sort nodes by CPU / memory"
    };
    let text = vec![
        Line::from(Span::styled(
            " mtop controls ",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(" q / Ctrl-C       Quit and restore terminal"),
        Line::from(" ↑↓ / j k         Select node"),
        Line::from(" PageUp/Down      Scroll node list"),
        Line::from(" Enter / Esc      Toggle details / close help"),
        Line::from(sort_help),
        Line::from(" n / p            Sort nodes by network / power"),
        Line::from(" i                Sort by node ID"),
        Line::from(" r                Request a refresh"),
        Line::from(" ?                Close this help"),
        Line::from(" CPU values are actual percent (8 CPUs can reach 800%)."),
        Line::from(" Unknown or stale values are shown as N/A or STALE."),
    ];
    let mut paragraph = Paragraph::new(text).block(
        Block::bordered()
            .border_type(ratatui::widgets::BorderType::Rounded)
            .title(" Help "),
    );
    if !state.no_color {
        paragraph = paragraph.style(Style::default().bg(Color::Black).fg(Color::White));
    }
    frame.render_widget(paragraph, area);
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width.min(area.width),
        height.min(area.height),
    )
}

fn link_style(view: &MetricView) -> Style {
    match view {
        MetricView::Available { stale: false, .. } => Style::default().fg(Color::Green),
        MetricView::Unavailable { .. } => Style::default().fg(Color::Red),
        MetricView::Available { stale: true, .. } | MetricView::Loading => {
            Style::default().fg(Color::Yellow)
        }
    }
}

fn aggregate_cpu_text(value: Option<f64>, max: Option<f64>, valid: usize, total: usize) -> String {
    match (value, max) {
        (Some(value), Some(max)) => format!("CPU% {value:.0}/{max:.0}{}", coverage(valid, total)),
        _ => format!("CPU% N/A{}", coverage(valid, total)),
    }
}

fn coverage(valid: usize, total: usize) -> String {
    if total > 0 && valid < total {
        format!(" · partial {valid}/{total}")
    } else {
        String::new()
    }
}

fn compact_coverage(valid: usize, total: usize) -> String {
    if total > 0 && valid < total {
        format!(" · {valid}/{total}")
    } else {
        String::new()
    }
}

fn pair_percent(value: Option<f64>, max: Option<f64>) -> String {
    match (value, max) {
        (Some(value), Some(max)) => format!("{value:.0}/{max:.0}"),
        _ => "N/A".into(),
    }
}

fn pair_rate(first: Option<f64>, second: Option<f64>) -> String {
    match (first, second) {
        (Some(a), Some(b)) => format!("{:.1}/{:.1} MB/s", a / 1_000_000.0, b / 1_000_000.0),
        _ => "N/A".into(),
    }
}

fn memory_text(resources: &ResourceValues) -> String {
    match (resources.memory_used_bytes, resources.memory_total_bytes) {
        (Some(used), Some(total)) => format!("{:.1}/{:.1}", gib(used), gib(total)),
        _ => "N/A".into(),
    }
}

fn cpu_temperature_text(value: Option<f64>) -> String {
    match value {
        Some(value) if value.is_finite() && value > 0.0 && value < 150.0 => {
            format!("{value:.1}°C")
        }
        _ => "N/A".into(),
    }
}

fn fan_speed_text(value: Option<f64>) -> String {
    match value {
        Some(value) if value.is_finite() && (0.0..=100_000.0).contains(&value) => {
            format!("{value:.0} RPM")
        }
        _ => "N/A".into(),
    }
}

fn fan_speed_detail_text(view: &MetricView, value: Option<f64>) -> String {
    if matches!(
        view,
        MetricView::Available { snapshot, .. }
            if snapshot.errors.contains_key("fan_speed")
    ) {
        "N/A (update Agent)".into()
    } else {
        fan_speed_text(value)
    }
}

fn gpu_cell(resources: &ResourceValues) -> String {
    match resources
        .gpu_percent
        .filter(|value| resources.gpu_fresh && value.is_finite() && (0.0..=100.0).contains(value))
    {
        Some(value) => format!("{value:.1}"),
        None => "N/A".into(),
    }
}

fn gib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}

fn format_age(age: Duration) -> String {
    if age.as_secs() < 1 {
        "<1s".into()
    } else {
        format!("{}s", age.as_secs())
    }
}

fn truncate(value: &str, max_width: usize) -> String {
    if UnicodeWidthStr::width(value) <= max_width {
        return value.to_owned();
    }
    if max_width <= 1 {
        return "…".chars().take(max_width).collect();
    }
    let target = max_width - 1;
    let mut result = String::new();
    let mut width = 0;
    for ch in value.chars() {
        let ch_width = UnicodeWidthStr::width(ch.encode_utf8(&mut [0; 4]));
        if width + ch_width > target {
            break;
        }
        result.push(ch);
        width += ch_width;
    }
    result.push('…');
    result
}
