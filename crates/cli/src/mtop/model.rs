use std::{
    cmp::Ordering,
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use macluster_protocol::types::MetricSnapshot;

const METRICS_STALE_AFTER: Duration = Duration::from_secs(6);
const CPU_HISTORY_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginIdentity {
    pub host: String,
    pub machine_uuid: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredNode {
    pub id: String,
    pub host: String,
    pub machine_uuid: Option<String>,
    pub queues: Vec<String>,
    pub local_transport: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Login,
    Compute,
    LoginCompute,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayNodeIdentity {
    pub id: String,
    pub host: String,
    pub role: NodeRole,
    pub queues: Vec<String>,
    pub compute_member: bool,
}

pub fn display_node_identities(
    login: &LoginIdentity,
    configured: &[ConfiguredNode],
    selected_queue: Option<&str>,
) -> Vec<DisplayNodeIdentity> {
    let local_node = configured.iter().find(|node| {
        node.local_transport
            || login.machine_uuid.as_ref().is_some_and(|uuid| {
                node.machine_uuid
                    .as_ref()
                    .is_some_and(|node_uuid| node_uuid.eq_ignore_ascii_case(uuid))
            })
    });
    let merge_login = local_node.is_some_and(|node| {
        !node.queues.is_empty()
            && selected_queue.is_none_or(|queue| node.queues.iter().any(|member| member == queue))
    });
    let mut rows = Vec::new();
    if merge_login {
        let node = local_node.expect("merge_login requires a matching node");
        rows.push(DisplayNodeIdentity {
            id: node.id.clone(),
            host: node.host.clone(),
            role: NodeRole::LoginCompute,
            queues: node.queues.clone(),
            compute_member: true,
        });
    } else {
        rows.push(DisplayNodeIdentity {
            // A leading `@` cannot be a configured NodeId, so this internal
            // key cannot collide with a real node named `login`.
            id: "@login".into(),
            host: login.host.clone(),
            role: NodeRole::Login,
            queues: Vec::new(),
            compute_member: false,
        });
    }
    for node in configured {
        if local_node.is_some_and(|local| local.id == node.id) {
            continue;
        }
        if selected_queue.is_some_and(|queue| !node.queues.iter().any(|member| member == queue)) {
            continue;
        }
        rows.push(DisplayNodeIdentity {
            id: node.id.clone(),
            host: node.host.clone(),
            role: NodeRole::Compute,
            queues: node.queues.clone(),
            compute_member: true,
        });
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    rows
}

#[derive(Clone, Debug)]
pub enum MetricView {
    Loading,
    Unavailable {
        reason: String,
    },
    Available {
        snapshot: MetricSnapshot,
        age: Duration,
        stale: bool,
    },
}

#[derive(Default)]
pub struct NodeMetricCache {
    last_success: Option<(MetricSnapshot, Instant)>,
    last_error: Option<String>,
}

impl NodeMetricCache {
    pub fn apply_success(&mut self, snapshot: MetricSnapshot, received_at: Instant) {
        self.last_success = Some((snapshot, received_at));
        self.last_error = None;
    }

    pub fn apply_error(&mut self, reason: String) {
        self.last_error = Some(reason);
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn view_at(&self, now: Instant) -> MetricView {
        if let Some((snapshot, received_at)) = &self.last_success {
            let age = now.saturating_duration_since(*received_at);
            return MetricView::Available {
                snapshot: snapshot.clone(),
                age,
                stale: age >= METRICS_STALE_AFTER,
            };
        }
        match &self.last_error {
            Some(reason) => MetricView::Unavailable {
                reason: reason.clone(),
            },
            None => MetricView::Loading,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortKey {
    Id,
    Cpu,
    Memory,
    Network,
    Power,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug, Default)]
pub struct ResourceValues {
    pub fresh: bool,
    pub cpu_percent: Option<f64>,
    pub cpu_max_percent: Option<f64>,
    pub cpu_temp_celsius: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub disk_read_bytes_per_sec: Option<f64>,
    pub disk_write_bytes_per_sec: Option<f64>,
    pub network_rx_bytes_per_sec: Option<f64>,
    pub network_tx_bytes_per_sec: Option<f64>,
    pub power_watts: Option<f64>,
    pub power_scope: Option<String>,
    pub fan_speed_rpm: Option<f64>,
    pub power_fresh: bool,
    pub gpu_percent: Option<f64>,
    pub gpu_fresh: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CpuTemperatureAggregate {
    pub max_celsius: Option<f64>,
    pub valid_nodes: usize,
    pub total_nodes: usize,
}

pub fn aggregate_cpu_temperature(rows: &[ResourceValues]) -> CpuTemperatureAggregate {
    let mut result = CpuTemperatureAggregate {
        total_nodes: rows.len(),
        ..CpuTemperatureAggregate::default()
    };
    for row in rows {
        if !row.fresh {
            continue;
        }
        let Some(value) = row
            .cpu_temp_celsius
            .filter(|value| value.is_finite() && *value > 0.0 && *value < 150.0)
        else {
            continue;
        };
        result.valid_nodes += 1;
        result.max_celsius = Some(result.max_celsius.map_or(value, |max| max.max(value)));
    }
    result
}

#[derive(Clone, Debug)]
pub struct SortRow {
    pub id: String,
    pub resources: ResourceValues,
}

impl SortRow {
    pub fn new(id: impl Into<String>, resources: ResourceValues) -> Self {
        Self {
            id: id.into(),
            resources,
        }
    }
}

pub fn sort_rows(rows: &mut [SortRow], key: SortKey, direction: SortDirection) {
    rows.sort_by(|left, right| compare_rows(left, right, key, direction));
}

fn compare_rows(
    left: &SortRow,
    right: &SortRow,
    key: SortKey,
    direction: SortDirection,
) -> Ordering {
    if key == SortKey::Id {
        return left.id.cmp(&right.id);
    }
    let left_value = sort_value(&left.resources, key);
    let right_value = sort_value(&right.resources, key);
    match (left_value, right_value) {
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left.id.cmp(&right.id),
        (Some(left_value), Some(right_value)) => {
            if key == SortKey::Power {
                let scope_order = left.resources.power_scope.cmp(&right.resources.power_scope);
                if scope_order != Ordering::Equal {
                    return scope_order;
                }
            }
            let value_order = left_value
                .partial_cmp(&right_value)
                .unwrap_or(Ordering::Equal);
            let value_order = if direction == SortDirection::Descending {
                value_order.reverse()
            } else {
                value_order
            };
            value_order.then_with(|| left.id.cmp(&right.id))
        }
    }
}

fn sort_value(resources: &ResourceValues, key: SortKey) -> Option<f64> {
    if key == SortKey::Power && resources.power_fresh {
        return resources.power_watts.filter(|value| value.is_finite());
    }
    if !resources.fresh {
        return None;
    }
    let finite = |value: f64| value.is_finite().then_some(value);
    match key {
        SortKey::Id => None,
        SortKey::Cpu => resources
            .cpu_percent
            .zip(resources.cpu_max_percent)
            .filter(|(_, maximum)| *maximum > 0.0)
            .and_then(|(value, maximum)| finite(value / maximum)),
        SortKey::Memory => resources
            .memory_used_bytes
            .zip(resources.memory_total_bytes)
            .filter(|(_, total)| *total > 0)
            .map(|(used, total)| used as f64 / total as f64),
        SortKey::Network => resources
            .network_rx_bytes_per_sec
            .zip(resources.network_tx_bytes_per_sec)
            .and_then(|(rx, tx)| finite(rx + tx)),
        SortKey::Power if resources.power_fresh => resources.power_watts.and_then(finite),
        SortKey::Power => None,
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CpuAggregate {
    pub cpu_percent: Option<f64>,
    pub cpu_max_percent: Option<f64>,
    pub valid_nodes: usize,
    pub total_nodes: usize,
}

pub fn aggregate_cpu(rows: &[ResourceValues]) -> CpuAggregate {
    let mut result = CpuAggregate {
        total_nodes: rows.len(),
        ..CpuAggregate::default()
    };
    let mut cpu = 0.0;
    let mut maximum = 0.0;
    for row in rows {
        if !row.fresh {
            continue;
        }
        if let Some((value, limit)) = row
            .cpu_percent
            .zip(row.cpu_max_percent)
            .filter(|(value, limit)| value.is_finite() && limit.is_finite() && *limit > 0.0)
        {
            cpu += value;
            maximum += limit;
            result.valid_nodes += 1;
        }
    }
    if result.valid_nodes > 0 {
        result.cpu_percent = Some(cpu);
        result.cpu_max_percent = Some(maximum);
    }
    result
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct MemoryAggregate {
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub valid_nodes: usize,
    pub total_nodes: usize,
}

pub fn aggregate_memory(rows: &[ResourceValues]) -> MemoryAggregate {
    let mut result = MemoryAggregate {
        total_nodes: rows.len(),
        ..MemoryAggregate::default()
    };
    let mut used = 0_u64;
    let mut total = 0_u64;
    for row in rows {
        if !row.fresh {
            continue;
        }
        if let Some((row_used, row_total)) = row.memory_used_bytes.zip(row.memory_total_bytes) {
            used = used.saturating_add(row_used);
            total = total.saturating_add(row_total);
            result.valid_nodes += 1;
        }
    }
    if result.valid_nodes > 0 {
        result.used_bytes = Some(used);
        result.total_bytes = Some(total);
    }
    result
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DiskAggregate {
    pub read_bytes_per_sec: Option<f64>,
    pub write_bytes_per_sec: Option<f64>,
    pub valid_nodes: usize,
    pub total_nodes: usize,
}

pub fn aggregate_disk(rows: &[ResourceValues]) -> DiskAggregate {
    let (first, second, valid_nodes) = aggregate_io(rows, |row| {
        row.disk_read_bytes_per_sec
            .zip(row.disk_write_bytes_per_sec)
    });
    DiskAggregate {
        read_bytes_per_sec: first,
        write_bytes_per_sec: second,
        valid_nodes,
        total_nodes: rows.len(),
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetworkAggregate {
    pub rx_bytes_per_sec: Option<f64>,
    pub tx_bytes_per_sec: Option<f64>,
    pub valid_nodes: usize,
    pub total_nodes: usize,
}

pub fn aggregate_network(rows: &[ResourceValues]) -> NetworkAggregate {
    let (first, second, valid_nodes) = aggregate_io(rows, |row| {
        row.network_rx_bytes_per_sec
            .zip(row.network_tx_bytes_per_sec)
    });
    NetworkAggregate {
        rx_bytes_per_sec: first,
        tx_bytes_per_sec: second,
        valid_nodes,
        total_nodes: rows.len(),
    }
}

fn aggregate_io(
    rows: &[ResourceValues],
    values: impl Fn(&ResourceValues) -> Option<(f64, f64)>,
) -> (Option<f64>, Option<f64>, usize) {
    let mut valid_nodes = 0;
    let mut first = 0.0;
    let mut second = 0.0;
    for row in rows {
        if !row.fresh {
            continue;
        }
        if let Some((a, b)) = values(row).filter(|(a, b)| a.is_finite() && b.is_finite()) {
            first += a;
            second += b;
            valid_nodes += 1;
        }
    }
    if valid_nodes > 0 {
        (Some(first), Some(second), valid_nodes)
    } else {
        (None, None, valid_nodes)
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PowerAggregate {
    pub watts: f64,
    pub valid_nodes: usize,
    pub total_nodes: usize,
}

pub fn aggregate_power(rows: &[ResourceValues]) -> BTreeMap<String, PowerAggregate> {
    let mut scopes = BTreeMap::<String, PowerAggregate>::new();
    for row in rows {
        if !row.power_fresh {
            continue;
        }
        let (Some(scope), Some(watts)) = (&row.power_scope, row.power_watts) else {
            continue;
        };
        if !watts.is_finite() || watts < 0.0 {
            continue;
        }
        let aggregate = scopes.entry(scope.clone()).or_default();
        aggregate.watts += watts;
        aggregate.valid_nodes += 1;
    }
    for aggregate in scopes.values_mut() {
        aggregate.total_nodes = rows.len();
    }
    scopes
}

#[derive(Clone, Debug, PartialEq)]
pub struct CpuPoint {
    pub at: Instant,
    pub percent: Option<f64>,
    pub maximum: Option<f64>,
}

#[derive(Default)]
pub struct CpuHistory {
    points: VecDeque<CpuPoint>,
    capacity: Option<f64>,
}

impl CpuHistory {
    pub fn record(&mut self, at: Instant, percent: Option<f64>, maximum: Option<f64>) {
        if let (Some(old), Some(new)) = (self.capacity, maximum)
            && old != new
        {
            self.points.clear();
        }
        if maximum.is_some() {
            self.capacity = maximum;
        }
        self.points.push_back(CpuPoint {
            at,
            percent,
            maximum,
        });
        while self
            .points
            .front()
            .is_some_and(|point| at.saturating_duration_since(point.at) > CPU_HISTORY_WINDOW)
        {
            self.points.pop_front();
        }
    }

    pub fn points(&self) -> &VecDeque<CpuPoint> {
        &self.points
    }
}
