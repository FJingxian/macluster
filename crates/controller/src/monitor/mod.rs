//! Shared controller-side sampling for all local mtop clients.

mod processes;
mod sampler;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use macluster_core::config::{ClusterConfig, NodeConfig};
use macluster_protocol::{
    control::{
        MAX_CONTROL_MONITOR_NODES, MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES,
        MAX_MONITOR_PROCESS_ROWS, MonitorSnapshot, NodeMonitorRow, ProcessRow,
    },
    identifiers::{Id128, NodeId},
    types::MetricSnapshot,
};

use self::{processes::ProcessSampler, sampler::MetricSampler};

const MONITOR_LEASE: Duration = Duration::from_secs(30);
const METRIC_INTERVAL: Duration = Duration::from_secs(2);
const PROCESS_INTERVAL: Duration = Duration::from_secs(1);
const METRIC_STALE_AFTER: Duration = Duration::from_secs(6);
const PROCESS_STALE_AFTER: Duration = Duration::from_secs(10);
const LIVENESS_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const MAX_MONITOR_ERROR_BYTES: usize = 1_024;
const MAX_METRIC_ERROR_FIELDS: usize = 64;

pub type MetricSampleFn =
    dyn Fn(&NodeId, &NodeConfig) -> Result<MetricSnapshot, String> + Send + Sync + 'static;
/// `needs_full_sample` indicates that the initial snapshot is partial and a
/// regular full sample should immediately follow it.
pub type InitialMetricSampleFn =
    dyn Fn(&NodeId, &NodeConfig) -> Result<(MetricSnapshot, bool), String> + Send + Sync + 'static;
pub type ProcessSampleFn =
    dyn Fn(&NodeId, &NodeConfig) -> Result<Vec<ProcessRow>, String> + Send + Sync + 'static;

struct Subscription {
    nodes: BTreeSet<NodeId>,
    processes: Option<NodeId>,
    expires_at: Instant,
}

#[derive(Default)]
struct MetricCache {
    snapshot: Option<MetricSnapshot>,
    sampled_at: Option<Instant>,
    request_latency_ms: Option<u64>,
    error: Option<String>,
    consecutive_failures: u8,
    next_sample_at: Option<Instant>,
}

#[derive(Default)]
struct ProcessCache {
    rows: Option<Vec<ProcessRow>>,
    sampled_at: Option<Instant>,
    error: Option<String>,
    consecutive_failures: u8,
    next_sample_at: Option<Instant>,
}

fn metric_retry_delay(consecutive_failures: u8) -> Duration {
    match consecutive_failures {
        0 | 1 => METRIC_INTERVAL,
        2 => Duration::from_secs(4),
        _ => Duration::from_secs(15),
    }
}

fn process_retry_delay(consecutive_failures: u8) -> Duration {
    match consecutive_failures {
        0 => PROCESS_INTERVAL,
        1 => Duration::from_secs(5),
        2 => Duration::from_secs(10),
        _ => Duration::from_secs(30),
    }
}

/// A single cache and sampler set shared by every authenticated IPC client.
/// Sampling is only scheduled for nodes covered by an unexpired subscription.
pub struct MonitorHub {
    config: ClusterConfig,
    subscriptions: HashMap<Id128, Subscription>,
    metric_cache: BTreeMap<NodeId, MetricCache>,
    process_cache: BTreeMap<NodeId, ProcessCache>,
    metric_sampler: MetricSampler,
    process_sampler: ProcessSampler,
    liveness_state_dir: Option<PathBuf>,
    last_liveness_refresh: Option<Instant>,
    unreachable_nodes: BTreeSet<NodeId>,
    agent_responding: BTreeMap<NodeId, bool>,
    job_counts: HashMap<NodeId, (u32, u32)>,
    sequence: u64,
    metric_cursor: usize,
    process_cursor: usize,
}

impl MonitorHub {
    pub fn new(config: ClusterConfig, namespace: String) -> Self {
        Self::new_with_optional_liveness(config, namespace, None)
    }

    /// Construct the production monitor with access to the controller's
    /// lightweight liveness journal. Nodes with a failed reachability probe are
    /// omitted from monitor sampling until the controller observes recovery.
    pub fn new_with_liveness(config: ClusterConfig, namespace: String, state_dir: PathBuf) -> Self {
        Self::new_with_optional_liveness(config, namespace, Some(state_dir))
    }

    fn new_with_optional_liveness(
        config: ClusterConfig,
        namespace: String,
        liveness_state_dir: Option<PathBuf>,
    ) -> Self {
        let metric_pool = crate::ssh::SshPool::new(namespace.clone());
        let process_pool = metric_pool.clone();
        let initial_pool = metric_pool.clone();
        let metric_sample: Arc<MetricSampleFn> = Arc::new(move |node_id, node| {
            sampler::sample_node(node_id, node, &metric_pool, false).map(|(snapshot, _)| snapshot)
        });
        let initial_metric_sample: Arc<InitialMetricSampleFn> =
            Arc::new(move |node_id, node| sampler::sample_node(node_id, node, &initial_pool, true));
        let process_sample: Arc<ProcessSampleFn> =
            Arc::new(move |node_id, node| processes::sample_node(node_id, node, &process_pool));
        Self::with_progressive_samplers(
            config,
            metric_sample,
            initial_metric_sample,
            process_sample,
        )
        .with_liveness_state_dir(liveness_state_dir)
    }

    fn with_liveness_state_dir(mut self, state_dir: Option<PathBuf>) -> Self {
        self.liveness_state_dir = state_dir;
        self
    }

    /// Inject deterministic probes for service-level regression tests and
    /// future monitoring backends. Production construction uses `new`.
    pub fn with_samplers(
        config: ClusterConfig,
        metric_sample: Arc<MetricSampleFn>,
        process_sample: Arc<ProcessSampleFn>,
    ) -> Self {
        let initial_metric_sample = Arc::clone(&metric_sample);
        let initial_metric_sample: Arc<InitialMetricSampleFn> = Arc::new(move |node_id, node| {
            initial_metric_sample(node_id, node).map(|snapshot| (snapshot, false))
        });
        Self::with_progressive_samplers(
            config,
            metric_sample,
            initial_metric_sample,
            process_sample,
        )
    }

    /// Construct a monitor with separate first-sample and full-sample probes.
    /// Existing callers can keep using `with_samplers`; this method lets
    /// production and deterministic tests publish fast initial data.
    pub fn with_progressive_samplers(
        config: ClusterConfig,
        metric_sample: Arc<MetricSampleFn>,
        initial_metric_sample: Arc<InitialMetricSampleFn>,
        process_sample: Arc<ProcessSampleFn>,
    ) -> Self {
        let metric_cache = config
            .nodes
            .keys()
            .filter_map(|id| NodeId::new(id.clone()).ok())
            .map(|id| (id, MetricCache::default()))
            .collect();
        let process_cache = config
            .nodes
            .keys()
            .filter_map(|id| NodeId::new(id.clone()).ok())
            .map(|id| (id, ProcessCache::default()))
            .collect();
        Self {
            config,
            subscriptions: HashMap::new(),
            metric_cache,
            process_cache,
            metric_sampler: MetricSampler::new(metric_sample, initial_metric_sample),
            process_sampler: ProcessSampler::new(process_sample),
            liveness_state_dir: None,
            last_liveness_refresh: None,
            unreachable_nodes: BTreeSet::new(),
            agent_responding: BTreeMap::new(),
            job_counts: HashMap::new(),
            sequence: 1,
            metric_cursor: 0,
            process_cursor: 0,
        }
    }

    pub fn subscribe(&mut self, client: Id128, node_ids: Vec<NodeId>, now: Instant) {
        self.expire(now);
        if node_ids.len() > MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES {
            return;
        }
        let nodes = node_ids
            .into_iter()
            .filter(|node_id| self.config.nodes.contains_key(node_id.as_str()))
            .collect();
        let process_watch = self
            .subscriptions
            .get(&client)
            .and_then(|subscription| subscription.processes.clone());
        self.subscriptions.insert(
            client,
            Subscription {
                nodes,
                processes: process_watch,
                expires_at: now + MONITOR_LEASE,
            },
        );
        self.poll_and_schedule(now);
    }

    pub fn watch_processes(
        &mut self,
        client: Id128,
        node_id: Option<NodeId>,
        now: Instant,
    ) -> bool {
        self.expire(now);
        let Some(subscription) = self.subscriptions.get_mut(&client) else {
            return false;
        };
        if node_id
            .as_ref()
            .is_some_and(|node_id| !subscription.nodes.contains(node_id))
        {
            return false;
        }
        subscription.processes = node_id;
        subscription.expires_at = now + MONITOR_LEASE;
        self.poll_and_schedule(now);
        true
    }

    pub fn renew(&mut self, client: Id128, now: Instant) -> bool {
        self.expire(now);
        let Some(subscription) = self.subscriptions.get_mut(&client) else {
            return false;
        };
        subscription.expires_at = now + MONITOR_LEASE;
        self.poll_and_schedule(now);
        true
    }

    pub fn disconnect(&mut self, client: Id128) {
        self.subscriptions.remove(&client);
    }

    pub fn expire(&mut self, now: Instant) {
        self.subscriptions
            .retain(|_, subscription| subscription.expires_at > now);
    }

    pub fn active_subscribers(&self) -> usize {
        self.subscriptions.len()
    }

    pub fn update_job_counts(&mut self, counts: HashMap<NodeId, (u32, u32)>) {
        if self.job_counts != counts {
            self.job_counts = counts;
            self.sequence = self.sequence.saturating_add(1);
        }
    }

    pub fn snapshot(&mut self, generation: u64, page: usize, now: Instant) -> MonitorSnapshot {
        self.expire(now);
        self.poll_and_schedule(now);
        let nodes = self
            .config
            .nodes
            .keys()
            .filter_map(|id| NodeId::new(id.clone()).ok())
            .map(|node_id| self.row(node_id, now))
            .collect::<Vec<_>>();
        let total_pages = nodes.len().div_ceil(MAX_CONTROL_MONITOR_NODES).max(1);
        let start = page.saturating_mul(MAX_CONTROL_MONITOR_NODES);
        let page_nodes = nodes
            .into_iter()
            .skip(start)
            .take(MAX_CONTROL_MONITOR_NODES)
            .collect();
        MonitorSnapshot {
            sequence: self.sequence,
            sampled_unix_ms: now_unix_ms(),
            generation,
            page,
            total_pages,
            nodes: page_nodes,
        }
    }

    fn row(&self, node_id: NodeId, now: Instant) -> NodeMonitorRow {
        let metrics = self.metric_cache.get(&node_id);
        let (mut snapshot, age, stale, mut sample_error) = match metrics {
            Some(cache) => match (&cache.snapshot, cache.sampled_at) {
                (Some(snapshot), Some(sampled_at)) => {
                    let age = now.saturating_duration_since(sampled_at);
                    let age_ms = duration_ms(age);
                    let snapshot = snapshot.clone();
                    (
                        snapshot,
                        Some(age_ms),
                        age >= METRIC_STALE_AFTER,
                        cache.error.clone(),
                    )
                }
                _ => (
                    macluster_metrics::unavailable(
                        now_unix_ms(),
                        cache
                            .error
                            .as_deref()
                            .unwrap_or("waiting for first monitor sample"),
                    ),
                    None,
                    true,
                    cache.error.clone(),
                ),
            },
            None => (
                macluster_metrics::unavailable(now_unix_ms(), "node is not configured"),
                None,
                true,
                Some("node is not configured".into()),
            ),
        };
        snapshot.stale = stale;

        let process = self.process_cache.get(&node_id);
        let process_watched = self
            .subscriptions
            .values()
            .any(|subscription| subscription.processes.as_ref() == Some(&node_id));
        let (process_rows, process_age_ms, process_stale, process_error) = match process {
            _ if !process_watched => (None, None, false, None),
            Some(cache) => match (&cache.rows, cache.sampled_at) {
                (Some(rows), Some(sampled_at)) => {
                    let age = now.saturating_duration_since(sampled_at);
                    (
                        Some(rows.clone()),
                        Some(duration_ms(age)),
                        age >= PROCESS_STALE_AFTER,
                        cache.error.clone(),
                    )
                }
                _ => (None, None, false, cache.error.clone()),
            },
            None => (None, None, false, None),
        };
        let (running_tasks, waiting_tasks) =
            self.job_counts.get(&node_id).copied().unwrap_or_default();
        let confirmed_offline = self.unreachable_nodes.contains(&node_id);
        let agent_responding = self.agent_responding.get(&node_id).copied();
        if agent_responding == Some(false) {
            sample_error.get_or_insert_with(|| {
                "host is reachable, but the macluster Agent is not responding".into()
            });
        }
        NodeMonitorRow {
            node_id,
            metrics: snapshot,
            age_ms: age,
            stale,
            confirmed_offline,
            agent_responding,
            sample_error,
            request_latency_ms: metrics.and_then(|cache| cache.request_latency_ms),
            consecutive_failures: metrics.map_or(0, |cache| cache.consecutive_failures),
            running_tasks,
            waiting_tasks,
            processes: process_rows,
            process_age_ms,
            process_stale,
            process_error,
        }
    }

    fn poll_and_schedule(&mut self, now: Instant) {
        self.refresh_liveness(now);

        for result in self.metric_sampler.poll() {
            if self.unreachable_nodes.contains(&result.node_id) {
                continue;
            }
            if let Some(cache) = self.metric_cache.get_mut(&result.node_id) {
                cache.request_latency_ms = Some(result.request_latency_ms);
                match result.result {
                    Ok(snapshot) => {
                        cache.snapshot = Some(bound_metric_snapshot(snapshot));
                        cache.sampled_at = Some(result.completed_at);
                        cache.error = None;
                        cache.consecutive_failures = 0;
                        cache.next_sample_at = Some(result.completed_at + METRIC_INTERVAL);
                    }
                    Err(error) => {
                        cache.error = Some(bound_text(error, MAX_MONITOR_ERROR_BYTES));
                        cache.consecutive_failures = cache.consecutive_failures.saturating_add(1);
                        cache.next_sample_at = Some(
                            result.completed_at + metric_retry_delay(cache.consecutive_failures),
                        );
                    }
                }
                self.sequence = self.sequence.saturating_add(1);
            }
        }

        let active_nodes = self
            .subscriptions
            .values()
            .flat_map(|subscription| subscription.nodes.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mut active_nodes = active_nodes.into_iter().collect::<Vec<_>>();
        let mut metric_last_scheduled = None;
        let mut metric_offset = 0;
        if !active_nodes.is_empty() {
            metric_offset = self.metric_cursor % active_nodes.len();
            active_nodes.rotate_left(metric_offset);
        }
        for (index, node_id) in active_nodes.iter().enumerate() {
            if self.unreachable_nodes.contains(node_id) {
                continue;
            }
            if !self.metric_sampler.has_capacity() {
                break;
            }
            let due = self
                .metric_cache
                .get(node_id)
                .is_some_and(|cache| cache.next_sample_at.is_none_or(|next| now >= next));
            if !due {
                continue;
            }
            let Some(node) = self.config.nodes.get(node_id.as_str()) else {
                continue;
            };
            let initial = self
                .metric_cache
                .get(node_id)
                .is_some_and(|cache| cache.snapshot.is_none());
            let requested = if initial {
                self.metric_sampler
                    .request_initial(node_id.clone(), node.clone())
            } else {
                self.metric_sampler.request(node_id.clone(), node.clone())
            };
            if requested && let Some(cache) = self.metric_cache.get_mut(&node_id) {
                cache.next_sample_at = Some(now + METRIC_INTERVAL);
                metric_last_scheduled = Some(index);
            }
        }
        if !active_nodes.is_empty() {
            self.metric_cursor = advance_cursor_after_batch(
                metric_offset,
                active_nodes.len(),
                metric_last_scheduled,
            );
        }

        for result in self.process_sampler.poll() {
            if self.unreachable_nodes.contains(&result.node_id) {
                continue;
            }
            let watched = self
                .subscriptions
                .values()
                .any(|subscription| subscription.processes.as_ref() == Some(&result.node_id));
            if watched && let Some(cache) = self.process_cache.get_mut(&result.node_id) {
                match result.result {
                    Ok(mut rows) => {
                        rows.retain(|row| row.cpu_percent.is_finite() && row.cpu_percent >= 0.0);
                        rows.truncate(MAX_MONITOR_PROCESS_ROWS);
                        for row in &mut rows {
                            row.memory = bound_text(std::mem::take(&mut row.memory), 64);
                            row.cpu_time = bound_text(std::mem::take(&mut row.cpu_time), 64);
                            row.command = bound_text(std::mem::take(&mut row.command), 512);
                        }
                        cache.rows = Some(rows);
                        cache.sampled_at = Some(result.completed_at);
                        cache.error = None;
                        cache.consecutive_failures = 0;
                        cache.next_sample_at = Some(result.completed_at + PROCESS_INTERVAL);
                    }
                    Err(error) => {
                        cache.error = Some(bound_text(error, MAX_MONITOR_ERROR_BYTES));
                        cache.consecutive_failures = cache.consecutive_failures.saturating_add(1);
                        cache.next_sample_at = Some(
                            result.completed_at + process_retry_delay(cache.consecutive_failures),
                        );
                    }
                }
                self.sequence = self.sequence.saturating_add(1);
            }
        }

        if self.subscriptions.is_empty() || !self.process_sampler.has_capacity() {
            return;
        }
        let watched = self
            .subscriptions
            .values()
            .filter_map(|subscription| subscription.processes.clone())
            .collect::<BTreeSet<_>>();
        let mut watched = watched.iter().cloned().collect::<Vec<_>>();
        let mut process_last_scheduled = None;
        let mut process_offset = 0;
        if !watched.is_empty() {
            process_offset = self.process_cursor % watched.len();
            watched.rotate_left(process_offset);
        }
        for (index, node_id) in watched.iter().enumerate() {
            if self.unreachable_nodes.contains(node_id) {
                continue;
            }
            if !self.process_sampler.has_capacity() {
                break;
            }
            let due = self
                .process_cache
                .get(node_id)
                .is_some_and(|cache| cache.next_sample_at.is_none_or(|next| now >= next));
            if !due {
                continue;
            }
            let Some(node) = self.config.nodes.get(node_id.as_str()) else {
                continue;
            };
            if self.process_sampler.request(node_id.clone(), node.clone())
                && let Some(cache) = self.process_cache.get_mut(&node_id)
            {
                cache.next_sample_at = Some(now + PROCESS_INTERVAL);
                process_last_scheduled = Some(index);
            }
        }
        if !watched.is_empty() {
            self.process_cursor =
                advance_cursor_after_batch(process_offset, watched.len(), process_last_scheduled);
        }
    }

    fn refresh_liveness(&mut self, now: Instant) {
        if self
            .last_liveness_refresh
            .is_some_and(|last| now.saturating_duration_since(last) < LIVENESS_REFRESH_INTERVAL)
        {
            return;
        }
        self.last_liveness_refresh = Some(now);
        let Some(state_dir) = self.liveness_state_dir.as_deref() else {
            return;
        };
        let Ok(records) = crate::liveness::read(state_dir, &self.config.share_uuid) else {
            return;
        };

        let unreachable = self
            .config
            .nodes
            .iter()
            .filter_map(|(id, node)| {
                let node_id = NodeId::new(id.clone()).ok()?;
                let expected_identity = node.machine_uuid.as_deref().unwrap_or(node.host.as_str());
                let record = records.get(id)?;
                (record.identity_key.eq_ignore_ascii_case(expected_identity)
                    && record.is_confirmed_offline())
                .then_some(node_id)
            })
            .collect::<BTreeSet<_>>();
        let now_ms = now_unix_ms();
        let agent_responding = self
            .config
            .nodes
            .iter()
            .filter_map(|(id, node)| {
                let node_id = NodeId::new(id.clone()).ok()?;
                let expected_identity = node.machine_uuid.as_deref().unwrap_or(node.host.as_str());
                let record = records.get(id)?;
                if !record.was_recently_reachable(expected_identity, now_ms)
                    || record.consecutive_failures > 0
                    || record.agent_sampled_unix_ms.is_none_or(|sampled| {
                        now_ms.saturating_sub(sampled) > crate::liveness::RECENTLY_ONLINE_TTL_MS
                    })
                {
                    return None;
                }
                record
                    .agent_responding
                    .map(|responding| (node_id, responding))
            })
            .collect::<BTreeMap<_, _>>();

        if unreachable == self.unreachable_nodes && agent_responding == self.agent_responding {
            return;
        }
        for node_id in unreachable.difference(&self.unreachable_nodes) {
            if let Some(cache) = self.metric_cache.get_mut(node_id) {
                cache.error = Some("node is unreachable; waiting for a successful probe".into());
                cache.consecutive_failures = cache
                    .consecutive_failures
                    .max(crate::liveness::OFFLINE_AFTER_FAILURES);
                cache.next_sample_at = None;
            }
            if let Some(cache) = self.process_cache.get_mut(node_id) {
                cache.error = Some("node is unreachable; waiting for a successful probe".into());
                cache.consecutive_failures = cache
                    .consecutive_failures
                    .max(crate::liveness::OFFLINE_AFTER_FAILURES);
                cache.next_sample_at = None;
            }
        }
        for node_id in self.unreachable_nodes.difference(&unreachable) {
            if let Some(cache) = self.metric_cache.get_mut(node_id) {
                cache.snapshot = None;
                cache.sampled_at = None;
                cache.error = None;
                cache.consecutive_failures = 0;
                cache.next_sample_at = Some(now);
            }
            if let Some(cache) = self.process_cache.get_mut(node_id) {
                cache.rows = None;
                cache.sampled_at = None;
                cache.error = None;
                cache.consecutive_failures = 0;
                cache.next_sample_at = Some(now);
            }
        }
        self.unreachable_nodes = unreachable;
        self.agent_responding = agent_responding;
        self.sequence = self.sequence.saturating_add(1);
    }
}

fn advance_cursor_after_batch(start: usize, len: usize, last_scheduled: Option<usize>) -> usize {
    if len == 0 {
        return 0;
    }
    (start + last_scheduled.map_or(1, |index| index.saturating_add(1))) % len
}

#[cfg(test)]
mod tests {
    use super::advance_cursor_after_batch;

    #[test]
    fn cursor_advances_past_the_last_scheduled_node_in_a_rotated_batch() {
        assert_eq!(advance_cursor_after_batch(0, 5, Some(2)), 3);
        assert_eq!(advance_cursor_after_batch(4, 5, Some(1)), 1);
    }

    #[test]
    fn cursor_advances_one_position_when_no_node_was_scheduled() {
        assert_eq!(advance_cursor_after_batch(2, 5, None), 3);
        assert_eq!(advance_cursor_after_batch(0, 0, None), 0);
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn bound_metric_snapshot(mut snapshot: MetricSnapshot) -> MetricSnapshot {
    snapshot.errors = snapshot
        .errors
        .into_iter()
        .take(MAX_METRIC_ERROR_FIELDS)
        .map(|(key, value)| {
            (
                bound_text(key, 128),
                bound_text(value, MAX_MONITOR_ERROR_BYTES),
            )
        })
        .collect();
    if let Some(fans) = snapshot.fan_readings.as_mut() {
        fans.retain(|fan| fan.rpm <= 100_000);
        fans.truncate(16);
        for fan in fans {
            fan.name = bound_text(std::mem::take(&mut fan.name), 64);
            if fan.max_rpm.is_some_and(|rpm| rpm > 100_000) {
                fan.max_rpm = None;
            }
        }
    }
    if let Some(disk) = snapshot.system_disk_capacity.as_mut() {
        disk.mount_point = bound_text(std::mem::take(&mut disk.mount_point), 128);
        disk.used_bytes = disk.used_bytes.min(disk.total_bytes);
    }
    snapshot
        .external_disk_capacities
        .retain(|disk| disk.total_bytes > 0);
    snapshot.external_disk_capacities.truncate(8);
    for disk in &mut snapshot.external_disk_capacities {
        disk.mount_point = bound_text(std::mem::take(&mut disk.mount_point), 128);
        disk.used_bytes = disk.used_bytes.min(disk.total_bytes);
    }
    snapshot
}

fn bound_text(mut value: String, max_bytes: usize) -> String {
    if value.len() > max_bytes {
        let mut boundary = max_bytes;
        while !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.truncate(boundary);
    }
    value
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
