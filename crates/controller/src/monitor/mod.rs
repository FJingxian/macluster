//! Shared controller-side sampling for all local mtop clients.

mod processes;
mod sampler;

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
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
const PROCESS_INTERVAL: Duration = Duration::from_secs(3);
const METRIC_STALE_AFTER: Duration = Duration::from_secs(6);
const PROCESS_STALE_AFTER: Duration = Duration::from_secs(10);
const MAX_MONITOR_ERROR_BYTES: usize = 1_024;
const MAX_METRIC_ERROR_FIELDS: usize = 64;

pub type MetricSampleFn =
    dyn Fn(&NodeId, &NodeConfig) -> Result<MetricSnapshot, String> + Send + Sync + 'static;
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
    error: Option<String>,
    next_sample_at: Option<Instant>,
}

#[derive(Default)]
struct ProcessCache {
    rows: Option<Vec<ProcessRow>>,
    sampled_at: Option<Instant>,
    error: Option<String>,
    next_sample_at: Option<Instant>,
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
    job_counts: HashMap<NodeId, (u32, u32)>,
    sequence: u64,
}

impl MonitorHub {
    pub fn new(config: ClusterConfig, namespace: String) -> Self {
        let metric_pool = crate::ssh::SshPool::new(namespace.clone());
        let process_pool = metric_pool.clone();
        let metric_sample: Arc<MetricSampleFn> =
            Arc::new(move |node_id, node| sampler::sample_node(node_id, node, &metric_pool));
        let process_sample: Arc<ProcessSampleFn> =
            Arc::new(move |node_id, node| processes::sample_node(node_id, node, &process_pool));
        Self::with_samplers(config, metric_sample, process_sample)
    }

    /// Inject deterministic probes for service-level regression tests and
    /// future monitoring backends. Production construction uses `new`.
    pub fn with_samplers(
        config: ClusterConfig,
        metric_sample: Arc<MetricSampleFn>,
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
            metric_sampler: MetricSampler::new(metric_sample),
            process_sampler: ProcessSampler::new(process_sample),
            job_counts: HashMap::new(),
            sequence: 1,
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
        let (mut snapshot, age, stale, sample_error) = match metrics {
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
        NodeMonitorRow {
            node_id,
            metrics: snapshot,
            age_ms: age,
            stale,
            sample_error,
            running_tasks,
            waiting_tasks,
            processes: process_rows,
            process_age_ms,
            process_stale,
            process_error,
        }
    }

    fn poll_and_schedule(&mut self, now: Instant) {
        for result in self.metric_sampler.poll() {
            if let Some(cache) = self.metric_cache.get_mut(&result.node_id) {
                match result.result {
                    Ok(snapshot) => {
                        cache.snapshot = Some(bound_metric_snapshot(snapshot));
                        cache.sampled_at = Some(result.completed_at);
                        cache.error = None;
                    }
                    Err(error) => cache.error = Some(bound_text(error, MAX_MONITOR_ERROR_BYTES)),
                }
                self.sequence = self.sequence.saturating_add(1);
            }
        }

        let active_nodes = self
            .subscriptions
            .values()
            .flat_map(|subscription| subscription.nodes.iter().cloned())
            .collect::<BTreeSet<_>>();
        for node_id in active_nodes {
            let due = self
                .metric_cache
                .get(&node_id)
                .is_some_and(|cache| cache.next_sample_at.is_none_or(|next| now >= next));
            if !due {
                continue;
            }
            let Some(node) = self.config.nodes.get(node_id.as_str()) else {
                continue;
            };
            if self.metric_sampler.request(node_id.clone(), node.clone())
                && let Some(cache) = self.metric_cache.get_mut(&node_id)
            {
                cache.next_sample_at = Some(now + METRIC_INTERVAL);
            }
        }

        for result in self.process_sampler.poll() {
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
                    }
                    Err(error) => cache.error = Some(bound_text(error, MAX_MONITOR_ERROR_BYTES)),
                }
                self.sequence = self.sequence.saturating_add(1);
            }
        }

        if self.subscriptions.is_empty() || self.process_sampler.is_in_flight() {
            return;
        }
        let mut watched = self
            .subscriptions
            .values()
            .filter_map(|subscription| subscription.processes.clone())
            .collect::<BTreeSet<_>>();
        watched.retain(|node_id| {
            self.process_cache
                .get(node_id)
                .is_some_and(|cache| cache.next_sample_at.is_none_or(|next| now >= next))
        });
        let Some(node_id) = watched.into_iter().next() else {
            return;
        };
        let Some(node) = self.config.nodes.get(node_id.as_str()) else {
            return;
        };
        if self.process_sampler.request(node_id.clone(), node.clone())
            && let Some(cache) = self.process_cache.get_mut(&node_id)
        {
            cache.next_sample_at = Some(now + PROCESS_INTERVAL);
        }
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
