//! Bounded asynchronous reconciliation used by the long-running controller.

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::{
    config::Transport,
    maintenance::ResetBarrierPolicy,
    scheduler::{NodeEligibility, next_dispatch},
    storage::{Storage, SubmitError},
};
use macluster_protocol::control::{ControllerHello, ControllerLifecycle};
use macluster_protocol::{
    control::MaintenanceScope,
    identifiers::{Id128, NodeId},
    types::{
        ControllerEpoch, INTERACTIVE_PTY_FEATURE, JobMode, JobRecord, JobState, Operation,
        ProtocolError, ResponseBody,
    },
};

use crate::{
    ControllerError, ControllerService,
    events::RuntimeSignal,
    transport::{NodeTransport, TransportError},
    wake::{ControllerWake, WakeError, notify_controller},
};

const PROBE_WORKERS: usize = 8;
const CONTROL_WORKERS: usize = 4;
const SHARE_WORKERS: usize = 1;
const SNAPSHOT_WORKERS: usize = 2;
const WORK_QUEUE_FACTOR: usize = 1;
const NODE_STATUS_TTL: Duration = Duration::from_secs(6);
const NODE_HEALTH_TTL: Duration = Duration::from_secs(60);
const NODE_HEALTH_RETRY: Duration = Duration::from_secs(5);
const SHARE_HEALTH_TTL: Duration = Duration::from_secs(10);
const SHARE_HEALTH_RETRY: Duration = Duration::from_secs(5);
const MAX_WORK_RESULT_AGE: Duration = Duration::from_secs(12);
const MAX_IDLE_RECONCILE_INTERVAL: Duration = Duration::from_secs(2);
const JOB_STORAGE_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const JOB_STORAGE_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

type WorkerTask<R> = Box<dyn FnOnce() -> R + Send + 'static>;

struct WorkerPool<R: Send + 'static> {
    sender: SyncSender<WorkerTask<R>>,
    receiver: Receiver<R>,
    pending: usize,
    max_pending: usize,
}

impl<R: Send + 'static> WorkerPool<R> {
    fn new(
        worker_count: usize,
        queue_capacity: usize,
        signal: Option<RuntimeSignal>,
    ) -> io::Result<Self> {
        let worker_count = worker_count.max(1);
        let (sender, tasks) = mpsc::sync_channel::<WorkerTask<R>>(queue_capacity);
        let tasks = Arc::new(Mutex::new(tasks));
        let (results, receiver) = mpsc::channel();
        for index in 0..worker_count {
            let tasks = Arc::clone(&tasks);
            let results = results.clone();
            let signal = signal.clone();
            thread::Builder::new()
                .name(format!("macluster-worker-{index}"))
                .spawn(move || {
                    loop {
                        let task = match tasks.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(task) = task else { return };
                        if results.send(task()).is_err() {
                            return;
                        }
                        if let Some(signal) = &signal {
                            signal.notify();
                        }
                    }
                })?;
        }
        drop(results);
        Ok(Self {
            sender,
            receiver,
            pending: 0,
            max_pending: worker_count + queue_capacity,
        })
    }

    fn try_spawn(&mut self, task: impl FnOnce() -> R + Send + 'static) -> bool {
        if self.pending >= self.max_pending {
            return false;
        }
        match self.sender.try_send(Box::new(task)) {
            Ok(()) => {
                self.pending += 1;
                true
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }

    fn poll(&mut self) -> Vec<R> {
        let mut results = Vec::new();
        while let Ok(result) = self.receiver.try_recv() {
            self.pending = self.pending.saturating_sub(1);
            results.push(result);
        }
        results
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkKind {
    Probe,
    Health,
    Start,
    Cancel,
    ShareHealth,
    PublishSnapshot,
}

#[derive(Clone, Debug)]
struct WorkTag {
    epoch: ControllerEpoch,
    config_digest: String,
    node_id: Option<String>,
    generation: u64,
    operation_id: u64,
    kind: WorkKind,
    job_id: Option<u64>,
    started_at: Instant,
}

struct WorkerCompletion {
    tag: WorkTag,
    received_at: Instant,
    result: WorkerResult,
}

enum WorkerResult {
    Probe(ProbeResult),
    Control(Result<ResponseBody, String>),
    ShareHealth(bool),
    PublishSnapshot(Result<(), String>),
}

struct ProbeResult {
    fence_error: Option<String>,
    status: Option<Result<ResponseBody, ProbeError>>,
    health: Option<Result<ResponseBody, String>>,
}

enum ProbeError {
    NotFound,
    Failed(String),
    MissingExecution { job_id: u64, detail: String },
}

#[derive(Clone, Copy, Debug)]
struct InFlightNodeOperation {
    id: u64,
    kind: WorkKind,
}

struct NodeStatusCache {
    online: bool,
    occupied: bool,
    sampled_at: Instant,
}

struct NodeHealthCache {
    valid: bool,
    ready: bool,
    interactive_pty: bool,
    namespaced_jobs: bool,
    sampled_at: Instant,
    retry_at: Instant,
}

struct NodeRuntime {
    generation: u64,
    in_flight: Option<InFlightNodeOperation>,
    fenced: bool,
    status: Option<NodeStatusCache>,
    health: Option<NodeHealthCache>,
    next_probe_at: Instant,
    probe_failures: u8,
    last_probe_error: Option<String>,
    next_control_at: Instant,
    control_failures: u8,
    pending_start: Option<JobRecord>,
}

impl NodeRuntime {
    fn new(now: Instant) -> Self {
        Self {
            generation: 0,
            in_flight: None,
            fenced: false,
            status: None,
            health: None,
            next_probe_at: now,
            probe_failures: 0,
            last_probe_error: None,
            next_control_at: now,
            control_failures: 0,
            pending_start: None,
        }
    }

    fn status_fresh(&self, now: Instant) -> bool {
        self.status.as_ref().is_some_and(|status| {
            now.saturating_duration_since(status.sampled_at) < NODE_STATUS_TTL
        })
    }

    fn health_fresh(&self, now: Instant) -> bool {
        self.health.as_ref().is_some_and(|health| {
            health.valid && now.saturating_duration_since(health.sampled_at) < NODE_HEALTH_TTL
        })
    }

    fn health_probe_due(&self, now: Instant) -> bool {
        self.health.as_ref().is_none_or(|health| {
            if health.valid && health.ready {
                now.saturating_duration_since(health.sampled_at) >= NODE_HEALTH_TTL
            } else {
                now >= health.retry_at
            }
        })
    }
}

struct SnapshotRetry {
    attempts: u8,
    retry_at: Instant,
}

struct RuntimeState {
    digest: String,
    previous_digest: Option<String>,
    reloaded_affected_nodes: std::collections::HashSet<String>,
    nodes: HashMap<String, NodeRuntime>,
    node_probe_pool: WorkerPool<WorkerCompletion>,
    control_pool: WorkerPool<WorkerCompletion>,
    share_pool: WorkerPool<WorkerCompletion>,
    snapshot_pool: WorkerPool<WorkerCompletion>,
    share_in_flight: Option<u64>,
    share_ready: Option<(bool, Instant)>,
    next_share_probe: Instant,
    snapshot_in_flight: HashMap<u64, u64>,
    snapshot_retry: HashMap<u64, SnapshotRetry>,
    next_operation_id: u64,
    node_cursor: usize,
    queue_cursor: usize,
    probe_interval: Duration,
}

impl RuntimeState {
    #[cfg(test)]
    fn new<T: NodeTransport>(
        service: &ControllerService<T>,
        probe_interval: Duration,
    ) -> Result<Self, ControllerError> {
        Self::new_with_signal(service, probe_interval, None)
    }

    fn new_with_signal<T: NodeTransport>(
        service: &ControllerService<T>,
        probe_interval: Duration,
        signal: Option<RuntimeSignal>,
    ) -> Result<Self, ControllerError> {
        let now = Instant::now();
        let configured_nodes = service.config.nodes.len().max(1);
        let probe_workers = PROBE_WORKERS.min(configured_nodes);
        let control_workers = CONTROL_WORKERS.min(configured_nodes);
        Ok(Self {
            digest: service.config.execution_digest().unwrap_or_default(),
            previous_digest: None,
            reloaded_affected_nodes: std::collections::HashSet::new(),
            nodes: service
                .config
                .nodes
                .keys()
                .map(|id| (id.clone(), NodeRuntime::new(now)))
                .collect(),
            node_probe_pool: WorkerPool::new(
                probe_workers,
                probe_workers * WORK_QUEUE_FACTOR,
                signal.clone(),
            )?,
            control_pool: WorkerPool::new(
                control_workers,
                control_workers * WORK_QUEUE_FACTOR,
                signal.clone(),
            )?,
            share_pool: WorkerPool::new(
                SHARE_WORKERS,
                SHARE_WORKERS * WORK_QUEUE_FACTOR,
                signal.clone(),
            )?,
            snapshot_pool: WorkerPool::new(
                SNAPSHOT_WORKERS,
                SNAPSHOT_WORKERS * WORK_QUEUE_FACTOR,
                signal,
            )?,
            share_in_flight: None,
            share_ready: None,
            next_share_probe: now,
            snapshot_in_flight: HashMap::new(),
            snapshot_retry: HashMap::new(),
            next_operation_id: 1,
            node_cursor: 0,
            queue_cursor: 0,
            probe_interval,
        })
    }

    fn next_deadline(&self, now: Instant) -> Instant {
        let fallback = now + MAX_IDLE_RECONCILE_INTERVAL;
        let mut deadline = fallback;
        if self.share_in_flight.is_none() {
            deadline = deadline.min(self.next_share_probe);
        }
        for node in self.nodes.values() {
            if node.in_flight.is_some() {
                continue;
            }
            deadline = deadline.min(node.next_probe_at);
            if let Some(health) = &node.health {
                deadline = deadline.min(if health.valid && health.ready {
                    health.sampled_at + NODE_HEALTH_TTL
                } else {
                    health.retry_at
                });
            }
            if node.pending_start.is_some() {
                deadline = deadline.min(node.next_control_at);
            }
        }
        if deadline <= now { fallback } else { deadline }
    }

    fn operation_id(&mut self) -> u64 {
        let id = self.next_operation_id;
        self.next_operation_id = self.next_operation_id.wrapping_add(1).max(1);
        id
    }

    fn pending_work(&self) -> usize {
        self.node_probe_pool.pending
            + self.control_pool.pending
            + self.share_pool.pending
            + self.snapshot_pool.pending
    }

    fn maintenance_blockers<T: NodeTransport>(
        &self,
        service: &ControllerService<T>,
        scope: &MaintenanceScope,
    ) -> Result<Vec<String>, ControllerError> {
        let mut blockers = Vec::new();
        let in_scope = |node: Option<&NodeId>| match scope {
            MaintenanceScope::Cluster => true,
            MaintenanceScope::Nodes(nodes) => node.is_some_and(|node| nodes.contains(node)),
        };
        for job in service.storage.list_active_jobs()? {
            let scoped = in_scope(job.node.as_ref());
            let label = match job.state {
                JobState::Starting | JobState::Running | JobState::Cancelling if scoped => {
                    Some(format!(
                        "job {} is {:?} on {}",
                        job.id,
                        job.state,
                        job.node.as_ref().map_or("unknown", NodeId::as_str)
                    ))
                }
                _ if (scoped || matches!(scope, MaintenanceScope::Cluster))
                    && (job.snapshot_sync_pending || job.log_sync_pending) =>
                {
                    Some(format!("job {} output synchronization is pending", job.id))
                }
                _ => None,
            };
            if let Some(label) = label {
                blockers.push(label);
            }
            if blockers.len() >= 32 {
                return Ok(blockers);
            }
        }

        for (node_id, node) in &self.nodes {
            if !service.node_is_maintenance_scoped(node_id) {
                continue;
            }
            if node.in_flight.is_some() {
                blockers.push(format!(
                    "node {node_id} has a controller operation in flight"
                ));
            } else if node.pending_start.is_some() {
                blockers.push(format!("node {node_id} has a pending start operation"));
            } else if node.status_fresh(Instant::now())
                && node.status.as_ref().is_some_and(|status| status.occupied)
            {
                blockers.push(format!("node {node_id} still reports an active execution"));
            } else if !node.status_fresh(Instant::now()) {
                blockers.push(match &node.last_probe_error {
                    Some(error) => format!("node {node_id} execution verification failed: {error}"),
                    None => format!("node {node_id} execution state is not freshly verified"),
                });
            }
            if blockers.len() >= 32 {
                break;
            }
        }
        Ok(blockers)
    }

    fn apply_config_reload<T: NodeTransport>(
        &mut self,
        service: &ControllerService<T>,
        old_digest: String,
        scope: &MaintenanceScope,
    ) {
        let mut affected = match scope {
            MaintenanceScope::Cluster => self
                .nodes
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>(),
            MaintenanceScope::Nodes(nodes) => nodes.iter().map(ToString::to_string).collect(),
        };
        self.nodes.retain(|node_id, _| {
            service.config.nodes.contains_key(node_id) && !affected.contains(node_id)
        });
        let now = Instant::now();
        for node_id in service.config.nodes.keys() {
            if !self.nodes.contains_key(node_id) {
                self.nodes.insert(node_id.clone(), NodeRuntime::new(now));
                affected.insert(node_id.clone());
            }
        }
        self.previous_digest = Some(old_digest);
        self.reloaded_affected_nodes = affected;
        self.digest = service.config.execution_digest().unwrap_or_default();
        if matches!(scope, MaintenanceScope::Cluster) {
            self.share_ready = None;
            self.next_share_probe = now;
        }
    }

    fn tag_identity_current(&self, tag: &WorkTag, now: Instant) -> bool {
        if tag.config_digest == self.digest {
            return true;
        }
        tag.node_id.as_ref().is_some_and(|node_id| {
            self.previous_digest.as_deref() == Some(tag.config_digest.as_str())
                && !self.reloaded_affected_nodes.contains(node_id)
                && now.saturating_duration_since(tag.started_at) <= MAX_WORK_RESULT_AGE
        })
    }

    fn tag<T: NodeTransport>(
        &self,
        service: &ControllerService<T>,
        node_id: Option<String>,
        generation: u64,
        operation_id: u64,
        kind: WorkKind,
        job_id: Option<u64>,
    ) -> WorkTag {
        WorkTag {
            epoch: service.epoch,
            config_digest: self.digest.clone(),
            node_id,
            generation,
            operation_id,
            kind,
            job_id,
            started_at: Instant::now(),
        }
    }

    fn share_ready(&self, now: Instant) -> bool {
        self.share_ready.is_some_and(|(ready, sampled_at)| {
            ready && now.saturating_duration_since(sampled_at) < SHARE_HEALTH_TTL
        })
    }

    fn poll_workers<T: NodeTransport>(
        &mut self,
        service: &mut ControllerService<T>,
    ) -> Result<(), ControllerError> {
        let completions = self
            .node_probe_pool
            .poll()
            .into_iter()
            .chain(self.control_pool.poll())
            .chain(self.share_pool.poll())
            .chain(self.snapshot_pool.poll())
            .collect::<Vec<_>>();
        for completion in completions {
            self.handle_completion(service, completion)?;
        }
        Ok(())
    }

    fn handle_completion<T: NodeTransport>(
        &mut self,
        service: &mut ControllerService<T>,
        completion: WorkerCompletion,
    ) -> Result<(), ControllerError> {
        let now = Instant::now();
        let tag = completion.tag;
        let identity_current = tag.epoch == service.epoch && self.tag_identity_current(&tag, now);
        match tag.kind {
            WorkKind::ShareHealth => {
                if self.share_in_flight == Some(tag.operation_id) {
                    self.share_in_flight = None;
                }
                if !identity_current
                    || now.saturating_duration_since(tag.started_at) > MAX_WORK_RESULT_AGE
                {
                    self.next_share_probe = now + Duration::from_secs(1);
                    return Ok(());
                }
                if let WorkerResult::ShareHealth(ready) = completion.result {
                    self.share_ready = Some((ready, tag.started_at));
                    self.next_share_probe = now
                        + if ready {
                            SHARE_HEALTH_TTL
                        } else {
                            SHARE_HEALTH_RETRY
                        };
                }
            }
            WorkKind::PublishSnapshot => {
                let Some(job_id) = tag.job_id else {
                    return Ok(());
                };
                if self.snapshot_in_flight.get(&job_id) == Some(&tag.operation_id) {
                    self.snapshot_in_flight.remove(&job_id);
                }
                if !identity_current
                    || now.saturating_duration_since(tag.started_at) > MAX_WORK_RESULT_AGE
                {
                    return Ok(());
                }
                match completion.result {
                    WorkerResult::PublishSnapshot(Ok(())) => {
                        self.snapshot_retry.remove(&job_id);
                    }
                    WorkerResult::PublishSnapshot(Err(_)) => {
                        let attempts = self
                            .snapshot_retry
                            .get(&job_id)
                            .map_or(1, |retry| retry.attempts.saturating_add(1));
                        self.snapshot_retry.insert(
                            job_id,
                            SnapshotRetry {
                                attempts,
                                retry_at: now + retry_delay(attempts),
                            },
                        );
                    }
                    _ => {}
                }
            }
            WorkKind::Probe | WorkKind::Health | WorkKind::Start | WorkKind::Cancel => {
                let Some(node_id) = tag.node_id.as_deref() else {
                    return Ok(());
                };
                let Some(runtime) = self.nodes.get_mut(node_id) else {
                    return Ok(());
                };
                if runtime
                    .in_flight
                    .is_none_or(|in_flight| in_flight.id != tag.operation_id)
                {
                    return Ok(());
                }
                runtime.in_flight = None;
                if !identity_current {
                    runtime.status = None;
                    runtime.next_probe_at = now;
                    return Ok(());
                }
                if !node_result_is_current(
                    &tag,
                    service.epoch,
                    &tag.config_digest,
                    runtime.generation,
                    now,
                ) {
                    runtime.status = None;
                    runtime.next_probe_at = now;
                    return Ok(());
                }
                match tag.kind {
                    WorkKind::Probe | WorkKind::Health => {
                        if let WorkerResult::Probe(probe) = completion.result {
                            match tag.kind {
                                WorkKind::Probe => self.apply_probe(
                                    service,
                                    node_id,
                                    &tag,
                                    completion.received_at,
                                    probe,
                                )?,
                                WorkKind::Health => self.apply_health(
                                    service,
                                    node_id,
                                    &tag,
                                    completion.received_at,
                                    probe.health,
                                ),
                                _ => {}
                            }
                        }
                    }
                    WorkKind::Start | WorkKind::Cancel => {
                        runtime.next_probe_at = now;
                        runtime.status = None;
                        match completion.result {
                            WorkerResult::Control(Ok(_)) => {
                                runtime.control_failures = 0;
                            }
                            WorkerResult::Control(Err(_error)) => {
                                runtime.control_failures =
                                    runtime.control_failures.saturating_add(1);
                                if tag.kind == WorkKind::Start
                                    && let Some(job_id) = tag.job_id
                                    && let Some(job) = service.storage.get_job(job_id)?
                                    && job.state == JobState::Starting
                                    && job
                                        .node
                                        .as_ref()
                                        .is_some_and(|node| node.as_str() == node_id)
                                {
                                    // Keep the stable reservation and token. If the
                                    // remote accepted Start but its reply was lost,
                                    // the retry is idempotent; if it rejected Start,
                                    // the same job can recover when the node returns.
                                    runtime.pending_start = Some(job);
                                }
                            }
                            _ => {}
                        }
                        runtime.next_control_at = now + retry_delay(runtime.control_failures);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn apply_probe<T: NodeTransport>(
        &mut self,
        service: &mut ControllerService<T>,
        node_id: &str,
        tag: &WorkTag,
        received_at: Instant,
        probe: ProbeResult,
    ) -> Result<(), ControllerError> {
        let probe_interval = self.probe_interval;
        let Some(runtime) = self.nodes.get_mut(node_id) else {
            return Ok(());
        };
        if let Some(error) = probe.fence_error {
            runtime.last_probe_error = Some(error.chars().take(256).collect());
            service.fenced_nodes.remove(node_id);
            runtime.fenced = false;
            runtime.status = None;
            runtime.probe_failures = runtime.probe_failures.saturating_add(1);
            runtime.next_probe_at = received_at + retry_delay(runtime.probe_failures);
            service.idle_since.remove(node_id);
            return Ok(());
        }
        runtime.fenced = true;
        service.fenced_nodes.insert(node_id.to_owned());

        match probe.status {
            Some(Ok(ResponseBody::Execution(status))) => {
                let id = NodeId::new(node_id.to_owned()).expect("validated node ID");
                let (online, occupied) = service.reconcile_status(&id, status)?;
                runtime.status = Some(NodeStatusCache {
                    online,
                    occupied,
                    sampled_at: tag.started_at,
                });
                runtime.probe_failures = 0;
                runtime.last_probe_error = None;
                runtime.next_probe_at = received_at + probe_interval;
                if online && !occupied {
                    service
                        .idle_since
                        .entry(node_id.to_owned())
                        .or_insert_with(now_ms);
                } else {
                    service.idle_since.remove(node_id);
                }
            }
            Some(Err(ProbeError::NotFound)) => {
                runtime.status = Some(NodeStatusCache {
                    online: true,
                    occupied: false,
                    sampled_at: tag.started_at,
                });
                runtime.probe_failures = 0;
                runtime.last_probe_error = None;
                runtime.next_probe_at = received_at + probe_interval;
                service
                    .idle_since
                    .entry(node_id.to_owned())
                    .or_insert_with(now_ms);
            }
            Some(Err(ProbeError::MissingExecution { job_id, detail })) => {
                let id = NodeId::new(node_id.to_owned()).expect("validated node ID");
                service.missing_execution(&id, job_id, &detail)?;
                runtime.status = Some(NodeStatusCache {
                    online: true,
                    occupied: true,
                    sampled_at: tag.started_at,
                });
                runtime.probe_failures = 0;
                runtime.last_probe_error = None;
                runtime.next_probe_at = received_at + probe_interval;
                service.idle_since.remove(node_id);
            }
            Some(Err(ProbeError::Failed(error))) => {
                runtime.last_probe_error = Some(error.chars().take(256).collect());
                runtime.status = None;
                runtime.probe_failures = runtime.probe_failures.saturating_add(1);
                runtime.next_probe_at = received_at + retry_delay(runtime.probe_failures);
                service.idle_since.remove(node_id);
            }
            None => {
                runtime.status = None;
                runtime.probe_failures = runtime.probe_failures.saturating_add(1);
                runtime.next_probe_at = received_at + retry_delay(runtime.probe_failures);
                service.idle_since.remove(node_id);
            }
            Some(Ok(_)) => {
                runtime.status = None;
                runtime.probe_failures = runtime.probe_failures.saturating_add(1);
                runtime.next_probe_at = received_at + retry_delay(runtime.probe_failures);
                service.idle_since.remove(node_id);
            }
        }

        Ok(())
    }

    fn apply_health<T: NodeTransport>(
        &mut self,
        service: &ControllerService<T>,
        node_id: &str,
        tag: &WorkTag,
        received_at: Instant,
        health_result: Option<Result<ResponseBody, String>>,
    ) {
        let Some(runtime) = self.nodes.get_mut(node_id) else {
            return;
        };
        runtime.health = Some(match health_result {
            Some(Ok(ResponseBody::Health(health))) => {
                let expected_digest = service.config.execution_digest().unwrap_or_default();
                let ready = health.execution_digest == expected_digest
                    && health.primary_share_ready
                    && service
                        .config
                        .shares
                        .keys()
                        .all(|share_id| health.shares.get(share_id).copied().unwrap_or(false));
                NodeHealthCache {
                    valid: true,
                    ready,
                    namespaced_jobs: health.features.iter().any(|feature| {
                        feature == macluster_protocol::types::NAMESPACED_JOBS_FEATURE
                    }),
                    interactive_pty: health
                        .features
                        .iter()
                        .any(|feature| feature == INTERACTIVE_PTY_FEATURE),
                    sampled_at: tag.started_at,
                    retry_at: received_at
                        + if ready {
                            NODE_HEALTH_TTL
                        } else {
                            NODE_HEALTH_RETRY
                        },
                }
            }
            _ => NodeHealthCache {
                valid: false,
                ready: false,
                interactive_pty: false,
                namespaced_jobs: false,
                sampled_at: tag.started_at,
                retry_at: received_at + NODE_HEALTH_RETRY,
            },
        });
    }

    fn schedule_share_probe<T: NodeTransport>(&mut self, service: &ControllerService<T>) {
        let now = Instant::now();
        if self.share_in_flight.is_some() || now < self.next_share_probe {
            return;
        }
        let operation_id = self.operation_id();
        let tag = self.tag(service, None, 0, operation_id, WorkKind::ShareHealth, None);
        let config = service.config.clone();
        if self.share_pool.try_spawn(move || {
            let ready = crate::verify_shared_storage(&config);
            WorkerCompletion {
                tag,
                received_at: Instant::now(),
                result: WorkerResult::ShareHealth(ready),
            }
        }) {
            self.share_in_flight = Some(operation_id);
        }
    }

    fn schedule_probes<T: NodeTransport>(
        &mut self,
        service: &ControllerService<T>,
    ) -> Result<(), ControllerError> {
        let now = Instant::now();
        let ids = service.config.nodes.keys().cloned().collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(());
        }
        let cursor = self.node_cursor % ids.len();
        for offset in 0..ids.len() {
            let id = &ids[(cursor + offset) % ids.len()];
            let Some(config) = service.config.nodes.get(id) else {
                continue;
            };
            let Some(runtime) = self.nodes.get(id) else {
                continue;
            };
            if runtime.in_flight.is_some() || runtime.pending_start.is_some() {
                continue;
            }
            if service.node_is_maintenance_scoped(id)
                && runtime.status_fresh(now)
                && runtime
                    .status
                    .as_ref()
                    .is_some_and(|status| !status.occupied)
            {
                continue;
            }
            let health_due = runtime.health_probe_due(now);
            let health_only = health_due && runtime.status_fresh(now);
            if !health_only && now < runtime.next_probe_at {
                continue;
            }
            let already_fenced = runtime.fenced && service.fenced_nodes.contains(id);
            let generation = runtime.generation;
            let node_id = NodeId::new(id.clone()).expect("validated node ID");
            let expected_execution = service.storage.node_execution_to_reconcile(&node_id)?;
            let node_config = config.clone();
            let transport = Arc::clone(&service.transport);
            let operation_id = self.operation_id();
            let tag = self.tag(
                service,
                Some(id.clone()),
                generation,
                operation_id,
                if health_only {
                    WorkKind::Health
                } else {
                    WorkKind::Probe
                },
                None,
            );
            let worker_tag = tag.clone();
            if self.node_probe_pool.try_spawn(move || {
                let fence_error = if already_fenced {
                    None
                } else {
                    match transport.call(
                        &node_id,
                        &node_config,
                        Operation::Fence {
                            controller: worker_tag.epoch,
                        },
                    ) {
                        Ok(ResponseBody::Ack) => None,
                        Ok(_) => Some("fence returned an unexpected response".into()),
                        Err(error) => Some(error.to_string()),
                    }
                };
                let (status, health) =
                    if fence_error.is_none() && worker_tag.kind == WorkKind::Health {
                        (
                            None,
                            Some(
                                transport
                                    .call(&node_id, &node_config, Operation::Health)
                                    .map_err(|error| error.to_string()),
                            ),
                        )
                    } else if fence_error.is_none() {
                        let status = Some(
                            match transport.call(&node_id, &node_config, Operation::Status) {
                                Err(TransportError::Remote(ProtocolError::NotFound)) => {
                                    match expected_execution {
                                        Some(job) => match job.start_token {
                                            Some(token) => match transport.call(
                                                &node_id,
                                                &node_config,
                                                Operation::RecoverJob {
                                                    controller: worker_tag.epoch,
                                                    start_token: token,
                                                    job_id: job.id,
                                                },
                                            ) {
                                                Ok(ResponseBody::Execution(status)) => {
                                                    Ok(ResponseBody::Execution(status))
                                                }
                                                Ok(_) => Err(ProbeError::MissingExecution {
                                                    job_id: job.id,
                                                    detail: "unexpected recovery response".into(),
                                                }),
                                                Err(error) => Err(ProbeError::MissingExecution {
                                                    job_id: job.id,
                                                    detail: error.to_string(),
                                                }),
                                            },
                                            None => Err(ProbeError::MissingExecution {
                                                job_id: job.id,
                                                detail: "controller has no execution token".into(),
                                            }),
                                        },
                                        None => Err(ProbeError::NotFound),
                                    }
                                }
                                Err(error) => Err(ProbeError::Failed(error.to_string())),
                                Ok(response) => Ok(response),
                            },
                        );
                        (status, None)
                    } else {
                        (None, None)
                    };
                WorkerCompletion {
                    tag: worker_tag,
                    received_at: Instant::now(),
                    result: WorkerResult::Probe(ProbeResult {
                        fence_error,
                        status,
                        health,
                    }),
                }
            }) {
                self.nodes
                    .get_mut(id)
                    .expect("node runtime exists")
                    .in_flight = Some(InFlightNodeOperation {
                    id: operation_id,
                    kind: if health_only {
                        WorkKind::Health
                    } else {
                        WorkKind::Probe
                    },
                });
            }
        }
        self.node_cursor = (cursor + 1) % ids.len();
        Ok(())
    }

    fn schedule_controls<T: NodeTransport>(
        &mut self,
        service: &mut ControllerService<T>,
        jobs: &[JobRecord],
    ) -> Result<(), ControllerError> {
        let now = Instant::now();
        let cancel_by_node = jobs
            .iter()
            .filter(|job| job.state == JobState::Cancelling)
            .filter_map(|job| {
                job.node
                    .as_ref()
                    .map(|node| (node.to_string(), job.clone()))
            })
            .collect::<HashMap<_, _>>();

        // Cancellation has priority over Start, including a reservation that
        // has not yet been sent to the agent.
        for (node_id, job) in &cancel_by_node {
            let Some(snapshot) = self.nodes.get(node_id) else {
                continue;
            };
            if snapshot.in_flight.is_none()
                && snapshot
                    .pending_start
                    .as_ref()
                    .is_some_and(|start| start.id == job.id)
            {
                service.storage.finish_job(
                    job.id,
                    JobState::Cancelled,
                    Some(130),
                    Some("cancelled before Start was sent to the node".into()),
                )?;
                if let Some(runtime) = self.nodes.get_mut(node_id) {
                    runtime.pending_start = None;
                    runtime.generation = runtime.generation.wrapping_add(1);
                    runtime.status = None;
                    runtime.next_probe_at = now;
                }
                continue;
            }
            if snapshot.in_flight.is_some() || !snapshot.fenced || now < snapshot.next_control_at {
                continue;
            }
            let (Some(start_token), Some(node_config)) = (
                job.start_token,
                service.config.nodes.get(node_id.as_str()).cloned(),
            ) else {
                continue;
            };
            let Ok(node) = NodeId::new(node_id.clone()) else {
                continue;
            };
            let generation = snapshot.generation.wrapping_add(1);
            let operation_id = self.operation_id();
            let tag = self.tag(
                service,
                Some(node_id.clone()),
                generation,
                operation_id,
                WorkKind::Cancel,
                Some(job.id),
            );
            let worker_tag = tag.clone();
            let transport = Arc::clone(&service.transport);
            let operation = Operation::CancelJob {
                controller: service.epoch,
                start_token,
                job_id: job.id,
                force: job.cancel_force,
            };
            if self.control_pool.try_spawn(move || WorkerCompletion {
                received_at: Instant::now(),
                tag: worker_tag,
                result: WorkerResult::Control(
                    transport
                        .call(&node, &node_config, operation)
                        .map_err(|error| error.to_string()),
                ),
            }) && let Some(runtime) = self.nodes.get_mut(node_id)
            {
                runtime.generation = generation;
                runtime.status = None;
                runtime.in_flight = Some(InFlightNodeOperation {
                    id: operation_id,
                    kind: WorkKind::Cancel,
                });
            }
        }

        let node_ids = self.nodes.keys().cloned().collect::<Vec<_>>();
        for node_id in node_ids {
            if cancel_by_node.contains_key(&node_id) {
                continue;
            }
            let Some(snapshot) = self.nodes.get(&node_id) else {
                continue;
            };
            let Some(pending) = snapshot.pending_start.clone() else {
                continue;
            };
            if snapshot.in_flight.is_some() || !snapshot.fenced || now < snapshot.next_control_at {
                continue;
            }
            let Some(current) = service.storage.get_job(pending.id)? else {
                if let Some(runtime) = self.nodes.get_mut(&node_id) {
                    runtime.pending_start = None;
                    runtime.status = None;
                }
                continue;
            };
            if current.state == JobState::Cancelling {
                service.storage.finish_job(
                    current.id,
                    JobState::Cancelled,
                    Some(130),
                    Some("cancelled before Start was sent to the node".into()),
                )?;
                if let Some(runtime) = self.nodes.get_mut(&node_id) {
                    runtime.pending_start = None;
                    runtime.status = None;
                    runtime.next_probe_at = now;
                }
                continue;
            }
            if current.state != JobState::Starting {
                if let Some(runtime) = self.nodes.get_mut(&node_id) {
                    runtime.pending_start = None;
                    runtime.status = None;
                    runtime.next_probe_at = now;
                }
                continue;
            }
            let (Some(start_token), Some(node_config)) = (
                current.start_token,
                service.config.nodes.get(node_id.as_str()).cloned(),
            ) else {
                continue;
            };
            let Ok(node) = NodeId::new(node_id.clone()) else {
                continue;
            };
            let generation = snapshot.generation.wrapping_add(1);
            let operation_id = self.operation_id();
            let tag = self.tag(
                service,
                Some(node_id.clone()),
                generation,
                operation_id,
                WorkKind::Start,
                Some(current.id),
            );
            let worker_tag = tag.clone();
            let transport = Arc::clone(&service.transport);
            let operation = Operation::StartJob {
                controller: service.epoch,
                start_token,
                job_id: current.id,
                spec: current.spec.clone(),
            };
            if self.control_pool.try_spawn(move || WorkerCompletion {
                received_at: Instant::now(),
                tag: worker_tag,
                result: WorkerResult::Control(
                    transport
                        .call(&node, &node_config, operation)
                        .map_err(|error| error.to_string()),
                ),
            }) && let Some(runtime) = self.nodes.get_mut(&node_id)
            {
                runtime.pending_start = None;
                runtime.generation = generation;
                runtime.status = None;
                runtime.in_flight = Some(InFlightNodeOperation {
                    id: operation_id,
                    kind: WorkKind::Start,
                });
            }
        }
        Ok(())
    }

    fn schedule_snapshots<T: NodeTransport>(
        &mut self,
        service: &ControllerService<T>,
        jobs: &[JobRecord],
        queues: &[String],
    ) {
        if !self.share_ready(Instant::now()) || queues.is_empty() {
            return;
        }
        let cursor = self.queue_cursor % queues.len();
        for offset in 0..queues.len() {
            let queue = &queues[(cursor + offset) % queues.len()];
            let Some(head) = jobs
                .iter()
                .filter(|job| job.state == JobState::Pending && job.spec.queue.as_str() == queue)
                .min_by_key(|job| job.id)
                .filter(|job| job.snapshot_sync_pending)
            else {
                continue;
            };
            if self.snapshot_in_flight.contains_key(&head.id)
                || self
                    .snapshot_retry
                    .get(&head.id)
                    .is_some_and(|retry| Instant::now() < retry.retry_at)
            {
                continue;
            }
            let job_id = head.id;
            let operation_id = self.operation_id();
            let tag = self.tag(
                service,
                None,
                0,
                operation_id,
                WorkKind::PublishSnapshot,
                Some(job_id),
            );
            let state_dir = service.storage.root().to_path_buf();
            let shared_root = service.config.shared_root.clone();
            if self.snapshot_pool.try_spawn(move || {
                let result = crate::publish_snapshot_bounded(
                    &state_dir,
                    job_id,
                    &shared_root,
                    Duration::from_secs(10),
                );
                WorkerCompletion {
                    tag,
                    received_at: Instant::now(),
                    result: WorkerResult::PublishSnapshot(result),
                }
            }) {
                self.snapshot_in_flight.insert(job_id, operation_id);
            }
        }
    }

    fn dispatch<T: NodeTransport>(
        &mut self,
        service: &mut ControllerService<T>,
        mut jobs: Vec<JobRecord>,
        queues: &[String],
    ) -> Result<(), ControllerError> {
        service.refresh_reset_barrier_policy()?;
        if !self.share_ready(Instant::now()) || !service.dispatch_allowed() || queues.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        let mut availability = self.availability(service, now);
        let cursor = self.queue_cursor % queues.len();
        for offset in 0..queues.len() {
            let queue_name = &queues[(cursor + offset) % queues.len()];
            let Some(queue_config) = service.config.queue_for_dispatch(queue_name) else {
                continue;
            };
            let queue = macluster_protocol::identifiers::QueueName::new(queue_name.clone())
                .expect("validated config queue ID");
            let head = jobs
                .iter()
                .filter(|job| job.state == JobState::Pending && job.spec.queue == queue)
                .min_by_key(|job| job.id)
                .cloned();
            let Some(head) = head else {
                continue;
            };
            if head.snapshot_sync_pending {
                continue;
            }
            let waiting_reason = if let Some(pinned) = head
                .spec
                .node
                .as_ref()
                .filter(|node| service.config.is_login_node(node.as_str()))
            {
                Some(format!(
                    "job is pinned to login node '{}', which is excluded from compute jobs; cancel it with mkill and resubmit on a compute node",
                    pinned
                ))
            } else if let Some(reason) =
                crate::namespace_waiting_reason(&head, &queue_config, &availability)
            {
                Some(reason)
            } else if head.spec.mode == JobMode::Interactive {
                let compatible = queue_config.nodes.iter().any(|member| {
                    availability.iter().any(|node| {
                        node.id.as_str() == member
                            && node.online
                            && node.interactive_pty
                            && head
                                .spec
                                .node
                                .as_ref()
                                .is_none_or(|pinned| pinned == &node.id)
                    })
                });
                (!compatible).then(|| {
                        "waiting for an online node with interactive PTY support; cancel and resubmit with msub to trigger an Agent update if needed".to_owned()
                })
            } else {
                None
            };
            let updated = service
                .storage
                .set_waiting_reason(head.id, waiting_reason)?;
            if let Some(job) = jobs.iter_mut().find(|job| job.id == head.id) {
                *job = updated;
            }
            let Some(dispatch) = next_dispatch(&queue, &queue_config, &jobs, &availability) else {
                continue;
            };
            let reserved = match service
                .storage
                .reserve_job(dispatch.job_id, dispatch.node_id.clone())
            {
                Ok(job) => job,
                Err(SubmitError::NodeBusy(_)) => {
                    if let Some(node) = availability
                        .iter_mut()
                        .find(|node| node.id == dispatch.node_id)
                    {
                        node.occupied = true;
                    }
                    continue;
                }
                Err(SubmitError::InvalidTransition(_, _, _)) => {
                    jobs = service.storage.list_reconcile_jobs()?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if let Some(job) = jobs.iter_mut().find(|job| job.id == reserved.id) {
                *job = reserved.clone();
            }
            if let Some(node) = availability
                .iter_mut()
                .find(|node| node.id == dispatch.node_id)
            {
                node.occupied = true;
            }
            if let Some(runtime) = self.nodes.get_mut(dispatch.node_id.as_str()) {
                runtime.generation = runtime.generation.wrapping_add(1);
                runtime.status = None;
                runtime.pending_start = Some(reserved);
                runtime.next_probe_at = now;
                service.idle_since.remove(dispatch.node_id.as_str());
            }
        }
        self.queue_cursor = (cursor + 1) % queues.len();
        Ok(())
    }

    fn availability<T: NodeTransport>(
        &self,
        service: &ControllerService<T>,
        now: Instant,
    ) -> Vec<NodeEligibility> {
        service
            .config
            .nodes
            .iter()
            .map(|(id, config)| {
                let runtime = self.nodes.get(id);
                let status_fresh = runtime.is_some_and(|runtime| runtime.status_fresh(now));
                let status = runtime.and_then(|runtime| runtime.status.as_ref());
                let online = runtime.is_some_and(|runtime| runtime.fenced)
                    && status_fresh
                    && status.is_some_and(|status| status.online);
                let busy = !status_fresh
                    || status.is_none_or(|status| status.occupied)
                    || runtime.is_some_and(|runtime| {
                        runtime
                            .in_flight
                            .is_some_and(|operation| operation.kind != WorkKind::Probe)
                            || runtime.pending_start.is_some()
                    });
                let requires_health = config.transport == Transport::Local
                    || config.machine_uuid.is_some()
                    || config.execution_uid.is_some()
                    || !service.config.shares.is_empty();
                let health = runtime.and_then(|runtime| runtime.health.as_ref());
                let health_fresh = runtime.is_some_and(|runtime| runtime.health_fresh(now));
                let node_storage_ready =
                    !requires_health || (health_fresh && health.is_some_and(|health| health.ready));
                let interactive_pty =
                    health_fresh && health.is_some_and(|health| health.interactive_pty);
                let namespaced_jobs =
                    health_fresh && health.is_some_and(|health| health.namespaced_jobs);
                let idle_since_unix_ms = if online && !busy {
                    service.idle_since.get(id).copied().unwrap_or(0)
                } else {
                    0
                };
                NodeEligibility {
                    id: NodeId::new(id.clone()).expect("validated node ID"),
                    idle_since_unix_ms,
                    online,
                    storage_ready: self.share_ready(now) && node_storage_ready,
                    drain_requested: service.node_is_maintenance_scoped(id),
                    occupied: busy,
                    interactive_pty,
                    namespaced_jobs,
                }
            })
            .collect()
    }
}

pub(crate) fn run_forever<T: NodeTransport + 'static>(
    service: &mut ControllerService<T>,
    interval: Duration,
) -> Result<(), ControllerError> {
    run_forever_with_idle_maintenance(service, interval, || false, |_| Ok(false))
}

pub(crate) fn run_forever_with_idle_maintenance<T: NodeTransport + 'static>(
    service: &mut ControllerService<T>,
    interval: Duration,
    requested: impl FnMut() -> bool,
    apply: impl FnMut(&mut ControllerService<T>) -> Result<bool, ControllerError>,
) -> Result<(), ControllerError> {
    run_forever_with_shutdown(service, interval, || false, requested, apply)
}

pub(crate) fn run_forever_with_shutdown<T: NodeTransport + 'static>(
    service: &mut ControllerService<T>,
    interval: Duration,
    shutdown_requested: impl FnMut() -> bool,
    requested: impl FnMut() -> bool,
    apply: impl FnMut(&mut ControllerService<T>) -> Result<bool, ControllerError>,
) -> Result<(), ControllerError> {
    run_forever_with_control_inner(
        service,
        interval,
        None,
        shutdown_requested,
        requested,
        apply,
    )
}

pub(crate) fn run_forever_with_control<T: NodeTransport + 'static>(
    service: &mut ControllerService<T>,
    interval: Duration,
    listener: &mut crate::ControlListener<'_>,
    hello: ControllerHello,
    config_path: std::path::PathBuf,
    maintenance: crate::maintenance::MaintenanceCoordinator,
    shutdown_requested: impl FnMut() -> bool,
    requested: impl FnMut() -> bool,
    apply: impl FnMut(&mut ControllerService<T>) -> Result<bool, ControllerError>,
) -> Result<(), ControllerError> {
    let storage = Storage::open(service.storage.root())?;
    let api = crate::ControlApi::new_with_maintenance(
        service.config.clone(),
        storage,
        hello,
        config_path,
        maintenance,
    );
    run_forever_with_control_inner(
        service,
        interval,
        Some((listener, api)),
        shutdown_requested,
        requested,
        apply,
    )
}

fn run_forever_with_control_inner<T: NodeTransport + 'static>(
    service: &mut ControllerService<T>,
    interval: Duration,
    mut control: Option<(&mut crate::ControlListener<'_>, crate::ControlApi)>,
    mut shutdown_requested: impl FnMut() -> bool,
    mut requested: impl FnMut() -> bool,
    mut apply: impl FnMut(&mut ControllerService<T>) -> Result<bool, ControllerError>,
) -> Result<(), ControllerError> {
    let wake = match ControllerWake::bind(service.storage.root()) {
        Ok(wake) => Some(wake),
        Err(WakeError::PathTooLong(path)) => {
            eprintln!(
                "macluster: controller wake path is too long ({}); continuing with periodic reconciliation",
                path.display()
            );
            None
        }
        Err(error) => return Err(error.into()),
    };
    let (signal, mut waiter) = RuntimeSignal::pair();
    let _wake_forwarder = wake
        .map(|wake| {
            WakeForwarder::start(wake, signal.clone(), service.storage.root().to_path_buf())
        })
        .transpose()?;
    if let Some((listener, _)) = control.as_mut() {
        listener.set_runtime_signal(signal.clone());
    }
    let mut runtime = RuntimeState::new_with_signal(
        service,
        interval.max(Duration::from_secs(1)),
        Some(signal.clone()),
    )?;
    let mut queue_names = service.config.queues.keys().cloned().collect::<Vec<_>>();
    let mut next_maintenance_attempt = Instant::now();
    let mut next_job_storage_sweep = Instant::now();
    let mut web_service: Option<crate::web::WebService> = None;
    if let Some((_, api)) = control.as_mut() {
        service.set_maintenance_scope(api.maintenance_scope());
    }

    loop {
        if shutdown_requested() {
            let drain_deadline = Instant::now() + Duration::from_secs(9);
            while runtime.pending_work() > 0 && Instant::now() < drain_deadline {
                runtime.poll_workers(service)?;
                if runtime.pending_work() > 0 {
                    waiter.wait_until(Instant::now() + Duration::from_millis(25));
                }
            }
            eprintln!(
                "macluster: controller is shutting down; durable jobs remain available for recovery"
            );
            return Ok(());
        }
        let reset_policy = service.refresh_reset_barrier_policy()?;
        let maintenance_active = service.refresh_maintenance_barrier()?;
        runtime.poll_workers(service)?;
        if let Some((_, api)) = control.as_mut() {
            let scope = api.maintenance_scope();
            service.set_maintenance_scope(scope.clone());
            if let Some(scope) = scope {
                let blockers = runtime.maintenance_blockers(service, &scope)?;
                api.refresh_maintenance_blockers(blockers);
            }
        }
        if let Some((listener, api)) = control.as_mut() {
            let lifecycle = if reset_policy.is_some() || maintenance_active {
                ControllerLifecycle::Paused
            } else if !service.dispatch_enabled
                || service.maintenance_recovery_blocked
                || api.maintenance_recovery_required()
            {
                ControllerLifecycle::RecoveryPending
            } else {
                ControllerLifecycle::Ready
            };
            api.set_lifecycle(lifecycle);
            api.expire_monitor_subscriptions(Instant::now());
            for _ in 0..16 {
                let Some(event) = listener.poll_event() else {
                    break;
                };
                match event {
                    crate::PendingControlEvent::Request(request) => {
                        let control_request = request.request().clone();
                        let result = if let Err(error) =
                            api.validate_generation(control_request.expected_generation)
                        {
                            Err(error)
                        } else if let macluster_protocol::control::ControlCommand::StartWeb {
                            port,
                        } = control_request.command.clone()
                        {
                            if let Some(web_service) = web_service.as_mut() {
                                web_service
                                    .start_or_reuse(port)
                                    .map_err(web_start_control_error)
                            } else {
                                match crate::web::WebService::bind_and_start(
                                    listener.binding().clone(),
                                    service.config.clone(),
                                    port,
                                ) {
                                    Ok((started, payload)) => {
                                        web_service = Some(started);
                                        Ok(payload)
                                    }
                                    Err(error) => Err(web_start_control_error(error)),
                                }
                            }
                        } else if let macluster_protocol::control::ControlCommand::FanControl {
                            node_id,
                            policy,
                        } = control_request.command.clone()
                        {
                            if policy.is_some_and(|requested| {
                                requested != macluster_protocol::types::FanPolicy::System
                            }) && (maintenance_active || reset_policy.is_some())
                            {
                                Err(crate::control::maintenance_error(
                                    "fan policy changes are paused during controller maintenance",
                                ))
                            } else {
                                dispatch_fan_control(service, node_id, policy)
                            }
                        } else if let macluster_protocol::control::ControlCommand::CompleteMaintenance {
                            ticket,
                            candidate_config_digest,
                            candidate_journal_digest,
                        } = control_request.command.clone()
                        {
                            let scope = api.maintenance_scope();
                            let drain_ready = if let Some(scope) = scope.as_ref() {
                                let blockers = runtime.maintenance_blockers(service, scope)?;
                                api.refresh_maintenance_blockers(blockers.clone());
                                blockers.is_empty()
                            } else {
                                false
                            };
                            if !drain_ready {
                                Err(crate::control::maintenance_error(
                                    "maintenance still has active jobs, output sync, or in-flight node operations",
                                ))
                            } else {
                                match api.prepare_maintenance_completion(
                                    &ticket,
                                    &candidate_config_digest,
                                    &candidate_journal_digest,
                                ) {
                                    Ok((next_config, scope)) => {
                                        let old_digest = runtime.digest.clone();
                                        match service.reload_quiescent_config(
                                            next_config.clone(),
                                            &scope,
                                        ) {
                                            Ok(()) => {
                                                runtime.apply_config_reload(
                                                    service,
                                                    old_digest,
                                                    &scope,
                                                );
                                                match api.finish_maintenance_completion(
                                                    &ticket,
                                                    next_config,
                                                ) {
                                                    Ok(()) => {
                                                        service.set_maintenance_recovery_blocked(false);
                                                        if let Some(web_service) = web_service.as_ref() {
                                                            web_service.update_config(service.config.clone());
                                                        }
                                                        queue_names = service
                                                            .config
                                                            .queues
                                                            .keys()
                                                            .cloned()
                                                            .collect();
                                                        service.set_maintenance_scope(
                                                            api.maintenance_scope(),
                                                        );
                                                        if let Err(error) =
                                                            listener.set_hello(api.hello().clone())
                                                        {
                                                            eprintln!(
                                                                "macluster: could not publish new controller generation: {error}"
                                                            );
                                                        }
                                                        Ok(macluster_protocol::control::ControlPayload::Maintenance(None))
                                                    }
                                                    Err(error) => Err(error),
                                                }
                                            }
                                            Err(error) => Err(crate::control::maintenance_error(
                                                error.to_string(),
                                            )),
                                        }
                                    }
                                    Err(error) => Err(error),
                                }
                            }
                        } else {
                            api.handle(request.client_session(), control_request)
                        };
                        if let Err(error) = request.respond(result)
                            && !matches!(error, crate::IpcError::ClientDisconnected)
                        {
                            eprintln!(
                                "macluster: could not respond to local controller request: {error}"
                            );
                        }
                        service.set_maintenance_scope(api.maintenance_scope());
                    }
                    crate::PendingControlEvent::Disconnected(session) => api.disconnect(session),
                }
            }
        }
        let now = Instant::now();
        if reset_policy.is_none() && !maintenance_active && now >= next_job_storage_sweep {
            next_job_storage_sweep = now + JOB_STORAGE_SWEEP_INTERVAL;
            match Id128::parse(&service.config.share_uuid) {
                Ok(namespace) => match service.storage.enforce_job_storage_limit(
                    &service.config.shared_root,
                    namespace,
                    JOB_STORAGE_LIMIT_BYTES,
                ) {
                    Ok(report) => {
                        if !report.pruned_job_ids.is_empty() {
                            eprintln!(
                                "macluster: removed {} oldest terminal job log record(s); managed job storage is now {:.2} GiB",
                                report.pruned_job_ids.len(),
                                report.bytes_after as f64 / (1024.0 * 1024.0 * 1024.0)
                            );
                        }
                        if report.over_limit_bytes > 0 {
                            eprintln!(
                                "macluster: managed job storage remains {:.2} GiB, above the 1 GiB limit; active, unsynchronized, or otherwise non-prunable data is retained",
                                report.bytes_after as f64 / (1024.0 * 1024.0 * 1024.0)
                            );
                        }
                    }
                    Err(error) => {
                        eprintln!("macluster: could not enforce the 1 GiB job log limit: {error}")
                    }
                },
                Err(error) => eprintln!(
                    "macluster: could not enforce the 1 GiB job log limit because the storage namespace is invalid: {error}"
                ),
            }
        }
        let address_maintenance = reset_policy.is_none() && !maintenance_active && requested();
        if address_maintenance {
            let all_jobs = service.storage.list_active_jobs()?;
            if all_jobs.iter().all(|job| {
                !matches!(
                    job.state,
                    JobState::Starting | JobState::Running | JobState::Cancelling
                )
            }) {
                let quiescent = runtime.node_probe_pool.pending == 0
                    && runtime.control_pool.pending == 0
                    && runtime.share_pool.pending == 0
                    && runtime.snapshot_pool.pending == 0;
                if quiescent && Instant::now() >= next_maintenance_attempt {
                    if apply(service)? {
                        runtime = RuntimeState::new_with_signal(
                            service,
                            interval.max(Duration::from_secs(1)),
                            Some(signal.clone()),
                        )?;
                        queue_names = service.config.queues.keys().cloned().collect();
                    }
                    next_maintenance_attempt = Instant::now() + Duration::from_secs(30);
                }
                waiter.wait_until(runtime.next_deadline(Instant::now()));
                continue;
            }
        }
        runtime.schedule_share_probe(service);
        let jobs = service.storage.list_reconcile_jobs()?;
        runtime.schedule_controls(service, &jobs)?;
        runtime.schedule_probes(service)?;
        if !reset_policy.is_some_and(|policy| policy.discard_terminal_sync) {
            runtime.schedule_snapshots(service, &jobs, &queue_names);
        }
        if !address_maintenance {
            runtime.dispatch(service, jobs, &queue_names)?;
        }
        if let Some(policy) = reset_policy {
            let all_jobs = service.storage.list_active_jobs()?;
            if reset_drain_complete(&all_jobs, policy) {
                eprintln!("macluster: reset barrier drained active work; controller is exiting");
                return Ok(());
            }
        }
        if maintenance_active {
            let all_jobs = service.storage.list_active_jobs()?;
            if maintenance_drain_complete(&all_jobs) {
                eprintln!("macluster: node maintenance drained active work; controller is exiting");
                return Ok(());
            }
        }
        waiter.wait_until(runtime.next_deadline(Instant::now()));
    }
}

fn dispatch_fan_control<T: NodeTransport>(
    service: &ControllerService<T>,
    selected_node: Option<NodeId>,
    policy: Option<macluster_protocol::types::FanPolicy>,
) -> Result<macluster_protocol::control::ControlPayload, macluster_protocol::control::ControlError>
{
    use macluster_protocol::{
        control::{ControlPayload, NodeFanControlResult},
        types::{Operation, ResponseBody},
    };

    let targets = if let Some(node_id) = selected_node {
        let node = service.config.nodes.get(node_id.as_str()).ok_or_else(|| {
            crate::control::invalid_request(format!("node '{node_id}' is not in the cluster"))
        })?;
        vec![(node_id, node)]
    } else {
        if service.config.nodes.len() > 128 {
            return Err(crate::control::invalid_request(
                "cluster-wide fan control supports at most 128 nodes per request; target a node individually",
            ));
        }
        service
            .config
            .nodes
            .iter()
            .filter_map(|(id, node)| NodeId::new(id.clone()).ok().map(|id| (id, node)))
            .collect::<Vec<_>>()
    };
    if targets.is_empty() {
        return Err(crate::control::invalid_request(
            "cluster has no registered nodes",
        ));
    }

    let targets = std::sync::Arc::new(targets);
    let next_target = std::sync::atomic::AtomicUsize::new(0);
    let transport = std::sync::Arc::clone(&service.transport);
    let results = std::thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::channel();
        for _ in 0..targets.len().min(8) {
            let sender = sender.clone();
            let transport = std::sync::Arc::clone(&transport);
            let targets = std::sync::Arc::clone(&targets);
            let next_target = &next_target;
            scope.spawn(move || {
                loop {
                    let index = next_target.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some((node_id, node)) = targets.get(index) else {
                        break;
                    };
                    let node_id = node_id.clone();
                    let operation = match policy {
                        Some(policy) => Operation::SetFanPolicy { policy },
                        None => Operation::QueryFanPolicy,
                    };
                    let result = match transport.call(&node_id, node, operation) {
                        Ok(ResponseBody::FanControl(status)) => NodeFanControlResult {
                            node_id,
                            status: Some(status),
                            error: None,
                        },
                        Ok(_) => NodeFanControlResult {
                            node_id,
                            status: None,
                            error: Some(
                                "node agent returned an unexpected fan-control response".into(),
                            ),
                        },
                        Err(error) => NodeFanControlResult {
                            node_id,
                            status: None,
                            error: Some(error.to_string()),
                        },
                    };
                    let _ = sender.send(result);
                }
            });
        }
        drop(sender);
        receiver.into_iter().collect::<Vec<_>>()
    });
    let mut results = results;
    results.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    Ok(ControlPayload::FanControl(results))
}

struct WakeForwarder {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    state_dir: std::path::PathBuf,
}

impl WakeForwarder {
    fn start(
        wake: ControllerWake,
        signal: RuntimeSignal,
        state_dir: std::path::PathBuf,
    ) -> io::Result<Self> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("macluster-wake-forwarder".into())
            .spawn(move || {
                while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                    match wake.wait(Duration::from_secs(60)) {
                        Ok(true) => signal.notify(),
                        Ok(false) => {}
                        Err(error) => {
                            eprintln!("macluster: controller wake listener failed: {error}");
                            signal.notify();
                            return;
                        }
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
            state_dir,
        })
    }
}

impl Drop for WakeForwarder {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        let _ = notify_controller(&self.state_dir);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn web_start_control_error(
    error: crate::web::WebError,
) -> macluster_protocol::control::ControlError {
    let code = if matches!(
        &error,
        crate::web::WebError::PortConflict(_) | crate::web::WebError::RunningPortConflict { .. }
    ) {
        macluster_protocol::control::ControlErrorCode::Conflict
    } else {
        macluster_protocol::control::ControlErrorCode::Unavailable
    };
    macluster_protocol::control::ControlError {
        code,
        message: format!("cannot start local web monitor: {error}"),
    }
}

fn reset_drain_complete(jobs: &[JobRecord], policy: ResetBarrierPolicy) -> bool {
    jobs.iter().all(|job| {
        !matches!(
            job.state,
            JobState::Starting | JobState::Running | JobState::Cancelling
        ) && (policy.discard_terminal_sync || !job.snapshot_sync_pending)
    })
}

fn maintenance_drain_complete(jobs: &[JobRecord]) -> bool {
    jobs.iter().all(|job| {
        !matches!(
            job.state,
            JobState::Starting | JobState::Running | JobState::Cancelling
        ) && !job.snapshot_sync_pending
            && !job.log_sync_pending
    })
}

fn retry_delay(failures: u8) -> Duration {
    let seconds = 1_u64
        .checked_shl(u32::from(failures.saturating_sub(1).min(5)))
        .unwrap_or(30)
        .min(30);
    Duration::from_secs(seconds)
}

fn node_result_is_current(
    tag: &WorkTag,
    epoch: ControllerEpoch,
    config_digest: &str,
    generation: u64,
    now: Instant,
) -> bool {
    tag.epoch == epoch
        && tag.config_digest == config_digest
        && tag.generation == generation
        && now.saturating_duration_since(tag.started_at) <= MAX_WORK_RESULT_AGE
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::{
        InFlightNodeOperation, NODE_HEALTH_RETRY, NODE_HEALTH_TTL, NodeHealthCache, NodeRuntime,
        NodeStatusCache, RuntimeState, WakeForwarder, WorkKind, WorkTag, WorkerCompletion,
        WorkerPool, WorkerResult, maintenance_drain_complete, node_result_is_current, now_ms,
        reset_drain_complete, retry_delay, run_forever,
    };
    use crate::events::RuntimeSignal;
    use macluster_core::maintenance::ResetBarrierPolicy;
    use macluster_core::scheduler::next_dispatch;
    use macluster_protocol::control::MaintenanceScope;
    use macluster_protocol::{
        identifiers::{ControllerUuid, Id128, NodeId, QueueName, RequestId},
        types::{ControllerEpoch, JobMode, JobRecord, JobSpec, JobState},
    };
    use std::time::{Duration, Instant};

    struct IsolatedNodeTransport;

    struct ReceiptTransport(bool);
    impl crate::transport::NodeTransport for ReceiptTransport {
        fn call(
            &self,
            _: &NodeId,
            _: &macluster_core::config::NodeConfig,
            operation: macluster_protocol::types::Operation,
        ) -> Result<macluster_protocol::types::ResponseBody, crate::transport::TransportError>
        {
            use macluster_protocol::types::{
                ExecutionStatus, Operation, ProtocolError, ResponseBody, RuntimePhase,
            };
            match operation {
                Operation::Fence { .. } => Ok(ResponseBody::Ack),
                Operation::RecoverJob {
                    start_token,
                    job_id,
                    ..
                } if self.0 => Ok(ResponseBody::Execution(ExecutionStatus {
                    start_token,
                    job_id,
                    phase: RuntimePhase::Idle,
                    terminal_state: Some(JobState::NodeLost),
                    boot_id: "boot".into(),
                    runner_pid: None,
                    child_pid: None,
                    exit_code: None,
                    end_reason: Some("recovered durable receipt after agent-state loss".into()),
                    log_sync_pending: false,
                })),
                _ => Err(crate::transport::TransportError::Remote(
                    ProtocolError::NotFound,
                )),
            }
        }
    }

    #[test]
    fn runtime_recovers_receipts_and_keeps_unverifiable_missing_executions_reserved() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        for available in [true, false] {
            let root =
                std::env::temp_dir().join(format!("macluster-runtime-receipt-{}", Id128::random()));
            std::fs::create_dir_all(&root).unwrap();
            let config = login_and_worker_config(&root);
            let storage = Storage::open(root.join("controller")).unwrap();
            let job = submit_dispatch_test_job(&storage, &config.shared_root, None);
            storage
                .reserve_job(job.id, NodeId::new("worker").unwrap())
                .unwrap();
            storage.mark_running(job.id).unwrap();
            let mut service =
                ControllerService::new(config, storage, ReceiptTransport(available)).unwrap();
            let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
            runtime.schedule_probes(&service).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while runtime.nodes["worker"].status.is_none() {
                runtime.poll_workers(&mut service).unwrap();
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            let record = service.storage.get_job(job.id).unwrap().unwrap();
            if available {
                assert_eq!(record.state, JobState::NodeLost);
                assert!(!runtime.nodes["worker"].status.as_ref().unwrap().occupied);
            } else {
                assert_eq!(record.state, JobState::Running);
                assert!(
                    record
                        .waiting_reason
                        .as_deref()
                        .unwrap()
                        .contains("receipt")
                );
                assert!(runtime.nodes["worker"].status.as_ref().unwrap().occupied);
            }
            drop(runtime);
            drop(service);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    impl crate::transport::NodeTransport for IsolatedNodeTransport {
        fn call(
            &self,
            node_id: &macluster_protocol::identifiers::NodeId,
            _node: &macluster_core::config::NodeConfig,
            operation: macluster_protocol::types::Operation,
        ) -> Result<macluster_protocol::types::ResponseBody, crate::transport::TransportError>
        {
            use macluster_protocol::types::{Operation, ProtocolError, ResponseBody};

            match operation {
                Operation::Fence { .. } => Ok(ResponseBody::Ack),
                Operation::Status => {
                    if node_id.as_str() == "node-z-slow" {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(crate::transport::TransportError::Remote(
                        ProtocolError::NotFound,
                    ))
                }
                _ => Err(crate::transport::TransportError::Protocol(
                    "unexpected test operation".into(),
                )),
            }
        }
    }

    struct StartCountingTransport(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl crate::transport::NodeTransport for StartCountingTransport {
        fn call(
            &self,
            _node_id: &macluster_protocol::identifiers::NodeId,
            _node: &macluster_core::config::NodeConfig,
            operation: macluster_protocol::types::Operation,
        ) -> Result<macluster_protocol::types::ResponseBody, crate::transport::TransportError>
        {
            use macluster_protocol::types::{Operation, ResponseBody, StartResult};

            match operation {
                Operation::StartJob { start_token, .. } => {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok(ResponseBody::Started(StartResult {
                        start_token,
                        accepted: true,
                        runner_pid: Some(7),
                    }))
                }
                Operation::CancelJob { .. } | Operation::Fence { .. } => Ok(ResponseBody::Ack),
                Operation::Health => Ok(ResponseBody::Health(
                    macluster_protocol::types::NodeHealth {
                        machine_uuid: String::new(),
                        execution_uid: 0,
                        execution_digest: String::new(),
                        primary_share_ready: true,
                        shares: Default::default(),
                        features: vec![macluster_protocol::types::INTERACTIVE_PTY_FEATURE.into()],
                    },
                )),
                Operation::Status => Err(crate::transport::TransportError::Remote(
                    macluster_protocol::types::ProtocolError::NotFound,
                )),
                _ => Err(crate::transport::TransportError::Protocol(
                    "unexpected test operation".into(),
                )),
            }
        }
    }

    struct RecordingDispatchTransport {
        started_on: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        execution_digest: String,
    }

    impl crate::transport::NodeTransport for RecordingDispatchTransport {
        fn call(
            &self,
            node_id: &NodeId,
            _node: &macluster_core::config::NodeConfig,
            operation: macluster_protocol::types::Operation,
        ) -> Result<macluster_protocol::types::ResponseBody, crate::transport::TransportError>
        {
            use macluster_protocol::types::{
                NodeHealth, Operation, ProtocolError, ResponseBody, StartResult,
            };

            match operation {
                Operation::StartJob { start_token, .. } => {
                    self.started_on.lock().unwrap().push(node_id.to_string());
                    Ok(ResponseBody::Started(StartResult {
                        start_token,
                        accepted: true,
                        runner_pid: Some(7),
                    }))
                }
                Operation::CancelJob { .. } | Operation::Fence { .. } => Ok(ResponseBody::Ack),
                Operation::Health => Ok(ResponseBody::Health(NodeHealth {
                    machine_uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                    execution_uid: 501,
                    execution_digest: self.execution_digest.clone(),
                    primary_share_ready: true,
                    shares: Default::default(),
                    features: vec![],
                })),
                Operation::Status => Err(crate::transport::TransportError::Remote(
                    ProtocolError::NotFound,
                )),
                _ => Err(crate::transport::TransportError::Protocol(
                    "unexpected dispatch test operation".into(),
                )),
            }
        }
    }

    struct SimulatedFleetTransport;

    impl crate::transport::NodeTransport for SimulatedFleetTransport {
        fn call(
            &self,
            node_id: &macluster_protocol::identifiers::NodeId,
            _node: &macluster_core::config::NodeConfig,
            operation: macluster_protocol::types::Operation,
        ) -> Result<macluster_protocol::types::ResponseBody, crate::transport::TransportError>
        {
            use macluster_protocol::types::{NodeHealth, Operation, ProtocolError, ResponseBody};
            use std::collections::BTreeMap;

            match operation {
                Operation::Fence { .. } => Ok(ResponseBody::Ack),
                Operation::Status => {
                    let index = node_id
                        .as_str()
                        .rsplit('-')
                        .next()
                        .and_then(|suffix| suffix.parse::<usize>().ok())
                        .unwrap();
                    match index % 4 {
                        0 => {
                            std::thread::sleep(Duration::from_millis(120));
                            Err(crate::transport::TransportError::Remote(
                                ProtocolError::NotFound,
                            ))
                        }
                        1 => Err(crate::transport::TransportError::Timeout),
                        _ => Err(crate::transport::TransportError::Remote(
                            ProtocolError::NotFound,
                        )),
                    }
                }
                Operation::Health => Ok(ResponseBody::Health(NodeHealth {
                    machine_uuid: String::new(),
                    execution_uid: 0,
                    execution_digest: String::new(),
                    primary_share_ready: true,
                    shares: BTreeMap::new(),
                    features: Vec::new(),
                })),
                _ => Err(crate::transport::TransportError::Protocol(
                    "unexpected test operation".into(),
                )),
            }
        }
    }

    fn simulated_fleet_config(
        root: &std::path::Path,
        node_count: usize,
    ) -> macluster_core::config::ClusterConfig {
        use macluster_core::config::ClusterConfig;
        use std::fs;

        let shared_root = root.join("shared");
        fs::create_dir_all(&shared_root).unwrap();
        let node_ids = (0..node_count)
            .map(|index| format!("node-{index:03}"))
            .collect::<Vec<_>>();
        let mut config_text = format!(
            r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "{}"
protocol_version = 1

[queues.mini01]
nodes = [{}]
scheduler = "fifo"
"#,
            shared_root.display(),
            node_ids[0],
            node_ids
                .iter()
                .map(|node| format!("\"{node}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for (index, node) in node_ids.iter().enumerate() {
            config_text.push_str(&format!(
                "\n[nodes.{node}]\nhost = \"192.0.2.{}\"\ntransport = \"ssh\"\n",
                index + 1
            ));
        }
        ClusterConfig::parse(&config_text).unwrap()
    }

    fn login_and_worker_config(root: &std::path::Path) -> macluster_core::config::ClusterConfig {
        use macluster_core::config::ClusterConfig;
        use std::fs;

        let shared_root = root.join("shared");
        fs::create_dir_all(&shared_root).unwrap();
        ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"mini01\"\nlogin_node = \"login\"\nshared_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"login\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"login\", \"worker\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.worker]\nhost = \"192.0.2.2\"\ntransport = \"ssh\"\n",
            shared_root.display()
        ))
        .unwrap()
    }

    fn submit_dispatch_test_job(
        storage: &macluster_core::storage::Storage,
        shared_root: &std::path::Path,
        pinned_node: Option<&str>,
    ) -> JobRecord {
        let snapshot = storage.stage_snapshot(b"#!/bin/bash\ntrue\n").unwrap();
        let job = storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: pinned_node.map(|node| NodeId::new(node).unwrap()),
                    name: "login exclusion".into(),
                    cwd: shared_root.display().to_string(),
                    stdout_path: shared_root.join("jobs/%j/out").display().to_string(),
                    stderr_path: shared_root.join("jobs/%j/err").display().to_string(),
                    walltime_secs: None,
                    env: Default::default(),
                    mode: JobMode::Batch,
                    snapshot: Some(snapshot),
                },
            )
            .unwrap();
        storage.publish_snapshot(job.id, shared_root).unwrap();
        job
    }

    #[test]
    fn address_reload_preserves_pending_logs_and_rejects_active_tasks_or_topology_changes() {
        let root =
            std::env::temp_dir().join(format!("macluster-address-reload-{}", Id128::random()));
        let config = login_and_worker_config(&root);
        let storage = macluster_core::storage::Storage::open(root.join("state")).unwrap();
        let job = submit_dispatch_test_job(&storage, &config.shared_root, None);
        let mut service =
            crate::ControllerService::new(config.clone(), storage, IsolatedNodeTransport).unwrap();
        service
            .storage
            .reserve_job(job.id, NodeId::new("worker").unwrap())
            .unwrap();
        service.storage.mark_running(job.id).unwrap();
        let mut next = config.clone();
        next.nodes.get_mut("worker").unwrap().host = "192.0.2.3".into();
        assert!(service.apply_idle_address_config(next.clone()).is_err());
        service
            .storage
            .finish_job(job.id, JobState::Completed, Some(0), None)
            .unwrap();
        service.storage.set_log_sync_pending(job.id, true).unwrap();
        service.apply_idle_address_config(next.clone()).unwrap();
        assert_eq!(service.config.nodes["worker"].host, "192.0.2.3");
        let retained = service.storage.get_job(job.id).unwrap().unwrap();
        assert_eq!(retained.state, JobState::Completed);
        assert!(retained.log_sync_pending);
        next.shared_root = root.join("unrelated");
        assert!(service.apply_idle_address_config(next).is_err());
        drop(service);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn address_maintenance_waits_for_active_tasks_and_never_dispatches_queued_work() {
        let root =
            std::env::temp_dir().join(format!("macluster-address-idle-hook-{}", Id128::random()));
        let config = login_and_worker_config(&root);
        let state = root.join("state");
        let storage = macluster_core::storage::Storage::open(&state).unwrap();
        let active = submit_dispatch_test_job(&storage, &config.shared_root, None);
        let queued = submit_dispatch_test_job(&storage, &config.shared_root, None);
        storage
            .reserve_job(active.id, NodeId::new("worker").unwrap())
            .unwrap();
        storage.mark_running(active.id).unwrap();
        let mut service =
            crate::ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let finish = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            let storage = macluster_core::storage::Storage::open(state).unwrap();
            storage
                .finish_job(active.id, JobState::Completed, Some(0), None)
                .unwrap();
            storage.set_log_sync_pending(active.id, true).unwrap();
        });
        let result = super::run_forever_with_idle_maintenance(
            &mut service,
            Duration::from_secs(1),
            || true,
            |service| {
                assert_eq!(
                    service.storage.get_job(active.id).unwrap().unwrap().state,
                    JobState::Completed
                );
                assert_eq!(
                    service.storage.get_job(queued.id).unwrap().unwrap().state,
                    JobState::Pending
                );
                Err(std::io::Error::other("address idle hook reached").into())
            },
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("address idle hook reached")
        );
        finish.join().unwrap();
        drop(service);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_shot_dispatch_skips_login_even_when_legacy_config_lists_it_first() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::{fs, sync::Mutex};

        let root = std::env::temp_dir().join(format!(
            "macluster-login-dispatch-once-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = login_and_worker_config(&root);
        let digest = config.execution_digest().unwrap();
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let started_on = std::sync::Arc::new(Mutex::new(Vec::new()));
        let mut service = ControllerService::new(
            config,
            storage,
            RecordingDispatchTransport {
                started_on: started_on.clone(),
                execution_digest: digest,
            },
        )
        .unwrap();
        let job = submit_dispatch_test_job(&service.storage, &shared_root, None);
        let job = service.storage.get_job(job.id).unwrap().unwrap();

        service.tick_with_storage_health(true).unwrap();

        assert_eq!(*started_on.lock().unwrap(), vec!["worker"]);
        assert_eq!(
            service
                .storage
                .get_job(job.id)
                .unwrap()
                .unwrap()
                .node
                .unwrap()
                .as_str(),
            "worker"
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dispatch_skips_login_even_when_legacy_config_lists_it_first() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-login-dispatch-runtime-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = login_and_worker_config(&root);
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let job = submit_dispatch_test_job(&service.storage, &shared_root, None);
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        runtime.share_ready = Some((true, now));
        for (id, node) in &service.config.nodes {
            let state = runtime.nodes.get_mut(id).unwrap();
            state.fenced = true;
            state.status = Some(NodeStatusCache {
                online: true,
                occupied: false,
                sampled_at: now,
            });
            if node.transport == macluster_core::config::Transport::Local {
                state.health = Some(NodeHealthCache {
                    valid: true,
                    ready: true,
                    interactive_pty: true,
                    namespaced_jobs: true,
                    sampled_at: now,
                    retry_at: now,
                });
            }
        }
        let jobs = service.storage.list_reconcile_jobs().unwrap();

        runtime
            .dispatch(&mut service, jobs, &["mini01".into()])
            .unwrap();

        assert_eq!(
            service
                .storage
                .get_job(job.id)
                .unwrap()
                .unwrap()
                .node
                .unwrap()
                .as_str(),
            "worker"
        );
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_start_rpc_requeues_reserved_job_with_the_same_token() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-start-retry-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = login_and_worker_config(&root);
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let submitted = submit_dispatch_test_job(&service.storage, &shared_root, None);
        let reserved = service
            .storage
            .reserve_job(submitted.id, NodeId::new("worker").unwrap())
            .unwrap();
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        let operation_id = 41;
        let generation = 7;
        let now = Instant::now();
        let node = runtime.nodes.get_mut("worker").unwrap();
        node.fenced = true;
        node.generation = generation;
        node.in_flight = Some(InFlightNodeOperation {
            id: operation_id,
            kind: WorkKind::Start,
        });
        let completion = WorkerCompletion {
            tag: WorkTag {
                epoch: service.epoch,
                config_digest: runtime.digest.clone(),
                node_id: Some("worker".into()),
                generation,
                operation_id,
                kind: WorkKind::Start,
                job_id: Some(reserved.id),
                started_at: now,
            },
            received_at: now,
            result: WorkerResult::Control(Err("remote start rejected".into())),
        };

        runtime.handle_completion(&mut service, completion).unwrap();

        let retry = runtime.nodes["worker"]
            .pending_start
            .as_ref()
            .expect("failed Start must remain queued for retry");
        assert_eq!(retry.id, reserved.id);
        assert_eq!(retry.start_token, reserved.start_token);
        assert!(runtime.nodes["worker"].next_control_at > now);
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_shot_dispatch_explains_legacy_jobs_pinned_to_login() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::{fs, sync::Mutex};

        let root = std::env::temp_dir().join(format!(
            "macluster-login-pinned-once-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = login_and_worker_config(&root);
        let digest = config.execution_digest().unwrap();
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let started_on = std::sync::Arc::new(Mutex::new(Vec::new()));
        let mut service = ControllerService::new(
            config,
            storage,
            RecordingDispatchTransport {
                started_on: started_on.clone(),
                execution_digest: digest,
            },
        )
        .unwrap();
        let job = submit_dispatch_test_job(&service.storage, &shared_root, Some("login"));

        service.tick_with_storage_health(true).unwrap();

        let stored = service.storage.get_job(job.id).unwrap().unwrap();
        assert_eq!(stored.state, JobState::Pending);
        assert!(
            stored
                .waiting_reason
                .unwrap()
                .contains("pinned to login node 'login'")
        );
        assert!(started_on.lock().unwrap().is_empty());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_dispatch_explains_legacy_jobs_pinned_to_login() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-login-pinned-runtime-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = login_and_worker_config(&root);
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let job = submit_dispatch_test_job(&service.storage, &shared_root, Some("login"));
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        runtime.share_ready = Some((true, now));
        for (id, node) in &service.config.nodes {
            let state = runtime.nodes.get_mut(id).unwrap();
            state.fenced = true;
            state.status = Some(NodeStatusCache {
                online: true,
                occupied: false,
                sampled_at: now,
            });
            if node.transport == macluster_core::config::Transport::Local {
                state.health = Some(NodeHealthCache {
                    valid: true,
                    ready: true,
                    interactive_pty: true,
                    namespaced_jobs: true,
                    sampled_at: now,
                    retry_at: now,
                });
            }
        }
        let jobs = service.storage.list_reconcile_jobs().unwrap();

        runtime
            .dispatch(&mut service, jobs, &["mini01".into()])
            .unwrap();

        let stored = service.storage.get_job(job.id).unwrap().unwrap();
        assert_eq!(stored.state, JobState::Pending);
        assert!(
            stored
                .waiting_reason
                .unwrap()
                .contains("pinned to login node 'login'")
        );
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_slow_worker_does_not_block_another_worker_result() {
        let mut pool = WorkerPool::new(2, 2, None).unwrap();
        assert!(pool.try_spawn(|| {
            std::thread::sleep(Duration::from_millis(150));
            1
        }));
        assert!(pool.try_spawn(|| 2));

        let deadline = Instant::now() + Duration::from_millis(100);
        let mut fast_finished = false;
        while Instant::now() < deadline {
            fast_finished |= pool.poll().contains(&2);
            if fast_finished {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(fast_finished, "fast task waited for an unrelated slow task");
    }

    #[test]
    fn worker_completion_bursts_wake_once_and_keep_all_results_available() {
        let (signal, mut waiter) = RuntimeSignal::pair();
        let mut pool = WorkerPool::new(4, 8, Some(signal)).unwrap();
        for value in 0..8 {
            assert!(pool.try_spawn(move || value));
        }

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut results = Vec::new();
        while pool.pending > 0 && Instant::now() < deadline {
            waiter.wait_until(deadline);
            results.extend(pool.poll());
        }
        results.sort_unstable();
        assert_eq!(results, (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn an_external_wake_datagram_signals_the_runtime_waiter() {
        use crate::wake::{ControllerWake, notify_controller};

        let root =
            std::env::temp_dir().join(format!("macluster-wake-forwarder-{}", Id128::random()));
        std::fs::create_dir_all(&root).unwrap();
        let wake = ControllerWake::bind(&root).unwrap();
        let (signal, mut waiter) = RuntimeSignal::pair();
        let forwarder = WakeForwarder::start(wake, signal, root.clone()).unwrap();

        notify_controller(&root).unwrap();

        assert!(waiter.wait_until(Instant::now() + Duration::from_secs(1)));
        drop(forwarder);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn next_deadline_uses_the_earliest_probe_and_has_a_two_second_idle_cap() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;

        let root = std::env::temp_dir().join(format!("macluster-deadline-{}", Id128::random()));
        let config = login_and_worker_config(&root);
        let storage = Storage::open(root.join("controller")).unwrap();
        let service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        runtime.next_share_probe = now + Duration::from_secs(20);
        for node in runtime.nodes.values_mut() {
            node.next_probe_at = now + Duration::from_secs(20);
            node.health = Some(NodeHealthCache {
                valid: true,
                ready: true,
                interactive_pty: true,
                namespaced_jobs: true,
                sampled_at: now,
                retry_at: now + NODE_HEALTH_TTL,
            });
        }

        assert_eq!(
            runtime.next_deadline(now),
            now + Duration::from_secs(2),
            "external barrier and offline submissions must be revisited within two seconds"
        );
        runtime.nodes.get_mut("worker").unwrap().next_probe_at = now + Duration::from_millis(250);
        assert_eq!(runtime.next_deadline(now), now + Duration::from_millis(250));

        drop(runtime);
        drop(service);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retry_delay_grows_to_a_bounded_cap() {
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(1), Duration::from_secs(1));
        assert_eq!(retry_delay(3), Duration::from_secs(4));
        assert_eq!(retry_delay(20), Duration::from_secs(30));
    }

    fn reset_test_job(state: JobState, snapshot_sync_pending: bool) -> JobRecord {
        let node = NodeId::new("node-0").unwrap();
        JobRecord {
            id: 7,
            spec: JobSpec {
                storage_namespace: None,
                queue: QueueName::new("mini01").unwrap(),
                node: Some(node.clone()),
                name: "reset test".into(),
                cwd: "/tmp".into(),
                stdout_path: "/tmp/out-%j".into(),
                stderr_path: "/tmp/err-%j".into(),
                walltime_secs: None,
                env: Default::default(),
                mode: JobMode::Batch,
                snapshot: None,
            },
            state,
            node: Some(node),
            start_token: None,
            cancel_force: false,
            created_unix_ms: 1,
            started_unix_ms: None,
            finished_unix_ms: None,
            exit_code: None,
            end_reason: None,
            snapshot_sync_pending,
            log_sync_pending: false,
            waiting_reason: None,
        }
    }

    #[test]
    fn reset_force_drain_ignores_sync_flags_but_waits_for_active_execution() {
        let cancelled_snapshot = reset_test_job(JobState::Cancelled, true);
        assert!(!reset_drain_complete(
            &[cancelled_snapshot.clone()],
            ResetBarrierPolicy::default()
        ));
        assert!(reset_drain_complete(
            &[cancelled_snapshot],
            ResetBarrierPolicy {
                discard_terminal_sync: true
            }
        ));

        let queued_snapshot = reset_test_job(JobState::Pending, true);
        assert!(reset_drain_complete(
            &[queued_snapshot],
            ResetBarrierPolicy {
                discard_terminal_sync: true
            }
        ));

        for state in [JobState::Starting, JobState::Running, JobState::Cancelling] {
            assert!(!reset_drain_complete(
                &[reset_test_job(state, true)],
                ResetBarrierPolicy {
                    discard_terminal_sync: true
                }
            ));
        }
    }

    #[test]
    fn maintenance_drain_waits_for_active_work_and_sync_but_allows_queued_jobs() {
        assert!(maintenance_drain_complete(&[reset_test_job(
            JobState::Pending,
            false
        )]));
        assert!(!maintenance_drain_complete(&[reset_test_job(
            JobState::Pending,
            true
        )]));
        for state in [JobState::Starting, JobState::Running, JobState::Cancelling] {
            assert!(!maintenance_drain_complete(&[reset_test_job(state, false)]));
        }
    }

    #[test]
    fn maintenance_ticket_waits_for_active_execution_and_output_sync_to_finish() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-maintenance-drain-blockers-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = simulated_fleet_config(&root, 2);
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let submitted = submit_dispatch_test_job(&service.storage, &shared_root, Some("node-000"));
        service
            .storage
            .reserve_job(submitted.id, NodeId::new("node-000").unwrap())
            .unwrap();
        service.storage.mark_running(submitted.id).unwrap();

        let now = Instant::now();
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        service.set_maintenance_scope(Some(MaintenanceScope::Cluster));
        for node in runtime.nodes.values_mut() {
            node.status = Some(NodeStatusCache {
                online: true,
                occupied: false,
                sampled_at: now,
            });
        }
        let active = runtime
            .maintenance_blockers(&service, &MaintenanceScope::Cluster)
            .unwrap();
        assert!(
            active
                .iter()
                .any(|blocker| blocker.contains("job 1 is Running"))
        );

        service
            .storage
            .finish_job(submitted.id, JobState::Completed, Some(0), None)
            .unwrap();
        service
            .storage
            .set_log_sync_pending(submitted.id, true)
            .unwrap();
        let syncing = runtime
            .maintenance_blockers(&service, &MaintenanceScope::Cluster)
            .unwrap();
        assert!(
            syncing
                .iter()
                .any(|blocker| blocker.contains("output synchronization is pending"))
        );

        service
            .storage
            .set_log_sync_pending(submitted.id, false)
            .unwrap();
        assert!(
            runtime
                .maintenance_blockers(&service, &MaintenanceScope::Cluster)
                .unwrap()
                .is_empty()
        );
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scoped_maintenance_blocks_only_affected_nodes_from_dispatch() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-scoped-maintenance-dispatch-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = simulated_fleet_config(&root, 2);
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        let now = Instant::now();
        runtime.share_ready = Some((true, now));
        for node in runtime.nodes.values_mut() {
            node.fenced = true;
            node.status = Some(NodeStatusCache {
                online: true,
                occupied: false,
                sampled_at: now,
            });
        }
        service.set_maintenance_scope(Some(MaintenanceScope::Nodes(vec![
            NodeId::new("node-000").unwrap(),
        ])));
        let availability = runtime.availability(&service, now);
        assert!(
            availability
                .iter()
                .find(|node| node.id.as_str() == "node-000")
                .unwrap()
                .drain_requested
        );
        assert!(
            !availability
                .iter()
                .find(|node| node.id.as_str() == "node-001")
                .unwrap()
                .drain_requested
        );

        let job = submit_dispatch_test_job(&service.storage, &shared_root, None);
        let job = service.storage.get_job(job.id).unwrap().unwrap();
        let queue = service.config.queue_for_dispatch("mini01").unwrap();
        let queue_id = QueueName::new("mini01").unwrap();
        let dispatch = next_dispatch(&queue_id, &queue, &[job], &availability)
            .expect("unaffected node should still receive work");
        assert_eq!(dispatch.node_id.as_str(), "node-001");
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn maintenance_barrier_disables_dispatch_until_it_is_removed() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::{fs, os::fd::AsRawFd};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-maintenance-barrier-dispatch-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config_path = root.join("config.toml");
        fs::write(&config_path, "[cluster]\n").unwrap();
        let state_dir = root.join("controller");
        let config = simulated_fleet_config(&root, 1);
        let storage = Storage::open(&state_dir).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config_path);
        fs::write(
            &barrier,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "config_path": config_path,
                "state_dir": state_dir,
                "owner_pid": 1234
            }))
            .unwrap(),
        )
        .unwrap();
        let barrier_owner = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&barrier)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(barrier_owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB,) },
            0
        );
        service.set_maintenance_barrier_context(
            barrier.clone(),
            config_path.clone(),
            state_dir.clone(),
        );

        assert!(service.refresh_maintenance_barrier().unwrap());
        assert!(!service.dispatch_allowed());
        drop(barrier_owner);
        fs::remove_file(&barrier).unwrap();
        assert!(!service.refresh_maintenance_barrier().unwrap());
        assert!(service.dispatch_allowed());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_exits_after_maintenance_barrier_drains() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::{fs, os::fd::AsRawFd};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-maintenance-drain-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config_path = root.join("config.toml");
        fs::write(&config_path, "[cluster]\n").unwrap();
        let state_dir = root.join("controller");
        let config = simulated_fleet_config(&root, 1);
        let storage = Storage::open(&state_dir).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config_path);
        fs::write(
            &barrier,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "config_path": config_path,
                "state_dir": state_dir,
                "owner_pid": 1234
            }))
            .unwrap(),
        )
        .unwrap();
        let barrier_owner = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&barrier)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(barrier_owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB,) },
            0
        );
        service.set_maintenance_barrier_context(barrier.clone(), config_path, state_dir);

        run_forever(&mut service, Duration::from_secs(1)).unwrap();

        assert!(barrier.is_file());
        assert!(!service.dispatch_allowed());
        drop(barrier_owner);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn idle_controller_does_not_run_one_hundred_reconciliation_cycles_in_ten_seconds() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let root = std::env::temp_dir().join(format!("macluster-idle-runtime-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = login_and_worker_config(&root);
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let start = Instant::now();
        let mut loop_checks = 0_u32;

        super::run_forever_with_shutdown(
            &mut service,
            Duration::from_secs(1),
            || {
                loop_checks += 1;
                start.elapsed() >= Duration::from_secs(10)
            },
            || false,
            |_| Ok(false),
        )
        .unwrap();

        assert!(
            loop_checks < 100,
            "idle runtime ran {loop_checks} reconciliation cycles in ten seconds"
        );
        eprintln!("idle controller reconciliation cycles over ten seconds: {loop_checks}");
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_barrier_disables_dispatch_and_is_removed_when_temporary_barrier_clears() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-barrier-dispatch-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("config.toml");
        fs::write(&config_path, "[cluster]\n").unwrap();
        let state_dir = root.join("controller");
        let config = simulated_fleet_config(&root, 1);
        let storage = Storage::open(&state_dir).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let barrier = root.join("config.toml.macluster-reset.json");
        fs::write(
            &barrier,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "phase": "DRAINING",
                "config_path": config_path,
                "state_dir": state_dir,
                "discard_terminal_sync": true
            }))
            .unwrap(),
        )
        .unwrap();
        service.set_reset_barrier_context(barrier.clone(), config_path, state_dir);

        let policy = service.refresh_reset_barrier_policy().unwrap().unwrap();
        assert!(policy.discard_terminal_sync);
        assert!(!service.dispatch_allowed());

        fs::remove_file(&barrier).unwrap();
        assert!(service.refresh_reset_barrier_policy().unwrap().is_none());
        assert!(service.dispatch_allowed());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_shot_tick_reads_reset_barrier_before_dispatching_queued_jobs() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use macluster_protocol::{
            identifiers::{Id128, RequestId},
            types::{JobMode, JobSpec, JobState},
        };
        use std::{collections::BTreeMap, fs};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-barrier-once-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("config.toml");
        let state_dir = root.join("controller");
        let config = simulated_fleet_config(&root, 1);
        let shared_root = config.shared_root.clone();
        let storage = Storage::open(&state_dir).unwrap();
        let starts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut service =
            ControllerService::new(config, storage, StartCountingTransport(starts.clone()))
                .unwrap();
        let job = service
            .storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: None,
                    name: "queued during reset".into(),
                    cwd: shared_root.display().to_string(),
                    stdout_path: shared_root.join("jobs/%j/out").display().to_string(),
                    stderr_path: shared_root.join("jobs/%j/err").display().to_string(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Interactive,
                    snapshot: None,
                },
            )
            .unwrap();
        let barrier = root.join("config.toml.macluster-reset.json");
        fs::write(
            &barrier,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "phase": "DRAINING",
                "config_path": config_path,
                "state_dir": state_dir,
                "discard_terminal_sync": true
            }))
            .unwrap(),
        )
        .unwrap();
        service.set_reset_barrier_context(barrier, config_path, state_dir);

        service.tick_with_storage_health(true).unwrap();

        assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            service.storage.get_job(job.id).unwrap().unwrap().state,
            JobState::Pending
        );
        assert!(
            !service
                .storage
                .get_job(job.id)
                .unwrap()
                .unwrap()
                .snapshot_sync_pending
        );
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_reset_barrier_fails_closed_for_controller_dispatch() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::fs;

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-invalid-reset-barrier-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("config.toml");
        fs::write(&config_path, "[cluster]\n").unwrap();
        let state_dir = root.join("controller");
        let config = simulated_fleet_config(&root, 1);
        let storage = Storage::open(&state_dir).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let barrier = root.join("config.toml.macluster-reset.json");
        fs::write(&barrier, b"not-json").unwrap();
        service.set_reset_barrier_context(barrier, config_path, state_dir);

        assert!(service.refresh_reset_barrier_policy().is_err());
        assert!(!service.dispatch_allowed());
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nodes_that_fail_health_readiness_are_rechecked_quickly() {
        let sampled_at = Instant::now();
        let retry_at = sampled_at + NODE_HEALTH_RETRY;
        let mut node = NodeRuntime::new(sampled_at);
        node.health = Some(NodeHealthCache {
            valid: true,
            ready: false,
            interactive_pty: false,
            namespaced_jobs: false,
            sampled_at,
            retry_at,
        });

        assert!(!node.health_probe_due(sampled_at + Duration::from_secs(4)));
        assert!(node.health_probe_due(retry_at));

        node.health.as_mut().unwrap().ready = true;
        node.health.as_mut().unwrap().retry_at = sampled_at + NODE_HEALTH_TTL;
        assert!(!node.health_probe_due(sampled_at + Duration::from_secs(30)));
        assert!(node.health_probe_due(sampled_at + NODE_HEALTH_TTL));
    }

    #[test]
    fn worker_pool_rejects_work_beyond_its_running_and_queued_capacity() {
        let mut pool = WorkerPool::new(1, 1, None).unwrap();
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        assert!(pool.try_spawn(move || {
            entered_sender.send(()).unwrap();
            release_receiver.recv().unwrap();
            1
        }));
        entered_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        assert!(pool.try_spawn(|| 2));
        assert!(!pool.try_spawn(|| 3));
        release_sender.send(()).unwrap();
    }

    #[test]
    fn a_slow_node_probe_does_not_delay_another_nodes_availability() {
        use crate::ControllerService;
        use macluster_core::{config::ClusterConfig, storage::Storage};
        use std::{fs, time::SystemTime};

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-probe-isolation-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(root.join("shared")).unwrap();
        let config_text = format!(
            r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "node-a-fast"
protocol_version = 1

[queues.mini01]
nodes = ["node-a-fast", "node-z-slow"]
scheduler = "fifo"

[nodes.node-a-fast]
host = "192.0.2.1"
transport = "ssh"

[nodes.node-z-slow]
host = "192.0.2.2"
transport = "ssh"
"#,
            root.join("shared").display()
        );
        let config = ClusterConfig::parse(&config_text).unwrap();
        let storage = Storage::open(root.join("controller")).unwrap();
        let mut service = ControllerService::new(config, storage, IsolatedNodeTransport).unwrap();
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        runtime.schedule_probes(&service).unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        while runtime.nodes["node-a-fast"].status.is_none() && Instant::now() < deadline {
            runtime.poll_workers(&mut service).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }

        assert!(runtime.nodes["node-a-fast"].status_fresh(Instant::now()));
        assert!(runtime.nodes["node-z-slow"].in_flight.is_some());

        let deadline = Instant::now() + Duration::from_secs(1);
        while runtime.nodes["node-z-slow"].in_flight.is_some() && Instant::now() < deadline {
            runtime.poll_workers(&mut service).unwrap();
            std::thread::sleep(Duration::from_millis(2));
        }
        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_wins_over_a_start_that_has_not_left_the_controller() {
        use crate::ControllerService;
        use macluster_core::{config::ClusterConfig, storage::Storage};
        use macluster_protocol::{
            identifiers::{Id128, NodeId, QueueName, RequestId},
            types::{JobMode, JobSpec, JobState},
        };
        use std::{collections::BTreeMap, fs, time::SystemTime};

        let nonce = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-cancel-before-start-{}-{nonce}",
            std::process::id()
        ));
        let shared_root = root.join("shared");
        fs::create_dir_all(&shared_root).unwrap();
        let config = ClusterConfig::parse(&format!(
            r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "node-a-fast"
protocol_version = 1

[queues.mini01]
nodes = ["node-a-fast"]
scheduler = "fifo"

[nodes.node-a-fast]
host = "192.0.2.1"
transport = "ssh"
"#,
            shared_root.display()
        ))
        .unwrap();
        let storage = Storage::open(root.join("controller")).unwrap();
        let starts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut service =
            ControllerService::new(config, storage, StartCountingTransport(starts.clone()))
                .unwrap();
        let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
        let job = service
            .storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: None,
                    name: "interactive-shell".into(),
                    cwd: shared_root.display().to_string(),
                    stdout_path: shared_root.join("jobs/%j/out").display().to_string(),
                    stderr_path: shared_root.join("jobs/%j/err").display().to_string(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Interactive,
                    snapshot: None,
                },
            )
            .unwrap();
        let reserved = service
            .storage
            .reserve_job(job.id, NodeId::new("node-a-fast").unwrap())
            .unwrap();
        runtime.nodes.get_mut("node-a-fast").unwrap().fenced = true;
        runtime.nodes.get_mut("node-a-fast").unwrap().pending_start = Some(reserved);
        let cancelling = service.storage.request_cancel(job.id, false).unwrap();
        assert_eq!(cancelling.state, JobState::Cancelling);

        runtime
            .schedule_controls(&mut service, &[cancelling])
            .unwrap();

        let cancelled = service.storage.get_job(job.id).unwrap().unwrap();
        assert_eq!(cancelled.state, JobState::Cancelled);
        assert!(runtime.nodes["node-a-fast"].pending_start.is_none());
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(starts.load(std::sync::atomic::Ordering::SeqCst), 0);

        drop(runtime);
        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn simulated_8_and_32_node_fleets_keep_fast_probes_moving_past_slow_or_offline_nodes() {
        use crate::ControllerService;
        use macluster_core::storage::Storage;
        use std::{fs, time::SystemTime};

        for node_count in [8, 32] {
            let nonce = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "macluster-fleet-probe-{}-{node_count}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&root).unwrap();
            let config = simulated_fleet_config(&root, node_count);
            let storage = Storage::open(root.join("controller")).unwrap();
            let mut service =
                ControllerService::new(config, storage, SimulatedFleetTransport).unwrap();
            let mut runtime = RuntimeState::new(&service, Duration::from_secs(1)).unwrap();
            let expected_probe_capacity = node_count.min(super::PROBE_WORKERS) * 2;
            assert_eq!(runtime.node_probe_pool.max_pending, expected_probe_capacity);

            let mut fast_completed_before_slow = false;
            let all_fenced_deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < all_fenced_deadline {
                runtime.schedule_probes(&service).unwrap();
                runtime.poll_workers(&mut service).unwrap();
                if runtime.nodes["node-002"].status_fresh(Instant::now())
                    && runtime.nodes["node-000"].in_flight.is_some()
                {
                    fast_completed_before_slow = true;
                }
                if runtime.nodes.values().all(|node| node.fenced) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }

            assert!(fast_completed_before_slow);
            assert!(runtime.nodes.values().all(|node| node.fenced));
            drop(runtime);
            drop(service);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn late_results_from_old_epoch_config_generation_or_age_are_rejected() {
        let now = Instant::now();
        let epoch = ControllerEpoch {
            controller_uuid: ControllerUuid::random(),
            epoch: 7,
        };
        let tag = WorkTag {
            epoch,
            config_digest: "config-a".into(),
            node_id: Some("mini01-a".into()),
            generation: 3,
            operation_id: 11,
            kind: WorkKind::Probe,
            job_id: None,
            started_at: now,
        };

        assert!(node_result_is_current(&tag, epoch, "config-a", 3, now));
        assert!(!node_result_is_current(&tag, epoch, "config-b", 3, now));
        assert!(!node_result_is_current(&tag, epoch, "config-a", 4, now));
        assert!(!node_result_is_current(
            &tag,
            ControllerEpoch { epoch: 8, ..epoch },
            "config-a",
            3,
            now,
        ));
        assert!(!node_result_is_current(
            &tag,
            epoch,
            "config-a",
            3,
            now + Duration::from_secs(13),
        ));
    }
}
