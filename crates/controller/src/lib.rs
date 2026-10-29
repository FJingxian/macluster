//! Login-node reconciliation and whole-node FIFO dispatch.

pub mod compatibility;
mod control;
pub mod events;
mod ipc;
pub mod maintenance;
pub mod monitor;
mod runtime;
pub mod ssh;
pub mod transport;
pub mod wake;
pub mod web;

pub use control::ControlApi;
pub use ipc::{ControlListener, IpcError, PendingControlEvent, PendingControlRequest};

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    os::unix::{fs::OpenOptionsExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use macluster_core::{
    config::{ClusterConfig, Transport},
    maintenance::{ResetBarrierPolicy, read_maintenance_barrier, read_reset_barrier_policy},
    scheduler::{NodeEligibility, next_dispatch},
    storage::{Storage, SubmitError},
};
use macluster_protocol::{
    control::MaintenanceScope,
    identifiers::NodeId,
    types::{
        ControllerEpoch, ExecutionStatus, INTERACTIVE_PTY_FEATURE, JobMode, JobState, Operation,
        ProtocolError, ResponseBody, RuntimePhase,
    },
};
use thiserror::Error;

use crate::transport::{NodeTransport, TransportError, run_child_bounded};

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("controller storage error: {0}")]
    Storage(#[from] SubmitError),
    #[error("controller I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("controller wake error: {0}")]
    Wake(#[from] wake::WakeError),
}

pub struct ControllerService<T: NodeTransport> {
    pub(crate) config: ClusterConfig,
    pub(crate) storage: Storage,
    pub(crate) transport: Arc<T>,
    pub(crate) epoch: ControllerEpoch,
    pub(crate) fenced_nodes: HashSet<String>,
    pub(crate) idle_since: HashMap<String, u64>,
    pub(crate) dispatch_enabled: bool,
    pub(crate) maintenance_recovery_blocked: bool,
    pub(crate) reset_barrier_active: bool,
    pub(crate) reset_barrier_context: Option<(PathBuf, PathBuf, PathBuf)>,
    pub(crate) maintenance_barrier_active: bool,
    pub(crate) maintenance_barrier_context: Option<(PathBuf, PathBuf, PathBuf)>,
    pub(crate) maintenance_scope: Option<MaintenanceScope>,
}

impl<T: NodeTransport> ControllerService<T> {
    pub fn new(
        config: ClusterConfig,
        storage: Storage,
        transport: T,
    ) -> Result<Self, ControllerError> {
        let epoch = storage.begin_controller_epoch()?;
        Ok(Self {
            config,
            storage,
            transport: Arc::new(transport),
            epoch,
            fenced_nodes: HashSet::new(),
            idle_since: HashMap::new(),
            dispatch_enabled: true,
            maintenance_recovery_blocked: false,
            reset_barrier_active: false,
            reset_barrier_context: None,
            maintenance_barrier_active: false,
            maintenance_barrier_context: None,
            maintenance_scope: None,
        })
    }

    pub fn set_dispatch_enabled(&mut self, enabled: bool) {
        self.dispatch_enabled = enabled;
    }

    pub fn set_maintenance_recovery_blocked(&mut self, blocked: bool) {
        self.maintenance_recovery_blocked = blocked;
    }

    pub(crate) fn dispatch_allowed(&self) -> bool {
        self.dispatch_enabled
            && !self.maintenance_recovery_blocked
            && !self.reset_barrier_active
            && !self.maintenance_barrier_active
    }

    pub fn set_maintenance_scope(&mut self, scope: Option<MaintenanceScope>) {
        self.maintenance_scope = scope;
    }

    pub(crate) fn node_is_maintenance_scoped(&self, node_id: &str) -> bool {
        match self.maintenance_scope.as_ref() {
            Some(MaintenanceScope::Cluster) => true,
            Some(MaintenanceScope::Nodes(nodes)) => {
                nodes.iter().any(|node| node.as_str() == node_id)
            }
            None => false,
        }
    }

    /// Commit a validated candidate config after the runtime has confirmed the
    /// scoped drain, including in-flight worker operations. Unaffected nodes
    /// retain their runtime state and continue serving queued work.
    pub fn reload_quiescent_config(
        &mut self,
        config: ClusterConfig,
        scope: &MaintenanceScope,
    ) -> Result<(), ControllerError> {
        crate::maintenance::validate_scope_config_change(&self.config, &config, scope)
            .map_err(|error| io::Error::other(format!("unsafe scoped config reload: {error}")))?;
        let affected = |node: Option<&NodeId>| match scope {
            MaintenanceScope::Cluster => true,
            MaintenanceScope::Nodes(nodes) => node.is_some_and(|node| nodes.contains(node)),
        };
        let jobs = self.storage.list_jobs(None)?;
        if jobs.iter().any(|job| {
            let scoped = affected(job.node.as_ref());
            (scoped
                && matches!(
                    job.state,
                    JobState::Starting | JobState::Running | JobState::Cancelling
                ))
                || (scoped && (job.snapshot_sync_pending || job.log_sync_pending))
                || (matches!(scope, MaintenanceScope::Cluster)
                    && (job.snapshot_sync_pending || job.log_sync_pending))
        }) {
            return Err(io::Error::other(
                "cannot reload configuration while scoped jobs or output synchronization remain",
            )
            .into());
        }
        let affected_ids = self
            .config
            .nodes
            .keys()
            .chain(config.nodes.keys())
            .filter(|id| match scope {
                MaintenanceScope::Cluster => true,
                MaintenanceScope::Nodes(nodes) => {
                    nodes.iter().any(|node| node.as_str() == id.as_str())
                }
            })
            .cloned()
            .collect::<HashSet<_>>();
        self.config = config;
        self.fenced_nodes
            .retain(|node_id| !affected_ids.contains(node_id));
        self.idle_since
            .retain(|node_id, _| !affected_ids.contains(node_id));
        self.maintenance_scope = None;
        Ok(())
    }

    pub fn set_reset_barrier_context(
        &mut self,
        barrier_path: PathBuf,
        config_path: PathBuf,
        state_dir: PathBuf,
    ) {
        self.reset_barrier_context = Some((barrier_path, config_path, state_dir));
    }

    pub fn set_maintenance_barrier_context(
        &mut self,
        barrier_path: PathBuf,
        config_path: PathBuf,
        state_dir: PathBuf,
    ) {
        self.maintenance_barrier_context = Some((barrier_path, config_path, state_dir));
    }

    pub(crate) fn refresh_reset_barrier_policy(
        &mut self,
    ) -> Result<Option<ResetBarrierPolicy>, ControllerError> {
        let Some((barrier, config, state)) = self.reset_barrier_context.as_ref() else {
            self.reset_barrier_active = false;
            return Ok(None);
        };
        self.reset_barrier_active = barrier.exists();
        let policy = read_reset_barrier_policy(barrier, config, state)?;
        self.reset_barrier_active = policy.is_some();
        Ok(policy)
    }

    pub(crate) fn refresh_maintenance_barrier(&mut self) -> Result<bool, ControllerError> {
        let Some((barrier, config, state)) = self.maintenance_barrier_context.as_ref() else {
            self.maintenance_barrier_active = false;
            return Ok(false);
        };
        let active = read_maintenance_barrier(barrier, config, state)?;
        self.maintenance_barrier_active = active;
        Ok(active)
    }

    pub fn epoch(&self) -> ControllerEpoch {
        self.epoch
    }

    /// One bounded reconciliation and dispatch pass. `storage_ready` is
    /// independently probed by the caller and never blocks status RPCs.
    pub fn tick_with_storage_health(&mut self, storage_ready: bool) -> Result<(), ControllerError> {
        let reset_policy = self.refresh_reset_barrier_policy()?;
        self.refresh_maintenance_barrier()?;
        if storage_ready && !reset_policy.is_some_and(|policy| policy.discard_terminal_sync) {
            let pending: Vec<_> = self
                .storage
                .list_reconcile_jobs()?
                .into_iter()
                .filter(|job| job.snapshot_sync_pending)
                .collect();
            if let Some(job) = pending.first() {
                // NFS failures leave the local job accepted and pending. The
                // filesystem write runs in a killable child so it cannot hang
                // the controller's reconciliation loop.
                let _ = publish_snapshot_bounded(
                    self.storage.root(),
                    job.id,
                    &self.config.shared_root,
                    Duration::from_secs(10),
                );
            }
        }

        let mut availability = Vec::new();
        let now = now_ms();
        for (id, config) in &self.config.nodes {
            let node_id = NodeId::new(id.clone()).expect("validated config node ID");
            let transport_config = config;
            if !self.fenced_nodes.contains(id) {
                match self.transport.call(
                    &node_id,
                    transport_config,
                    Operation::Fence {
                        controller: self.epoch,
                    },
                ) {
                    Ok(ResponseBody::Ack) => {
                        self.fenced_nodes.insert(id.clone());
                    }
                    _ => {
                        self.idle_since.remove(id);
                        availability.push(NodeEligibility {
                            id: node_id,
                            idle_since_unix_ms: 0,
                            online: false,
                            storage_ready: false,
                            drain_requested: self.node_is_maintenance_scoped(id),
                            occupied: true,
                            interactive_pty: false,
                            namespaced_jobs: false,
                        });
                        continue;
                    }
                }
            }

            let status = self
                .transport
                .call(&node_id, transport_config, Operation::Status);
            let (online, occupied) = match status {
                Ok(ResponseBody::Execution(status)) => self.reconcile_status(&node_id, status)?,
                Err(TransportError::Remote(ProtocolError::NotFound)) => {
                    self.reconcile_missing_execution(&node_id)?
                }
                _ => (false, true),
            };
            let requires_health = transport_config.transport == Transport::Local
                || transport_config.machine_uuid.is_some()
                || transport_config.execution_uid.is_some()
                || !self.config.shares.is_empty();
            let health = self
                .transport
                .call(&node_id, transport_config, Operation::Health)
                .ok()
                .and_then(|response| match response {
                    ResponseBody::Health(health) => Some(health),
                    _ => None,
                });
            let interactive_pty = health.as_ref().is_some_and(|health| {
                health
                    .features
                    .iter()
                    .any(|feature| feature == INTERACTIVE_PTY_FEATURE)
            });
            let namespaced_jobs = health.as_ref().is_some_and(|health| {
                health
                    .features
                    .iter()
                    .any(|feature| feature == macluster_protocol::types::NAMESPACED_JOBS_FEATURE)
            });
            let node_storage_ready =
                if !requires_health {
                    true
                } else {
                    let expected_digest = self.config.execution_digest().unwrap_or_default();
                    health.as_ref().is_some_and(|health| {
                        health.execution_digest == expected_digest
                            && health.primary_share_ready
                            && self.config.shares.keys().all(|share_id| {
                                health.shares.get(share_id).copied().unwrap_or(false)
                            })
                    })
                };
            if online && !occupied {
                let idle_since = *self.idle_since.entry(id.clone()).or_insert(now);
                availability.push(NodeEligibility {
                    id: node_id,
                    idle_since_unix_ms: idle_since,
                    online,
                    storage_ready: storage_ready && node_storage_ready,
                    drain_requested: self.node_is_maintenance_scoped(id),
                    occupied,
                    interactive_pty,
                    namespaced_jobs,
                });
            } else {
                self.idle_since.remove(id);
                availability.push(NodeEligibility {
                    id: node_id,
                    idle_since_unix_ms: 0,
                    online,
                    storage_ready,
                    drain_requested: self.node_is_maintenance_scoped(id),
                    occupied,
                    interactive_pty,
                    namespaced_jobs,
                });
            }
        }

        self.deliver_cancellations()?;
        self.refresh_reset_barrier_policy()?;
        if !storage_ready || !self.dispatch_allowed() {
            return Ok(());
        }

        let mut jobs = self.storage.list_reconcile_jobs()?;
        for queue_name in self.config.queues.keys() {
            let queue_config = self
                .config
                .queue_for_dispatch(queue_name)
                .expect("queue came from validated config");
            let queue = macluster_protocol::identifiers::QueueName::new(queue_name.clone())
                .expect("validated config queue ID");
            let head = jobs
                .iter()
                .filter(|job| job.state == JobState::Pending && job.spec.queue == queue)
                .min_by_key(|job| job.id)
                .cloned();
            if let Some(head) = head {
                let waiting_reason = if let Some(pinned) = head
                    .spec
                    .node
                    .as_ref()
                    .filter(|node| self.config.is_login_node(node.as_str()))
                {
                    Some(format!(
                        "job is pinned to login node '{}', which is excluded from compute jobs; cancel it with mkill and resubmit on a compute node",
                        pinned
                    ))
                } else if let Some(reason) =
                    namespace_waiting_reason(&head, &queue_config, &availability)
                {
                    Some(reason)
                } else if head.spec.mode == JobMode::Interactive {
                    let has_compatible_node = availability.iter().any(|node| {
                        queue_config
                            .nodes
                            .iter()
                            .any(|member| member == node.id.as_str())
                            && node.online
                            && node.interactive_pty
                            && head
                                .spec
                                .node
                                .as_ref()
                                .is_none_or(|pinned| pinned == &node.id)
                    });
                    (!has_compatible_node).then(|| {
                        "waiting for an online node with interactive PTY support; cancel and resubmit with msub to trigger an Agent update if needed".to_owned()
                    })
                } else {
                    None
                };
                let updated = self.storage.set_waiting_reason(head.id, waiting_reason)?;
                if let Some(job) = jobs.iter_mut().find(|job| job.id == updated.id) {
                    *job = updated;
                }
            }
            loop {
                let Some(dispatch) = next_dispatch(&queue, &queue_config, &jobs, &availability)
                else {
                    break;
                };
                let reserved = match self
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
                        jobs = self.storage.list_reconcile_jobs()?;
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
                let token = reserved
                    .start_token
                    .expect("reservation generates stable start token");
                let Some(node_config) = self.config.nodes.get(dispatch.node_id.as_str()) else {
                    continue;
                };
                let operation = Operation::StartJob {
                    controller: self.epoch,
                    start_token: token,
                    job_id: reserved.id,
                    spec: reserved.spec.clone(),
                };
                // An ambiguous SSH failure retains STARTING and the same token.
                let _ = self
                    .transport
                    .call(&dispatch.node_id, node_config, operation);
            }
        }
        Ok(())
    }

    pub(crate) fn reconcile_status(
        &self,
        node_id: &NodeId,
        status: ExecutionStatus,
    ) -> Result<(bool, bool), ControllerError> {
        let Some(job) = self.storage.get_job(status.job_id)? else {
            // Unknown execution identity remains occupied until an operator reconciles it.
            return Ok((true, true));
        };
        if job.node.as_ref() != Some(node_id) || job.start_token != Some(status.start_token) {
            return Ok((true, true));
        }
        if job.waiting_reason.is_some() {
            self.storage.set_waiting_reason(job.id, None)?;
        }
        if let Some(terminal) = status.terminal_state {
            if !job.state.is_terminal() {
                self.storage.finish_job(
                    job.id,
                    terminal,
                    status.exit_code,
                    status.end_reason.clone(),
                )?;
            }
            if job.log_sync_pending != status.log_sync_pending {
                self.storage
                    .set_log_sync_pending(job.id, status.log_sync_pending)?;
            }
            // Keep the node reserved until terminal output has reached shared
            // storage. Otherwise another job can overwrite the agent's active
            // record while the previous runner is still publishing its logs.
            return Ok((true, status.log_sync_pending));
        }
        if job.state == JobState::Starting && status.phase == RuntimePhase::Running {
            self.storage.mark_running(job.id)?;
        }
        Ok((true, true))
    }

    fn reconcile_missing_execution(&self, node: &NodeId) -> Result<(bool, bool), ControllerError> {
        let Some(job) = self.storage.node_execution_to_reconcile(node)? else {
            return Ok((true, false));
        };
        let Some(token) = job.start_token else {
            return self.missing_execution(node, job.id, "controller has no execution token");
        };
        let config = self
            .config
            .nodes
            .get(node.as_str())
            .expect("validated node");
        match self.transport.call(
            node,
            config,
            Operation::RecoverJob {
                controller: self.epoch,
                start_token: token,
                job_id: job.id,
            },
        ) {
            Ok(ResponseBody::Execution(status)) => self.reconcile_status(node, status),
            Ok(_) => self.missing_execution(node, job.id, "unexpected recovery response"),
            Err(error) => self.missing_execution(node, job.id, &error.to_string()),
        }
    }

    fn missing_execution(
        &self,
        node: &NodeId,
        job_id: u64,
        detail: &str,
    ) -> Result<(bool, bool), ControllerError> {
        if self
            .storage
            .get_job(job_id)?
            .is_some_and(|job| job.node.as_ref() == Some(node))
        {
            self.storage.set_waiting_reason(job_id, Some(format!(
                "agent execution state for job {job_id} on {node} is missing; recovery receipt could not be verified ({detail}). Node remains reserved. After resolving this job, a new msub can trigger an Agent update if the node is outdated; if the receipt is also lost, inspect the node before manual recovery."
            )))?;
        }
        Ok((true, true))
    }

    fn deliver_cancellations(&self) -> Result<(), ControllerError> {
        for job in self.storage.list_jobs(Some(JobState::Cancelling))? {
            let (Some(node_id), Some(start_token)) = (job.node.as_ref(), job.start_token) else {
                continue;
            };
            if !self.fenced_nodes.contains(node_id.as_str()) {
                continue;
            }
            let Some(node_config) = self.config.nodes.get(node_id.as_str()) else {
                continue;
            };
            let _ = self.transport.call(
                node_id,
                node_config,
                Operation::CancelJob {
                    controller: self.epoch,
                    start_token,
                    job_id: job.id,
                    force: job.cancel_force,
                },
            );
        }
        Ok(())
    }

    pub fn run_forever(&mut self, interval_secs: u64) -> Result<(), ControllerError> {
        runtime::run_forever(self, Duration::from_secs(interval_secs.max(1)))
    }

    pub fn run_forever_with_idle_maintenance(
        &mut self,
        interval_secs: u64,
        requested: impl FnMut() -> bool,
        apply: impl FnMut(&mut Self) -> Result<bool, ControllerError>,
    ) -> Result<(), ControllerError> {
        runtime::run_forever_with_idle_maintenance(
            self,
            Duration::from_secs(interval_secs.max(1)),
            requested,
            apply,
        )
    }

    pub fn run_forever_with_shutdown(
        &mut self,
        interval_secs: u64,
        shutdown_requested: impl FnMut() -> bool,
        requested: impl FnMut() -> bool,
        apply: impl FnMut(&mut Self) -> Result<bool, ControllerError>,
    ) -> Result<(), ControllerError> {
        runtime::run_forever_with_shutdown(
            self,
            Duration::from_secs(interval_secs.max(1)),
            shutdown_requested,
            requested,
            apply,
        )
    }

    pub fn run_forever_with_control(
        &mut self,
        interval_secs: u64,
        listener: &mut ControlListener<'_>,
        hello: macluster_protocol::control::ControllerHello,
        config_path: PathBuf,
        maintenance: maintenance::MaintenanceCoordinator,
        shutdown_requested: impl FnMut() -> bool,
        requested: impl FnMut() -> bool,
        apply: impl FnMut(&mut Self) -> Result<bool, ControllerError>,
    ) -> Result<(), ControllerError> {
        runtime::run_forever_with_control(
            self,
            Duration::from_secs(interval_secs.max(1)),
            listener,
            hello,
            config_path,
            maintenance,
            shutdown_requested,
            requested,
            apply,
        )
    }

    pub fn apply_idle_address_config(
        &mut self,
        config: ClusterConfig,
    ) -> Result<(), ControllerError> {
        let jobs = self.storage.list_jobs(None)?;
        if jobs.iter().any(|job| {
            matches!(
                job.state,
                JobState::Starting | JobState::Running | JobState::Cancelling
            )
        }) {
            return Err(
                io::Error::other("cannot reload node addresses while tasks are active").into(),
            );
        }
        let mut expected = self.config.clone();
        for (node_id, node) in &mut expected.nodes {
            let Some(replacement) = config.nodes.get(node_id) else {
                return Err(io::Error::other("address reload cannot remove nodes").into());
            };
            node.host = replacement.host.clone();
            node.remote_binary = replacement.remote_binary.clone();
        }
        if expected != config {
            return Err(
                io::Error::other("idle address reload only permits node address changes").into(),
            );
        }
        self.config = config;
        self.fenced_nodes.clear();
        self.idle_since.clear();
        Ok(())
    }
}

fn namespace_waiting_reason(
    job: &macluster_protocol::types::JobRecord,
    queue: &macluster_core::config::QueueConfig,
    nodes: &[NodeEligibility],
) -> Option<String> {
    (job.spec.storage_namespace.is_some() && !nodes.iter().any(|node| {
        node.online && node.namespaced_jobs && queue.nodes.iter().any(|id| id == node.id.as_str())
            && job.spec.node.as_ref().is_none_or(|pinned| pinned == &node.id)
    })).then(|| "waiting for an online node that advertises namespaced job storage support; this job remains queued while nodes reconnect or are updated".into())
}

pub fn verify_shared_storage(config: &ClusterConfig) -> bool {
    let Some(server) = config.nodes.get(config.storage_server.as_str()) else {
        return false;
    };
    let Ok(executable) = std::env::current_exe() else {
        return false;
    };
    let mut command = Command::new(executable);
    command.args([
        "internal",
        "primary-share-check",
        "--root",
        &config.shared_root.to_string_lossy(),
        "--source-root",
        &config.primary_source_root().to_string_lossy(),
        "--uuid",
        &config.share_uuid,
        "--host",
        &server.host,
        "--local-server",
        if server.transport == Transport::Local {
            "yes"
        } else {
            "no"
        },
    ]);
    crate::transport::run_child_bounded(command, None, Duration::from_secs(6))
        .is_ok_and(|output| output.status.success())
}

pub fn publish_snapshot_bounded(
    state_dir: &Path,
    job_id: u64,
    shared_root: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = Command::new(executable);
    command
        .arg("--state-dir")
        .arg(state_dir)
        .args(["internal", "publish-snapshot", "--job-id"])
        .arg(job_id.to_string())
        .arg("--shared-root")
        .arg(shared_root);
    let output = run_child_bounded(command, None, timeout).map_err(|error| error.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(if detail.is_empty() {
            format!("snapshot publisher exited with {}", output.status)
        } else {
            detail
        })
    }
}

/// The direct filesystem probe is called only by the killable internal CLI
/// subprocess; the controller loop itself never touches a possibly stalled NFS mount.
pub fn verify_primary_share_direct(
    root: &Path,
    source_root: &Path,
    share_uuid: &str,
    server_host: &str,
    local_server: bool,
) -> bool {
    let marker_path = root.join(".macluster-share-id");
    let Ok(marker_metadata) = fs::symlink_metadata(&marker_path) else {
        return false;
    };
    if !marker_metadata.is_file() || marker_metadata.file_type().is_symlink() {
        return false;
    }
    let marker = match fs::read_to_string(marker_path) {
        Ok(value) => value,
        Err(_) => return false,
    };
    if marker.trim() != share_uuid {
        return false;
    }
    if local_server {
        #[cfg(target_vendor = "apple")]
        {
            use std::{ffi::CString, os::unix::ffi::OsStrExt};
            let Ok(path) = CString::new(root.as_os_str().as_bytes()) else {
                return false;
            };
            let mut info = std::mem::MaybeUninit::<libc::statfs>::zeroed();
            if unsafe { libc::statfs(path.as_ptr(), info.as_mut_ptr()) } != 0 {
                return false;
            }
            let info = unsafe { info.assume_init() };
            let filesystem = unsafe {
                std::ffi::CStr::from_ptr(info.f_fstypename.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            return filesystem != "nfs" && info.f_flags & (libc::MNT_LOCAL as u32) != 0;
        }
        #[cfg(not(target_vendor = "apple"))]
        return false;
    }
    let mounts = match Command::new("/sbin/mount").output() {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };
    let output = String::from_utf8_lossy(&mounts.stdout);
    primary_nfs_mount_matches(&output, server_host, source_root, root)
}

fn primary_nfs_mount_matches(
    mount_output: &str,
    server_host: &str,
    source_root: &Path,
    mount_root: &Path,
) -> bool {
    let expected = format!(
        "{server_host}:{} on {} (nfs",
        source_root.display(),
        mount_root.display()
    );
    mount_output.lines().any(|line| line.starts_with(&expected))
}

pub struct InstanceLock {
    file: fs::File,
    state_dir: PathBuf,
}
impl InstanceLock {
    pub fn acquire(state_dir: &Path) -> Result<Self, io::Error> {
        fs::create_dir_all(state_dir)?;
        let state_dir = state_dir.canonicalize()?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(state_dir.join("controller.lock"))?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { file, state_dir })
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}
impl Drop for InstanceLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod primary_share_tests {
    use super::primary_nfs_mount_matches;
    use std::path::Path;

    #[test]
    fn primary_mount_validation_accepts_distinct_source_and_mount_paths() {
        let output = "192.168.2.1:/Volumes/Storage/macluster on /Users/Shared/macluster (nfs, nodev, nosuid)\n";
        assert!(primary_nfs_mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!primary_nfs_mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Users/Shared/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!primary_nfs_mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/other"),
        ));
    }
}

#[cfg(test)]
mod status_reconciliation_tests {
    use super::*;
    use macluster_core::{config::ClusterConfig, storage::Storage};
    use macluster_protocol::{
        framing::sha256_hex,
        identifiers::{Id128, QueueName, RequestId},
        types::{JobSpec, SnapshotRef},
    };

    struct UnusedTransport;

    impl NodeTransport for UnusedTransport {
        fn call(
            &self,
            _node_id: &NodeId,
            _node: &macluster_core::config::NodeConfig,
            _operation: Operation,
        ) -> Result<ResponseBody, TransportError> {
            Err(TransportError::Io("unused test transport".into()))
        }
    }

    #[test]
    fn terminal_execution_with_pending_logs_keeps_node_occupied() {
        let root = std::env::temp_dir().join(format!(
            "macluster-controller-log-pending-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let shared = root.join("shared");
        fs::create_dir_all(&shared).unwrap();
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"mini01\"\nshared_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"worker\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"worker\"]\nscheduler = \"fifo\"\n\n[nodes.worker]\nhost = \"192.0.2.1\"\ntransport = \"ssh\"\n",
            shared.display()
        ))
        .unwrap();
        let storage = Storage::open(root.join("state")).unwrap();
        let bytes = b"#!/bin/bash\ntrue\n";
        let digest = sha256_hex(bytes).unwrap();
        let snapshot = storage.stage_snapshot(bytes).unwrap();
        assert_eq!(snapshot.sha256, digest);
        let job = storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: None,
                    name: "log-pending".into(),
                    cwd: shared.to_string_lossy().into_owned(),
                    stdout_path: shared
                        .join("jobs/%j/stdout.log")
                        .to_string_lossy()
                        .into_owned(),
                    stderr_path: shared
                        .join("jobs/%j/stderr.log")
                        .to_string_lossy()
                        .into_owned(),
                    walltime_secs: None,
                    env: Default::default(),
                    mode: JobMode::Batch,
                    snapshot: Some(SnapshotRef {
                        sha256: snapshot.sha256.clone(),
                        size_bytes: snapshot.size_bytes,
                    }),
                },
            )
            .unwrap();
        storage.publish_snapshot(job.id, &shared).unwrap();
        let reserved = storage
            .reserve_job(job.id, NodeId::new("worker").unwrap())
            .unwrap();
        storage.mark_running(job.id).unwrap();
        storage
            .finish_job(job.id, JobState::Completed, Some(0), None)
            .unwrap();
        storage.set_log_sync_pending(job.id, true).unwrap();
        let token = reserved.start_token.unwrap();
        let service = ControllerService::new(config, storage, UnusedTransport).unwrap();

        let availability = service
            .reconcile_status(
                &NodeId::new("worker").unwrap(),
                ExecutionStatus {
                    start_token: token,
                    job_id: job.id,
                    phase: RuntimePhase::Idle,
                    terminal_state: Some(JobState::Completed),
                    boot_id: "boot".into(),
                    runner_pid: None,
                    child_pid: None,
                    exit_code: Some(0),
                    end_reason: None,
                    log_sync_pending: true,
                },
            )
            .unwrap();

        assert_eq!(availability, (true, true));
        drop(service);
        let _ = fs::remove_dir_all(root);
    }
}

mod task_resources;
