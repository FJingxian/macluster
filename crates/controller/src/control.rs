//! Serialized controller admission and query operations for local IPC clients.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use macluster_core::{
    config::ClusterConfig,
    storage::{Storage, SubmitError},
    submission::{AdmissionError, admit_submission},
};
use macluster_protocol::{
    control::{
        AgentCompatibilityRecord, AgentCompatibilityState, ControlCommand, ControlError,
        ControlErrorCode, ControlPayload, ControlRequest, ControllerHello, ControllerLifecycle,
        JobPage, MAX_CONTROL_COMPATIBILITY_NODES, MAX_CONTROL_JOB_PAGE, MAX_CONTROL_MONITOR_NODES,
        MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES, MAX_CONTROL_SNAPSHOT_CHUNK_BYTES, QueueSummary,
    },
    framing::{ChunkAssembler, MAX_SNAPSHOT_BYTES},
    identifiers::{Id128, NodeId},
    types::JobState,
};

use crate::compatibility::{
    CompatibilityCache, CompatibilityRefresher, CompatibilityState, CompatibilityView,
};
use crate::monitor::MonitorHub;

const MAX_ACTIVE_UPLOADS: usize = 4;
const SNAPSHOT_UPLOAD_TTL: Duration = Duration::from_secs(10 * 60);

struct SnapshotUpload {
    assembler: ChunkAssembler,
    expires_at: Instant,
}

/// Controller-owned API state. It processes all durable writes on the runtime
/// thread and drops unfinished uploads when the authenticated client disconnects.
pub struct ControlApi {
    config: ClusterConfig,
    storage: Storage,
    hello: ControllerHello,
    compatibility: Arc<CompatibilityCache>,
    compatibility_refresher: CompatibilityRefresher,
    monitor: MonitorHub,
    last_monitor_job_counts_at: Option<Instant>,
    uploads: HashMap<(Id128, Id128), SnapshotUpload>,
}

impl ControlApi {
    pub fn new(config: ClusterConfig, storage: Storage, hello: ControllerHello) -> Self {
        let compatibility = Arc::new(CompatibilityCache::new(hello.config_generation));
        let compatibility_refresher = CompatibilityRefresher::start(
            Arc::clone(&compatibility),
            config.clone(),
            hello.namespace.clone(),
        );
        let monitor = MonitorHub::new(config.clone(), hello.namespace.clone());
        Self {
            config,
            storage,
            hello,
            compatibility,
            compatibility_refresher,
            monitor,
            last_monitor_job_counts_at: None,
            uploads: HashMap::new(),
        }
    }

    pub fn set_lifecycle(&mut self, lifecycle: ControllerLifecycle) {
        self.hello.lifecycle = lifecycle;
    }

    pub fn handle(
        &mut self,
        client_session: Id128,
        request: ControlRequest,
    ) -> Result<ControlPayload, ControlError> {
        self.expire_uploads();
        self.monitor.expire(Instant::now());
        match request.command {
            ControlCommand::Status => Ok(ControlPayload::Status(self.hello.clone())),
            ControlCommand::QueryAgentCompatibility { node_ids } => {
                if node_ids.len() > MAX_CONTROL_COMPATIBILITY_NODES {
                    return Err(invalid_request("too many node compatibility entries"));
                }
                let now = Instant::now();
                for node_id in &node_ids {
                    let view =
                        self.compatibility
                            .view(node_id, self.hello.config_generation, None, now);
                    let age = self
                        .compatibility
                        .age(node_id, self.hello.config_generation, now);
                    if view == CompatibilityView::Stale || age.is_none() {
                        self.compatibility_refresher
                            .request(node_id, self.hello.config_generation);
                    }
                }
                let records = node_ids
                    .into_iter()
                    .map(|node_id| {
                        let view = self.compatibility.view(
                            &node_id,
                            self.hello.config_generation,
                            None,
                            now,
                        );
                        let state = match view {
                            CompatibilityView::Current => AgentCompatibilityState::Current,
                            CompatibilityView::Mismatch => AgentCompatibilityState::Mismatch,
                            CompatibilityView::Unknown => AgentCompatibilityState::Unknown,
                            CompatibilityView::Stale => AgentCompatibilityState::Stale,
                        };
                        let age_ms = self
                            .compatibility
                            .age(&node_id, self.hello.config_generation, now)
                            .map(|age| age.as_millis().min(u64::MAX as u128) as u64);
                        AgentCompatibilityRecord {
                            node_id,
                            state,
                            age_ms,
                        }
                    })
                    .collect();
                Ok(ControlPayload::AgentCompatibility(records))
            }
            ControlCommand::PublishAgentCompatibility { entries } => {
                if entries.len() > MAX_CONTROL_COMPATIBILITY_NODES {
                    return Err(invalid_request("too many node compatibility entries"));
                }
                let mut seen = HashSet::with_capacity(entries.len());
                let now = Instant::now();
                let mut updates = Vec::with_capacity(entries.len());
                for entry in entries {
                    if !seen.insert(entry.node_id.clone()) {
                        return Err(invalid_request("duplicate node compatibility entry"));
                    }
                    if !self.config.nodes.contains_key(entry.node_id.as_str()) {
                        return Err(invalid_request(format!(
                            "node '{}' is not in the active cluster config",
                            entry.node_id
                        )));
                    }
                    if Duration::from_millis(entry.age_ms) > crate::compatibility::COMPATIBILITY_TTL
                    {
                        return Err(invalid_request(
                            "compatibility observation is older than the 60 second cache limit",
                        ));
                    }
                    let state = match entry.state {
                        AgentCompatibilityState::Current => CompatibilityState::Current,
                        AgentCompatibilityState::Mismatch => CompatibilityState::Mismatch,
                        AgentCompatibilityState::Unknown => CompatibilityState::Unknown,
                        AgentCompatibilityState::Stale => {
                            return Err(invalid_request(
                                "stale compatibility is a cache view and cannot be published",
                            ));
                        }
                    };
                    updates.push((entry.node_id, state, entry.boot_id, entry.age_ms));
                }
                let mut records = Vec::with_capacity(updates.len());
                for (node_id, state, boot_id, age_ms) in updates {
                    if !self.compatibility.publish(
                        &node_id,
                        self.hello.config_generation,
                        state,
                        boot_id,
                        now.checked_sub(Duration::from_millis(age_ms))
                            .unwrap_or(now),
                    ) {
                        return Err(ControlError {
                            code: ControlErrorCode::StaleGeneration,
                            message: "compatibility result belongs to an old config generation"
                                .into(),
                        });
                    }
                    records.push(AgentCompatibilityRecord {
                        node_id,
                        state: match state {
                            CompatibilityState::Current => AgentCompatibilityState::Current,
                            CompatibilityState::Mismatch => AgentCompatibilityState::Mismatch,
                            CompatibilityState::Unknown => AgentCompatibilityState::Unknown,
                        },
                        age_ms: Some(age_ms),
                    });
                }
                Ok(ControlPayload::AgentCompatibility(records))
            }
            ControlCommand::MonitorSnapshot { page } => {
                let total_pages = self
                    .config
                    .nodes
                    .len()
                    .div_ceil(MAX_CONTROL_MONITOR_NODES)
                    .max(1);
                if page >= total_pages {
                    return Err(invalid_request("monitor snapshot page is out of range"));
                }
                let now = Instant::now();
                if self.last_monitor_job_counts_at.is_none_or(|sampled_at| {
                    now.saturating_duration_since(sampled_at) >= Duration::from_secs(1)
                }) {
                    self.refresh_monitor_job_counts()?;
                    self.last_monitor_job_counts_at = Some(now);
                }
                let snapshot = self
                    .monitor
                    .snapshot(self.hello.config_generation, page, now);
                Ok(ControlPayload::MonitorSnapshot(snapshot))
            }
            ControlCommand::SubscribeMonitor { node_ids } => {
                if node_ids.len() > MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES {
                    return Err(invalid_request("too many monitor subscription nodes"));
                }
                let mut seen = HashSet::with_capacity(node_ids.len());
                for node_id in &node_ids {
                    if !seen.insert(node_id.clone()) {
                        return Err(invalid_request("duplicate monitor subscription node"));
                    }
                    if !self.config.nodes.contains_key(node_id.as_str()) {
                        return Err(invalid_request(format!(
                            "node '{}' is not in the active cluster config",
                            node_id
                        )));
                    }
                }
                self.monitor
                    .subscribe(client_session, node_ids, Instant::now());
                Ok(ControlPayload::MonitorSubscribed)
            }
            ControlCommand::WatchProcesses { node_id } => {
                if node_id
                    .as_ref()
                    .is_some_and(|node_id| !self.config.nodes.contains_key(node_id.as_str()))
                {
                    return Err(invalid_request("process watch node is not configured"));
                }
                if !self
                    .monitor
                    .watch_processes(client_session, node_id, Instant::now())
                {
                    return Err(invalid_request(
                        "process watch requires an active monitor subscription for that node",
                    ));
                }
                Ok(ControlPayload::MonitorAcknowledged)
            }
            ControlCommand::BeginSnapshot {
                upload_id,
                size_bytes,
                sha256,
            } => {
                self.require_ready()?;
                if size_bytes > MAX_SNAPSHOT_BYTES {
                    return Err(invalid_request("script exceeds the 8 MiB limit"));
                }
                if self
                    .uploads
                    .keys()
                    .any(|(session, _)| *session == client_session)
                {
                    return Err(conflict(
                        "a snapshot upload is already active on this connection",
                    ));
                }
                if self.uploads.len() >= MAX_ACTIVE_UPLOADS {
                    return Err(ControlError {
                        code: ControlErrorCode::Busy,
                        message: "controller is handling the maximum number of script uploads"
                            .into(),
                    });
                }
                let assembler = ChunkAssembler::new(size_bytes, &sha256)
                    .map_err(|error| invalid_request(error.to_string()))?;
                self.uploads.insert(
                    (client_session, upload_id),
                    SnapshotUpload {
                        assembler,
                        expires_at: Instant::now() + SNAPSHOT_UPLOAD_TTL,
                    },
                );
                Ok(ControlPayload::SnapshotProgress { offset: 0 })
            }
            ControlCommand::PutSnapshotChunk {
                upload_id,
                offset,
                bytes,
            } => {
                self.require_ready()?;
                if bytes.len() > MAX_CONTROL_SNAPSHOT_CHUNK_BYTES {
                    return Err(invalid_request("script chunk exceeds 256 KiB"));
                }
                let upload = self
                    .uploads
                    .get_mut(&(client_session, upload_id))
                    .ok_or_else(|| invalid_request("script upload is absent or expired"))?;
                let offset = upload
                    .assembler
                    .push(offset, &bytes)
                    .map_err(|error| invalid_request(error.to_string()))?;
                upload.expires_at = Instant::now() + SNAPSHOT_UPLOAD_TTL;
                Ok(ControlPayload::SnapshotProgress { offset })
            }
            ControlCommand::FinishSnapshot { upload_id } => {
                self.require_ready()?;
                let upload = self
                    .uploads
                    .remove(&(client_session, upload_id))
                    .ok_or_else(|| invalid_request("script upload is absent or expired"))?;
                let bytes = upload
                    .assembler
                    .finish()
                    .map_err(|error| invalid_request(error.to_string()))?;
                let snapshot = self.storage.stage_snapshot(&bytes).map_err(storage_error)?;
                Ok(ControlPayload::SnapshotFinished(snapshot))
            }
            ControlCommand::AbortSnapshot { upload_id } => {
                self.uploads.remove(&(client_session, upload_id));
                Ok(ControlPayload::SnapshotProgress { offset: 0 })
            }
            ControlCommand::Submit { request_id, spec } => {
                self.require_ready()?;
                let record = admit_submission(&self.storage, &self.config, request_id, spec)
                    .map_err(admission_error)?;
                Ok(ControlPayload::Submission(record))
            }
            ControlCommand::LookupRequest { request_id } => self
                .storage
                .get_job_by_request_id(request_id)
                .map(ControlPayload::Lookup)
                .map_err(storage_error),
            ControlCommand::LookupJob { job_id } => self
                .storage
                .get_job(job_id)
                .map(|job| {
                    job.map(ControlPayload::Job)
                        .ok_or_else(|| invalid_request(format!("job {job_id} was not found")))
                })
                .map_err(storage_error)?,
            ControlCommand::QueryJobs {
                offset,
                limit,
                state,
                active_only,
            } => {
                if limit == 0 || limit > MAX_CONTROL_JOB_PAGE {
                    return Err(invalid_request(
                        "job query page size must be between 1 and 256",
                    ));
                }
                let jobs = if active_only {
                    self.storage
                        .list_active_jobs_page(offset, limit)
                        .map_err(storage_error)?
                } else {
                    self.storage
                        .list_jobs_page(state, offset, limit)
                        .map_err(storage_error)?
                };
                let next_offset =
                    (jobs.len() == limit).then_some(offset.saturating_add(jobs.len()));
                Ok(ControlPayload::Jobs(JobPage { jobs, next_offset }))
            }
            ControlCommand::QueryQueues => {
                let counts = self
                    .storage
                    .queue_job_counts()
                    .map_err(storage_error)?
                    .into_iter()
                    .map(|counts| (counts.queue.clone(), counts))
                    .collect::<HashMap<_, _>>();
                let queues = self
                    .config
                    .queues
                    .keys()
                    .map(|name| {
                        let counts = counts.get(name);
                        QueueSummary {
                            name: name.clone(),
                            nodes: self.config.queue_compute_nodes(name),
                            pending: counts.map_or(0, |counts| counts.pending),
                            running: counts.map_or(0, |counts| counts.running),
                            completed: counts.map_or(0, |counts| counts.completed),
                            failed: counts.map_or(0, |counts| counts.failed),
                        }
                    })
                    .collect();
                Ok(ControlPayload::Queues(queues))
            }
            ControlCommand::CancelJob { job_id, force } => self
                .storage
                .request_cancel(job_id, force)
                .map(ControlPayload::Job)
                .map_err(storage_error),
        }
    }

    pub fn disconnect(&mut self, client_session: Id128) {
        self.uploads
            .retain(|(session, _), _| *session != client_session);
        self.monitor.disconnect(client_session);
    }

    pub fn expire_monitor_subscriptions(&mut self, now: Instant) {
        self.monitor.expire(now);
    }

    fn require_ready(&self) -> Result<(), ControlError> {
        if self.hello.lifecycle == ControllerLifecycle::Ready {
            Ok(())
        } else {
            Err(ControlError {
                code: ControlErrorCode::Maintenance,
                message: format!(
                    "controller is {:?}; retry after recovery or maintenance completes",
                    self.hello.lifecycle
                ),
            })
        }
    }

    fn expire_uploads(&mut self) {
        let now = Instant::now();
        self.uploads.retain(|_, upload| upload.expires_at > now);
    }

    fn refresh_monitor_job_counts(&mut self) -> Result<(), ControlError> {
        let jobs = self.storage.list_monitor_jobs().map_err(storage_error)?;
        let mut counts = self
            .config
            .nodes
            .keys()
            .filter_map(|id| NodeId::new(id.clone()).ok())
            .map(|node_id| (node_id, (0_u32, 0_u32)))
            .collect::<std::collections::HashMap<_, _>>();
        for job in jobs {
            match job.state {
                JobState::Starting | JobState::Running | JobState::Cancelling => {
                    if let Some(target) = job.node.as_ref()
                        && let Ok(node_id) = NodeId::new(target.to_string())
                        && let Some((running, _)) = counts.get_mut(&node_id)
                    {
                        *running = running.saturating_add(1);
                    }
                }
                JobState::Pending => {
                    let targets = job.spec.node.as_ref().map_or_else(
                        || self.config.queue_compute_nodes(job.spec.queue.as_str()),
                        |node| vec![node.to_string()],
                    );
                    for target in targets {
                        if let Ok(node_id) = NodeId::new(target)
                            && let Some((_, waiting)) = counts.get_mut(&node_id)
                        {
                            *waiting = waiting.saturating_add(1);
                        }
                    }
                }
                _ => {}
            }
        }
        self.monitor.update_job_counts(counts);
        Ok(())
    }
}

fn invalid_request(message: impl Into<String>) -> ControlError {
    ControlError {
        code: ControlErrorCode::InvalidRequest,
        message: message.into(),
    }
}

fn conflict(message: impl Into<String>) -> ControlError {
    ControlError {
        code: ControlErrorCode::Conflict,
        message: message.into(),
    }
}

fn admission_error(error: AdmissionError) -> ControlError {
    let code = match &error {
        AdmissionError::Storage(SubmitError::RequestConflict) => ControlErrorCode::Conflict,
        AdmissionError::Storage(_) => ControlErrorCode::Unavailable,
        AdmissionError::StorageNamespace
        | AdmissionError::UnknownQueue(_)
        | AdmissionError::LoginNode(_)
        | AdmissionError::NodeNotInQueue { .. }
        | AdmissionError::InvalidSharedPath { .. } => ControlErrorCode::InvalidRequest,
    };
    ControlError {
        code,
        message: error.to_string(),
    }
}

fn storage_error(error: SubmitError) -> ControlError {
    let code = match &error {
        SubmitError::RequestConflict => ControlErrorCode::Conflict,
        SubmitError::NotFound(_) => ControlErrorCode::InvalidRequest,
        SubmitError::SnapshotTooLarge
        | SubmitError::SnapshotMismatch
        | SubmitError::MissingSnapshot
        | SubmitError::InvalidPageSize => ControlErrorCode::InvalidRequest,
        _ => ControlErrorCode::Unavailable,
    };
    ControlError {
        code,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use macluster_core::{config::ClusterConfig, storage::Storage};
    use macluster_protocol::{
        control::{
            AgentCompatibilityState, AgentCompatibilityUpdate, ControlRequest, ControllerLifecycle,
        },
        identifiers::{ControllerUuid, Id128, NodeId, RequestId},
        types::ControllerEpoch,
    };

    use super::{ControlApi, ControlCommand, ControlErrorCode, ControlPayload};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("macluster-compat-api-{}", Id128::random()));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn config(&self) -> ClusterConfig {
            ClusterConfig::parse(&format!(
                "[cluster]\nname=\"compat\"\ndefault_queue=\"q\"\nlogin_node=\"login\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n",
                self.0.display(),
                unsafe { libc::geteuid() }
            ))
            .unwrap()
        }

        fn api(&self) -> ControlApi {
            let config = self.config();
            let storage = Storage::open(self.0.join("state")).unwrap();
            let hello = macluster_protocol::control::ControllerHello {
                protocol_version: macluster_protocol::control::CONTROL_PROTOCOL_VERSION,
                binding_digest: "b".repeat(64),
                namespace: config.share_uuid.clone(),
                uid: unsafe { libc::geteuid() },
                build_id: "test".into(),
                capabilities: vec!["agent.compatibility.v1".into(), "monitor.v1".into()],
                controller_epoch: ControllerEpoch {
                    controller_uuid: ControllerUuid::random(),
                    epoch: 1,
                },
                config_generation: 12,
                lifecycle: ControllerLifecycle::Ready,
            };
            ControlApi::new(config, storage, hello)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(command: ControlCommand) -> ControlRequest {
        ControlRequest {
            request_id: RequestId(Id128::random()),
            expected_generation: Some(12),
            command,
        }
    }

    #[test]
    fn compatibility_is_shared_with_freshness_and_unknown_is_not_current() {
        let fixture = Fixture::new();
        let mut api = fixture.api();
        let node_id: NodeId = "login".parse().unwrap();
        api.handle(
            Id128::random(),
            request(ControlCommand::PublishAgentCompatibility {
                entries: vec![AgentCompatibilityUpdate {
                    node_id: node_id.clone(),
                    state: AgentCompatibilityState::Mismatch,
                    boot_id: Some("boot-1".into()),
                    age_ms: 0,
                }],
            }),
        )
        .unwrap();
        let response = api
            .handle(
                Id128::random(),
                request(ControlCommand::QueryAgentCompatibility {
                    node_ids: vec![node_id.clone()],
                }),
            )
            .unwrap();
        let ControlPayload::AgentCompatibility(records) = response else {
            panic!("unexpected control response")
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_id, node_id);
        assert_eq!(records[0].state, AgentCompatibilityState::Mismatch);
        assert_eq!(records[0].age_ms, Some(0));

        let missing: NodeId = "unconfigured".parse().unwrap();
        let response = api
            .handle(
                Id128::random(),
                request(ControlCommand::QueryAgentCompatibility {
                    node_ids: vec![missing],
                }),
            )
            .unwrap();
        let ControlPayload::AgentCompatibility(records) = response else {
            panic!("unexpected control response")
        };
        assert_eq!(records[0].state, AgentCompatibilityState::Unknown);
    }

    #[test]
    fn invalid_compatibility_batch_does_not_partially_update_the_cache() {
        let fixture = Fixture::new();
        let mut api = fixture.api();
        let error = api
            .handle(
                Id128::random(),
                request(ControlCommand::PublishAgentCompatibility {
                    entries: vec![
                        AgentCompatibilityUpdate {
                            node_id: "login".parse().unwrap(),
                            state: AgentCompatibilityState::Mismatch,
                            boot_id: None,
                            age_ms: 0,
                        },
                        AgentCompatibilityUpdate {
                            node_id: "unconfigured".parse().unwrap(),
                            state: AgentCompatibilityState::Current,
                            boot_id: None,
                            age_ms: 0,
                        },
                    ],
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::InvalidRequest);

        let response = api
            .handle(
                Id128::random(),
                request(ControlCommand::QueryAgentCompatibility {
                    node_ids: vec!["login".parse().unwrap()],
                }),
            )
            .unwrap();
        let ControlPayload::AgentCompatibility(records) = response else {
            panic!("unexpected control response")
        };
        assert_eq!(records[0].state, AgentCompatibilityState::Unknown);
    }

    #[test]
    fn stale_compatibility_cannot_be_published_as_an_observation() {
        let fixture = Fixture::new();
        let mut api = fixture.api();
        let error = api
            .handle(
                Id128::random(),
                request(ControlCommand::PublishAgentCompatibility {
                    entries: vec![AgentCompatibilityUpdate {
                        node_id: "login".parse().unwrap(),
                        state: AgentCompatibilityState::Stale,
                        boot_id: None,
                        age_ms: 60_001,
                    }],
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::InvalidRequest);
    }

    #[test]
    fn monitor_subscription_and_details_are_bound_to_ipc_session() {
        let fixture = Fixture::new();
        let mut api = fixture.api();
        let session = Id128::random();
        let login: NodeId = "login".parse().unwrap();

        assert!(matches!(
            api.handle(
                session,
                request(ControlCommand::SubscribeMonitor {
                    node_ids: vec![login.clone()],
                }),
            )
            .unwrap(),
            ControlPayload::MonitorSubscribed
        ));
        assert!(matches!(
            api.handle(
                session,
                request(ControlCommand::WatchProcesses {
                    node_id: Some(login.clone()),
                }),
            )
            .unwrap(),
            ControlPayload::MonitorAcknowledged
        ));
        let snapshot = api
            .handle(
                session,
                request(ControlCommand::MonitorSnapshot { page: 0 }),
            )
            .unwrap();
        let ControlPayload::MonitorSnapshot(snapshot) = snapshot else {
            panic!("unexpected control response")
        };
        assert_eq!(snapshot.total_pages, 1);
        assert!(snapshot.nodes.iter().all(|row| row.node_id == login));

        api.disconnect(session);
        let error = api
            .handle(
                session,
                request(ControlCommand::WatchProcesses {
                    node_id: Some(login),
                }),
            )
            .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::InvalidRequest);
    }

    #[test]
    fn monitor_counts_unpinned_pending_tasks_on_every_node_in_their_queue() {
        use std::collections::BTreeMap;

        use macluster_protocol::{
            identifiers::QueueName,
            types::{JobMode, JobSpec},
        };

        let fixture = Fixture::new();
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname=\"monitor-counts\"\ndefault_queue=\"q\"\nlogin_node=\"login\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker-a\",\"worker-b\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker-a]\nhost=\"192.0.2.50\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\nssh_user=\"worker\"\n[nodes.worker-b]\nhost=\"192.0.2.51\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\nssh_user=\"worker\"\n",
            fixture.0.display(),
            unsafe { libc::geteuid() }
        ))
        .unwrap();
        let storage = Storage::open(fixture.0.join("state")).unwrap();
        storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: Some(Id128::parse(&config.share_uuid).unwrap()),
                    queue: QueueName::new("q").unwrap(),
                    node: None,
                    name: "pending".into(),
                    cwd: fixture.0.display().to_string(),
                    stdout_path: fixture.0.join("out.log").display().to_string(),
                    stderr_path: fixture.0.join("err.log").display().to_string(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Interactive,
                    snapshot: None,
                },
            )
            .unwrap();
        let hello = macluster_protocol::control::ControllerHello {
            protocol_version: macluster_protocol::control::CONTROL_PROTOCOL_VERSION,
            binding_digest: "b".repeat(64),
            namespace: config.share_uuid.clone(),
            uid: unsafe { libc::geteuid() },
            build_id: "test".into(),
            capabilities: vec!["monitor.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 12,
            lifecycle: ControllerLifecycle::Ready,
        };
        let mut api = ControlApi::new(config, storage, hello);
        let response = api
            .handle(
                Id128::random(),
                request(ControlCommand::MonitorSnapshot { page: 0 }),
            )
            .unwrap();
        let ControlPayload::MonitorSnapshot(snapshot) = response else {
            panic!("unexpected control response")
        };
        let counts = snapshot
            .nodes
            .into_iter()
            .map(|row| (row.node_id.to_string(), row.waiting_tasks))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(counts["worker-a"], 1);
        assert_eq!(counts["worker-b"], 1);
        assert_eq!(counts["login"], 0);
    }
}
