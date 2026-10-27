//! Versioned control messages for the local CLI-to-controller IPC channel.

use serde::{Deserialize, Serialize};

use crate::{
    identifiers::{Id128, NodeId, RequestId},
    types::{ControllerEpoch, JobRecord, JobSpec, JobState, MetricSnapshot, SnapshotRef},
};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_CONTROL_JOB_PAGE: usize = 256;
pub const MAX_CONTROL_COMPATIBILITY_NODES: usize = 128;
pub const MAX_CONTROL_MONITOR_NODES: usize = 128;
pub const MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES: usize = 4096;
pub const MAX_MONITOR_PROCESS_ROWS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    pub binding_digest: String,
    pub namespace: String,
    pub uid: u32,
    pub build_id: String,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerLifecycle {
    Ready,
    Paused,
    RecoveryPending,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", content = "nodes", rename_all = "snake_case")]
pub enum MaintenanceScope {
    Cluster,
    Nodes(Vec<NodeId>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    Draining,
    Ready,
    Applying,
    RecoveryRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceTicket {
    pub operation_id: Id128,
    pub token: Id128,
    pub generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceStatus {
    pub ticket: MaintenanceTicket,
    pub scope: MaintenanceScope,
    pub phase: MaintenancePhase,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControllerHello {
    pub protocol_version: u16,
    pub binding_digest: String,
    pub namespace: String,
    pub uid: u32,
    pub build_id: String,
    pub capabilities: Vec<String>,
    pub controller_epoch: ControllerEpoch,
    pub config_generation: u64,
    pub lifecycle: ControllerLifecycle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    WrongPeer,
    WrongCluster,
    IncompatibleProtocol,
    Busy,
    StaleGeneration,
    Maintenance,
    Unavailable,
    Conflict,
    InvalidRequest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlError {
    pub code: ControlErrorCode,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", content = "value", rename_all = "snake_case")]
pub enum HelloResponse {
    Accepted(ControllerHello),
    Rejected(ControlError),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlCommand {
    Status,
    BeginMaintenance {
        operation_id: Id128,
        scope: MaintenanceScope,
        journal_digest: String,
    },
    InspectMaintenance,
    CompleteMaintenance {
        ticket: MaintenanceTicket,
        candidate_config_digest: String,
        candidate_journal_digest: String,
    },
    AbortMaintenance {
        ticket: MaintenanceTicket,
    },
    QueryAgentCompatibility {
        node_ids: Vec<NodeId>,
    },
    PublishAgentCompatibility {
        entries: Vec<AgentCompatibilityUpdate>,
    },
    MonitorSnapshot {
        page: usize,
    },
    SubscribeMonitor {
        node_ids: Vec<NodeId>,
    },
    WatchProcesses {
        node_id: Option<NodeId>,
    },
    BeginSnapshot {
        upload_id: Id128,
        size_bytes: u64,
        sha256: String,
    },
    PutSnapshotChunk {
        upload_id: Id128,
        offset: u64,
        bytes: Vec<u8>,
    },
    FinishSnapshot {
        upload_id: Id128,
    },
    AbortSnapshot {
        upload_id: Id128,
    },
    Submit {
        request_id: RequestId,
        spec: JobSpec,
    },
    LookupRequest {
        request_id: RequestId,
    },
    LookupJob {
        job_id: u64,
    },
    QueryJobs {
        offset: usize,
        limit: usize,
        state: Option<JobState>,
        active_only: bool,
    },
    QueryQueues,
    CancelJob {
        job_id: u64,
        force: bool,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "payload", content = "value", rename_all = "snake_case")]
pub enum ControlPayload {
    Status(ControllerHello),
    Maintenance(Option<MaintenanceStatus>),
    AgentCompatibility(Vec<AgentCompatibilityRecord>),
    MonitorSnapshot(MonitorSnapshot),
    MonitorSubscribed,
    MonitorAcknowledged,
    SnapshotProgress { offset: u64 },
    SnapshotFinished(SnapshotRef),
    Submission(JobRecord),
    Lookup(Option<JobRecord>),
    Job(JobRecord),
    Jobs(JobPage),
    Queues(Vec<QueueSummary>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentCompatibilityState {
    Current,
    Mismatch,
    Unknown,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentCompatibilityUpdate {
    pub node_id: NodeId,
    pub state: AgentCompatibilityState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    #[serde(default)]
    pub age_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentCompatibilityRecord {
    pub node_id: NodeId,
    pub state: AgentCompatibilityState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MonitorSnapshot {
    pub sequence: u64,
    pub sampled_unix_ms: u64,
    pub generation: u64,
    pub page: usize,
    pub total_pages: usize,
    pub nodes: Vec<NodeMonitorRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NodeMonitorRow {
    pub node_id: NodeId,
    pub metrics: MetricSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_ms: Option<u64>,
    pub stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_error: Option<String>,
    pub running_tasks: u32,
    pub waiting_tasks: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<ProcessRow>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_age_ms: Option<u64>,
    #[serde(default)]
    pub process_stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ProcessRow {
    pub pid: u32,
    pub cpu_percent: f64,
    pub memory: String,
    pub cpu_time: String,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JobPage {
    pub jobs: Vec<JobRecord>,
    pub next_offset: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueSummary {
    pub name: String,
    pub nodes: Vec<String>,
    pub pending: u64,
    pub running: u64,
    pub completed: u64,
    pub failed: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ControlRequest {
    pub request_id: RequestId,
    #[serde(default)]
    pub expected_generation: Option<u64>,
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ControlResponse {
    pub request_id: RequestId,
    pub result: Result<ControlPayload, ControlError>,
}
