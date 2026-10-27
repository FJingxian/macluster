//! Versioned control messages for the local CLI-to-controller IPC channel.

use serde::{Deserialize, Serialize};

use crate::{
    identifiers::{Id128, RequestId},
    types::{ControllerEpoch, JobRecord, JobSpec, JobState, SnapshotRef},
};

pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_CONTROL_JOB_PAGE: usize = 256;

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
    SnapshotProgress { offset: u64 },
    SnapshotFinished(SnapshotRef),
    Submission(JobRecord),
    Lookup(Option<JobRecord>),
    Job(JobRecord),
    Jobs(JobPage),
    Queues(Vec<QueueSummary>),
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
