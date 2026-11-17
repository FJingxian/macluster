//! Versioned control messages for the local CLI-to-controller IPC channel.

use serde::{Deserialize, Serialize};

use crate::{
    identifiers::{Id128, NodeId, QueueName, RequestId},
    types::{
        ControllerEpoch, FanControlStatus, FanPolicy, JobRecord, JobSpec, JobState, MetricSnapshot,
        SnapshotRef,
    },
};

pub const CONTROL_PROTOCOL_VERSION: u16 = 2;
pub const MAX_CONTROL_SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_CONTROL_JOB_PAGE: usize = 256;
pub const MAX_CONTROL_COMPATIBILITY_NODES: usize = 128;
pub const MAX_CONTROL_MONITOR_NODES: usize = 128;
pub const MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES: usize = 4096;
// ps already enumerates the full process table. Keep enough rows for tall
// terminals while bounding monitor frames and retained controller state.
pub const MAX_MONITOR_PROCESS_ROWS: usize = 1024;
pub const MULTI_ENTRY_CLIENT_FEATURE: &str = "multi-entry-client.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientDescriptor {
    pub cluster_uuid: String,
    pub cluster_name: String,
    pub default_queue: QueueName,
    pub config_generation: u64,
    pub controller_build_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub controller_binary: String,
    pub controller_uid: u32,
    pub capabilities: Vec<String>,
    pub primary_mount_root: String,
    pub primary_source_root: String,
    pub primary_source_host: String,
    pub shares: Vec<ClientShareDescriptor>,
    pub queues: Vec<ClientQueueDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientShareDescriptor {
    pub id: String,
    pub server: NodeId,
    #[serde(default = "default_storage_protocol")]
    pub protocol: String,
    pub source_root: String,
    pub server_host: String,
    pub mount_root: String,
    pub share_uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smb_user: Option<String>,
}

fn default_storage_protocol() -> String {
    "nfs".into()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientQueueDescriptor {
    pub name: QueueName,
    pub nodes: Vec<NodeId>,
}

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
    /// A cluster-wide barrier that keeps dispatch paused everywhere while
    /// allowing the drain check to defer node-status probes for endpoints
    /// already confirmed unreachable by the caller. Active jobs and pending
    /// state-changing operations still block maintenance.
    ClusterExceptUnreachable(Vec<NodeId>),
    Nodes(Vec<NodeId>),
    NamedShare(String),
    StorageProvider(NodeId),
}

impl MaintenanceScope {
    pub fn is_cluster_wide(&self) -> bool {
        matches!(self, Self::Cluster | Self::ClusterExceptUnreachable(_))
    }

    pub fn deferred_unreachable_nodes(&self) -> &[NodeId] {
        match self {
            Self::ClusterExceptUnreachable(nodes) => nodes,
            Self::Cluster | Self::Nodes(_) | Self::NamedShare(_) | Self::StorageProvider(_) => &[],
        }
    }
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
    SubscribeJobResources {
        job_id: u64,
    },
    JobResourceSnapshot {
        job_id: u64,
    },
    UnsubscribeJobResources,
    Status,
    ClientDescriptor,
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
    ReconcileNode {
        node_id: NodeId,
        job_id: u64,
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
    FanControl {
        node_id: Option<NodeId>,
        policy: Option<FanPolicy>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "payload", content = "value", rename_all = "snake_case")]
pub enum ControlPayload {
    JobResourcesSubscribed,
    JobResourceSnapshot(crate::resources::JobResourceSnapshot),
    Status(ControllerHello),
    ClientDescriptor(ClientDescriptor),
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
    FanControl(FanControlPayload),
    ReconciliationRequested { accepted: bool },
}

/// Fan-control response accepts the older vector-only wire shape while the
/// controller and CLI are on different builds. New controllers include the
/// hidden-node count in the detailed shape.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FanControlPayload {
    Detailed {
        nodes: Vec<NodeFanControlResult>,
        #[serde(default)]
        hidden_unreachable: usize,
    },
    Legacy(Vec<NodeFanControlResult>),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct NodeFanControlResult {
    pub node_id: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<FanControlStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    /// True only after the controller's three-probe offline threshold is met.
    #[serde(default)]
    pub confirmed_offline: bool,
    /// Recent Agent responsiveness, separate from host-level ping liveness.
    /// `Some(false)` means the host is reachable but its Agent has not
    /// answered; such a node is visible but is not dispatch-eligible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_responding: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_latency_ms: Option<u64>,
    #[serde(default)]
    pub consecutive_failures: u8,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
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

#[cfg(test)]
mod monitor_row_tests {
    use super::NodeMonitorRow;

    #[test]
    fn monitor_rows_from_older_controllers_keep_unknown_request_latency() {
        let row: NodeMonitorRow = serde_json::from_value(serde_json::json!({
            "node_id": "worker-a",
            "metrics": {
                "sampled_unix_ms": 1,
                "cpu_percent": null,
                "cpu_max_percent": null,
                "memory_total_bytes": null,
                "memory_used_bytes": null,
                "swap_used_bytes": null,
                "disk_read_bytes_per_sec": null,
                "disk_write_bytes_per_sec": null,
                "network_rx_bytes_per_sec": null,
                "network_tx_bytes_per_sec": null,
                "power_watts": null,
                "power_scope": null,
                "cpu_temp_celsius": null,
                "fan_speed_rpm": null,
                "stale": false,
                "errors": {}
            },
            "age_ms": 0,
            "stale": false,
            "running_tasks": 0,
            "waiting_tasks": 0
        }))
        .expect("older monitor row should remain readable");

        assert_eq!(row.request_latency_ms, None);
    }
}

#[cfg(test)]
mod maintenance_scope_tests {
    use super::MaintenanceScope;
    use crate::identifiers::NodeId;

    #[test]
    fn unreachable_node_exclusions_survive_serialization_as_cluster_scope() {
        let scope =
            MaintenanceScope::ClusterExceptUnreachable(vec![NodeId::new("default-003").unwrap()]);
        let encoded = serde_json::to_vec(&scope).unwrap();
        let decoded: MaintenanceScope = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, scope);
        assert!(decoded.is_cluster_wide());
        assert_eq!(
            decoded.deferred_unreachable_nodes(),
            &[NodeId::new("default-003").unwrap()]
        );
    }
}

#[cfg(test)]
mod client_descriptor_tests {
    use super::{ClientDescriptor, ControlPayload};

    #[test]
    fn legacy_control_payloads_deserialize_without_client_descriptor() {
        let payload: ControlPayload =
            serde_json::from_value(serde_json::json!({"payload": "monitor_acknowledged"})).unwrap();
        assert_eq!(payload, ControlPayload::MonitorAcknowledged);
    }

    #[test]
    fn client_descriptor_reports_generation_queues_and_share_paths() {
        let descriptor = ClientDescriptor {
            cluster_uuid: "f779bcf5-ea85-5caa-9579-74b395f3cce5".into(),
            cluster_name: "multi-entry".into(),
            default_queue: "compute".parse().unwrap(),
            config_generation: 17,
            controller_build_id: "macluster/test".into(),
            controller_binary: "/opt/homebrew/bin/macluster".into(),
            controller_uid: 501,
            capabilities: vec![super::MULTI_ENTRY_CLIENT_FEATURE.into()],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![super::ClientShareDescriptor {
                id: "tools".into(),
                server: "login".parse().unwrap(),
                protocol: "nfs".into(),
                source_root: "/opt/homebrew".into(),
                server_host: "192.0.2.1".into(),
                mount_root: "/opt/homebrew".into(),
                share_uuid: "82d02835-f6ab-52b4-aaab-f90cafde9981".into(),
                smb_user: None,
            }],
            queues: vec![super::ClientQueueDescriptor {
                name: "compute".parse().unwrap(),
                nodes: vec!["worker-a".parse().unwrap()],
            }],
        };

        let encoded = serde_json::to_value(&descriptor).unwrap();
        assert_eq!(encoded["config_generation"], 17);
        assert_eq!(encoded["queues"][0]["nodes"][0], "worker-a");
        assert_eq!(encoded["shares"][0]["mount_root"], "/opt/homebrew");
        assert_eq!(
            encoded["capabilities"][0],
            super::MULTI_ENTRY_CLIENT_FEATURE
        );
    }

    #[test]
    fn legacy_client_descriptor_defaults_a_missing_controller_binary() {
        let descriptor: ClientDescriptor = serde_json::from_value(serde_json::json!({
            "cluster_uuid": "f779bcf5-ea85-5caa-9579-74b395f3cce5",
            "cluster_name": "legacy",
            "default_queue": "compute",
            "config_generation": 1,
            "controller_build_id": "old",
            "controller_uid": 501,
            "capabilities": [],
            "primary_mount_root": "/Users/Shared/macluster",
            "primary_source_root": "/Users/Shared/macluster",
            "primary_source_host": "192.0.2.1",
            "shares": [],
            "queues": []
        }))
        .unwrap();

        assert!(descriptor.controller_binary.is_empty());
    }

    #[test]
    fn client_share_descriptor_round_trips_smb_user_and_accepts_legacy_json() {
        let descriptor = super::ClientShareDescriptor {
            id: "nas".into(),
            server: "nas-01".parse().unwrap(),
            protocol: "smb".into(),
            source_root: "/data".into(),
            server_host: "192.0.2.20".into(),
            mount_root: "/Users/Shared/nas-data".into(),
            share_uuid: "63f5531b-0e1d-56c5-bf98-90ef8f83df5f".into(),
            smb_user: Some("smb-user".into()),
        };
        let mut value = serde_json::to_value(&descriptor).unwrap();
        assert_eq!(value["smb_user"], "smb-user");

        value.as_object_mut().unwrap().remove("smb_user");
        let legacy: super::ClientShareDescriptor = serde_json::from_value(value).unwrap();
        assert_eq!(legacy.smb_user, None);
    }
}
