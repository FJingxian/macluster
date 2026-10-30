use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identifiers::{ControllerUuid, Id128, NodeId, QueueName, RequestId, StartToken};

pub const PROTOCOL_VERSION: u16 = 1;
pub const INTERACTIVE_PTY_FEATURE: &str = "agent.interactive-pty.v1";
pub const METRICS_FAN_SPEED_FEATURE: &str = "metrics.fan-speed.v1";
/// Internal JobSpec environment marker: keep the submitted PATH authoritative
/// instead of adding Agent-registered tool directories ahead of it.
pub const EXPLICIT_TASK_PATH_ENV: &str = "MCLUSTER_INTERNAL_EXPLICIT_PATH";
/// Internal JobSpec marker enabling optional per-task resource and output logs.
pub const VERBOSE_TASK_LOG_ENV: &str = "MCLUSTER_INTERNAL_VERBOSE_LOG";
/// Visible shared root for the sidecar logs produced by verbose submissions.
pub const VERBOSE_TASK_LOG_ROOT_ENV: &str = "MCLUSTER_INTERNAL_VERBOSE_LOG_ROOT";
/// Sidecar names reserved inside each verbose task's shared job directory.
pub const VERBOSE_TASK_LOG_FILES: &[&str] = &["monitor.log", "resources.jsonl", "summary.json"];
/// Internal JobSpec value used to scope a node-local Cargo target cache.
pub const ACTIVE_ENV_PREFIX_ENV: &str = "MCLUSTER_INTERNAL_ACTIVE_ENV_PREFIX";
pub const NAMESPACED_JOBS_FEATURE: &str = "agent.namespaced-jobs.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobState {
    Pending,
    Starting,
    Running,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
    Timeout,
    NodeLost,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Timeout | Self::NodeLost
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimePhase {
    Idle,
    Reserved,
    Launching,
    Running,
    Cancelling,
    Cleaning,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeConnectionState {
    Online,
    Unreachable,
    Reconciling,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StorageHealth {
    Ready,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchedulerKind {
    Fifo,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotRef {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobMode {
    #[default]
    Batch,
    Interactive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_namespace: Option<Id128>,
    pub queue: QueueName,
    pub node: Option<NodeId>,
    pub name: String,
    pub cwd: String,
    pub stdout_path: String,
    pub stderr_path: String,
    pub walltime_secs: Option<u64>,
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub mode: JobMode,
    #[serde(default)]
    pub snapshot: Option<SnapshotRef>,
}

impl JobSpec {
    /// Protect task metadata from user-selected stdout/stderr destinations.
    /// Check numeric IDs and the submission template before an ID is allocated.
    pub fn verbose_log_output_conflicts(
        &self,
        shared_root: &std::path::Path,
        output: &std::path::Path,
    ) -> bool {
        if self.env.get(VERBOSE_TASK_LOG_ENV).map(String::as_str) != Some("1") {
            return false;
        }
        let mut jobs = shared_root.join("jobs");
        if let Some(namespace) = self.storage_namespace {
            jobs.push(namespace.to_string());
        }
        let absolute;
        let output = if output.is_absolute() {
            output
        } else {
            absolute = shared_root.join(output);
            &absolute
        };
        // Reserve case variants too: typical macOS volumes are case-insensitive,
        // and canonicalize() does not normalize the spelling of every component.
        let mut parts = output.components();
        for expected in jobs.components() {
            let Some(actual) = parts.next() else {
                // An output file cannot replace a required metadata directory.
                return true;
            };
            if !actual
                .as_os_str()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(expected.as_os_str().as_encoded_bytes())
            {
                return false;
            }
        }
        let Some(job_part) = parts.next() else {
            return true;
        };
        let Some(job) = job_part.as_os_str().to_str() else {
            return false;
        };
        if job != "%j" && job.parse::<u64>().is_err() {
            return false;
        }
        match parts.next() {
            None => true,
            Some(part) => part.as_os_str().to_str().is_some_and(|name| {
                VERBOSE_TASK_LOG_FILES
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
            }),
        }
    }

    /// Check a concrete job directory after resolving filesystem aliases.
    pub fn verbose_log_output_conflicts_in(
        &self,
        directory: &std::path::Path,
        output: &std::path::Path,
    ) -> bool {
        if self.env.get(VERBOSE_TASK_LOG_ENV).map(String::as_str) != Some("1") {
            return false;
        }
        let mut parts = output.components();
        for expected in directory.components() {
            let Some(actual) = parts.next() else {
                return true;
            };
            if !actual
                .as_os_str()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(expected.as_os_str().as_encoded_bytes())
            {
                return false;
            }
        }
        match parts.next() {
            None => true,
            Some(part) => part.as_os_str().to_str().is_some_and(|name| {
                VERBOSE_TASK_LOG_FILES
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
            }),
        }
    }

    pub fn shared_job_dir(&self, shared_root: &std::path::Path, job_id: u64) -> std::path::PathBuf {
        let root = shared_root.join("jobs");
        let root = match self.storage_namespace {
            Some(namespace) => root.join(namespace.to_string()),
            None => root,
        };
        root.join(job_id.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JobRecord {
    pub id: u64,
    pub spec: JobSpec,
    pub state: JobState,
    pub node: Option<NodeId>,
    #[serde(default)]
    pub start_token: Option<StartToken>,
    #[serde(default)]
    pub cancel_force: bool,
    pub created_unix_ms: u64,
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub end_reason: Option<String>,
    pub snapshot_sync_pending: bool,
    pub log_sync_pending: bool,
    pub waiting_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeRecord {
    pub id: NodeId,
    pub host: String,
    pub machine_fingerprint: Option<String>,
    pub runtime_phase: RuntimePhase,
    pub drain_requested: bool,
    pub connection: NodeConnectionState,
    pub storage: StorageHealth,
    pub online_logical_cpus: Option<u32>,
    pub architecture: Option<String>,
    pub capabilities: Vec<String>,
    pub active_job: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueRecord {
    pub name: QueueName,
    pub nodes: Vec<NodeId>,
    pub scheduler: SchedulerKind,
}

/// Maximum age accepted for a cached power sample exposed by the power helper.
pub const POWER_SAMPLE_CACHE_TTL_MS: u64 = 60_000;

/// Read-only per-fan values copied from the platform sensor sampler. This is
/// telemetry only; it does not imply that the fan can be safely controlled.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FanReading {
    pub name: String,
    pub rpm: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_rpm: Option<u32>,
}

/// Capacity information for a locally mounted filesystem.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiskCapacity {
    pub mount_point: String,
    pub used_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetricSnapshot {
    pub sampled_unix_ms: u64,
    pub cpu_percent: Option<f64>,
    pub cpu_max_percent: Option<f64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_used_bytes: Option<u64>,
    pub swap_used_bytes: Option<u64>,
    pub disk_read_bytes_per_sec: Option<f64>,
    pub disk_write_bytes_per_sec: Option<f64>,
    pub network_rx_bytes_per_sec: Option<f64>,
    pub network_tx_bytes_per_sec: Option<f64>,
    pub power_watts: Option<f64>,
    pub power_scope: Option<String>,
    #[serde(default)]
    pub cpu_temp_celsius: Option<f64>,
    // Serialize `null` when no sensor exists. Older Agents omit this field;
    // mtop uses that distinction to explain that an Agent update is needed.
    #[serde(default)]
    pub fan_speed_rpm: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fan_readings: Option<Vec<FanReading>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_disk_capacity: Option<DiskCapacity>,
    #[serde(default)]
    pub external_disk_capacities: Vec<DiskCapacity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_window_ms: Option<u32>,
    pub stale: bool,
    pub errors: BTreeMap<String, String>,
}

#[cfg(test)]
mod metric_snapshot_tests {
    use super::{DiskCapacity, MetricSnapshot};

    #[test]
    fn metric_snapshot_round_trips_cpu_temperature() {
        let value = serde_json::json!({
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
            "cpu_temp_celsius": 42.5,
            "stale": false,
            "errors": {}
        });

        let snapshot: MetricSnapshot = serde_json::from_value(value).unwrap();
        let encoded = serde_json::to_value(snapshot).unwrap();

        assert_eq!(encoded["cpu_temp_celsius"], 42.5);
    }

    #[test]
    fn metric_snapshot_round_trips_average_fan_speed() {
        let mut value = serde_json::json!({
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
            "fan_speed_rpm": 1375.5,
            "stale": false,
            "errors": {}
        });

        let snapshot: MetricSnapshot = serde_json::from_value(value.clone()).unwrap();
        value = serde_json::to_value(snapshot).unwrap();

        assert_eq!(value["fan_speed_rpm"], 1375.5);
    }

    #[test]
    fn metric_snapshot_round_trips_gpu_utilization_and_source_age() {
        let value = serde_json::json!({
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
            "gpu_percent": 73.5,
            "gpu_source": "macmon",
            "gpu_age_ms": 5,
            "gpu_window_ms": 100,
            "stale": false,
            "errors": {}
        });

        let snapshot: MetricSnapshot = serde_json::from_value(value).unwrap();
        let encoded = serde_json::to_value(snapshot).unwrap();

        assert_eq!(encoded["gpu_percent"], 73.5);
        assert_eq!(encoded["gpu_source"], "macmon");
        assert_eq!(encoded["gpu_age_ms"], 5);
        assert_eq!(encoded["gpu_window_ms"], 100);
    }

    #[test]
    fn metric_snapshot_accepts_legacy_json_without_gpu_fields() {
        let legacy = serde_json::json!({
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
            "stale": false,
            "errors": {}
        });

        let snapshot: MetricSnapshot = serde_json::from_value(legacy).unwrap();

        assert_eq!(snapshot.gpu_percent, None);
        assert_eq!(snapshot.gpu_source, None);
        assert_eq!(snapshot.gpu_age_ms, None);
        assert_eq!(snapshot.gpu_window_ms, None);
        assert_eq!(snapshot.system_disk_capacity, None);
        assert!(snapshot.external_disk_capacities.is_empty());
    }

    #[test]
    fn metric_snapshot_round_trips_system_and_external_disk_capacities() {
        let snapshot = MetricSnapshot {
            sampled_unix_ms: 1,
            cpu_percent: None,
            cpu_max_percent: None,
            memory_total_bytes: None,
            memory_used_bytes: None,
            swap_used_bytes: None,
            disk_read_bytes_per_sec: None,
            disk_write_bytes_per_sec: None,
            network_rx_bytes_per_sec: None,
            network_tx_bytes_per_sec: None,
            power_watts: None,
            power_scope: None,
            cpu_temp_celsius: None,
            fan_speed_rpm: None,
            fan_readings: None,
            power_age_ms: None,
            system_disk_capacity: Some(DiskCapacity {
                mount_point: "/".into(),
                used_bytes: 1,
                total_bytes: 2,
            }),
            external_disk_capacities: vec![DiskCapacity {
                mount_point: "/Volumes/data".into(),
                used_bytes: 3,
                total_bytes: 4,
            }],
            gpu_percent: None,
            gpu_source: None,
            gpu_age_ms: None,
            gpu_window_ms: None,
            stale: false,
            errors: Default::default(),
        };

        let encoded = serde_json::to_value(&snapshot).unwrap();
        let decoded: MetricSnapshot = serde_json::from_value(encoded).unwrap();

        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn metric_snapshot_accepts_legacy_json_without_power_age() {
        let legacy = serde_json::json!({
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
            "stale": false,
            "errors": {}
        });

        let snapshot: MetricSnapshot = serde_json::from_value(legacy).unwrap();

        assert_eq!(snapshot.cpu_temp_celsius, None);
        assert_eq!(snapshot.power_age_ms, None);
        let encoded = serde_json::to_value(snapshot).unwrap();
        assert!(encoded.get("power_age_ms").is_none());
        assert_eq!(
            encoded.get("cpu_temp_celsius"),
            Some(&serde_json::Value::Null)
        );
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeHealth {
    pub machine_uuid: String,
    pub execution_uid: u32,
    pub execution_digest: String,
    pub primary_share_ready: bool,
    pub shares: BTreeMap<String, bool>,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControllerEpoch {
    pub controller_uuid: ControllerUuid,
    pub epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StartResult {
    pub start_token: StartToken,
    pub accepted: bool,
    pub runner_pid: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionStatus {
    pub start_token: StartToken,
    pub job_id: u64,
    pub phase: RuntimePhase,
    #[serde(default)]
    pub terminal_state: Option<JobState>,
    pub boot_id: String,
    pub runner_pid: Option<u32>,
    pub child_pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub end_reason: Option<String>,
    #[serde(default)]
    pub log_sync_pending: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogCursor {
    pub job_id: u64,
    pub stream_id: String,
    pub offset: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogChunk {
    pub stream_id: String,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub eof: bool,
    pub source: String,
    pub stale: bool,
}

/// Fan policy selected for one node. `System` yields fans to macOS; `Auto`
/// and `Power` run temperature curves in the privileged node helper.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FanPolicy {
    System,
    Auto,
    Power,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FanControlStatus {
    pub policy: FanPolicy,
    pub supported: bool,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub average_temperature_deci_celsius: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_rpm: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum FanHelperCommand {
    Status,
    Set { policy: FanPolicy },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FanHelperResponse {
    pub status: FanControlStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Request {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub operation: Operation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum Operation {
    TaskResources {
        controller: ControllerEpoch,
        start_token: StartToken,
        job_id: u64,
    },
    Ping,
    Status,
    RecoverJob {
        controller: ControllerEpoch,
        start_token: StartToken,
        job_id: u64,
    },
    Health,
    Fence {
        controller: ControllerEpoch,
    },
    StartJob {
        controller: ControllerEpoch,
        start_token: StartToken,
        job_id: u64,
        spec: JobSpec,
    },
    CancelJob {
        controller: ControllerEpoch,
        start_token: StartToken,
        job_id: u64,
        force: bool,
    },
    QueryFanPolicy,
    SetFanPolicy {
        policy: FanPolicy,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Response {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub result: Result<ResponseBody, ProtocolError>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ResponseBody {
    TaskResources(crate::resources::TaskResourceSample),
    Pong,
    Health(NodeHealth),
    Started(StartResult),
    Execution(ExecutionStatus),
    FanControl(FanControlStatus),
    Ack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, thiserror::Error)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("protocol version is incompatible")]
    IncompatibleVersion,
    #[error("request conflicts with existing state")]
    Conflict,
    #[error("node is busy")]
    Busy,
    #[error("resource was not found")]
    NotFound,
    #[error("operation is not permitted")]
    NotPermitted,
    #[error("storage is unavailable")]
    StorageUnavailable,
    #[error("request failed: {0}")]
    Failed(String),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConfigRevision(pub u64);

#[cfg(test)]
mod interactive_job_compatibility_tests {
    use super::{JobSpec, NodeHealth};
    use serde_json::json;

    #[test]
    fn job_spec_without_mode_deserializes_as_batch() {
        let legacy = json!({
            "queue": "mini01",
            "node": null,
            "name": "legacy",
            "cwd": "/share/projects",
            "stdout_path": "/share/jobs/%j/stdout.log",
            "stderr_path": "/share/jobs/%j/stderr.log",
            "walltime_secs": null,
            "env": {},
            "snapshot": { "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size_bytes": 1 }
        });

        let decoded: JobSpec = serde_json::from_value(legacy).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();

        assert_eq!(encoded["mode"], "batch");
        assert_eq!(encoded["snapshot"]["size_bytes"], 1);
    }

    #[test]
    fn old_node_health_without_features_deserializes_with_empty_features() {
        let legacy = json!({
            "machine_uuid": "old-agent",
            "execution_uid": 501,
            "execution_digest": "digest",
            "primary_share_ready": true,
            "shares": {}
        });

        let decoded: NodeHealth = serde_json::from_value(legacy).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();

        assert_eq!(encoded["features"], json!([]));
    }
}
