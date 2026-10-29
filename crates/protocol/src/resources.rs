//! Task process-group observations, distinct from whole-node metrics.
use crate::{
    identifiers::{NodeId, StartToken},
    types::JobState,
};
use serde::{Deserialize, Serialize};

pub const TASK_RESOURCE_INTERVAL_MS: u64 = 5_000;
pub const TASK_RESOURCE_FEATURE: &str = "task.resources.v1";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TaskResourceSample {
    pub schema_version: u8,
    pub observed_unix_ms: u64,
    #[serde(default)]
    pub age_ms: u64,
    #[serde(default)]
    pub interval_ms: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub rss_bytes: Option<u64>,
    pub cpu_time_seconds: f64,
    pub memory_time_gib_seconds: f64,
    pub memory_peak_sampled_bytes: u64,
    pub process_count: usize,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub coverage: String,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct JobResourceSnapshot {
    pub schema_version: u8,
    pub job_id: u64,
    pub node_id: Option<NodeId>,
    pub start_token: Option<StartToken>,
    pub state: JobState,
    pub sample: Option<TaskResourceSample>,
    pub age_ms: Option<u64>,
    pub stale: bool,
    pub error: Option<String>,
}
