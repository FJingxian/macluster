use std::{
    collections::HashSet,
    process::Command,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread,
    time::Duration,
};

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::{identifiers::NodeId, types::MetricSnapshot};

use crate::{
    ssh::{ConnectionKey, SshPool},
    transport::run_child_bounded,
};

const MAX_WORKERS: usize = 4;
const METRIC_TIMEOUT: Duration = Duration::from_secs(8);

struct MetricTask {
    node_id: NodeId,
    node: NodeConfig,
}

pub(super) struct MetricResult {
    pub(super) node_id: NodeId,
    pub(super) result: Result<MetricSnapshot, String>,
    pub(super) completed_at: std::time::Instant,
}

pub(super) struct MetricSampler {
    sender: SyncSender<MetricTask>,
    receiver: Receiver<MetricResult>,
    in_flight: HashSet<NodeId>,
}

impl MetricSampler {
    pub fn new(sample: Arc<super::MetricSampleFn>) -> Self {
        let (sender, tasks) = mpsc::sync_channel::<MetricTask>(MAX_WORKERS);
        let tasks = Arc::new(Mutex::new(tasks));
        let (results, receiver) = mpsc::channel();
        for index in 0..MAX_WORKERS {
            let tasks = Arc::clone(&tasks);
            let results = results.clone();
            let sample = Arc::clone(&sample);
            let _ = thread::Builder::new()
                .name(format!("monitor-metrics-{index}"))
                .spawn(move || {
                    loop {
                        let task = match tasks.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(task) = task else { return };
                        let result = sample(&task.node_id, &task.node);
                        if results
                            .send(MetricResult {
                                node_id: task.node_id,
                                result,
                                completed_at: std::time::Instant::now(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                });
        }
        drop(results);
        Self {
            sender,
            receiver,
            in_flight: HashSet::new(),
        }
    }

    pub fn request(&mut self, node_id: NodeId, node: NodeConfig) -> bool {
        if self.in_flight.len() >= MAX_WORKERS || self.in_flight.contains(&node_id) {
            return false;
        }
        match self.sender.try_send(MetricTask {
            node_id: node_id.clone(),
            node,
        }) {
            Ok(()) => {
                self.in_flight.insert(node_id);
                true
            }
            Err(mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn poll(&mut self) -> Vec<MetricResult> {
        let mut completed = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(result) => {
                    self.in_flight.remove(&result.node_id);
                    completed.push(result);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        completed
    }
}

pub(super) fn sample_node(
    node_id: &NodeId,
    node: &NodeConfig,
    pool: &SshPool,
) -> Result<MetricSnapshot, String> {
    if node.transport == Transport::Local {
        return Ok(macluster_metrics::sample_local());
    }
    let mut command = Command::new("/usr/bin/ssh");
    command.args([
        "-T",
        "-oLogLevel=ERROR",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=4",
        "-oConnectionAttempts=1",
    ]);
    node.add_ssh_identity_args(&mut command);
    if let Ok(key) = ConnectionKey::for_node(pool.namespace(), node_id.as_str(), node) {
        let _ = pool.append_args(&key, &mut command);
    }
    command.arg(&node.host).arg(&node.remote_binary);
    node.add_remote_config_args(&mut command);
    command.args(["internal", "metrics", "--json"]);
    let output = run_child_bounded(command, None, METRIC_TIMEOUT)
        .map_err(|error| format!("metric request failed: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if detail.is_empty() {
            format!("remote metric command exited with {}", output.status)
        } else {
            detail
        });
    }
    decode_remote_metrics(&output.stdout)
}

fn decode_remote_metrics(output: &[u8]) -> Result<MetricSnapshot, String> {
    let value: serde_json::Value = serde_json::from_slice(output)
        .map_err(|error| format!("remote metric response was invalid JSON: {error}"))?;
    let has_fan_speed_field = value.get("fan_speed_rpm").is_some();
    let mut snapshot: MetricSnapshot = serde_json::from_value(value)
        .map_err(|error| format!("remote metric response was invalid JSON: {error}"))?;
    if !has_fan_speed_field {
        snapshot.errors.entry("fan_speed".into()).or_insert_with(|| {
            "remote Agent predates fan-speed telemetry; update the Agent before fan RPM can be shown".into()
        });
    }
    Ok(snapshot)
}
