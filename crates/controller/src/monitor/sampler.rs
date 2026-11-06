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
    initial: bool,
}

pub(super) struct MetricResult {
    pub(super) node_id: NodeId,
    pub(super) result: Result<MetricSnapshot, String>,
    pub(super) completed_at: std::time::Instant,
    pub(super) request_latency_ms: u64,
    pub(super) final_result: bool,
}

pub(super) struct MetricSampler {
    sender: SyncSender<MetricTask>,
    receiver: Receiver<MetricResult>,
    in_flight: HashSet<NodeId>,
}

impl MetricSampler {
    pub fn new(
        sample: Arc<super::MetricSampleFn>,
        initial_sample: Arc<super::InitialMetricSampleFn>,
    ) -> Self {
        let (sender, tasks) = mpsc::sync_channel::<MetricTask>(MAX_WORKERS);
        let tasks = Arc::new(Mutex::new(tasks));
        let (results, receiver) = mpsc::channel();
        for index in 0..MAX_WORKERS {
            let tasks = Arc::clone(&tasks);
            let results = results.clone();
            let sample = Arc::clone(&sample);
            let initial_sample = Arc::clone(&initial_sample);
            let _ = thread::Builder::new()
                .name(format!("monitor-metrics-{index}"))
                .spawn(move || {
                    loop {
                        let task = match tasks.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(task) = task else { return };
                        let started_at = std::time::Instant::now();
                        let first = if task.initial {
                            initial_sample(&task.node_id, &task.node)
                        } else {
                            sample(&task.node_id, &task.node).map(|snapshot| (snapshot, false))
                        };
                        let completed_at = std::time::Instant::now();
                        match first {
                            Ok((snapshot, needs_full_sample)) => {
                                let progressive = task.initial && needs_full_sample;
                                if results
                                    .send(MetricResult {
                                        node_id: task.node_id.clone(),
                                        result: Ok(snapshot),
                                        completed_at,
                                        request_latency_ms: duration_ms(
                                            completed_at.saturating_duration_since(started_at),
                                        ),
                                        final_result: !progressive,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                                if progressive {
                                    let full_started_at = std::time::Instant::now();
                                    let full = sample(&task.node_id, &task.node);
                                    let full_completed_at = std::time::Instant::now();
                                    if results
                                        .send(MetricResult {
                                            node_id: task.node_id,
                                            result: full,
                                            completed_at: full_completed_at,
                                            request_latency_ms: duration_ms(
                                                full_completed_at
                                                    .saturating_duration_since(full_started_at),
                                            ),
                                            final_result: true,
                                        })
                                        .is_err()
                                    {
                                        return;
                                    }
                                }
                            }
                            Err(error) => {
                                if results
                                    .send(MetricResult {
                                        node_id: task.node_id,
                                        result: Err(error),
                                        completed_at,
                                        request_latency_ms: duration_ms(
                                            completed_at.saturating_duration_since(started_at),
                                        ),
                                        final_result: true,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
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
        self.request_with_phase(node_id, node, false)
    }

    pub fn request_initial(&mut self, node_id: NodeId, node: NodeConfig) -> bool {
        self.request_with_phase(node_id, node, true)
    }

    fn request_with_phase(&mut self, node_id: NodeId, node: NodeConfig, initial: bool) -> bool {
        if self.in_flight.len() >= MAX_WORKERS || self.in_flight.contains(&node_id) {
            return false;
        }
        match self.sender.try_send(MetricTask {
            node_id: node_id.clone(),
            node,
            initial,
        }) {
            Ok(()) => {
                self.in_flight.insert(node_id);
                true
            }
            Err(mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn has_capacity(&self) -> bool {
        self.in_flight.len() < MAX_WORKERS
    }

    pub fn poll(&mut self) -> Vec<MetricResult> {
        let mut completed = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(result) => {
                    if result.final_result {
                        self.in_flight.remove(&result.node_id);
                    }
                    completed.push(result);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        completed
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

pub(super) fn sample_node(
    node_id: &NodeId,
    node: &NodeConfig,
    pool: &SshPool,
    initial: bool,
) -> Result<(MetricSnapshot, bool), String> {
    sample_node_phase(node_id, node, pool, initial)
}

fn sample_node_phase(
    node_id: &NodeId,
    node: &NodeConfig,
    pool: &SshPool,
    initial: bool,
) -> Result<(MetricSnapshot, bool), String> {
    if node.transport == Transport::Local {
        return Ok((
            if initial {
                macluster_metrics::sample_local_fast()
            } else {
                macluster_metrics::sample_local()
            },
            initial,
        ));
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
    if initial {
        command.arg("--fast");
    }
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
    if initial {
        decode_remote_initial_metrics(&output.stdout)
    } else {
        decode_remote_metrics(&output.stdout).map(|snapshot| (snapshot, false))
    }
}

fn decode_remote_initial_metrics(output: &[u8]) -> Result<(MetricSnapshot, bool), String> {
    let value: serde_json::Value = serde_json::from_slice(output)
        .map_err(|error| format!("remote metric response was invalid JSON: {error}"))?;
    let progressive = value
        .get("sample_phase")
        .and_then(serde_json::Value::as_str)
        == Some("initial");
    let snapshot_value = if progressive {
        value
            .get("snapshot")
            .cloned()
            .ok_or_else(|| "remote initial metric response did not include a snapshot".to_owned())?
    } else {
        value
    };
    let has_fan_speed_field = snapshot_value.get("fan_speed_rpm").is_some();
    let mut snapshot: MetricSnapshot = serde_json::from_value(snapshot_value)
        .map_err(|error| format!("remote metric response was invalid JSON: {error}"))?;
    if !has_fan_speed_field {
        snapshot.errors.entry("fan_speed".into()).or_insert_with(|| {
            "remote Agent predates fan-speed telemetry; update the Agent before fan RPM can be shown".into()
        });
    }
    Ok((snapshot, progressive))
}

fn decode_remote_metrics(output: &[u8]) -> Result<MetricSnapshot, String> {
    decode_remote_initial_metrics(output).map(|(snapshot, _)| snapshot)
}

#[cfg(test)]
mod tests {
    use super::{MAX_WORKERS, MetricSampler, decode_remote_initial_metrics};
    use crate::monitor::{InitialMetricSampleFn, MetricSampleFn};
    use macluster_core::config::{NodeConfig, Transport};
    use macluster_protocol::identifiers::NodeId;
    use std::sync::{Arc, mpsc};

    fn node() -> NodeConfig {
        NodeConfig {
            host: "127.0.0.1".into(),
            transport: Transport::Local,
            remote_binary: "macluster".into(),
            ssh_user: None,
            ssh_port: None,
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: None,
            execution_uid: None,
        }
    }

    #[test]
    fn capacity_closes_at_the_bounded_worker_limit_and_returns_after_poll() {
        let (release, wait) = mpsc::channel::<()>();
        let wait = Arc::new(std::sync::Mutex::new(wait));
        let sample: Arc<MetricSampleFn> = Arc::new(move |_, _| {
            wait.lock().unwrap().recv().unwrap();
            Ok(macluster_metrics::unavailable(0, "test"))
        });
        let initial_sample: Arc<InitialMetricSampleFn> =
            Arc::new(|_, _| Ok((macluster_metrics::unavailable(0, "test"), false)));
        let mut sampler = MetricSampler::new(sample, initial_sample);
        assert!(sampler.has_capacity());

        for index in 0..MAX_WORKERS {
            assert!(sampler.request(NodeId::new(format!("node-{index}")).unwrap(), node()));
        }
        assert!(!sampler.has_capacity());

        for _ in 0..MAX_WORKERS {
            release.send(()).unwrap();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !sampler.has_capacity() && std::time::Instant::now() < deadline {
            let _ = sampler.poll();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(sampler.has_capacity());
    }

    #[test]
    fn initial_sample_is_published_before_full_sample_and_keeps_node_in_flight() {
        let (release, wait) = mpsc::channel::<()>();
        let wait = Arc::new(std::sync::Mutex::new(wait));
        let sample: Arc<MetricSampleFn> = Arc::new(move |_, _| {
            wait.lock().unwrap().recv().unwrap();
            Ok(macluster_metrics::unavailable(2, "full sample"))
        });
        let initial_sample: Arc<InitialMetricSampleFn> =
            Arc::new(|_, _| Ok((macluster_metrics::unavailable(1, "fast sample"), true)));
        let mut sampler = MetricSampler::new(sample, initial_sample);
        let node_id = NodeId::new("node-fast-initial").unwrap();

        assert!(sampler.request_initial(node_id.clone(), node()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let first = loop {
            if let Some(result) = sampler.poll().into_iter().next() {
                break Some(result);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        let Some(first) = first else {
            release.send(()).unwrap();
            panic!("fast initial sample was not published");
        };

        assert_eq!(first.result.unwrap().sampled_unix_ms, 1);
        assert!(!first.final_result);
        assert!(!sampler.request(node_id.clone(), node()));

        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let final_result = loop {
            if let Some(result) = sampler.poll().into_iter().next() {
                break Some(result);
            }
            if std::time::Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };

        let Some(final_result) = final_result else {
            panic!("full sample was not published");
        };
        assert_eq!(final_result.result.unwrap().sampled_unix_ms, 2);
        assert!(final_result.final_result);
        assert!(sampler.request(node_id, node()));
    }

    #[test]
    fn remote_initial_wrapper_is_decoded_as_progressive_but_legacy_payload_is_final() {
        let snapshot = macluster_metrics::unavailable(123, "fast sample");
        let initial = serde_json::to_vec(&serde_json::json!({
            "sample_phase": "initial",
            "snapshot": snapshot,
        }))
        .unwrap();
        let (decoded, progressive) = decode_remote_initial_metrics(&initial).unwrap();
        assert_eq!(decoded.sampled_unix_ms, 123);
        assert!(progressive);

        let legacy = serde_json::to_vec(&macluster_metrics::unavailable(456, "legacy")).unwrap();
        let (decoded, progressive) = decode_remote_initial_metrics(&legacy).unwrap();
        assert_eq!(decoded.sampled_unix_ms, 456);
        assert!(!progressive);
    }
}
