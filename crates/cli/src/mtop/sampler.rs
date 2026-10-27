use std::{
    collections::HashSet,
    process::{self, Child},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::types::MetricSnapshot;

const MAX_WORKERS: usize = 4;
const REMOTE_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Debug)]
pub enum SampleTarget {
    Local,
    Node {
        node_id: String,
        namespace: String,
        node: NodeConfig,
    },
}

impl SampleTarget {
    pub fn for_node(node_id: &str, namespace: &str, node: &NodeConfig) -> Self {
        match node.transport {
            Transport::Local => Self::Local,
            Transport::Ssh => Self::Node {
                node_id: node_id.to_owned(),
                namespace: namespace.to_owned(),
                node: node.clone(),
            },
        }
    }
}

#[derive(Debug)]
pub struct SampleResult {
    pub id: String,
    pub started_at: Instant,
    pub received_at: Instant,
    pub result: Result<MetricSnapshot, String>,
    pub final_result: bool,
}

struct SampleTask {
    id: String,
    target: SampleTarget,
    started_at: Instant,
    initial: bool,
}

type SampleFn = dyn Fn(&SampleTarget, &AtomicBool) -> Result<MetricSnapshot, String> + Send + Sync;

pub struct MetricSampler {
    task_sender: Sender<SampleTask>,
    result_receiver: Receiver<SampleResult>,
    inflight: HashSet<String>,
    worker_limit: usize,
    stop: Arc<AtomicBool>,
}

impl MetricSampler {
    pub fn new(worker_limit: usize) -> Self {
        Self::with_sample_fn(worker_limit, Arc::new(sample_target))
    }

    fn with_sample_fn(worker_limit: usize, sample: Arc<SampleFn>) -> Self {
        let worker_limit = worker_limit.clamp(1, MAX_WORKERS);
        let (task_sender, task_receiver) = mpsc::channel::<SampleTask>();
        let (result_sender, result_receiver) = mpsc::channel::<SampleResult>();
        let task_receiver = Arc::new(Mutex::new(task_receiver));
        let stop = Arc::new(AtomicBool::new(false));
        for _ in 0..worker_limit {
            let tasks = Arc::clone(&task_receiver);
            let results = result_sender.clone();
            let sample = Arc::clone(&sample);
            let worker_stop = Arc::clone(&stop);
            thread::spawn(move || worker_loop(tasks, results, sample, worker_stop));
        }
        drop(result_sender);
        Self {
            task_sender,
            result_receiver,
            inflight: HashSet::new(),
            worker_limit,
            stop,
        }
    }

    pub fn has_capacity(&self) -> bool {
        self.inflight.len() < self.worker_limit
    }

    pub fn in_flight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Submit one node request. In-flight node IDs are deduplicated, and the
    /// bounded queue never contains more work than there are workers.
    pub fn request(&mut self, id: impl Into<String>, target: SampleTarget) -> bool {
        self.request_with_phase(id, target, false)
    }

    pub fn request_initial(&mut self, id: impl Into<String>, target: SampleTarget) -> bool {
        self.request_with_phase(id, target, true)
    }

    fn request_with_phase(
        &mut self,
        id: impl Into<String>,
        target: SampleTarget,
        initial: bool,
    ) -> bool {
        let id = id.into();
        if !self.has_capacity() || self.inflight.contains(&id) {
            return false;
        }
        let task = SampleTask {
            id: id.clone(),
            target,
            started_at: Instant::now(),
            initial,
        };
        if self.task_sender.send(task).is_err() {
            return false;
        }
        self.inflight.insert(id);
        true
    }

    pub fn poll(&mut self) -> Vec<SampleResult> {
        let mut completed = Vec::new();
        loop {
            match self.result_receiver.try_recv() {
                Ok(result) => {
                    if result.final_result {
                        self.inflight.remove(&result.id);
                    }
                    completed.push(result);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        completed
    }
}

impl Drop for MetricSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn worker_loop(
    tasks: Arc<Mutex<Receiver<SampleTask>>>,
    results: Sender<SampleResult>,
    sample: Arc<SampleFn>,
    stop: Arc<AtomicBool>,
) {
    loop {
        let task = match tasks.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => return,
        };
        let Ok(task) = task else { return };
        if task.initial {
            if let Ok((snapshot, progressive)) = sample_initial_target(&task.target, &stop) {
                let _ = results.send(SampleResult {
                    id: task.id.clone(),
                    started_at: task.started_at,
                    received_at: Instant::now(),
                    result: Ok(snapshot),
                    final_result: !progressive,
                });
                if !progressive {
                    continue;
                }
            }
        }
        let result = sample(&task.target, &stop);
        let _ = results.send(SampleResult {
            id: task.id,
            started_at: task.started_at,
            received_at: Instant::now(),
            result,
            final_result: true,
        });
    }
}

fn sample_initial_target(
    target: &SampleTarget,
    stop: &AtomicBool,
) -> Result<(MetricSnapshot, bool), String> {
    if stop.load(Ordering::SeqCst) {
        return Err("metric sample cancelled".into());
    }
    match target {
        SampleTarget::Local => Ok((macluster_metrics::sample_local_fast(), true)),
        SampleTarget::Node {
            node_id,
            namespace,
            node,
        } => sample_remote_phase(node_id, namespace, node, stop, true),
    }
}

fn sample_target(target: &SampleTarget, stop: &AtomicBool) -> Result<MetricSnapshot, String> {
    if stop.load(Ordering::SeqCst) {
        return Err("metric sample cancelled".into());
    }
    match target {
        SampleTarget::Local => Ok(macluster_metrics::sample_local()),
        SampleTarget::Node {
            node_id,
            namespace,
            node,
        } => sample_remote(node_id, namespace, node, stop),
    }
}

fn sample_remote(
    node_id: &str,
    namespace: &str,
    node: &NodeConfig,
    stop: &AtomicBool,
) -> Result<MetricSnapshot, String> {
    sample_remote_phase(node_id, namespace, node, stop, false).map(|(snapshot, _)| snapshot)
}

fn sample_remote_phase(
    node_id: &str,
    namespace: &str,
    node: &NodeConfig,
    stop: &AtomicBool,
    initial: bool,
) -> Result<(MetricSnapshot, bool), String> {
    let mut command = process::Command::new("/usr/bin/ssh");
    command.args([
        "-T",
        "-oLogLevel=ERROR",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=4",
        "-oConnectionAttempts=1",
    ]);
    node.add_ssh_identity_args(&mut command);
    super::ssh::add_control_args(namespace, node_id, node, &mut command);
    command.arg(&node.host).arg(&node.remote_binary);
    node.add_remote_config_args(&mut command);
    command.arg("internal").arg("metrics").arg("--json");
    if initial {
        command.arg("--fast");
    }
    let mut child = command
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not start ssh: {error}"))?;
    match wait_child(&mut child, REMOTE_TIMEOUT, Some(stop))? {
        ChildWait::Exited => {}
        ChildWait::Timeout => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("metric request timed out after 8s".into());
        }
        ChildWait::Cancelled => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("metric request cancelled".into());
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not read ssh result: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if detail.is_empty() {
            format!("ssh exited with {}", output.status)
        } else {
            detail
        });
    }
    let (mut snapshot, progressive) = if initial {
        decode_remote_initial_metrics(&output.stdout)?
    } else {
        (decode_remote_metrics(&output.stdout)?, false)
    };
    if let Some(reason) = snapshot.errors.get_mut("power")
        && reason == "no supported non-interactive power sampler was found"
    {
        *reason = "remote agent predates power sampling; rerun mnode -a for this node to update it"
            .into();
    }
    Ok((snapshot, progressive))
}

fn decode_remote_initial_metrics(output: &[u8]) -> Result<(MetricSnapshot, bool), String> {
    let value: serde_json::Value = serde_json::from_slice(output)
        .map_err(|error| format!("remote initial metric response was invalid JSON: {error}"))?;
    if value
        .get("sample_phase")
        .and_then(serde_json::Value::as_str)
        == Some("initial")
    {
        let snapshot = serde_json::from_value(value.get("snapshot").cloned().ok_or_else(|| {
            "remote initial metric response did not include a snapshot".to_owned()
        })?)
        .map_err(|error| format!("remote initial metric response was invalid JSON: {error}"))?;
        Ok((snapshot, true))
    } else {
        Ok((decode_remote_metrics(output)?, false))
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWait {
    Exited,
    Timeout,
    Cancelled,
}

fn wait_child(
    child: &mut Child,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> Result<ChildWait, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(ChildWait::Exited);
        }
        if cancel.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return Ok(ChildWait::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(ChildWait::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    use super::{ChildWait, MetricSampler, SampleTarget, decode_remote_metrics, wait_child};
    use macluster_metrics::unavailable;
    use std::process::{Command, Stdio};

    fn collect(sampler: &mut MetricSampler, expected: usize) -> Vec<super::SampleResult> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut results = Vec::new();
        while results.len() < expected && Instant::now() < deadline {
            results.extend(sampler.poll());
            thread::sleep(Duration::from_millis(5));
        }
        results
    }

    #[test]
    fn remote_metric_compatibility_distinguishes_old_agents_from_fanless_nodes() {
        let old_payload = serde_json::to_value(unavailable(1, "fixture")).unwrap();
        let mut old_payload = old_payload;
        old_payload.as_object_mut().unwrap().remove("fan_speed_rpm");
        let old = decode_remote_metrics(&serde_json::to_vec(&old_payload).unwrap()).unwrap();
        assert!(old.errors["fan_speed"].contains("predates fan-speed telemetry"));

        let new_payload = serde_json::to_vec(&unavailable(1, "fixture")).unwrap();
        let new = decode_remote_metrics(&new_payload).unwrap();
        assert!(!new.errors.contains_key("fan_speed"));
        assert_eq!(new.fan_speed_rpm, None);
    }

    #[test]
    fn worker_limit_is_four_and_node_failures_are_isolated() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let sampler_active = Arc::clone(&active);
        let sampler_peak = Arc::clone(&peak);
        let mut sampler = MetricSampler::with_sample_fn(
            40,
            Arc::new(move |target, _cancel| {
                let now = sampler_active.fetch_add(1, Ordering::SeqCst) + 1;
                sampler_peak.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(35));
                sampler_active.fetch_sub(1, Ordering::SeqCst);
                let SampleTarget::Node { node, .. } = target else {
                    unreachable!()
                };
                if node.host == "fail" {
                    Err("unreachable".into())
                } else {
                    Ok(unavailable(1, "fixture"))
                }
            }),
        );
        let node = |host: &str| SampleTarget::Node {
            node_id: host.into(),
            namespace: "test".into(),
            node: macluster_core::config::NodeConfig {
                host: host.into(),
                transport: macluster_core::config::Transport::Ssh,
                remote_binary: "macluster".into(),
                ssh_user: None,
                ssh_port: None,
                ssh_identity_file: None,
                remote_config: None,
                machine_uuid: None,
                execution_uid: None,
            },
        };
        let mut results = Vec::new();
        for wave in 0..2 {
            for i in wave * 4..wave * 4 + 4 {
                assert!(sampler.request(
                    format!("node-{i}"),
                    node(if i == 1 { "fail" } else { "ok" })
                ));
            }
            assert_eq!(sampler.in_flight_count(), 4);
            results.extend(collect(&mut sampler, 4));
        }
        assert_eq!(results.len(), 8);
        assert!(results.iter().any(|result| result.result.is_err()));
        assert!(results.iter().any(|result| result.result.is_ok()));
        assert!(peak.load(Ordering::SeqCst) <= 4);
    }

    #[test]
    fn duplicate_request_for_one_node_is_rejected_until_result_is_received() {
        let mut sampler = MetricSampler::with_sample_fn(
            2,
            Arc::new(|_, _cancel| {
                thread::sleep(Duration::from_millis(30));
                Ok(unavailable(1, "fixture"))
            }),
        );
        assert!(sampler.request("same", SampleTarget::Local));
        assert!(!sampler.request("same", SampleTarget::Local));
        let results = collect(&mut sampler, 1);
        assert_eq!(results.len(), 1);
        assert!(sampler.request("same", SampleTarget::Local));
    }

    #[test]
    fn timed_out_child_is_killed_and_reaped() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 2"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        assert_eq!(
            wait_child(&mut child, Duration::from_millis(50), None).unwrap(),
            ChildWait::Timeout
        );
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cancelled_child_is_killed_promptly() {
        use std::sync::atomic::AtomicBool;

        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 2"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let cancel = AtomicBool::new(true);
        assert_eq!(
            wait_child(&mut child, Duration::from_secs(8), Some(&cancel)).unwrap(),
            ChildWait::Cancelled
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
