use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use macluster_controller::{
    ControllerService,
    transport::{NodeTransport, TransportError},
};
use macluster_core::{
    config::{ClusterConfig, NodeConfig},
    storage::Storage,
};
use macluster_protocol::{
    identifiers::{Id128, NodeId, QueueName},
    types::{
        ExecutionStatus, JobMode, JobSpec, JobState, Operation, ProtocolError, ResponseBody,
        RuntimePhase,
    },
};

#[derive(Clone, Default)]
struct FakeTransport {
    state: Arc<Mutex<FakeState>>,
}

#[derive(Default)]
struct FakeState {
    jobs: BTreeMap<String, ExecutionStatus>,
    starts: usize,
    lose_start_reply_once: bool,
    features: Vec<String>,
    lose_status_once: bool,
    recovery_state: Option<JobState>,
    recoveries: usize,
}

impl FakeTransport {
    fn lose_next_start_reply(&self) {
        self.state.lock().unwrap().lose_start_reply_once = true;
    }
    fn set_terminal(&self, node: &str, state: JobState) {
        let mut shared = self.state.lock().unwrap();
        let status = shared.jobs.get_mut(node).unwrap();
        status.terminal_state = Some(state);
        status.phase = RuntimePhase::Idle;
        status.exit_code = Some(0);
    }
    fn set_running(&self, node: &str) {
        self.state.lock().unwrap().jobs.get_mut(node).unwrap().phase = RuntimePhase::Running;
    }
    fn add_interactive_pty(&self) {
        self.state
            .lock()
            .unwrap()
            .features
            .push("agent.interactive-pty.v1".into());
    }
    fn starts(&self) -> usize {
        self.state.lock().unwrap().starts
    }
}

impl NodeTransport for FakeTransport {
    fn call(
        &self,
        node_id: &NodeId,
        _node: &NodeConfig,
        operation: Operation,
    ) -> Result<ResponseBody, TransportError> {
        let mut state = self.state.lock().unwrap();
        match operation {
            Operation::RecoverJob {
                start_token,
                job_id,
                ..
            } => {
                let terminal = state.recovery_state;
                let status = state
                    .jobs
                    .get_mut(node_id.as_str())
                    .ok_or(TransportError::Remote(ProtocolError::NotFound))?;
                assert_eq!(status.job_id, job_id);
                assert_eq!(status.start_token, start_token);
                if let Some(terminal) = terminal {
                    status.terminal_state = Some(terminal);
                    status.phase = RuntimePhase::Idle;
                }
                let response = status.clone();
                state.recoveries += 1;
                Ok(ResponseBody::Execution(response))
            }
            Operation::Fence { .. } => Ok(ResponseBody::Ack),
            Operation::Status if state.lose_status_once => {
                state.lose_status_once = false;
                Err(TransportError::Remote(ProtocolError::NotFound))
            }
            Operation::Status => state
                .jobs
                .get(node_id.as_str())
                .cloned()
                .map(ResponseBody::Execution)
                .ok_or(TransportError::Remote(ProtocolError::NotFound)),
            Operation::StartJob {
                controller: _,
                start_token,
                job_id,
                spec,
            } => {
                if let Some(existing) = state.jobs.get(node_id.as_str()) {
                    if existing.start_token == start_token && existing.job_id == job_id {
                        return Ok(ResponseBody::Started(
                            macluster_protocol::types::StartResult {
                                start_token,
                                accepted: true,
                                runner_pid: Some(44),
                            },
                        ));
                    }
                    if existing.terminal_state.is_none() {
                        return Err(TransportError::Remote(ProtocolError::Busy));
                    }
                }
                state.starts += 1;
                let status = ExecutionStatus {
                    start_token,
                    job_id,
                    phase: RuntimePhase::Launching,
                    terminal_state: None,
                    boot_id: "boot-a".into(),
                    runner_pid: Some(44),
                    child_pid: None,
                    exit_code: None,
                    end_reason: None,
                    log_sync_pending: false,
                };
                state.jobs.insert(node_id.to_string(), status);
                let lose_reply = std::mem::take(&mut state.lose_start_reply_once);
                if lose_reply {
                    return Err(TransportError::Timeout);
                }
                let _ = spec;
                Ok(ResponseBody::Started(
                    macluster_protocol::types::StartResult {
                        start_token,
                        accepted: true,
                        runner_pid: Some(44),
                    },
                ))
            }
            Operation::CancelJob {
                start_token,
                job_id,
                ..
            } => {
                if let Some(status) = state
                    .jobs
                    .get_mut(node_id.as_str())
                    .filter(|status| status.start_token == start_token && status.job_id == job_id)
                {
                    status.terminal_state = Some(JobState::Cancelled);
                    status.phase = RuntimePhase::Idle;
                }
                Ok(ResponseBody::Ack)
            }
            Operation::Health => Ok(ResponseBody::Health(
                macluster_protocol::types::NodeHealth {
                    machine_uuid: String::new(),
                    execution_uid: 0,
                    execution_digest: String::new(),
                    primary_share_ready: true,
                    shares: BTreeMap::new(),
                    features: state.features.clone(),
                },
            )),
            Operation::QueryFanPolicy => Ok(ResponseBody::FanControl(
                macluster_protocol::types::FanControlStatus {
                    policy: macluster_protocol::types::FanPolicy::System,
                    supported: false,
                    active: false,
                    average_temperature_deci_celsius: None,
                    target_rpm: None,
                    message: None,
                },
            )),
            Operation::SetFanPolicy { policy } => Ok(ResponseBody::FanControl(
                macluster_protocol::types::FanControlStatus {
                    policy,
                    supported: false,
                    active: false,
                    average_temperature_deci_celsius: None,
                    target_rpm: None,
                    message: None,
                },
            )),
            Operation::Ping => Ok(ResponseBody::Pong),
        }
    }
}

#[test]
fn namespaced_submission_stays_pending_with_an_update_hint_on_legacy_agents() {
    let (root, config, storage, mut spec) = fixture();
    spec.storage_namespace = Some(Id128::parse(&config.share_uuid).unwrap());
    let job = storage
        .submit_once(macluster_protocol::identifiers::RequestId::random(), spec)
        .unwrap();
    storage
        .publish_snapshot(job.id, &config.shared_root)
        .unwrap();
    let transport = FakeTransport::default();
    let mut controller = ControllerService::new(config, storage, transport.clone()).unwrap();
    controller.tick_with_storage_health(true).unwrap();
    let pending = controller_storage(&root).get_job(job.id).unwrap().unwrap();
    assert_eq!(pending.state, JobState::Pending);
    assert!(
        pending
            .waiting_reason
            .as_deref()
            .unwrap()
            .contains("this job remains queued")
    );
    assert!(
        !pending
            .waiting_reason
            .as_deref()
            .unwrap()
            .contains("cancel and resubmit")
    );
    assert_eq!(transport.starts(), 0);
    transport
        .state
        .lock()
        .unwrap()
        .features
        .push(macluster_protocol::types::NAMESPACED_JOBS_FEATURE.into());
    controller.tick_with_storage_health(true).unwrap();
    assert_eq!(
        controller_storage(&root)
            .get_job(job.id)
            .unwrap()
            .unwrap()
            .state,
        JobState::Starting
    );
    assert_eq!(transport.starts(), 1);
    drop(controller);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_agent_state_recovers_the_reserved_execution_instead_of_leaving_it_running() {
    for terminal in [JobState::NodeLost, JobState::Cancelled] {
        let (root, config, storage, spec) = fixture();
        let job = storage
            .submit_once(macluster_protocol::identifiers::RequestId::random(), spec)
            .unwrap();
        storage
            .publish_snapshot(job.id, &config.shared_root)
            .unwrap();
        let transport = FakeTransport::default();
        let mut controller = ControllerService::new(config, storage, transport.clone()).unwrap();
        controller.tick_with_storage_health(true).unwrap();
        transport.set_running("mini01-a");
        controller.tick_with_storage_health(true).unwrap();
        if terminal == JobState::Cancelled {
            controller_storage(&root)
                .request_cancel(job.id, true)
                .unwrap();
        }
        {
            let mut state = transport.state.lock().unwrap();
            state.lose_status_once = true;
            state.recovery_state = Some(terminal);
        }
        controller.tick_with_storage_health(true).unwrap();
        assert_eq!(
            controller_storage(&root)
                .get_job(job.id)
                .unwrap()
                .unwrap()
                .state,
            terminal
        );
        assert_eq!(transport.state.lock().unwrap().recoveries, 1);
        fs::remove_dir_all(root).unwrap();
    }
}

fn fixture() -> (PathBuf, ClusterConfig, Storage, JobSpec) {
    let root = std::env::temp_dir().join(format!(
        "macluster-controller-{}-{}",
        std::process::id(),
        Id128::random()
    ));
    let shared = root.join("shared");
    fs::create_dir_all(shared.join("projects")).unwrap();
    fs::write(
        shared.join(".macluster-share-id"),
        "00000000-0000-4000-8000-000000000001\n",
    )
    .unwrap();
    let config_text = format!(
        r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "{}"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "mini01-a"
protocol_version = 1

[queues.mini01]
nodes = ["mini01-a"]
scheduler = "fifo"

[nodes.mini01-a]
host = "192.168.2.1"
transport = "ssh"
"#,
        shared.display()
    );
    let config = ClusterConfig::parse(&config_text).unwrap();
    let state_dir = root.join("controller");
    let storage = Storage::open(&state_dir).unwrap();
    let snapshot_bytes = b"#!/bin/bash\necho hi\n";
    let snapshot = storage.stage_snapshot(snapshot_bytes).unwrap();
    let spec = JobSpec {
        storage_namespace: None,
        queue: QueueName::new("mini01").unwrap(),
        node: None,
        name: "test".into(),
        cwd: shared.join("projects").to_string_lossy().into_owned(),
        stdout_path: shared
            .join("jobs/%j/stdout.log")
            .to_string_lossy()
            .into_owned(),
        stderr_path: shared
            .join("jobs/%j/stderr.log")
            .to_string_lossy()
            .into_owned(),
        walltime_secs: None,
        env: BTreeMap::new(),
        mode: JobMode::Batch,
        snapshot: Some(snapshot),
    };
    (root, config, storage, spec)
}

#[test]
fn controller_commits_reservation_before_start_and_reconciles_terminal_status() {
    let (root, config, storage, spec) = fixture();
    let job = storage
        .submit_once(
            macluster_protocol::identifiers::RequestId(Id128::random()),
            spec,
        )
        .unwrap();
    storage
        .publish_snapshot(job.id, &root.join("shared"))
        .unwrap();
    let transport = FakeTransport::default();
    let mut controller = ControllerService::new(config, storage, transport.clone()).unwrap();

    controller.tick_with_storage_health(true).unwrap();
    let starting = controller_storage(&root).get_job(job.id).unwrap().unwrap();
    assert_eq!(starting.state, JobState::Starting);
    assert!(starting.start_token.is_some());
    assert_eq!(transport.starts(), 1);

    transport.set_running("mini01-a");
    controller.tick_with_storage_health(true).unwrap();
    assert_eq!(
        controller_storage(&root)
            .get_job(job.id)
            .unwrap()
            .unwrap()
            .state,
        JobState::Running
    );

    transport.set_terminal("mini01-a", JobState::Completed);
    controller.tick_with_storage_health(true).unwrap();
    assert_eq!(
        controller_storage(&root)
            .get_job(job.id)
            .unwrap()
            .unwrap()
            .state,
        JobState::Completed
    );
    assert!(root.join("shared/jobs/1/script.sh").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ambiguous_start_keeps_reservation_and_stable_token_for_reconciliation() {
    let (root, config, storage, spec) = fixture();
    let job = storage
        .submit_once(
            macluster_protocol::identifiers::RequestId(Id128::random()),
            spec,
        )
        .unwrap();
    storage
        .publish_snapshot(job.id, &root.join("shared"))
        .unwrap();
    let transport = FakeTransport::default();
    transport.lose_next_start_reply();
    let mut controller = ControllerService::new(config, storage, transport.clone()).unwrap();

    controller.tick_with_storage_health(true).unwrap();
    let starting = controller_storage(&root).get_job(job.id).unwrap().unwrap();
    let token = starting.start_token;
    assert_eq!(starting.state, JobState::Starting);
    assert_eq!(transport.starts(), 1);

    transport.set_running("mini01-a");
    controller.tick_with_storage_health(true).unwrap();
    let running = controller_storage(&root).get_job(job.id).unwrap().unwrap();
    assert_eq!(running.state, JobState::Running);
    assert_eq!(running.start_token, token);
    assert_eq!(transport.starts(), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_interactive_job_reports_agent_update_requirement() {
    let (root, config, storage, mut spec) = fixture();
    spec.mode = JobMode::Interactive;
    spec.snapshot = None;
    let job = storage
        .submit_once(
            macluster_protocol::identifiers::RequestId(Id128::random()),
            spec,
        )
        .unwrap();
    let transport = FakeTransport::default();
    let mut controller = ControllerService::new(config, storage, transport.clone()).unwrap();

    controller.tick_with_storage_health(true).unwrap();

    let waiting = controller_storage(&root).get_job(job.id).unwrap().unwrap();
    assert_eq!(waiting.state, JobState::Pending);
    assert_eq!(transport.starts(), 0);
    assert!(
        waiting
            .waiting_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("resubmit with msub"))
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn pending_interactive_wait_reason_clears_when_capable_node_appears() {
    let (root, config, storage, mut spec) = fixture();
    spec.mode = JobMode::Interactive;
    spec.snapshot = None;
    let job = storage
        .submit_once(
            macluster_protocol::identifiers::RequestId(Id128::random()),
            spec,
        )
        .unwrap();
    let transport = FakeTransport::default();
    let mut controller = ControllerService::new(config, storage, transport.clone()).unwrap();

    controller.tick_with_storage_health(true).unwrap();
    transport.add_interactive_pty();
    controller.tick_with_storage_health(true).unwrap();

    let started = controller_storage(&root).get_job(job.id).unwrap().unwrap();
    assert_eq!(started.state, JobState::Starting);
    assert_eq!(started.waiting_reason, None);
    assert_eq!(transport.starts(), 1);
    fs::remove_dir_all(root).unwrap();
}

fn controller_storage(root: &PathBuf) -> Storage {
    Storage::open(root.join("controller")).unwrap()
}
