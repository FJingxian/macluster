use std::{fs, path::PathBuf};

use macluster_controller::ControlApi;
use macluster_core::{config::ClusterConfig, storage::Storage};
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ControlCommand, ControlPayload, ControlRequest, ControllerHello,
        ControllerLifecycle,
    },
    identifiers::{ControllerUuid, Id128, NodeId, QueueName, RequestId},
    types::{ControllerEpoch, JobMode, JobSpec, JobState},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("macluster-service-recovery-{}", Id128::random()));
        fs::create_dir_all(root.join("state")).unwrap();
        fs::create_dir_all(root.join("shared")).unwrap();
        Self(root)
    }

    fn state_dir(&self) -> PathBuf {
        self.0.join("state")
    }

    fn config(&self) -> ClusterConfig {
        ClusterConfig::parse(&format!(
            "[cluster]\nname=\"recovery-test\"\nlogin_node=\"login\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-a83a-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker]\nhost=\"192.0.2.20\"\ntransport=\"ssh\"\nssh_user=\"worker\"\n",
            self.0.join("shared").display(),
            unsafe { libc::geteuid() }
        ))
        .unwrap()
    }

    fn hello(&self, config: &ClusterConfig) -> ControllerHello {
        ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: "a".repeat(64),
            namespace: config.share_uuid.clone(),
            uid: unsafe { libc::geteuid() },
            build_id: "service-recovery-test".into(),
            capabilities: vec!["jobs.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 5,
            lifecycle: ControllerLifecycle::Ready,
        }
    }

    fn api(&self, config: &ClusterConfig) -> ControlApi {
        ControlApi::new(
            config.clone(),
            Storage::open(self.state_dir()).unwrap(),
            self.hello(config),
        )
    }

    fn spec(&self, config: &ClusterConfig) -> JobSpec {
        JobSpec {
            storage_namespace: Some(Id128::parse(&config.share_uuid).unwrap()),
            queue: QueueName::new("q").unwrap(),
            node: None,
            name: "lost acknowledgement recovery".into(),
            cwd: config.shared_root.display().to_string(),
            stdout_path: config.shared_root.join("stdout.log").display().to_string(),
            stderr_path: config.shared_root.join("stderr.log").display().to_string(),
            walltime_secs: None,
            env: Default::default(),
            mode: JobMode::Interactive,
            snapshot: None,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn submit_request(request_id: RequestId, spec: JobSpec) -> ControlRequest {
    ControlRequest {
        request_id: RequestId::random(),
        expected_generation: Some(5),
        command: ControlCommand::Submit { request_id, spec },
    }
}

#[test]
fn accepted_submission_survives_lost_acknowledgement_and_controller_restart() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let request_id = RequestId::random();
    let spec = fixture.spec(&config);

    let mut first_controller = fixture.api(&config);
    let accepted = first_controller
        .handle(Id128::random(), submit_request(request_id, spec.clone()))
        .unwrap();
    let ControlPayload::Submission(accepted) = accepted else {
        panic!("controller did not persist the submission")
    };
    // The client loses the reply after the durable submission was accepted.
    drop(first_controller);

    let mut restarted_controller = fixture.api(&config);
    let retried = restarted_controller
        .handle(Id128::random(), submit_request(request_id, spec))
        .unwrap();
    let ControlPayload::Submission(retried) = retried else {
        panic!("retry did not return the original submission")
    };
    assert_eq!(retried.id, accepted.id);
    let lookup = restarted_controller
        .handle(
            Id128::random(),
            ControlRequest {
                request_id: RequestId::random(),
                expected_generation: Some(5),
                command: ControlCommand::LookupRequest { request_id },
            },
        )
        .unwrap();
    assert!(matches!(lookup, ControlPayload::Lookup(Some(job)) if job.id == accepted.id));

    drop(restarted_controller);
    let storage = Storage::open(fixture.state_dir()).unwrap();
    let jobs = storage.list_jobs(None).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, accepted.id);
}

#[test]
fn terminal_log_sync_state_survives_controller_state_reopen() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let storage = Storage::open(fixture.state_dir()).unwrap();
    let job = storage
        .submit_once(RequestId::random(), fixture.spec(&config))
        .unwrap();
    let worker = NodeId::new("worker").unwrap();
    storage.reserve_job(job.id, worker).unwrap();
    storage.mark_running(job.id).unwrap();
    storage
        .finish_job(job.id, JobState::Completed, Some(0), None)
        .unwrap();
    storage.set_log_sync_pending(job.id, true).unwrap();
    drop(storage);

    let reopened = Storage::open(fixture.state_dir()).unwrap();
    let recovered = reopened.get_job(job.id).unwrap().unwrap();
    assert_eq!(recovered.state, JobState::Completed);
    assert!(recovered.log_sync_pending);
    assert!(
        reopened
            .list_reconcile_jobs()
            .unwrap()
            .iter()
            .any(|record| record.id == job.id && record.log_sync_pending)
    );
}
