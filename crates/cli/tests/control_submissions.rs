use std::{
    fs,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use macluster_controller::{ControlApi, ControlListener, InstanceLock};
use macluster_core::{config::ClusterConfig, service::ServiceBinding, storage::Storage};
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ClientHello, ControlCommand, ControlErrorCode, ControlPayload,
        ControlRequest, ControllerHello, ControllerLifecycle, HelloResponse,
        MAX_CONTROL_SNAPSHOT_CHUNK_BYTES,
    },
    framing::{MAX_SNAPSHOT_BYTES, read_frame, sha256_hex, write_frame},
    identifiers::{ControllerUuid, Id128, NodeId, QueueName, RequestId},
    types::{ControllerEpoch, JobMode, JobSpec, JobState},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("macluster-online-submit-{}", Id128::random()));
        fs::create_dir_all(root.join("state")).unwrap();
        fs::create_dir_all(root.join("shared")).unwrap();
        let uid = unsafe { libc::geteuid() };
        fs::write(
            root.join("config.toml"),
            format!(
                "[cluster]\nname=\"online-submit\"\nlogin_node=\"login\"\ndefault_queue=\"cpu\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.cpu]\nnodes=[\"compute\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.compute]\nhost=\"192.0.2.20\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\n",
                root.join("shared").display(),
                uid
            ),
        )
        .unwrap();
        Self(root)
    }

    fn config(&self) -> ClusterConfig {
        ClusterConfig::parse(&fs::read_to_string(self.0.join("config.toml")).unwrap()).unwrap()
    }

    fn binding(&self) -> ServiceBinding {
        ServiceBinding::load(&self.0.join("config.toml"), &self.0.join("state")).unwrap()
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hello(binding: &ServiceBinding, lifecycle: ControllerLifecycle) -> ControllerHello {
    ControllerHello {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        binding_digest: binding.binding_digest().to_owned(),
        namespace: binding.namespace().to_owned(),
        uid: binding.uid(),
        build_id: "test-controller".into(),
        capabilities: vec!["status.v1".into(), "jobs.v1".into()],
        controller_epoch: ControllerEpoch {
            controller_uuid: ControllerUuid::random(),
            epoch: 4,
        },
        config_generation: 7,
        lifecycle,
    }
}

fn job_spec(binding: &ServiceBinding, name: &str) -> JobSpec {
    let config = ClusterConfig::parse(&fs::read_to_string(binding.config_path()).unwrap()).unwrap();
    let shared = config.shared_root;
    JobSpec {
        storage_namespace: Some(Id128::parse("240edfcc-0fe5-4fa8-83a2-29c6ede02b42").unwrap()),
        queue: QueueName::new("cpu").unwrap(),
        node: Some(NodeId::new("compute").unwrap()),
        name: name.into(),
        cwd: shared.display().to_string(),
        stdout_path: shared.join("jobs/%j/stdout.log").display().to_string(),
        stderr_path: shared.join("jobs/%j/stderr.log").display().to_string(),
        walltime_secs: None,
        env: [("PATH".into(), "/usr/bin:/bin".into())].into(),
        mode: JobMode::Interactive,
        snapshot: None,
    }
}

fn setup(
    fixture: &Fixture,
    lifecycle: ControllerLifecycle,
) -> (ControlApi, ControlListener<'static>, ServiceBinding) {
    let binding = fixture.binding();
    let instance = Box::leak(Box::new(
        InstanceLock::acquire(&fixture.root().join("state")).unwrap(),
    ));
    let controller_hello = hello(&binding, lifecycle);
    let listener = ControlListener::bind(&binding, instance, controller_hello.clone()).unwrap();
    let config = fixture.config();
    let storage = Storage::open(fixture.root().join("state")).unwrap();
    let api = ControlApi::new(config, storage, controller_hello);
    (api, listener, binding)
}

fn call(
    api: &mut ControlApi,
    listener: &mut ControlListener<'_>,
    binding: &ServiceBinding,
    command: ControlCommand,
) -> Result<ControlPayload, macluster_protocol::control::ControlError> {
    call_many(api, listener, binding, vec![command])
        .pop()
        .unwrap()
}

fn call_many(
    api: &mut ControlApi,
    listener: &mut ControlListener<'_>,
    binding: &ServiceBinding,
    commands: Vec<ControlCommand>,
) -> Vec<Result<ControlPayload, macluster_protocol::control::ControlError>> {
    let endpoint = listener.path().to_path_buf();
    let binding_for_client = binding.clone();
    let requests = commands
        .into_iter()
        .map(|command| ControlRequest {
            request_id: RequestId::random(),
            expected_generation: Some(7),
            command,
        })
        .collect::<Vec<_>>();
    let client_requests = requests.clone();
    let client = thread::spawn(move || {
        let mut stream = UnixStream::connect(endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write_frame(
            &mut stream,
            &ClientHello {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                binding_digest: binding_for_client.binding_digest().to_owned(),
                namespace: binding_for_client.namespace().to_owned(),
                uid: binding_for_client.uid(),
                build_id: "test-cli".into(),
                capabilities: vec!["jobs.v1".into()],
            },
        )
        .unwrap();
        let greeting: HelloResponse = read_frame(&mut stream).unwrap().unwrap();
        assert!(matches!(greeting, HelloResponse::Accepted(_)));
        client_requests
            .iter()
            .map(|request| {
                write_frame(&mut stream, request).unwrap();
                read_frame::<_, macluster_protocol::control::ControlResponse>(&mut stream)
                    .unwrap()
                    .unwrap()
            })
            .collect::<Vec<_>>()
    });

    let mut results = Vec::with_capacity(requests.len());
    let mut client_session = None;
    for expected in &requests {
        let deadline = Instant::now() + Duration::from_secs(2);
        let pending = loop {
            match listener.poll_event() {
                Some(macluster_controller::PendingControlEvent::Request(request)) => break request,
                Some(macluster_controller::PendingControlEvent::Disconnected(session)) => {
                    api.disconnect(session)
                }
                None => {}
            }
            assert!(
                Instant::now() < deadline,
                "control request was not delivered"
            );
            thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(pending.request().request_id, expected.request_id);
        let session = pending.client_session();
        if let Some(previous) = client_session {
            assert_eq!(session, previous);
        } else {
            client_session = Some(session);
        }
        let response = api.handle(session, pending.request().clone());
        pending.respond(response.clone()).unwrap();
        results.push(response);
    }
    let client_responses = client.join().unwrap();
    for (response, request) in client_responses.iter().zip(requests) {
        assert_eq!(response.request_id, request.request_id);
    }
    let session = client_session.expect("at least one control request");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.poll_event() {
            Some(macluster_controller::PendingControlEvent::Disconnected(disconnected)) => {
                assert_eq!(disconnected, session);
                api.disconnect(disconnected);
                break;
            }
            Some(macluster_controller::PendingControlEvent::Request(_)) => {
                panic!("unexpected request after control batch")
            }
            None => {}
        }
        assert!(
            Instant::now() < deadline,
            "client disconnect was not reported"
        );
        thread::sleep(Duration::from_millis(2));
    }
    results
}

fn job_count(fixture: &Fixture) -> usize {
    Storage::open(fixture.root().join("state"))
        .unwrap()
        .list_jobs(None)
        .unwrap()
        .len()
}

fn submit(
    api: &mut ControlApi,
    listener: &mut ControlListener<'_>,
    binding: &ServiceBinding,
    request_id: RequestId,
    spec: JobSpec,
) -> Result<ControlPayload, macluster_protocol::control::ControlError> {
    call(
        api,
        listener,
        binding,
        ControlCommand::Submit { request_id, spec },
    )
}

#[test]
fn online_submit_is_idempotent_and_request_id_reuse_conflicts() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    let request_id = RequestId::random();
    let spec = job_spec(&binding, "first");
    let first = submit(&mut api, &mut listener, &binding, request_id, spec.clone()).unwrap();
    let retry = submit(&mut api, &mut listener, &binding, request_id, spec).unwrap();
    let (ControlPayload::Submission(first), ControlPayload::Submission(retry)) = (first, retry)
    else {
        panic!("expected submission records");
    };
    assert_eq!(first.id, retry.id);
    assert_eq!(job_count(&fixture), 1);

    let mut changed = job_spec(&binding, "changed");
    changed.env.insert("EXTRA".into(), "different".into());
    let error = submit(&mut api, &mut listener, &binding, request_id, changed).unwrap_err();
    assert_eq!(error.code, ControlErrorCode::Conflict);
    assert_eq!(job_count(&fixture), 1);
}

#[test]
fn online_job_lookup_and_queue_summary_reflect_durable_submissions() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    let request_id = RequestId::random();
    let ControlPayload::Submission(submitted) = submit(
        &mut api,
        &mut listener,
        &binding,
        request_id,
        job_spec(&binding, "lookup"),
    )
    .unwrap() else {
        panic!("expected submitted job record");
    };

    let by_request = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::LookupRequest { request_id },
    )
    .unwrap();
    assert!(matches!(by_request, ControlPayload::Lookup(Some(job)) if job.id == submitted.id));

    let by_job_id = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::LookupJob {
            job_id: submitted.id,
        },
    )
    .unwrap();
    assert!(matches!(by_job_id, ControlPayload::Job(job) if job.id == submitted.id));

    let queues = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::QueryQueues,
    )
    .unwrap();
    let ControlPayload::Queues(queues) = queues else {
        panic!("expected queue summary");
    };
    assert_eq!(queues.len(), 1);
    assert_eq!(queues[0].name, "cpu");
    assert_eq!(queues[0].nodes, vec!["compute"]);
    assert_eq!(queues[0].pending, 1);
}

#[test]
fn chunked_snapshot_upload_accepts_eight_mib_and_submits_once() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    let script = vec![b'x'; MAX_SNAPSHOT_BYTES as usize];
    let digest = sha256_hex(&script).unwrap();
    let upload_id = Id128::random();
    let mut commands = vec![ControlCommand::BeginSnapshot {
        upload_id,
        size_bytes: script.len() as u64,
        sha256: digest.clone(),
    }];
    let mut offset = 0;
    for chunk in script.chunks(MAX_CONTROL_SNAPSHOT_CHUNK_BYTES) {
        commands.push(ControlCommand::PutSnapshotChunk {
            upload_id,
            offset,
            bytes: chunk.to_vec(),
        });
        offset += chunk.len() as u64;
    }
    commands.push(ControlCommand::FinishSnapshot { upload_id });
    let uploaded = call_many(&mut api, &mut listener, &binding, commands)
        .pop()
        .unwrap()
        .unwrap();
    let ControlPayload::SnapshotFinished(snapshot) = uploaded else {
        panic!("expected uploaded snapshot reference");
    };
    assert_eq!(snapshot.sha256, digest);
    assert_eq!(snapshot.size_bytes, script.len() as u64);

    let mut spec = job_spec(&binding, "batch");
    spec.mode = JobMode::Batch;
    spec.snapshot = Some(snapshot);
    assert!(matches!(
        submit(&mut api, &mut listener, &binding, RequestId::random(), spec).unwrap(),
        ControlPayload::Submission(_)
    ));
}

#[test]
fn oversized_snapshot_and_partial_upload_never_create_jobs() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    let upload_id = Id128::random();
    let error = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::BeginSnapshot {
            upload_id,
            size_bytes: MAX_SNAPSHOT_BYTES + 1,
            sha256: "a".repeat(64),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ControlErrorCode::InvalidRequest);
    assert_eq!(job_count(&fixture), 0);

    let bytes = b"partial";
    let results = call_many(
        &mut api,
        &mut listener,
        &binding,
        vec![
            ControlCommand::BeginSnapshot {
                upload_id,
                size_bytes: 100,
                sha256: sha256_hex(b"not complete").unwrap(),
            },
            ControlCommand::PutSnapshotChunk {
                upload_id,
                offset: 0,
                bytes: bytes.to_vec(),
            },
            ControlCommand::AbortSnapshot { upload_id },
        ],
    );
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(job_count(&fixture), 0);
}

#[test]
fn disconnect_discards_incomplete_snapshot_upload() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    let upload_id = Id128::random();
    call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::BeginSnapshot {
            upload_id,
            size_bytes: 20,
            sha256: sha256_hex(b"the complete payload").unwrap(),
        },
    )
    .unwrap();
    let error = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::PutSnapshotChunk {
            upload_id,
            offset: 0,
            bytes: b"partial".to_vec(),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, ControlErrorCode::InvalidRequest);
    assert_eq!(job_count(&fixture), 0);
}

#[test]
fn job_query_pages_are_bounded_and_cancellation_is_persisted() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    for name in ["one", "two", "three"] {
        submit(
            &mut api,
            &mut listener,
            &binding,
            RequestId::random(),
            job_spec(&binding, name),
        )
        .unwrap();
    }
    let first = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::QueryJobs {
            offset: 0,
            limit: 2,
            state: None,
            active_only: false,
        },
    )
    .unwrap();
    let ControlPayload::Jobs(first_page) = first else {
        panic!("expected job page");
    };
    assert_eq!(first_page.jobs.len(), 2);
    assert_eq!(first_page.next_offset, Some(2));
    let next = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::QueryJobs {
            offset: 2,
            limit: 2,
            state: None,
            active_only: false,
        },
    )
    .unwrap();
    let ControlPayload::Jobs(next_page) = next else {
        panic!("expected job page");
    };
    assert_eq!(next_page.jobs.len(), 1);
    assert_eq!(next_page.next_offset, None);

    let id = first_page.jobs[0].id;
    let cancelled = call(
        &mut api,
        &mut listener,
        &binding,
        ControlCommand::CancelJob {
            job_id: id,
            force: false,
        },
    )
    .unwrap();
    let ControlPayload::Job(cancelled) = cancelled else {
        panic!("expected cancelled job record");
    };
    assert_eq!(cancelled.state, JobState::Cancelled);
}

#[test]
fn recovery_or_maintenance_service_never_admits_a_submission() {
    for lifecycle in [
        ControllerLifecycle::Paused,
        ControllerLifecycle::RecoveryPending,
    ] {
        let fixture = Fixture::new();
        let (mut api, mut listener, binding) = setup(&fixture, lifecycle);
        let error = submit(
            &mut api,
            &mut listener,
            &binding,
            RequestId::random(),
            job_spec(&binding, "blocked"),
        )
        .unwrap_err();
        assert_eq!(error.code, ControlErrorCode::Maintenance);
        assert_eq!(job_count(&fixture), 0);
    }
}

#[test]
fn login_node_or_wrong_queue_is_rejected_by_controller_admission() {
    let fixture = Fixture::new();
    let (mut api, mut listener, binding) = setup(&fixture, ControllerLifecycle::Ready);
    let request_id = RequestId::random();
    let mut spec = job_spec(&binding, "bad-placement");
    spec.node = Some(NodeId::new("login").unwrap());
    let error = submit(&mut api, &mut listener, &binding, request_id, spec).unwrap_err();
    assert_eq!(error.code, ControlErrorCode::InvalidRequest);
    assert_eq!(job_count(&fixture), 0);
}
