mod common;
use macluster_controller::{ControlListener, InstanceLock, PendingControlEvent};
use macluster_core::service::ServiceBinding;
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ControlCommand, ControlPayload, ControllerHello,
        ControllerLifecycle,
    },
    identifiers::{ControllerUuid, Id128},
    resources::{JobResourceSnapshot, TASK_RESOURCE_FEATURE, TaskResourceSample},
    types::{ControllerEpoch, JobState},
};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn exercise(support: bool) -> (std::process::Output, usize) {
    let f = Fixture(std::env::temp_dir().join(format!("job-resource-cli-{}", Id128::random())));
    fs::create_dir_all(f.0.join("state")).unwrap();
    fs::create_dir_all(f.0.join("shared")).unwrap();
    let config = f.0.join("config.toml");
    let state = f.0.join("state");
    fs::write(&config,format!("[cluster]\nname=\"resource-test\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"192.0.2.10\"\ntransport=\"ssh\"\nremote_binary=\"/unused\"\n",f.0.join("shared").display())).unwrap();
    let binding = ServiceBinding::load(&config, &state).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let server_stop = stop.clone();
    let unsubscriptions = Arc::new(AtomicUsize::new(0));
    let server_unsubscriptions = unsubscriptions.clone();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let instance = InstanceLock::acquire(&state).unwrap();
        let hello = ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().into(),
            namespace: binding.namespace().into(),
            uid: binding.uid(),
            build_id: macluster_protocol::framing::sha256_hex(
                &fs::read(env!("CARGO_BIN_EXE_macluster")).unwrap(),
            )
            .unwrap(),
            capabilities: if support {
                vec![TASK_RESOURCE_FEATURE.into()]
            } else {
                vec![]
            },
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 1,
            lifecycle: ControllerLifecycle::Ready,
        };
        let mut listener = ControlListener::bind(&binding, &instance, hello.clone()).unwrap();
        tx.send(()).unwrap();
        let mut count = 0;
        while !server_stop.load(Ordering::SeqCst) {
            match listener.poll_event() {
                Some(PendingControlEvent::Request(request)) => {
                    let response = match request.request().command {
                        ControlCommand::Status => ControlPayload::Status(hello.clone()),
                        ControlCommand::QueryAgentCompatibility { .. } => {
                            ControlPayload::AgentCompatibility(vec![])
                        }
                        ControlCommand::SubscribeJobResources { job_id } => {
                            assert_eq!(job_id, 7);
                            ControlPayload::JobResourcesSubscribed
                        }
                        ControlCommand::JobResourceSnapshot { job_id } => {
                            count += 1;
                            ControlPayload::JobResourceSnapshot(JobResourceSnapshot {
                                schema_version: 1,
                                job_id,
                                node_id: Some("worker".parse().unwrap()),
                                start_token: None,
                                state: if count == 1 {
                                    JobState::Running
                                } else {
                                    JobState::Completed
                                },
                                sample: Some(TaskResourceSample {
                                    schema_version: 1,
                                    observed_unix_ms: count,
                                    age_ms: 0,
                                    interval_ms: Some(5000),
                                    cpu_percent: Some(123.0),
                                    rss_bytes: Some(1024),
                                    cpu_time_seconds: 1.0,
                                    memory_time_gib_seconds: 0.1,
                                    memory_peak_sampled_bytes: 1024,
                                    process_count: 1,
                                    source: "test".into(),
                                    coverage: "partial".into(),
                                    error: None,
                                }),
                                age_ms: Some(0),
                                stale: false,
                                error: None,
                            })
                        }
                        ControlCommand::UnsubscribeJobResources => {
                            server_unsubscriptions.fetch_add(1, Ordering::SeqCst);
                            ControlPayload::MonitorAcknowledged
                        }
                        ref other => panic!("unexpected request: {other:?}"),
                    };
                    request.respond(Ok(response)).unwrap();
                }
                _ => thread::sleep(Duration::from_millis(2)),
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let mut cmd = common::macluster_command();
    cmd.arg("--config")
        .arg(&config)
        .arg("--state-dir")
        .arg(f.0.join("state"))
        .args(["job", "--metrics", "7", "--follow", "--json"]);
    let output =
        macluster_controller::transport::run_child_bounded(cmd, None, Duration::from_secs(10))
            .unwrap();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    (output, unsubscriptions.load(Ordering::SeqCst))
}
#[test]
fn metrics_follow_is_json_lines_and_stops_at_terminal_state() {
    let (output, unsubs) = exercise(true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rows = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str::<JobResourceSnapshot>(s).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].sample.as_ref().unwrap().cpu_percent, Some(123.0));
    assert!(rows[1].state.is_terminal());
    assert_eq!(unsubs, 1);
}
#[test]
fn old_controller_fails_with_capability_guidance_instead_of_waiting() {
    let (output, unsubs) = exercise(false);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("lacks task.resources.v1"));
    assert_eq!(unsubs, 0);
}
