use std::{fs, os::unix::net::UnixStream, path::PathBuf, thread, time::Duration};

use macluster_controller::{
    ControlApi, ControlListener, InstanceLock, maintenance::MaintenanceCoordinator,
};
use macluster_core::{config::ClusterConfig, service::ServiceBinding, storage::Storage};
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ClientHello, ControlCommand, ControlPayload, ControlRequest,
        ControlResponse, ControllerHello, ControllerLifecycle, HelloResponse, MaintenanceScope,
    },
    framing::{read_frame, sha256_hex, write_frame},
    identifiers::{ControllerUuid, Id128, RequestId},
    types::ControllerEpoch,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("macluster-service-maintenance-{}", Id128::random()));
        fs::create_dir_all(root.join("state")).unwrap();
        fs::create_dir_all(root.join("shared")).unwrap();
        let fixture = Self(root);
        fixture.write_config("/tmp/macluster");
        fixture
    }

    fn write_config(&self, worker_binary: &str) {
        let config = format!(
            "[cluster]\nname=\"maintenance-test\"\nlogin_node=\"login\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-a83a-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker]\nhost=\"192.0.2.20\"\ntransport=\"ssh\"\nremote_binary=\"{}\"\nssh_user=\"worker\"\n",
            self.0.join("shared").display(),
            unsafe { libc::geteuid() },
            worker_binary
        );
        fs::write(self.config_path(), config).unwrap();
    }

    fn config_path(&self) -> PathBuf {
        self.0.join("config.toml")
    }

    fn state_dir(&self) -> PathBuf {
        self.0.join("state")
    }

    fn config(&self) -> ClusterConfig {
        ClusterConfig::parse(&fs::read_to_string(self.config_path()).unwrap()).unwrap()
    }

    fn binding(&self) -> ServiceBinding {
        ServiceBinding::load(&self.config_path(), &self.state_dir()).unwrap()
    }

    fn api(&self) -> (ControlApi, ControllerHello, String) {
        let config = self.config();
        let binding = self.binding();
        let bytes = fs::read(self.config_path()).unwrap();
        let digest = sha256_hex(&bytes).unwrap();
        let maintenance =
            MaintenanceCoordinator::open(&self.state_dir(), binding.binding_digest(), &digest)
                .unwrap();
        let journal_digest = maintenance.node_admin_journal_digest().unwrap();
        let hello = ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().into(),
            namespace: binding.namespace().into(),
            uid: binding.uid(),
            build_id: "test-controller".into(),
            capabilities: vec!["maintenance.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: maintenance.generation(),
            lifecycle: ControllerLifecycle::Ready,
        };
        let api = ControlApi::new_with_maintenance(
            config,
            Storage::open(self.state_dir()).unwrap(),
            hello.clone(),
            self.config_path(),
            maintenance,
        );
        (api, hello, journal_digest)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn client_hello(binding: &ServiceBinding) -> ClientHello {
    ClientHello {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        binding_digest: binding.binding_digest().to_owned(),
        namespace: binding.namespace().to_owned(),
        uid: binding.uid(),
        build_id: "test-client".into(),
        capabilities: vec!["maintenance.v1".into()],
    }
}

fn send_command(
    api: &mut ControlApi,
    listener: &mut ControlListener<'_>,
    binding: &ServiceBinding,
    generation: u64,
    command: ControlCommand,
) -> Result<ControlPayload, macluster_protocol::control::ControlError> {
    let endpoint = listener.path().to_path_buf();
    let hello = client_hello(binding);
    let client = thread::spawn(move || {
        let mut stream = UnixStream::connect(endpoint).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write_frame(&mut stream, &hello).unwrap();
        assert!(matches!(
            read_frame::<_, HelloResponse>(&mut stream)
                .unwrap()
                .unwrap(),
            HelloResponse::Accepted(_)
        ));
        let request_id = RequestId::random();
        write_frame(
            &mut stream,
            &ControlRequest {
                request_id,
                expected_generation: Some(generation),
                command,
            },
        )
        .unwrap();
        let response: ControlResponse = read_frame(&mut stream).unwrap().unwrap();
        assert_eq!(response.request_id, request_id);
        response.result
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "control request timed out"
        );
        match listener.poll_event() {
            Some(macluster_controller::PendingControlEvent::Request(request)) => {
                let session = request.client_session();
                let result = api.handle(session, request.request().clone());
                request.respond(result).unwrap();
                return client.join().unwrap();
            }
            Some(macluster_controller::PendingControlEvent::Disconnected(session)) => {
                api.disconnect(session);
            }
            None => thread::sleep(Duration::from_millis(2)),
        }
    }
}

#[test]
fn maintenance_ticket_survives_client_disconnect_and_controller_restart() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let (mut api, hello, journal_digest) = fixture.api();
    let instance = InstanceLock::acquire(&fixture.state_dir()).unwrap();
    let mut listener = ControlListener::bind(&binding, &instance, hello.clone()).unwrap();
    let operation_id = Id128::random();

    let response = send_command(
        &mut api,
        &mut listener,
        &binding,
        hello.config_generation,
        ControlCommand::BeginMaintenance {
            operation_id,
            scope: MaintenanceScope::Cluster,
            journal_digest,
        },
    )
    .unwrap();
    let ControlPayload::Maintenance(Some(status)) = response else {
        panic!("maintenance ticket was not returned")
    };
    assert_eq!(status.ticket.operation_id, operation_id);
    assert_eq!(
        status.phase,
        macluster_protocol::control::MaintenancePhase::Draining
    );

    drop(listener);
    drop(api);
    drop(instance);

    let binding = fixture.binding();
    let config_digest = sha256_hex(&fs::read(fixture.config_path()).unwrap()).unwrap();
    let restarted = MaintenanceCoordinator::open(
        &fixture.state_dir(),
        binding.binding_digest(),
        &config_digest,
    )
    .unwrap();
    let recovered = restarted.inspect().expect("ticket must survive restart");
    assert_eq!(recovered.ticket, status.ticket);
    assert_eq!(recovered.scope, MaintenanceScope::Cluster);
}

#[test]
fn config_reload_increments_generation_and_rejects_old_requests_on_existing_connections() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let (mut api, hello, journal_digest) = fixture.api();
    let instance = InstanceLock::acquire(&fixture.state_dir()).unwrap();
    let mut listener = ControlListener::bind(&binding, &instance, hello.clone()).unwrap();

    // Keep a monitor-like IPC connection open across the generation change.
    // Long-lived clients must not continue using a stale config generation.
    let endpoint = listener.path().to_path_buf();
    let binding_for_client = binding.clone();
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
    let (request_sender, request_receiver) = std::sync::mpsc::sync_channel(1);
    let stale_client = thread::spawn(move || {
        let mut stream = UnixStream::connect(endpoint).unwrap();
        let hello = client_hello(&binding_for_client);
        write_frame(&mut stream, &hello).unwrap();
        let greeting: HelloResponse = read_frame(&mut stream).unwrap().unwrap();
        let HelloResponse::Accepted(greeting) = greeting else {
            panic!("controller rejected a maintenance client")
        };
        ready_sender.send(greeting.config_generation).unwrap();
        request_receiver.recv().unwrap();
        write_frame(
            &mut stream,
            &ControlRequest {
                request_id: RequestId::random(),
                expected_generation: Some(greeting.config_generation),
                command: ControlCommand::Status,
            },
        )
        .unwrap();
        let response: ControlResponse = read_frame(&mut stream).unwrap().unwrap();
        response.result.unwrap_err().code
    });
    assert_eq!(ready_receiver.recv().unwrap(), hello.config_generation);

    let operation_id = Id128::random();
    let response = send_command(
        &mut api,
        &mut listener,
        &binding,
        hello.config_generation,
        ControlCommand::BeginMaintenance {
            operation_id,
            scope: MaintenanceScope::Cluster,
            journal_digest,
        },
    )
    .unwrap();
    let ControlPayload::Maintenance(Some(status)) = response else {
        panic!("maintenance ticket was not returned")
    };
    api.refresh_maintenance_blockers(Vec::new());

    fixture.write_config("/tmp/macluster-updated");
    let candidate_bytes = fs::read(fixture.config_path()).unwrap();
    let candidate_digest = sha256_hex(&candidate_bytes).unwrap();
    let journal_bytes = fs::read(fixture.state_dir().join("node-admin.json")).unwrap_or_default();
    let journal_digest = sha256_hex(&journal_bytes).unwrap();
    let (next_config, scope) = api
        .prepare_maintenance_completion(&status.ticket, &candidate_digest, &journal_digest)
        .unwrap();
    assert_eq!(scope, MaintenanceScope::Cluster);
    api.finish_maintenance_completion(&status.ticket, next_config)
        .unwrap();
    assert_eq!(api.hello().config_generation, hello.config_generation + 1);
    listener.set_hello(api.hello().clone()).unwrap();
    request_sender.send(()).unwrap();
    assert_eq!(
        stale_client.join().unwrap(),
        macluster_protocol::control::ControlErrorCode::StaleGeneration
    );
}
