use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use macluster_controller::{ControlListener, InstanceLock};
use macluster_core::service::ServiceBinding;
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ClientHello, ControlCommand, ControlErrorCode, ControlPayload,
        ControlRequest, ControlResponse, ControllerHello, ControllerLifecycle, HelloResponse,
    },
    framing::{read_frame, write_frame},
    identifiers::{ControllerUuid, Id128, RequestId},
    types::ControllerEpoch,
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("macluster-control-ipc-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir(root.join("state")).unwrap();
        fs::write(
            root.join("config.toml"),
            format!(
                "[cluster]\nname=\"ipc-test\"\nlogin_node=\"login\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster-agent\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n",
                root.display(),
                unsafe { libc::geteuid() }
            ),
        )
        .unwrap();
        Self(root)
    }

    fn root(&self) -> &Path {
        &self.0
    }

    fn binding(&self) -> ServiceBinding {
        ServiceBinding::load(&self.0.join("config.toml"), &self.0.join("state")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn controller_hello(binding: &ServiceBinding) -> ControllerHello {
    ControllerHello {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        binding_digest: binding.binding_digest().to_owned(),
        namespace: binding.namespace().to_owned(),
        uid: binding.uid(),
        build_id: "test-build".into(),
        capabilities: vec!["status.v1".into()],
        controller_epoch: ControllerEpoch {
            controller_uuid: ControllerUuid::random(),
            epoch: 1,
        },
        config_generation: 1,
        lifecycle: ControllerLifecycle::Ready,
    }
}

fn client_hello(binding: &ServiceBinding) -> ClientHello {
    ClientHello {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        binding_digest: binding.binding_digest().to_owned(),
        namespace: binding.namespace().to_owned(),
        uid: binding.uid(),
        build_id: "test-client".into(),
        capabilities: vec!["status.v1".into()],
    }
}

fn wrong_namespace(hello: &mut ClientHello) {
    hello.namespace = "another-cluster".into();
}

fn wrong_protocol(hello: &mut ClientHello) {
    hello.protocol_version += 1;
}

fn wrong_binding(hello: &mut ClientHello) {
    hello.binding_digest = "0".repeat(64);
}

fn wrong_claimed_uid(hello: &mut ClientHello) {
    hello.uid = hello.uid.wrapping_add(1);
}

fn connect_and_handshake(path: &Path, hello: &ClientHello) -> (UnixStream, HelloResponse) {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write_frame(&mut stream, hello).unwrap();
    let response = read_frame(&mut stream).unwrap().unwrap();
    (stream, response)
}

fn wait_request(listener: &mut ControlListener<'_>) -> macluster_controller::PendingControlRequest {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(request) = listener.poll_request() {
            return request;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a control request"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn authenticated_client_receives_status_and_correlated_response() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let hello = controller_hello(&binding);
    let instance = InstanceLock::acquire(&fixture.root().join("state")).unwrap();
    let mut listener = ControlListener::bind(&binding, &instance, hello.clone()).unwrap();
    let path = listener.path().to_path_buf();
    let client_identity = client_hello(&binding);
    let response_hello = hello.clone();

    let client = thread::spawn(move || {
        let (mut stream, greeting) = connect_and_handshake(&path, &client_identity);
        assert_eq!(greeting, HelloResponse::Accepted(hello.clone()));
        let request_id = RequestId(Id128::random());
        write_frame(
            &mut stream,
            &ControlRequest {
                request_id,
                expected_generation: Some(hello.config_generation),
                command: ControlCommand::Status,
            },
        )
        .unwrap();
        let response: ControlResponse = read_frame(&mut stream).unwrap().unwrap();
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.result, Ok(ControlPayload::Status(hello)));
    });

    let request = wait_request(&mut listener);
    assert_eq!(request.request().command, ControlCommand::Status);
    request
        .respond(Ok(ControlPayload::Status(response_hello)))
        .unwrap();
    client.join().unwrap();
}

#[test]
fn wrong_namespace_protocol_binding_and_claimed_uid_are_rejected() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let hello = controller_hello(&binding);
    let instance = InstanceLock::acquire(&fixture.root().join("state")).unwrap();
    let listener = ControlListener::bind(&binding, &instance, hello).unwrap();
    let path = listener.path().to_path_buf();

    let cases: [(fn(&mut ClientHello), ControlErrorCode); 4] = [
        (wrong_namespace, ControlErrorCode::WrongCluster),
        (wrong_protocol, ControlErrorCode::IncompatibleProtocol),
        (wrong_binding, ControlErrorCode::WrongCluster),
        (wrong_claimed_uid, ControlErrorCode::WrongPeer),
    ];
    for (mutate, expected_code) in cases {
        let mut client = client_hello(&binding);
        mutate(&mut client);
        let (_, response) = connect_and_handshake(&path, &client);
        let HelloResponse::Rejected(error) = response else {
            panic!("invalid hello was accepted");
        };
        assert_eq!(error.code, expected_code);
    }
}

#[test]
fn stale_socket_is_replaced_only_while_holding_instance_lock() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let path = binding.endpoint_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    let stale = UnixListener::bind(&path).unwrap();
    drop(stale);

    let instance = InstanceLock::acquire(&fixture.root().join("state")).unwrap();
    let listener = ControlListener::bind(&binding, &instance, controller_hello(&binding)).unwrap();
    assert!(path.exists());
    drop(listener);
    assert!(!path.exists());
}

#[test]
fn unrelated_endpoint_file_is_preserved_and_refused() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let path = binding.endpoint_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, b"keep this file").unwrap();

    let instance = InstanceLock::acquire(&fixture.root().join("state")).unwrap();
    let result = ControlListener::bind(&binding, &instance, controller_hello(&binding));
    assert!(result.is_err());
    assert_eq!(fs::read(path).unwrap(), b"keep this file");
    fs::remove_file(binding.endpoint_path()).unwrap();
}

#[test]
fn partial_handshake_does_not_block_another_client_request() {
    let fixture = Fixture::new();
    let binding = fixture.binding();
    let hello = controller_hello(&binding);
    let instance = InstanceLock::acquire(&fixture.root().join("state")).unwrap();
    let mut listener = ControlListener::bind(&binding, &instance, hello.clone()).unwrap();
    let path = listener.path().to_path_buf();

    let mut slow = UnixStream::connect(&path).unwrap();
    slow.write_all(&[0, 0]).unwrap();
    let client_path = path.clone();
    let client_identity = client_hello(&binding);
    let client = thread::spawn(move || {
        let (mut stream, greeting) = connect_and_handshake(&client_path, &client_identity);
        assert!(matches!(greeting, HelloResponse::Accepted(_)));
        let request_id = RequestId(Id128::random());
        write_frame(
            &mut stream,
            &ControlRequest {
                request_id,
                expected_generation: Some(hello.config_generation),
                command: ControlCommand::Status,
            },
        )
        .unwrap();
        let response: ControlResponse = read_frame(&mut stream).unwrap().unwrap();
        assert_eq!(response.request_id, request_id);
    });

    let start = Instant::now();
    let request = wait_request(&mut listener);
    assert!(start.elapsed() < Duration::from_secs(2));
    request.respond(Ok(ControlPayload::Status(hello))).unwrap();
    client.join().unwrap();
    drop(slow);
}
