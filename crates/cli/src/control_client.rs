use std::{io, os::unix::net::UnixStream, time::Duration};

use macluster_core::service::{ServiceBinding, ServiceError, peer_uid};
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ClientHello, ControlErrorCode, ControlPayload, ControlRequest,
        ControlResponse, ControllerHello, HelloResponse,
    },
    framing::{FrameError, read_frame, write_frame},
    identifiers::{Id128, RequestId},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControlClientError {
    #[error("controller is unavailable: {0}")]
    Io(#[from] io::Error),
    #[error("controller control frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("service binding error: {0}")]
    Binding(#[from] ServiceError),
    #[error("controller rejected the local request ({code:?}): {message}")]
    Remote {
        code: ControlErrorCode,
        message: String,
    },
    #[error("controller hello does not match this CLI's cluster binding")]
    WrongCluster,
    #[error("controller response did not match the request ID")]
    RequestMismatch,
}

pub struct ControlClient {
    stream: UnixStream,
    hello: ControllerHello,
}

impl ControlClient {
    pub fn connect(
        binding: &ServiceBinding,
        timeout: Duration,
    ) -> Result<Self, ControlClientError> {
        binding.prepare_endpoint_dir()?;
        let mut stream = UnixStream::connect(binding.endpoint_path())?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        if peer_uid(&stream)? != binding.uid() {
            return Err(ControlClientError::WrongCluster);
        }
        write_frame(
            &mut stream,
            &ClientHello {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                binding_digest: binding.binding_digest().to_owned(),
                namespace: binding.namespace().to_owned(),
                uid: binding.uid(),
                build_id: concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")).into(),
                capabilities: vec![
                    "status.v1".into(),
                    "jobs.v1".into(),
                    "snapshot.upload.v1".into(),
                    "agent.compatibility.v1".into(),
                    "monitor.v1".into(),
                    "maintenance.v1".into(),
                ],
            },
        )?;
        let response: HelloResponse = read_frame(&mut stream)?.ok_or_else(|| {
            ControlClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "controller closed during hello",
            ))
        })?;
        let hello = match response {
            HelloResponse::Accepted(hello) => hello,
            HelloResponse::Rejected(error) => {
                return Err(ControlClientError::Remote {
                    code: error.code,
                    message: error.message,
                });
            }
        };
        if hello.protocol_version != CONTROL_PROTOCOL_VERSION
            || hello.binding_digest != binding.binding_digest()
            || hello.namespace != binding.namespace()
            || hello.uid != binding.uid()
        {
            return Err(ControlClientError::WrongCluster);
        }
        Ok(Self { stream, hello })
    }

    pub fn hello(&self) -> &ControllerHello {
        &self.hello
    }

    pub fn set_timeouts(&self, timeout: Duration) -> Result<(), ControlClientError> {
        self.stream.set_read_timeout(Some(timeout))?;
        self.stream.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    pub fn shutdown_handle(&self) -> io::Result<UnixStream> {
        self.stream.try_clone()
    }

    pub fn call(&mut self, request: ControlRequest) -> Result<ControlResponse, ControlClientError> {
        let request_id = request.request_id;
        write_frame(&mut self.stream, &request)?;
        let response: ControlResponse = read_frame(&mut self.stream)?.ok_or_else(|| {
            ControlClientError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "controller closed before replying",
            ))
        })?;
        if response.request_id != request_id {
            return Err(ControlClientError::RequestMismatch);
        }
        Ok(response)
    }

    pub fn request(
        &mut self,
        command: macluster_protocol::control::ControlCommand,
    ) -> Result<ControlPayload, ControlClientError> {
        let response = self.call(ControlRequest {
            request_id: RequestId(Id128::random()),
            expected_generation: Some(self.hello.config_generation),
            command,
        })?;
        response.result.map_err(|error| ControlClientError::Remote {
            code: error.code,
            message: error.message,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        thread,
        time::{Duration, Instant},
    };

    use macluster_controller::{ControlListener, InstanceLock};
    use macluster_core::service::ServiceBinding;
    use macluster_protocol::{
        control::{CONTROL_PROTOCOL_VERSION, ControlPayload, ControllerHello, ControllerLifecycle},
        identifiers::{ControllerUuid, Id128},
        types::ControllerEpoch,
    };

    use super::ControlClient;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("macluster-cli-control-{}", Id128::random()));
            fs::create_dir_all(&root).unwrap();
            fs::create_dir(root.join("state")).unwrap();
            fs::write(
                root.join("config.toml"),
                format!(
                    "[cluster]\nname=\"cli-control\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"ssh\"\n",
                    root.display()
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

    fn hello(binding: &ServiceBinding) -> ControllerHello {
        ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().to_owned(),
            namespace: binding.namespace().to_owned(),
            uid: binding.uid(),
            build_id: "test-controller".into(),
            capabilities: vec!["status.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 9,
            lifecycle: ControllerLifecycle::Ready,
        }
    }

    fn wait_request(
        listener: &mut ControlListener<'_>,
    ) -> macluster_controller::PendingControlRequest {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(request) = listener.poll_request() {
                return request;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for status request"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn control_client_authenticates_controller_and_requests_status() {
        let fixture = Fixture::new();
        let binding = fixture.binding();
        let expected = hello(&binding);
        let instance = InstanceLock::acquire(&fixture.root().join("state")).unwrap();
        let mut listener = ControlListener::bind(&binding, &instance, expected.clone()).unwrap();
        let client_binding = binding.clone();
        let client_expected = expected.clone();
        let client = thread::spawn(move || {
            let mut client =
                ControlClient::connect(&client_binding, Duration::from_secs(2)).unwrap();
            assert_eq!(client.hello(), &client_expected);
            match client
                .request(macluster_protocol::control::ControlCommand::Status)
                .unwrap()
            {
                ControlPayload::Status(status) => status,
                _ => panic!("controller returned an unexpected status payload"),
            }
        });

        let request = wait_request(&mut listener);
        let response = expected.clone();
        request
            .respond(Ok(ControlPayload::Status(response)))
            .unwrap();
        assert_eq!(client.join().unwrap(), expected);
    }
}
