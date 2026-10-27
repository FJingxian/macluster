use std::{
    fs, io,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use macluster_core::service::{ServiceBinding, ServiceError, peer_uid};
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ClientHello, ControlCommand, ControlError, ControlErrorCode,
        ControlPayload, ControlRequest, ControlResponse, ControllerHello, HelloResponse,
    },
    framing::{FrameError, read_frame, write_frame},
    identifiers::Id128,
};
use thiserror::Error;

use crate::{InstanceLock, events::RuntimeSignal};

const MAX_CONNECTIONS: usize = 32;
const MAX_PENDING_REQUESTS: usize = 64;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MONITOR_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const BUSY_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("control IPC I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("control IPC frame error: {0}")]
    Frame(#[from] FrameError),
    #[error("service binding error: {0}")]
    Binding(#[from] ServiceError),
    #[error("control listener received a binding that does not match its instance lock")]
    InstanceLockMismatch,
    #[error("controller hello does not match its service binding")]
    InvalidHello,
    #[error("control endpoint is occupied by a non-owned or non-socket file: {0}")]
    UnsafeEndpoint(PathBuf),
    #[error("could not start control listener thread: {0}")]
    Thread(String),
    #[error("the control client disconnected before its request was answered")]
    ClientDisconnected,
}

pub struct ControlListener<'lock> {
    path: PathBuf,
    device: u64,
    inode: u64,
    stopping: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
    request_receiver: Receiver<PendingControlEvent>,
    runtime_signal: Arc<Mutex<Option<RuntimeSignal>>>,
    hello: Arc<Mutex<ControllerHello>>,
    _instance: &'lock InstanceLock,
}

pub struct PendingControlRequest {
    request: ControlRequest,
    response_sender: SyncSender<Result<ControlPayload, ControlError>>,
    client_session: Id128,
}

pub enum PendingControlEvent {
    Request(PendingControlRequest),
    Disconnected(Id128),
}

impl PendingControlRequest {
    pub fn request(&self) -> &ControlRequest {
        &self.request
    }

    pub fn client_session(&self) -> Id128 {
        self.client_session
    }

    pub fn respond(self, result: Result<ControlPayload, ControlError>) -> Result<(), IpcError> {
        self.response_sender
            .send(result)
            .map_err(|_| IpcError::ClientDisconnected)
    }
}

impl<'lock> ControlListener<'lock> {
    pub fn bind(
        binding: &ServiceBinding,
        instance: &'lock InstanceLock,
        hello: ControllerHello,
    ) -> Result<Self, IpcError> {
        if instance.state_dir() != binding.state_dir() {
            return Err(IpcError::InstanceLockMismatch);
        }
        if hello.protocol_version != CONTROL_PROTOCOL_VERSION
            || hello.binding_digest != binding.binding_digest()
            || hello.namespace != binding.namespace()
            || hello.uid != binding.uid()
        {
            return Err(IpcError::InvalidHello);
        }
        binding.prepare_endpoint_dir()?;
        let path = binding.endpoint_path();
        remove_stale_endpoint(&path, binding.uid())?;

        let listener = UnixListener::bind(&path)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == binding.uid() => {
                metadata
            }
            Ok(_) => {
                drop(listener);
                return Err(IpcError::UnsafeEndpoint(path));
            }
            Err(error) => {
                drop(listener);
                return Err(error.into());
            }
        };
        let device = metadata.dev();
        let inode = metadata.ino();
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
            drop(listener);
            remove_owned_socket(&path, binding.uid(), device, inode);
            return Err(error.into());
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                drop(listener);
                remove_owned_socket(&path, binding.uid(), device, inode);
                return Err(error.into());
            }
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != binding.uid()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            drop(listener);
            remove_owned_socket(&path, binding.uid(), device, inode);
            return Err(IpcError::UnsafeEndpoint(path));
        }

        let (request_sender, request_receiver) = mpsc::sync_channel(MAX_PENDING_REQUESTS);
        let stopping = Arc::new(AtomicBool::new(false));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let runtime_signal = Arc::new(Mutex::new(None));
        let shared_hello = Arc::new(Mutex::new(hello));
        let thread_stopping = Arc::clone(&stopping);
        let thread_connections = Arc::clone(&active_connections);
        let thread_signal = Arc::clone(&runtime_signal);
        let thread_hello = Arc::clone(&shared_hello);
        let thread_binding = binding.clone();
        let accept_thread = match thread::Builder::new()
            .name("macluster-control-accept".into())
            .spawn(move || {
                accept_loop(
                    listener,
                    thread_binding,
                    thread_hello,
                    request_sender,
                    thread_stopping,
                    thread_connections,
                    thread_signal,
                );
            }) {
            Ok(thread) => thread,
            Err(error) => {
                remove_owned_socket(&path, binding.uid(), device, inode);
                return Err(IpcError::Thread(error.to_string()));
            }
        };

        Ok(Self {
            path,
            device,
            inode,
            stopping,
            accept_thread: Some(accept_thread),
            request_receiver,
            runtime_signal,
            hello: shared_hello,
            _instance: instance,
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn set_runtime_signal(&mut self, signal: RuntimeSignal) {
        if let Ok(mut current) = self.runtime_signal.lock() {
            *current = Some(signal);
        }
    }

    /// Publish the current config generation/lifecycle for new local clients.
    /// Existing streams keep their original hello and are rejected by the
    /// generation fence after a successful config reload.
    pub fn set_hello(&self, hello: ControllerHello) -> Result<(), IpcError> {
        let mut current = self
            .hello
            .lock()
            .map_err(|_| IpcError::Thread("controller hello mutex is poisoned".into()))?;
        if hello.protocol_version != current.protocol_version
            || hello.binding_digest != current.binding_digest
            || hello.namespace != current.namespace
            || hello.uid != current.uid
        {
            return Err(IpcError::InvalidHello);
        }
        *current = hello;
        Ok(())
    }

    pub fn poll_request(&mut self) -> Option<PendingControlRequest> {
        loop {
            match self.request_receiver.try_recv() {
                Ok(PendingControlEvent::Request(request)) => return Some(request),
                Ok(PendingControlEvent::Disconnected(_)) => continue,
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return None,
            }
        }
    }

    pub fn poll_event(&mut self) -> Option<PendingControlEvent> {
        self.request_receiver.try_recv().ok()
    }
}

impl Drop for ControlListener<'_> {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.accept_thread.take() {
            let _ = thread.join();
        }
        remove_owned_socket(
            &self.path,
            unsafe { libc::geteuid() },
            self.device,
            self.inode,
        );
    }
}

fn remove_owned_socket(path: &std::path::Path, uid: u32, device: u64, inode: u64) {
    if fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_socket()
            && metadata.uid() == uid
            && metadata.dev() == device
            && metadata.ino() == inode
    }) {
        let _ = fs::remove_file(path);
    }
}

fn remove_stale_endpoint(path: &std::path::Path, expected_uid: u32) -> Result<(), IpcError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == expected_uid => {
            fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => Err(IpcError::UnsafeEndpoint(path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn accept_loop(
    listener: UnixListener,
    binding: ServiceBinding,
    hello: Arc<Mutex<ControllerHello>>,
    request_sender: SyncSender<PendingControlEvent>,
    stopping: Arc<AtomicBool>,
    active_connections: Arc<AtomicUsize>,
    runtime_signal: Arc<Mutex<Option<RuntimeSignal>>>,
) {
    loop {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if stopping.load(Ordering::Acquire) {
            return;
        }
        if peer_uid(&stream).map_or(true, |uid| uid != binding.uid()) {
            continue;
        }
        if !reserve_connection(&active_connections) {
            reject_busy(stream);
            continue;
        }

        let connection_count = Arc::clone(&active_connections);
        let connection_binding = binding.clone();
        let connection_hello = Arc::clone(&hello);
        let connection_requests = request_sender.clone();
        let connection_signal = Arc::clone(&runtime_signal);
        let spawn = thread::Builder::new()
            .name("macluster-control-client".into())
            .spawn(move || {
                serve_connection(
                    stream,
                    &connection_binding,
                    &connection_hello,
                    &connection_requests,
                    &connection_signal,
                );
                connection_count.fetch_sub(1, Ordering::AcqRel);
            });
        if spawn.is_err() {
            active_connections.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn reserve_connection(active: &AtomicUsize) -> bool {
    let mut current = active.load(Ordering::Acquire);
    loop {
        if current >= MAX_CONNECTIONS {
            return false;
        }
        match active.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn reject_busy(mut stream: UnixStream) {
    let _ = stream.set_write_timeout(Some(BUSY_WRITE_TIMEOUT));
    let _ = write_frame(
        &mut stream,
        &HelloResponse::Rejected(ControlError {
            code: ControlErrorCode::Busy,
            message: "controller is handling the maximum number of local clients".into(),
        }),
    );
}

fn serve_connection(
    mut stream: UnixStream,
    binding: &ServiceBinding,
    controller_hello: &Arc<Mutex<ControllerHello>>,
    request_sender: &SyncSender<PendingControlEvent>,
    runtime_signal: &Arc<Mutex<Option<RuntimeSignal>>>,
) {
    if stream.set_read_timeout(Some(HELLO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(HELLO_TIMEOUT)).is_err()
    {
        return;
    }
    let hello: ClientHello = match read_frame(&mut stream) {
        Ok(Some(hello)) => hello,
        Ok(None) | Err(_) => return,
    };
    if let Err(error) = validate_client_hello(&hello, binding) {
        let _ = write_frame(&mut stream, &HelloResponse::Rejected(error));
        return;
    }
    let initial_hello = match controller_hello.lock() {
        Ok(hello) => hello.clone(),
        Err(_) => return,
    };
    if write_frame(&mut stream, &HelloResponse::Accepted(initial_hello)).is_err() {
        return;
    }
    let client_session = Id128::random();
    let _disconnect_notice = DisconnectNotice {
        session: client_session,
        sender: request_sender.clone(),
        runtime_signal: Arc::clone(runtime_signal),
    };
    if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_err()
    {
        return;
    }

    loop {
        let request: ControlRequest = match read_frame(&mut stream) {
            Ok(Some(request)) => request,
            Ok(None) | Err(_) => return,
        };
        let monitor_session = matches!(
            &request.command,
            ControlCommand::SubscribeMonitor { .. }
                | ControlCommand::WatchProcesses { .. }
                | ControlCommand::MonitorSnapshot { .. }
        );
        let request_id = request.request_id;
        let current_generation = match controller_hello.lock() {
            Ok(hello) => hello.config_generation,
            Err(_) => return,
        };
        if request
            .expected_generation
            .is_some_and(|generation| generation != current_generation)
        {
            let response = ControlResponse {
                request_id,
                result: Err(ControlError {
                    code: ControlErrorCode::StaleGeneration,
                    message: "controller configuration changed; reconnect and retry".into(),
                }),
            };
            if write_frame(&mut stream, &response).is_err() {
                return;
            }
            continue;
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        match request_sender.try_send(PendingControlEvent::Request(PendingControlRequest {
            request,
            response_sender,
            client_session,
        })) {
            Ok(()) => notify_runtime(runtime_signal),
            Err(mpsc::TrySendError::Full(_)) => {
                let response = ControlResponse {
                    request_id,
                    result: Err(ControlError {
                        code: ControlErrorCode::Busy,
                        message: "controller request queue is full".into(),
                    }),
                };
                if write_frame(&mut stream, &response).is_err() {
                    return;
                }
                continue;
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return,
        }
        let result = match response_receiver.recv_timeout(REQUEST_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ControlError {
                code: ControlErrorCode::Busy,
                message: "controller did not process the request before its deadline".into(),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        if write_frame(&mut stream, &ControlResponse { request_id, result }).is_err() {
            return;
        }
        if monitor_session
            && stream
                .set_read_timeout(Some(MONITOR_SESSION_TIMEOUT))
                .is_err()
        {
            return;
        }
    }
}

struct DisconnectNotice {
    session: Id128,
    sender: SyncSender<PendingControlEvent>,
    runtime_signal: Arc<Mutex<Option<RuntimeSignal>>>,
}

impl Drop for DisconnectNotice {
    fn drop(&mut self) {
        if self
            .sender
            .try_send(PendingControlEvent::Disconnected(self.session))
            .is_ok()
        {
            notify_runtime(&self.runtime_signal);
        }
    }
}

fn notify_runtime(runtime_signal: &Mutex<Option<RuntimeSignal>>) {
    if let Ok(signal) = runtime_signal.lock()
        && let Some(signal) = signal.as_ref()
    {
        signal.notify();
    }
}

fn validate_client_hello(
    hello: &ClientHello,
    binding: &ServiceBinding,
) -> Result<(), ControlError> {
    if hello.protocol_version != CONTROL_PROTOCOL_VERSION {
        return Err(ControlError {
            code: ControlErrorCode::IncompatibleProtocol,
            message: format!(
                "control protocol version {} is unsupported; expected {}",
                hello.protocol_version, CONTROL_PROTOCOL_VERSION
            ),
        });
    }
    if hello.uid != binding.uid() {
        return Err(ControlError {
            code: ControlErrorCode::WrongPeer,
            message: "control client UID does not match the service owner".into(),
        });
    }
    if hello.namespace != binding.namespace() || hello.binding_digest != binding.binding_digest() {
        return Err(ControlError {
            code: ControlErrorCode::WrongCluster,
            message: "control client is bound to a different cluster or state directory".into(),
        });
    }
    if hello.build_id.is_empty()
        || hello.build_id.len() > 256
        || hello.capabilities.len() > 32
        || hello
            .capabilities
            .iter()
            .any(|capability| capability.len() > 128)
    {
        return Err(ControlError {
            code: ControlErrorCode::InvalidRequest,
            message: "control hello contains invalid build or capability fields".into(),
        });
    }
    Ok(())
}
