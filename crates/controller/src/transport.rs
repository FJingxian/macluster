//! Bounded subprocess transports for the framed node agent protocol.

use std::{
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::config::{NodeConfig, Transport};
use macluster_protocol::{
    framing::{read_frame, write_frame},
    identifiers::{NodeId, RequestId, StartToken},
    types::{Operation, PROTOCOL_VERSION, ProtocolError, Request, Response, ResponseBody},
};
use thiserror::Error;

use crate::ssh::{ConnectionKey, SshPool};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_OUTSTANDING_PROBES: usize = 64;
const INTERACTIVE_SSH_ALIVE_INTERVAL: &str = "-oServerAliveInterval=15";
const INTERACTIVE_SSH_ALIVE_COUNT: &str = "-oServerAliveCountMax=4";
static OUTSTANDING_PROBES: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("node transport error: {0}")]
    Io(String),
    #[error("node transport timed out")]
    Timeout,
    #[error("node transport probe limit reached")]
    Capacity,
    #[error("node agent rejected the request: {0}")]
    Remote(#[from] ProtocolError),
    #[error("node agent returned an invalid response: {0}")]
    Protocol(String),
}

pub trait NodeTransport: Send + Sync + 'static {
    fn call(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        operation: Operation,
    ) -> Result<ResponseBody, TransportError>;
}

#[derive(Clone, Debug)]
pub struct ClusterTransport {
    config_path: PathBuf,
    ssh_pool: SshPool,
    pub timeout: Duration,
}

impl ClusterTransport {
    pub fn new(config_path: PathBuf) -> Self {
        let namespace = format!("config-path:{}", config_path.display());
        Self::new_with_namespace(config_path, namespace)
    }

    pub fn new_with_namespace(config_path: PathBuf, namespace: impl Into<String>) -> Self {
        Self {
            config_path,
            ssh_pool: SshPool::new(namespace),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn command_for(node_id: &NodeId, node: &NodeConfig, config_path: &Path) -> Command {
        Self::command_for_with_pool(node_id, node, config_path, None)
            .expect("unpooled SSH command construction cannot fail")
    }

    fn command_for_with_pool(
        node_id: &NodeId,
        node: &NodeConfig,
        config_path: &Path,
        pool: Option<&SshPool>,
    ) -> Result<Command, TransportError> {
        match node.transport {
            Transport::Local => {
                let mut command = Command::new(&node.remote_binary);
                command.arg("--config").arg(config_path).args([
                    "internal",
                    "agent-stdio",
                    "--node",
                    node_id.as_str(),
                ]);
                Ok(command)
            }
            Transport::Ssh => {
                let mut command = Command::new("/usr/bin/ssh");
                command.args([
                    "-T",
                    "-oLogLevel=ERROR",
                    "-oBatchMode=yes",
                    "-oStrictHostKeyChecking=yes",
                    "-oConnectTimeout=5",
                    "-oServerAliveInterval=5",
                    "-oServerAliveCountMax=1",
                ]);
                node.add_ssh_identity_args(&mut command);
                if let Some(pool) = pool {
                    if let Ok(key) =
                        ConnectionKey::for_node(pool.namespace(), node_id.as_str(), node)
                    {
                        // Connection pooling is an optimization. If the private
                        // socket directory is unavailable, keep ordinary SSH
                        // transport available rather than blocking scheduling.
                        let _ = pool.append_args(&key, &mut command);
                    }
                }
                command.arg(&node.host).arg(&node.remote_binary);
                node.add_remote_config_args(&mut command);
                command.args(["internal", "agent-stdio", "--node", node_id.as_str()]);
                Ok(command)
            }
        }
    }

    #[cfg(test)]
    fn interactive_attach_command_for(
        node_id: &NodeId,
        node: &NodeConfig,
        config_path: &Path,
        job_id: u64,
        start_token: StartToken,
    ) -> Command {
        Self::interactive_attach_command_with_pool(
            node_id,
            node,
            config_path,
            job_id,
            start_token,
            None,
        )
        .expect("unpooled SSH command construction cannot fail")
    }

    fn interactive_attach_command_with_pool(
        node_id: &NodeId,
        node: &NodeConfig,
        config_path: &Path,
        job_id: u64,
        start_token: StartToken,
        pool: Option<&SshPool>,
    ) -> Result<Command, TransportError> {
        match node.transport {
            Transport::Local => {
                let mut command = Command::new(&node.remote_binary);
                command
                    .arg("--config")
                    .arg(config_path)
                    .args([
                        "internal",
                        "agent-attach",
                        "--node",
                        node_id.as_str(),
                        "--job-id",
                    ])
                    .arg(job_id.to_string())
                    .arg("--start-token")
                    .arg(start_token.to_string());
                Ok(command)
            }
            Transport::Ssh => {
                let mut command = Command::new("/usr/bin/ssh");
                command.args([
                    "-tt",
                    "-oLogLevel=ERROR",
                    "-oBatchMode=yes",
                    "-oStrictHostKeyChecking=yes",
                    "-oConnectTimeout=5",
                    INTERACTIVE_SSH_ALIVE_INTERVAL,
                    INTERACTIVE_SSH_ALIVE_COUNT,
                ]);
                node.add_ssh_identity_args(&mut command);
                if let Some(pool) = pool {
                    if let Ok(key) =
                        ConnectionKey::for_node(pool.namespace(), node_id.as_str(), node)
                    {
                        let _ = pool.append_args(&key, &mut command);
                    }
                }
                command.arg(&node.host).arg(&node.remote_binary);
                node.add_remote_config_args(&mut command);
                command
                    .args([
                        "internal",
                        "agent-attach",
                        "--node",
                        node_id.as_str(),
                        "--job-id",
                    ])
                    .arg(job_id.to_string())
                    .arg("--start-token")
                    .arg(start_token.to_string());
                Ok(command)
            }
        }
    }

    /// Attach to the runner-owned PTY on an allocated node. The caller owns
    /// local terminal mode and waits for the authoritative job record after
    /// this stdio relay exits.
    pub fn attach_interactive(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        job_id: u64,
        start_token: StartToken,
    ) -> Result<i32, TransportError> {
        let mut command = Self::interactive_attach_command_with_pool(
            node_id,
            node,
            &self.config_path,
            job_id,
            start_token,
            Some(&self.ssh_pool),
        )?;
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = command
            .status()
            .map_err(|error| TransportError::Io(error.to_string()))?;
        interactive_attach_exit_code(node.transport, node_id, status.code().unwrap_or(1))
    }
}

fn interactive_attach_exit_code(
    transport: Transport,
    node_id: &NodeId,
    exit_code: i32,
) -> Result<i32, TransportError> {
    if transport == Transport::Ssh && exit_code == 255 {
        return Err(TransportError::Io(format!(
            "interactive SSH connection to node '{node_id}' ended with exit status 255; see the SSH diagnostics above"
        )));
    }
    Ok(exit_code)
}

impl NodeTransport for ClusterTransport {
    fn call(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        operation: Operation,
    ) -> Result<ResponseBody, TransportError> {
        let request_id = RequestId::random();
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            operation,
        };
        let mut request_bytes = Vec::new();
        write_frame(&mut request_bytes, &request)
            .map_err(|error| TransportError::Protocol(error.to_string()))?;
        let command =
            Self::command_for_with_pool(node_id, node, &self.config_path, Some(&self.ssh_pool))?;
        let timeout = if self.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            self.timeout
        };
        let output = run_child_bounded(command, Some(request_bytes), timeout)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(TransportError::Io(if stderr.is_empty() {
                format!("node agent exited with {}", output.status)
            } else {
                stderr
            }));
        }
        let response = read_frame::<_, Response>(&mut Cursor::new(output.stdout))
            .map_err(|error| TransportError::Protocol(error.to_string()))?
            .ok_or_else(|| {
                TransportError::Protocol("node agent closed without a response".into())
            })?;
        if response.protocol_version != PROTOCOL_VERSION || response.request_id != request_id {
            return Err(TransportError::Protocol(
                "protocol version or request ID mismatch".into(),
            ));
        }
        response.result.map_err(TransportError::Remote)
    }
}

/// Kept as a source-compatible transport for the node enrollment code. New
/// controller and local-aware callers should use `ClusterTransport`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SshTransport {
    pub timeout: Duration,
}

impl NodeTransport for SshTransport {
    fn call(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        operation: Operation,
    ) -> Result<ResponseBody, TransportError> {
        let command = ClusterTransport::command_for(node_id, node, Path::new("/dev/null"));
        if node.transport == Transport::Local {
            return Err(TransportError::Io(
                "SshTransport cannot be used with a local node".into(),
            ));
        }
        let request_id = RequestId::random();
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            operation,
        };
        let mut request_bytes = Vec::new();
        write_frame(&mut request_bytes, &request)
            .map_err(|error| TransportError::Protocol(error.to_string()))?;
        let timeout = if self.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            self.timeout
        };
        let output = run_child_bounded(command, Some(request_bytes), timeout)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(TransportError::Io(if stderr.is_empty() {
                format!("ssh exited with {}", output.status)
            } else {
                stderr
            }));
        }
        let response = read_frame::<_, Response>(&mut Cursor::new(output.stdout))
            .map_err(|error| TransportError::Protocol(error.to_string()))?
            .ok_or_else(|| {
                TransportError::Protocol("remote agent closed without a response".into())
            })?;
        if response.protocol_version != PROTOCOL_VERSION || response.request_id != request_id {
            return Err(TransportError::Protocol(
                "protocol version or request ID mismatch".into(),
            ));
        }
        response.result.map_err(TransportError::Remote)
    }
}

struct ProbePermit;

impl ProbePermit {
    fn acquire() -> Result<Self, TransportError> {
        let mut active = OUTSTANDING_PROBES.load(Ordering::Acquire);
        loop {
            if active >= MAX_OUTSTANDING_PROBES {
                return Err(TransportError::Capacity);
            }
            match OUTSTANDING_PROBES.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(actual) => active = actual,
            }
        }
    }
}

impl Drop for ProbePermit {
    fn drop(&mut self) {
        OUTSTANDING_PROBES.fetch_sub(1, Ordering::AcqRel);
    }
}

type OutputReader = thread::JoinHandle<io::Result<Vec<u8>>>;
type InputWriter = thread::JoinHandle<io::Result<()>>;

fn io_threads_finished(
    stdout: &OutputReader,
    stderr: &OutputReader,
    writer: Option<&InputWriter>,
) -> bool {
    stdout.is_finished()
        && stderr.is_finished()
        && writer.is_none_or(thread::JoinHandle::is_finished)
}

fn wait_for_io_threads(
    stdout: &OutputReader,
    stderr: &OutputReader,
    writer: Option<&InputWriter>,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while !io_threads_finished(stdout, stderr, writer) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    io_threads_finished(stdout, stderr, writer)
}

fn spawn_child_reaper(
    child: Option<std::process::Child>,
    stdout: OutputReader,
    stderr: OutputReader,
    writer: Option<InputWriter>,
    permit: Arc<ProbePermit>,
) {
    let retained_permit = Arc::clone(&permit);
    let result = thread::Builder::new()
        .name("macluster-child-reaper".into())
        .spawn(move || {
            if let Some(mut child) = child {
                let _ = child.wait();
            }
            let _ = stdout.join();
            let _ = stderr.join();
            if let Some(writer) = writer {
                let _ = writer.join();
            }
            drop(permit);
        });
    if result.is_err() {
        // Fail closed: a stuck child or inherited pipe must continue to occupy
        // a probe slot even if the OS cannot create its reaper thread.
        std::mem::forget(retained_permit);
    }
}

fn read_capped<R: Read>(mut reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
    }
    Ok(kept)
}

#[cfg(unix)]
fn signal_process_group(pid: u32, signal: libc::c_int) {
    // `process_group(0)` below makes the child its own group leader.
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}

pub fn run_child_bounded(
    mut command: Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<Output, TransportError> {
    let permit = Arc::new(ProbePermit::acquire()?);
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| TransportError::Io(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| TransportError::Io("child stdout was not piped".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| TransportError::Io("child stderr was not piped".into()))?;
    let stdout_permit = Arc::clone(&permit);
    let stdout_reader = thread::spawn(move || {
        let _permit = stdout_permit;
        read_capped(stdout, MAX_STDOUT_BYTES)
    });
    let stderr_permit = Arc::clone(&permit);
    let stderr_reader = thread::spawn(move || {
        let _permit = stderr_permit;
        read_capped(stderr, MAX_STDERR_BYTES)
    });
    let writer = input.map(|bytes| {
        let mut stdin = child
            .stdin
            .take()
            .expect("piped stdin exists when input is set");
        let writer_permit = Arc::clone(&permit);
        thread::spawn(move || {
            let _permit = writer_permit;
            stdin.write_all(&bytes)
        })
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
            Ok(None) => break None,
            Err(error) => {
                #[cfg(unix)]
                signal_process_group(child.id(), libc::SIGKILL);
                let _ = child.kill();
                spawn_child_reaper(
                    Some(child),
                    stdout_reader,
                    stderr_reader,
                    writer,
                    Arc::clone(&permit),
                );
                return Err(TransportError::Io(error.to_string()));
            }
        }
    };
    let Some(status) = status else {
        #[cfg(unix)]
        signal_process_group(child.id(), libc::SIGTERM);
        let grace = Instant::now() + Duration::from_millis(150);
        while Instant::now() < grace && child.try_wait().ok().flatten().is_none() {
            thread::sleep(Duration::from_millis(10));
        }
        if child.try_wait().ok().flatten().is_none() {
            #[cfg(unix)]
            signal_process_group(child.id(), libc::SIGKILL);
            let _ = child.kill();
        }
        let reap_deadline = Instant::now() + Duration::from_millis(250);
        let mut reaped = child.try_wait().ok().flatten();
        while reaped.is_none() && Instant::now() < reap_deadline {
            thread::sleep(Duration::from_millis(10));
            reaped = child.try_wait().ok().flatten();
        }
        if reaped.is_none() {
            spawn_child_reaper(
                Some(child),
                stdout_reader,
                stderr_reader,
                writer,
                Arc::clone(&permit),
            );
            return Err(TransportError::Timeout);
        }
        #[cfg(unix)]
        signal_process_group(child.id(), libc::SIGKILL);
        if !wait_for_io_threads(
            &stdout_reader,
            &stderr_reader,
            writer.as_ref(),
            Duration::from_millis(250),
        ) {
            spawn_child_reaper(
                None,
                stdout_reader,
                stderr_reader,
                writer,
                Arc::clone(&permit),
            );
        }
        return Err(TransportError::Timeout);
    };
    if !wait_for_io_threads(
        &stdout_reader,
        &stderr_reader,
        writer.as_ref(),
        Duration::from_millis(100),
    ) {
        #[cfg(unix)]
        signal_process_group(child.id(), libc::SIGTERM);
        if !wait_for_io_threads(
            &stdout_reader,
            &stderr_reader,
            writer.as_ref(),
            Duration::from_millis(50),
        ) {
            #[cfg(unix)]
            signal_process_group(child.id(), libc::SIGKILL);
            if !wait_for_io_threads(
                &stdout_reader,
                &stderr_reader,
                writer.as_ref(),
                Duration::from_millis(250),
            ) {
                spawn_child_reaper(
                    None,
                    stdout_reader,
                    stderr_reader,
                    writer,
                    Arc::clone(&permit),
                );
                return Err(TransportError::Timeout);
            }
        }
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| TransportError::Io("stdout drain thread panicked".into()))?
        .map_err(|error| TransportError::Io(error.to_string()))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| TransportError::Io("stderr drain thread panicked".into()))?
        .map_err(|error| TransportError::Io(error.to_string()))?;
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| TransportError::Io("stdin writer thread panicked".into()))?
            .map_err(|error| TransportError::Io(error.to_string()))?;
    }
    drop(permit);
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn node(transport: Transport, binary: &str) -> NodeConfig {
        NodeConfig {
            host: "192.168.2.3".into(),
            transport,
            remote_binary: binary.into(),
            ssh_user: Some("operator".into()),
            ssh_port: Some(2222),
            ssh_identity_file: None,
            remote_config: Some("/Users/operator/.config/macluster/peer.toml".into()),
            machine_uuid: Some("00000000-0000-4000-8000-000000000003".into()),
            execution_uid: Some(501),
        }
    }

    #[test]
    fn local_transport_runs_the_configured_binary_without_ssh() {
        let command = ClusterTransport::command_for(
            &"login".parse().unwrap(),
            &node(Transport::Local, "/opt/macluster"),
            Path::new("/tmp/cluster.toml"),
        );
        assert_eq!(command.get_program(), "/opt/macluster");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(
            args,
            [
                "--config",
                "/tmp/cluster.toml",
                "internal",
                "agent-stdio",
                "--node",
                "login"
            ]
        );
    }

    #[test]
    fn remote_transport_keeps_strict_host_key_checking() {
        let command = ClusterTransport::command_for(
            &"mini01-a".parse().unwrap(),
            &node(Transport::Ssh, "/usr/local/bin/macluster"),
            Path::new("/tmp/cluster.toml"),
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(command.get_program(), "/usr/bin/ssh");
        assert!(args.iter().any(|arg| arg == "-oStrictHostKeyChecking=yes"));
        assert!(args.iter().any(|arg| arg == "-l"));
        assert!(args.iter().any(|arg| arg == "2222"));
    }

    #[test]
    fn controller_ssh_transport_uses_the_shared_pool_without_weakening_host_checks() {
        let node_id = "mini01-a".parse().unwrap();
        let node = node(Transport::Ssh, "/usr/local/bin/macluster");
        let pool = SshPool::new("transport-pool-test");
        let command = ClusterTransport::command_for_with_pool(
            &node_id,
            &node,
            Path::new("/tmp/cluster.toml"),
            Some(&pool),
        )
        .unwrap();
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|arg| arg == "-oControlMaster=auto"));
        assert!(args.iter().any(|arg| arg == "-oControlPersist=10"));
        assert!(args.iter().any(|arg| arg == "-oStrictHostKeyChecking=yes"));
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("-oControlPath=/tmp/"))
        );
        let control_path = args
            .iter()
            .find_map(|arg| arg.strip_prefix("-oControlPath="))
            .unwrap();
        if let Some(root) = Path::new(control_path).parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn local_interactive_attach_uses_agent_attach_command() {
        let token = macluster_protocol::identifiers::StartToken(
            macluster_protocol::identifiers::Id128::random(),
        );
        let command = ClusterTransport::interactive_attach_command_for(
            &"login".parse().unwrap(),
            &node(Transport::Local, "/opt/macluster"),
            Path::new("/tmp/cluster.toml"),
            17,
            token,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(command.get_program(), "/opt/macluster");
        assert_eq!(
            args,
            [
                "--config",
                "/tmp/cluster.toml",
                "internal",
                "agent-attach",
                "--node",
                "login",
                "--job-id",
                "17",
                "--start-token",
                token.to_string().as_str(),
            ]
        );
    }

    #[test]
    fn ssh_interactive_attach_uses_configured_identity_and_tty() {
        let token = macluster_protocol::identifiers::StartToken(
            macluster_protocol::identifiers::Id128::random(),
        );
        let command = ClusterTransport::interactive_attach_command_for(
            &"mini01-a".parse().unwrap(),
            &node(Transport::Ssh, "/usr/local/bin/macluster"),
            Path::new("/tmp/cluster.toml"),
            17,
            token,
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(command.get_program(), "/usr/bin/ssh");
        assert!(args.iter().any(|arg| arg == "-tt"));
        assert!(!args.iter().any(|arg| arg == "-T"));
        assert!(args.iter().any(|arg| arg == "-oLogLevel=ERROR"));
        assert!(args.iter().any(|arg| arg == "-oStrictHostKeyChecking=yes"));
        assert!(args.iter().any(|arg| arg == "-oServerAliveInterval=15"));
        assert!(args.iter().any(|arg| arg == "-oServerAliveCountMax=4"));
        assert!(args.windows(2).any(|pair| pair == ["-p", "2222"]));
        assert!(args.windows(2).any(|pair| pair == ["-l", "operator"]));
        let host_index = args.iter().position(|arg| arg == "192.168.2.3").unwrap();
        assert_eq!(args[host_index + 1], "/usr/local/bin/macluster");
        assert!(
            args.windows(2).any(|pair| {
                pair == ["--config", "/Users/operator/.config/macluster/peer.toml"]
            })
        );
        assert!(
            args.windows(2)
                .any(|pair| pair == ["internal", "agent-attach"])
        );
        assert!(args.windows(2).any(|pair| pair == ["--job-id", "17"]));
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--start-token", token.to_string().as_str()] })
        );
    }

    #[test]
    fn ssh_interactive_exit_255_is_reported_as_a_transport_failure() {
        let node_id = "mini01-a".parse().unwrap();
        let error = interactive_attach_exit_code(Transport::Ssh, &node_id, 255).unwrap_err();
        assert!(error.to_string().contains("interactive SSH connection"));
        assert!(error.to_string().contains("mini01-a"));
        assert_eq!(
            interactive_attach_exit_code(Transport::Local, &node_id, 255).unwrap(),
            255
        );
    }

    #[test]
    fn interactive_attach_child_inherits_callers_process_group() {
        let script = std::env::temp_dir().join(format!(
            "macluster-attach-pgrp-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::write(
            &script,
            "#!/bin/sh\nchild_group=$(/bin/ps -o pgid= -p $$ | /usr/bin/tr -d ' ')\nparent_group=$(/bin/ps -o pgid= -p $PPID | /usr/bin/tr -d ' ')\ntest \"$child_group\" = \"$parent_group\"\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let token = macluster_protocol::identifiers::StartToken(
            macluster_protocol::identifiers::Id128::random(),
        );
        let status = ClusterTransport::new(PathBuf::from("/dev/null"))
            .attach_interactive(
                &"login".parse().unwrap(),
                &node(Transport::Local, &script.to_string_lossy()),
                17,
                token,
            )
            .unwrap();
        let _ = fs::remove_file(script);
        assert_eq!(
            status, 0,
            "attach child did not inherit caller's process group"
        );
    }

    #[test]
    fn bounded_child_drains_large_stderr_without_blocking() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "dd if=/dev/zero bs=65536 count=4 1>&2 2>/dev/null; printf ok",
        ]);
        let output = run_child_bounded(command, None, Duration::from_secs(3)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ok");
        assert!(!output.stderr.is_empty());
    }

    #[test]
    fn bounded_child_times_out_and_returns_promptly() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5"]);
        let start = Instant::now();
        let result = run_child_bounded(command, None, Duration::from_millis(40));
        assert!(matches!(result, Err(TransportError::Timeout)));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
