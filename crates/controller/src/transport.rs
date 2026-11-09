//! Bounded subprocess transports for the framed node agent protocol.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Cursor, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::{
    agent_update::{AutoAgentUpdateEntry, AutoAgentUpdateReceipts},
    config::{NodeConfig, Transport},
};
use macluster_protocol::{
    framing::{read_frame, write_frame},
    identifiers::{Id128, NodeId, RequestId, StartToken},
    types::{Operation, PROTOCOL_VERSION, ProtocolError, Request, Response, ResponseBody},
};
use thiserror::Error;

use crate::ssh::{ConnectionKey, SshPool};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const NODE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const FAN_CONTROL_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const NFS_RECONCILE_TIMEOUT: Duration = Duration::from_secs(150);
const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 256 * 1024;
const MAX_OUTSTANDING_PROBES: usize = 64;
const AGENT_AUTO_UPDATE_RETRY: Duration = Duration::from_secs(30);
const AGENT_AUTO_UPDATE_TIMEOUT: Duration = Duration::from_secs(120);
const INTERACTIVE_SSH_ALIVE_INTERVAL: &str = "-oServerAliveInterval=15";
const INTERACTIVE_SSH_ALIVE_COUNT: &str = "-oServerAliveCountMax=4";
static OUTSTANDING_PROBES: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_AGENT_AUTO_UPDATES: AtomicUsize = AtomicUsize::new(0);
const MAX_CONCURRENT_AGENT_AUTO_UPDATES: usize = 4;

fn bounded_timeout(configured: Duration, maximum: Duration) -> Duration {
    if configured.is_zero() {
        maximum
    } else {
        configured.min(maximum)
    }
}

fn operation_timeout(operation: &Operation, configured: Duration) -> Duration {
    match operation {
        Operation::ReconcileNfs { .. } => NFS_RECONCILE_TIMEOUT,
        Operation::Fence { .. }
        | Operation::Status
        | Operation::RecoverJob { .. }
        | Operation::Health => bounded_timeout(configured, NODE_PROBE_TIMEOUT),
        Operation::SetFanPolicy { .. } | Operation::QueryFanPolicy => {
            bounded_timeout(configured, FAN_CONTROL_OPERATION_TIMEOUT)
        }
        _ if configured.is_zero() => DEFAULT_TIMEOUT,
        _ => configured,
    }
}

fn response_requires_agent_refresh(
    operation: &Operation,
    result: &Result<ResponseBody, TransportError>,
) -> bool {
    match result {
        Ok(ResponseBody::Health(health)) if matches!(operation, Operation::Health) => {
            health.build_id.as_deref() != Some(macluster_protocol::BUILD_ID)
        }
        Err(TransportError::Remote(ProtocolError::IncompatibleVersion)) => true,
        Err(TransportError::Io(error)) => agent_command_is_missing_or_incompatible(error),
        _ => false,
    }
}

fn agent_command_is_missing_or_incompatible(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.contains("no such file or directory")
        || error.contains("unknown command 'internal'")
        || error.contains("unexpected argument '--config'")
        || error.contains("unknown option '--config'")
        || error.contains("unrecognized option '--config'")
}

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

    /// A cheap reachability hint for retrying a known-offline SSH node. The
    /// controller uses it to avoid spawning SSH while the endpoint is down.
    fn endpoint_reachable(&self, _node: &NodeConfig, _timeout: Duration) -> Option<bool> {
        None
    }

    /// Host-level reachability, independent from whether the SSH/Agent
    /// endpoint is responding. Implementations can use ICMP as a fallback.
    fn host_reachable(&self, node: &NodeConfig, timeout: Duration) -> Option<bool> {
        self.endpoint_reachable(node, timeout)
    }
}

fn endpoint_probe_error(error: &io::Error) -> Option<bool> {
    let code = error.raw_os_error()?;
    if matches!(
        code,
        libc::ECONNREFUSED
            | libc::ETIMEDOUT
            | libc::ECONNRESET
            | libc::ECONNABORTED
            | libc::EHOSTUNREACH
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
    ) {
        Some(false)
    } else {
        // Errors such as macOS's local-network privacy denial are
        // inconclusive; let strict SSH report its own result.
        None
    }
}

fn is_explicit_host_unreachable(error: &io::Error) -> bool {
    error.raw_os_error().is_some_and(|code| {
        matches!(
            code,
            libc::EHOSTUNREACH | libc::ENETUNREACH | libc::EHOSTDOWN
        )
    })
}

#[derive(Clone, Debug)]
pub struct ClusterTransport {
    config_path: PathBuf,
    ssh_pool: SshPool,
    pub timeout: Duration,
    cluster_id: Option<String>,
    agent_update_retry_at: Arc<Mutex<HashMap<String, Instant>>>,
    local_agent: Arc<OnceLock<Result<LocalAgentArtifact, String>>>,
    agent_cache_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct LocalAgentArtifact {
    path: PathBuf,
    digest: String,
    architectures: HashSet<String>,
}

impl ClusterTransport {
    pub fn new(config_path: PathBuf) -> Self {
        let namespace = format!("config-path:{}", config_path.display());
        Self::new_with_namespace(config_path, namespace)
    }

    pub fn new_with_namespace(config_path: PathBuf, namespace: impl Into<String>) -> Self {
        let namespace = namespace.into();
        let cluster_id = Id128::parse(&namespace).ok().map(|_| namespace.clone());
        Self {
            config_path,
            ssh_pool: SshPool::new(namespace),
            timeout: DEFAULT_TIMEOUT,
            cluster_id,
            agent_update_retry_at: Arc::new(Mutex::new(HashMap::new())),
            local_agent: Arc::new(OnceLock::new()),
            agent_cache_root: None,
        }
    }

    pub fn set_agent_cache_root(&mut self, path: PathBuf) {
        self.agent_cache_root = Some(path);
    }

    fn call_once(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        operation: Operation,
    ) -> Result<ResponseBody, TransportError> {
        let timeout = operation_timeout(&operation, self.timeout);
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
        if response.request_id != request_id {
            return Err(TransportError::Protocol(
                "node agent returned a mismatched request ID".into(),
            ));
        }
        if response.protocol_version != PROTOCOL_VERSION {
            return Err(TransportError::Remote(ProtocolError::IncompatibleVersion));
        }
        response.result.map_err(TransportError::Remote)
    }

    fn begin_agent_auto_update(&self, node_id: &str) -> bool {
        let now = Instant::now();
        let Ok(mut retry_at) = self.agent_update_retry_at.lock() else {
            return false;
        };
        retry_at.retain(|_, until| now < *until);
        if retry_at.get(node_id).is_some_and(|until| now < *until) {
            return false;
        }
        retry_at.insert(node_id.to_owned(), now + AGENT_AUTO_UPDATE_RETRY);
        true
    }

    fn try_auto_refresh_agent(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
    ) -> Result<bool, TransportError> {
        if node.transport != Transport::Ssh
            || node.machine_uuid.is_none()
            || node.execution_uid.is_none()
        {
            return Ok(false);
        }
        let Some(cluster_id) = self.cluster_id.as_deref() else {
            return Ok(false);
        };
        let Some(home) = managed_agent_home(
            &node.remote_binary,
            node.remote_config.as_deref(),
            cluster_id,
        ) else {
            return Ok(false);
        };
        let Some(_permit) = AgentAutoUpdatePermit::acquire() else {
            return Ok(false);
        };
        if !self.begin_agent_auto_update(node_id.as_str()) {
            return Ok(false);
        }
        self.stage_managed_agent(node_id, node, cluster_id, &home)?;
        if let Err(error) = self.record_auto_update_receipt(node_id, node) {
            eprintln!(
                "macluster: updated Agent on {node_id}, but could not save its local update receipt: {error}"
            );
        }
        if let Some(root) = &self.agent_cache_root {
            let _ = fs::remove_file(root.join("mtop-agent-validation.json"));
        }
        eprintln!("macluster: automatically refreshed Agent on {node_id}");
        Ok(true)
    }

    fn stage_managed_agent(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        cluster_id: &str,
        home: &str,
    ) -> Result<(), TransportError> {
        let artifact = self.local_agent_artifact()?;
        let facts_command = concat!(
            "printf 'OS='; /usr/bin/uname -s; ",
            "printf 'ARCH='; /usr/bin/uname -m; ",
            "printf 'UID='; /usr/bin/id -u; ",
            "printf 'HOME='; /usr/bin/printenv HOME; ",
            "/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice"
        );
        let facts = self.ssh_output(node_id, node, facts_command, Duration::from_secs(8))?;
        if !facts.status.success() {
            return Err(TransportError::Io(command_failure(
                "node identity preflight failed",
                &facts,
            )));
        }
        let facts_text = String::from_utf8_lossy(&facts.stdout);
        let values = facts_text
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect::<HashMap<_, _>>();
        if values.get("OS").copied() != Some("Darwin")
            || values.get("HOME").copied() != Some(home)
            || values
                .get("UID")
                .and_then(|value| value.parse::<u32>().ok())
                != node.execution_uid
        {
            return Err(TransportError::Io(
                "automatic Agent update stopped because remote OS, HOME, or execution UID changed"
                    .into(),
            ));
        }
        let actual_machine_uuid = facts_text
            .lines()
            .find(|line| line.contains("IOPlatformUUID"))
            .and_then(|line| line.rsplit_once('=').map(|(_, value)| value.trim()))
            .map(|value| value.trim_matches('"').trim())
            .ok_or_else(|| TransportError::Io("remote IOPlatformUUID was not present".into()))?;
        Id128::parse(actual_machine_uuid).map_err(|error| {
            TransportError::Io(format!("invalid remote platform UUID: {error}"))
        })?;
        if !node
            .machine_uuid
            .as_deref()
            .is_some_and(|expected| expected.eq_ignore_ascii_case(actual_machine_uuid))
        {
            return Err(TransportError::Io(
                "automatic Agent update stopped because the registered machine identity changed"
                    .into(),
            ));
        }
        let remote_arch = values.get("ARCH").copied().unwrap_or_default();
        let expected_arch = match remote_arch {
            "arm64" | "aarch64" => "arm64",
            "x86_64" => "x86_64",
            other => {
                return Err(TransportError::Io(format!(
                    "automatic Agent update does not support remote architecture '{other}'"
                )));
            }
        };
        if !artifact.architectures.contains(expected_arch) {
            return Err(TransportError::Io(format!(
                "the running macluster binary has no {expected_arch} slice for node {node_id}"
            )));
        }

        let destination = node.remote_binary.as_str();
        let temporary = format!("{destination}.macluster-auto-{}.tmp", Id128::random());
        let expected_uid = node.execution_uid.expect("checked above");
        let preflight = managed_agent_preflight_script(home, cluster_id, destination, expected_uid);
        let preflight_result = self.ssh_output(node_id, node, preflight, Duration::from_secs(8))?;
        if !preflight_result.status.success() {
            return Err(TransportError::Io(command_failure(
                "managed Agent destination preflight failed",
                &preflight_result,
            )));
        }

        if let Err(error) = self.scp_to_node(node_id, node, &artifact.path, &temporary) {
            let _ = self.ssh_output(
                node_id,
                node,
                format!("/bin/rm -f {}", shell_quote(&temporary)),
                Duration::from_secs(5),
            );
            return Err(error);
        }
        let install = format!(
            "set -eu\ntemp={temp}\ndest={dest}\nexpected={expected}\n[ -f \"$temp\" ] && [ ! -L \"$temp\" ] || {{ echo 'staged Agent is not a regular file' >&2; exit 1; }}\nactual=$(/usr/bin/shasum -a 256 \"$temp\")\n[ \"${{actual%% *}}\" = \"$expected\" ] || {{ echo 'staged Agent checksum mismatch' >&2; exit 1; }}\n/bin/chmod 755 \"$temp\"\n/bin/mv -f \"$temp\" \"$dest\"\nactual=$(/usr/bin/shasum -a 256 \"$dest\")\n[ \"${{actual%% *}}\" = \"$expected\" ] || {{ echo 'installed Agent checksum mismatch' >&2; exit 1; }}\n",
            temp = shell_quote(&temporary),
            dest = shell_quote(destination),
            expected = shell_quote(&artifact.digest),
        );
        let installed = self.ssh_output(node_id, node, install, AGENT_AUTO_UPDATE_TIMEOUT)?;
        if !installed.status.success() {
            let _ = self.ssh_output(
                node_id,
                node,
                format!("/bin/rm -f {}", shell_quote(&temporary)),
                Duration::from_secs(5),
            );
            return Err(TransportError::Io(command_failure(
                "managed Agent activation failed",
                &installed,
            )));
        }
        Ok(())
    }

    fn local_agent_artifact(&self) -> Result<&LocalAgentArtifact, TransportError> {
        self.local_agent
            .get_or_init(load_local_agent_artifact)
            .as_ref()
            .map_err(|error| TransportError::Io(error.clone()))
    }

    fn record_auto_update_receipt(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
    ) -> Result<(), String> {
        let Some(root) = self.agent_cache_root.as_deref() else {
            return Ok(());
        };
        let cluster_id = self
            .cluster_id
            .as_deref()
            .ok_or_else(|| "cluster identity is unavailable".to_owned())?;
        let connection = ConnectionKey::for_node(cluster_id, node_id.as_str(), node)
            .and_then(|key| key.cache_fingerprint())
            .map_err(|error| error.to_string())?;
        let artifact = self
            .local_agent_artifact()
            .map_err(|error| error.to_string())?;
        let entry = AutoAgentUpdateEntry {
            remote_binary: node.remote_binary.clone(),
            machine_uuid: node
                .machine_uuid
                .clone()
                .ok_or_else(|| "registered machine identity is missing".to_owned())?,
            execution_uid: node
                .execution_uid
                .ok_or_else(|| "registered execution UID is missing".to_owned())?,
            connection_fingerprint: connection,
            build_id: macluster_protocol::BUILD_ID.to_owned(),
            sha256: artifact.digest.clone(),
        };
        AutoAgentUpdateReceipts::upsert_node_to_dir(root, node_id.to_string(), entry)
            .map_err(|error| error.to_string())
    }

    fn ssh_output(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        remote_command: impl AsRef<str>,
        timeout: Duration,
    ) -> Result<Output, TransportError> {
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
        if let Ok(key) = ConnectionKey::for_node(self.ssh_pool.namespace(), node_id.as_str(), node)
        {
            let _ = self.ssh_pool.append_args(&key, &mut command);
        }
        command.arg(&node.host).arg(remote_command.as_ref());
        run_child_bounded(command, None, timeout)
    }

    fn scp_to_node(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<(), TransportError> {
        let mut command = Command::new("/usr/bin/scp");
        node.add_pinned_host_key_args(&mut command);
        command.args(["-q", "-P"]);
        command.arg(node.ssh_port.unwrap_or(22).to_string());
        command.args([
            "-oLogLevel=ERROR",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oConnectTimeout=5",
        ]);
        if let Some(identity) = &node.ssh_identity_file {
            command.arg("-i").arg(identity).arg("-oIdentitiesOnly=yes");
        }
        if let Ok(key) = ConnectionKey::for_node(self.ssh_pool.namespace(), node_id.as_str(), node)
        {
            let _ = self.ssh_pool.append_args(&key, &mut command);
        }
        command.arg(local_path);
        let host = if node.host.contains(':') {
            format!("[{}]", node.host)
        } else {
            node.host.clone()
        };
        let host = node
            .ssh_user
            .as_deref()
            .map_or(host.clone(), |user| format!("{user}@{host}"));
        command.arg(format!("{host}:{remote_path}"));
        let output = run_child_bounded(command, None, AGENT_AUTO_UPDATE_TIMEOUT)?;
        if !output.status.success() {
            return Err(TransportError::Io(command_failure(
                "could not stage the current Agent binary",
                &output,
            )));
        }
        Ok(())
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
    fn endpoint_reachable(&self, node: &NodeConfig, timeout: Duration) -> Option<bool> {
        match node.transport {
            Transport::Local => Some(true),
            Transport::Ssh => {
                let address = node.host.parse::<Ipv4Addr>().ok()?;
                match TcpStream::connect_timeout(
                    &SocketAddr::from((address, node.ssh_port.unwrap_or(22))),
                    timeout,
                ) {
                    Ok(_) => Some(true),
                    Err(error) => endpoint_probe_error(&error),
                }
            }
        }
    }

    fn host_reachable(&self, node: &NodeConfig, timeout: Duration) -> Option<bool> {
        match node.transport {
            Transport::Local => Some(true),
            Transport::Ssh => {
                let address = node.host.parse::<Ipv4Addr>().ok()?;
                let endpoint = SocketAddr::from((address, node.ssh_port.unwrap_or(22)));
                if let Err(error) = TcpStream::connect_timeout(&endpoint, timeout)
                    && is_explicit_host_unreachable(&error)
                {
                    return Some(false);
                }
                ping_host(node, timeout)
            }
        }
    }

    fn call(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        operation: Operation,
    ) -> Result<ResponseBody, TransportError> {
        let result = self.call_once(node_id, node, operation.clone());
        if !response_requires_agent_refresh(&operation, &result) {
            return result;
        }
        match self.try_auto_refresh_agent(node_id, node) {
            Ok(true) => self.call_once(node_id, node, operation),
            Ok(false) => result,
            Err(error) => {
                eprintln!("macluster: automatic Agent update on {node_id} deferred: {error}");
                result
            }
        }
    }
}

fn managed_agent_home(binary: &str, config: Option<&str>, cluster_id: &str) -> Option<String> {
    if !safe_absolute_managed_path(binary) || !safe_cluster_id(cluster_id) {
        return None;
    }
    let config = config?;
    if !safe_absolute_managed_path(config) {
        return None;
    }
    let binary_suffix = format!("/.local/share/macluster/clusters/{cluster_id}/bin/");
    let config_suffix = format!("/.config/macluster/clusters/{cluster_id}/config.toml");
    let (home, binary_tail) = binary.rsplit_once(&binary_suffix)?;
    let (config_home, _) = config.rsplit_once(&config_suffix)?;
    if home.is_empty() || home != config_home {
        return None;
    }
    let mut parts = binary_tail.split('/');
    let digest = parts.next()?;
    if !valid_sha256(digest) || parts.next()? != "macluster" || parts.next().is_some() {
        return None;
    }
    Some(home.to_owned())
}

fn managed_agent_directories(home: &str, cluster_id: &str, binary: &str) -> Vec<String> {
    let relative = binary
        .strip_prefix(home)
        .expect("validated managed binary is under HOME");
    let parent = relative
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .expect("managed binary has a parent directory");
    let mut directories = Vec::new();
    let mut current = home.to_owned();
    for component in [
        ".local",
        "share",
        "macluster",
        "clusters",
        cluster_id,
        "bin",
    ] {
        current.push('/');
        current.push_str(component);
        directories.push(current.clone());
    }
    current.push('/');
    current.push_str(parent.rsplit('/').next().expect("digest directory exists"));
    directories.push(current);
    directories
}

fn managed_agent_preflight_script(
    home: &str,
    cluster_id: &str,
    binary: &str,
    expected_uid: u32,
) -> String {
    let uid = expected_uid.to_string();
    let mut script = String::from("set -eu\n");
    for directory in managed_agent_directories(home, cluster_id, binary) {
        let path = shell_quote(&directory);
        script.push_str(&format!(
            "if [ -L {path} ]; then echo 'managed Agent directory is a symlink' >&2; exit 1; elif [ -e {path} ]; then [ -d {path} ] && [ \"$(/usr/bin/stat -f '%u' {path})\" = '{uid}' ] || {{ echo 'managed Agent directory has an unexpected type or owner' >&2; exit 1; }}; else /bin/mkdir -m 700 {path}; [ -d {path} ] && [ ! -L {path} ] && [ \"$(/usr/bin/stat -f '%u' {path})\" = '{uid}' ] || {{ echo 'could not create a safe managed Agent directory' >&2; exit 1; }}; fi\n"
        ));
    }
    let path = shell_quote(binary);
    script.push_str(&format!(
        "if [ -L {path} ]; then echo 'registered Agent path is a symlink' >&2; exit 1; elif [ -e {path} ]; then [ -f {path} ] && [ \"$(/usr/bin/stat -f '%u' {path})\" = '{uid}' ] || {{ echo 'registered Agent file has an unexpected type or owner' >&2; exit 1; }}; fi\n"
    ));
    script
}

fn safe_cluster_id(value: &str) -> bool {
    Id128::parse(value).is_ok()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_absolute_managed_path(value: &str) -> bool {
    value.starts_with('/')
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn command_failure(context: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("{context}: command exited with {}", output.status)
    } else {
        format!("{context}: {stderr}")
    }
}

fn load_local_agent_artifact() -> Result<LocalAgentArtifact, String> {
    if !cfg!(target_os = "macos") {
        return Err("automatic Agent refresh is supported only from macOS".into());
    }
    let path = std::env::current_exe()
        .map_err(|error| format!("cannot locate the running macluster binary: {error}"))?
        .canonicalize()
        .map_err(|error| format!("cannot resolve the running macluster binary: {error}"))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect the running macluster binary: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("the running macluster binary is not a regular file".into());
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("cannot read the running macluster binary: {error}"))?;
    let digest = macluster_protocol::framing::sha256_hex(&bytes)
        .map_err(|error| format!("cannot hash the running macluster binary: {error}"))?;
    let build = run_child_bounded(
        {
            let mut command = Command::new(&path);
            command.args(["internal", "capabilities", "--json"]);
            command
        },
        None,
        Duration::from_secs(5),
    )
    .map_err(|error| format!("cannot verify the running binary build: {error}"))?;
    if !build.status.success() {
        return Err(command_failure(
            "the running binary build check failed",
            &build,
        ));
    }
    let build_id = serde_json::from_slice::<serde_json::Value>(&build.stdout)
        .ok()
        .and_then(|value| value.get("build_id")?.as_str().map(str::to_owned));
    if build_id.as_deref() != Some(macluster_protocol::BUILD_ID) {
        return Err(
            "the macluster binary on disk differs from the running controller build; restart the controller before automatic Agent update".into(),
        );
    }
    let output = Command::new("/usr/bin/lipo")
        .args(["-archs"])
        .arg(&path)
        .output()
        .map_err(|error| format!("cannot inspect the running binary architectures: {error}"))?;
    if !output.status.success() {
        return Err(command_failure(
            "lipo could not inspect the running binary",
            &output,
        ));
    }
    let architectures = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    if architectures.is_empty() {
        return Err("the running macluster binary has no supported architecture slices".into());
    }
    Ok(LocalAgentArtifact {
        path,
        digest,
        architectures,
    })
}

fn ping_host(node: &NodeConfig, timeout: Duration) -> Option<bool> {
    let address = node.host.parse::<Ipv4Addr>().ok()?;
    // macOS `ping -W` is in milliseconds. Keep the fallback short: it is only
    // used after SSH fails, and it prevents CPU pressure or a slow sshd from
    // being mistaken for a disconnected cable.
    let wait_ms = timeout.as_millis().clamp(100, 1_000).to_string();
    let address = address.to_string();
    let mut command = Command::new("/sbin/ping");
    command
        .arg("-n")
        .arg("-c")
        .arg("1")
        .arg("-q")
        .arg("-W")
        .arg(wait_ms)
        .arg(address)
        .stdin(Stdio::null());
    match run_child_bounded(
        command,
        None,
        timeout.saturating_add(Duration::from_millis(250)),
    ) {
        Ok(output) => {
            let diagnostic = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            let summary = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
            let output_text = format!("{diagnostic}\n{summary}");
            // Only explicit packet loss or a kernel-reported network-down
            // condition counts as unreachable. Permission, interface and
            // other local ping errors remain inconclusive; treating every
            // nonzero exit as host-down can hide a live node after macOS
            // privacy or network-policy denial.
            let packet_timeout = output_text.contains("request timeout for icmp_seq")
                || output_text.contains("100.0% packet loss")
                || output_text.contains("0 packets received");
            let explicit_network_unreachable = [
                "host is down",
                "host unreachable",
                "no route to host",
                "network is unreachable",
                "network is down",
            ]
            .iter()
            .any(|message| output_text.contains(message));
            if packet_timeout || explicit_network_unreachable {
                Some(false)
            } else if output_text.contains("bytes from")
                || (output_text.contains("packets received")
                    && !output_text.contains("0 packets received"))
            {
                Some(true)
            } else {
                None
            }
        }
        // A hung ping process does not prove the remote host is offline.
        // Keep this inconclusive so it cannot advance the offline counter.
        Err(TransportError::Timeout) => None,
        Err(_) => None,
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

struct AgentAutoUpdatePermit;

impl AgentAutoUpdatePermit {
    fn acquire() -> Option<Self> {
        let mut active = ACTIVE_AGENT_AUTO_UPDATES.load(Ordering::Acquire);
        loop {
            if active >= MAX_CONCURRENT_AGENT_AUTO_UPDATES {
                return None;
            }
            match ACTIVE_AGENT_AUTO_UPDATES.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self),
                Err(actual) => active = actual,
            }
        }
    }
}

impl Drop for AgentAutoUpdatePermit {
    fn drop(&mut self) {
        ACTIVE_AGENT_AUTO_UPDATES.fetch_sub(1, Ordering::AcqRel);
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
    fn endpoint_preflight_treats_local_network_permission_errors_as_unknown() {
        assert_eq!(
            endpoint_probe_error(&io::Error::from_raw_os_error(libc::ECONNREFUSED)),
            Some(false)
        );
        assert_eq!(
            endpoint_probe_error(&io::Error::from_raw_os_error(libc::EPERM)),
            None
        );
        assert_eq!(
            endpoint_probe_error(&io::Error::from_raw_os_error(libc::EACCES)),
            None
        );
    }

    #[test]
    fn nfs_reconciliation_uses_a_bounded_longer_timeout_only_for_that_operation() {
        let reconcile = Operation::ReconcileNfs {
            controller: macluster_protocol::types::ControllerEpoch {
                controller_uuid: macluster_protocol::identifiers::ControllerUuid(
                    macluster_protocol::identifiers::Id128::random(),
                ),
                epoch: 1,
            },
            config_toml: String::new(),
            obsolete_mounts: Vec::new(),
            obsolete_aliases: Vec::new(),
            obsolete_markers: Vec::new(),
            obsolete_exports: Vec::new(),
        };
        assert_eq!(
            operation_timeout(&reconcile, Duration::from_secs(5)),
            NFS_RECONCILE_TIMEOUT
        );
        assert_eq!(
            operation_timeout(&Operation::Ping, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
        assert_eq!(
            operation_timeout(&Operation::Ping, Duration::ZERO),
            DEFAULT_TIMEOUT
        );
        assert_eq!(
            operation_timeout(&Operation::Status, Duration::from_secs(15)),
            Duration::from_secs(5),
            "read-only execution probes must fail fast when a node is unreachable"
        );
        assert_eq!(
            operation_timeout(&Operation::Health, Duration::from_secs(15)),
            Duration::from_secs(5)
        );
        assert_eq!(
            operation_timeout(&Operation::Health, Duration::from_secs(2)),
            Duration::from_secs(2),
            "an explicitly shorter probe timeout must be preserved"
        );
        assert_eq!(
            operation_timeout(
                &Operation::Fence {
                    controller: macluster_protocol::types::ControllerEpoch {
                        controller_uuid: macluster_protocol::identifiers::ControllerUuid(
                            macluster_protocol::identifiers::Id128::random(),
                        ),
                        epoch: 1,
                    },
                },
                Duration::from_secs(15)
            ),
            Duration::from_secs(5),
            "fence probes are part of bounded node verification"
        );
        assert_eq!(
            operation_timeout(
                &Operation::SetFanPolicy {
                    policy: macluster_protocol::types::FanPolicy::Auto,
                },
                Duration::from_secs(15)
            ),
            Duration::from_secs(5),
            "fan operations should not wait on a stalled helper indefinitely"
        );
        assert_eq!(
            operation_timeout(&Operation::QueryFanPolicy, Duration::from_secs(15)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn stale_health_or_protocol_mismatch_requests_one_agent_refresh() {
        let old_health = ResponseBody::Health(macluster_protocol::types::NodeHealth {
            machine_uuid: "machine".into(),
            execution_uid: 501,
            build_id: Some("old-build".into()),
            logical_cpus: Some(8),
            execution_digest: "digest".into(),
            primary_share_ready: true,
            shares: Default::default(),
            features: Vec::new(),
        });
        assert!(response_requires_agent_refresh(
            &Operation::Health,
            &Ok(old_health)
        ));

        let current_health = ResponseBody::Health(macluster_protocol::types::NodeHealth {
            machine_uuid: "machine".into(),
            execution_uid: 501,
            build_id: Some(macluster_protocol::BUILD_ID.into()),
            logical_cpus: Some(8),
            execution_digest: "digest".into(),
            primary_share_ready: true,
            shares: Default::default(),
            features: Vec::new(),
        });
        assert!(!response_requires_agent_refresh(
            &Operation::Health,
            &Ok(current_health)
        ));
        assert!(response_requires_agent_refresh(
            &Operation::Fence {
                controller: macluster_protocol::types::ControllerEpoch {
                    controller_uuid: macluster_protocol::identifiers::ControllerUuid(
                        macluster_protocol::identifiers::Id128::random(),
                    ),
                    epoch: 1,
                },
            },
            &Err(TransportError::Remote(ProtocolError::IncompatibleVersion))
        ));
        assert!(!response_requires_agent_refresh(
            &Operation::Health,
            &Err(TransportError::Timeout)
        ));
        assert!(response_requires_agent_refresh(
            &Operation::Fence {
                controller: macluster_protocol::types::ControllerEpoch {
                    controller_uuid: macluster_protocol::identifiers::ControllerUuid(
                        macluster_protocol::identifiers::Id128::random(),
                    ),
                    epoch: 1,
                },
            },
            &Err(TransportError::Io(
                "zsh: no such file or directory: /Users/operator/.local/share/macluster/macluster"
                    .into()
            ))
        ));
        assert!(!response_requires_agent_refresh(
            &Operation::Health,
            &Err(TransportError::Io("Permission denied (publickey)".into()))
        ));
    }

    #[test]
    fn automatic_agent_refresh_is_limited_to_matching_managed_paths() {
        let cluster = "00000000-0000-4000-8000-0000000000aa";
        let digest = "a".repeat(64);
        let binary = format!(
            "/Users/operator/.local/share/macluster/clusters/{cluster}/bin/{digest}/macluster"
        );
        let config = format!("/Users/operator/.config/macluster/clusters/{cluster}/config.toml");

        assert_eq!(
            managed_agent_home(&binary, Some(&config), cluster).as_deref(),
            Some("/Users/operator")
        );
        assert_eq!(
            managed_agent_directories("/Users/operator", cluster, &binary)
                .last()
                .map(String::as_str),
            Some(
                format!("/Users/operator/.local/share/macluster/clusters/{cluster}/bin/{digest}")
                    .as_str()
            )
        );
        assert!(managed_agent_home(
            &binary,
            Some("/Users/other/.config/macluster/clusters/00000000-0000-4000-8000-0000000000aa/config.toml"),
            cluster
        )
        .is_none());
        assert!(managed_agent_home("/usr/local/bin/macluster", Some(&config), cluster).is_none());
        assert!(
            managed_agent_home(
                &binary.replace(&digest, "../../outside"),
                Some(&config),
                cluster
            )
            .is_none()
        );
    }

    #[test]
    fn automatic_agent_refresh_can_recreate_a_missing_managed_binary_safely() {
        let cluster = "00000000-0000-4000-8000-0000000000aa";
        let digest = "a".repeat(64);
        let binary = format!(
            "/Users/operator/.local/share/macluster/clusters/{cluster}/bin/{digest}/macluster"
        );
        let script = managed_agent_preflight_script("/Users/operator", cluster, &binary, 501);

        assert!(script.contains("/bin/mkdir -m 700"));
        assert!(script.contains("managed Agent directory is a symlink"));
        assert!(script.contains("registered Agent path is a symlink"));
        assert!(script.contains("elif [ -e '/Users/operator/.local/share/macluster/clusters/"));
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
