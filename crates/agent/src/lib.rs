//! SSH stdio agent and detached per-job runner.

pub mod admin;
pub mod log_sync;
pub mod runner;

use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use macluster_core::config::{ClusterConfig, NodeConfig};
use macluster_protocol::{
    framing::{MAX_SNAPSHOT_BYTES, read_frame, sha256_hex, write_frame},
    identifiers::{Id128, StartToken},
    types::{
        ControllerEpoch, ExecutionStatus, INTERACTIVE_PTY_FEATURE, JobMode, JobSpec, JobState,
        NodeHealth, Operation, PROTOCOL_VERSION, ProtocolError, Request, Response, ResponseBody,
        RuntimePhase, SnapshotRef, StartResult,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("agent state is invalid: {0}")]
    State(String),
    #[error("shared storage is not mounted or its marker does not match")]
    SharedStorage,
    #[error("shared script snapshot is missing or does not match its digest")]
    SnapshotMismatch,
    #[error("node already has an active job")]
    Busy,
    #[error("controller is fenced: {0}")]
    Fenced(String),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct AgentStore {
    #[serde(default)]
    owner_namespace: Option<String>,
    #[serde(default)]
    reset_fence: bool,
    #[serde(default)]
    pending_archive: Option<admin::PendingArchive>,
    #[serde(default)]
    pending_handoff: Option<admin::PendingHandoff>,
    #[serde(default)]
    retired_controllers: Vec<ControllerEpoch>,
    #[serde(default)]
    controller: Option<ControllerEpoch>,
    #[serde(default)]
    active: Option<AgentRecord>,
    #[serde(default)]
    tombstones: Vec<AgentRecord>,
    #[serde(default)]
    log_sync_shutdown: Option<Id128>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AgentRecord {
    controller: ControllerEpoch,
    start_token: StartToken,
    job_id: u64,
    node_id: String,
    shared_root: String,
    #[serde(default)]
    tool_paths: Vec<String>,
    #[serde(default)]
    named_shares: Vec<AgentNamedShare>,
    spec: JobSpec,
    phase: RuntimePhase,
    authorized: bool,
    runner_pid: Option<u32>,
    #[serde(default)]
    runner_start_id: Option<String>,
    child_pid: Option<u32>,
    #[serde(default)]
    child_start_id: Option<String>,
    #[serde(default)]
    task_start_gated: bool,
    #[serde(default)]
    share_uuid: Option<String>,
    #[serde(default)]
    storage_node_id: Option<String>,
    #[serde(default)]
    storage_host: Option<String>,
    #[serde(default)]
    storage_source_root: Option<String>,
    terminal_state: Option<JobState>,
    #[serde(default)]
    termination_cause: Option<JobState>,
    exit_code: Option<i32>,
    end_reason: Option<String>,
    cancel_requested: bool,
    force_cancel: bool,
    boot_id: String,
    log_sync_pending: bool,
    #[serde(default)]
    log_sync_retry_after_unix_ms: Option<u64>,
    started_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AgentNamedShare {
    share_uuid: String,
    server_node_id: String,
    server_host: String,
    source_root: String,
    mount_root: String,
}

const LOG_SYNC_RETRY_DELAY_MS: u64 = 5_000;

impl AgentRecord {
    fn status(&self) -> ExecutionStatus {
        ExecutionStatus {
            start_token: self.start_token,
            job_id: self.job_id,
            phase: self.phase,
            terminal_state: self.terminal_state,
            boot_id: self.boot_id.clone(),
            runner_pid: self.runner_pid,
            child_pid: self.child_pid,
            exit_code: self.exit_code,
            end_reason: self.end_reason.clone(),
            log_sync_pending: self.log_sync_pending,
        }
    }

    fn terminal(&self) -> bool {
        self.terminal_state.is_some()
    }
}

/// Handle one bounded framed request on SSH stdio. Stdout must contain only
/// protocol frames so the controller can parse it reliably.
pub fn serve_stdio<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    config: &ClusterConfig,
    state_dir: &Path,
    local_node_id: &str,
) -> Result<(), AgentError> {
    let Some(request) =
        read_frame::<_, Request>(input).map_err(|error| AgentError::State(error.to_string()))?
    else {
        return Ok(());
    };
    let response = handle_request(request, config, state_dir, local_node_id);
    write_frame(output, &response).map_err(|error| AgentError::State(error.to_string()))?;
    Ok(())
}

pub fn handle_request(
    request: Request,
    config: &ClusterConfig,
    state_dir: &Path,
    local_node_id: &str,
) -> Response {
    let request_id = request.request_id;
    let result = if request.protocol_version != PROTOCOL_VERSION {
        Err(ProtocolError::IncompatibleVersion)
    } else {
        match config.nodes.get(local_node_id) {
            Some(node) => validate_current_node_identity(node)
                .map_err(ProtocolError::Failed)
                .and_then(|_| {
                    handle_operation(request.operation, config, state_dir, local_node_id)
                }),
            None => Err(ProtocolError::Failed(format!(
                "node '{local_node_id}' is absent from the active config"
            ))),
        }
    };
    Response {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        result,
    }
}

fn handle_operation(
    operation: Operation,
    config: &ClusterConfig,
    state_dir: &Path,
    local_node_id: &str,
) -> Result<ResponseBody, ProtocolError> {
    match operation {
        Operation::Ping => Ok(ResponseBody::Pong),
        Operation::RecoverJob {
            controller,
            start_token,
            job_id,
        } => recover_job(
            controller,
            start_token,
            job_id,
            config,
            state_dir,
            local_node_id,
        )
        .map(ResponseBody::Execution),
        Operation::Status => {
            let status = status(state_dir)?;
            if status.terminal_state.is_some() && status.log_sync_pending {
                // A publisher failure must not make an otherwise reachable
                // node look offline. Its pending flag keeps the node reserved.
                let _ = log_sync::schedule(state_dir, config);
            }
            Ok(ResponseBody::Execution(status))
        }
        Operation::Health => node_health(config, local_node_id)
            .map(ResponseBody::Health)
            .map_err(|error| ProtocolError::Failed(error.to_string())),
        Operation::Fence { controller } => fence(controller, state_dir).map(|_| ResponseBody::Ack),
        Operation::StartJob {
            controller,
            start_token,
            job_id,
            spec,
        } => start_job(
            controller,
            start_token,
            job_id,
            spec,
            config,
            state_dir,
            local_node_id,
        )
        .map(ResponseBody::Started),
        Operation::CancelJob {
            controller,
            start_token,
            job_id,
            force,
        } => {
            cancel_job(controller, start_token, job_id, force, state_dir).map(|_| ResponseBody::Ack)
        }
    }
}

pub fn validate_node_identity(
    node: &NodeConfig,
    actual_machine_uuid: &str,
    actual_execution_uid: u32,
) -> Result<(), String> {
    if node
        .machine_uuid
        .as_deref()
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(actual_machine_uuid))
    {
        return Err("machine UUID does not match the registered node identity".into());
    }
    if node
        .execution_uid
        .is_some_and(|expected| expected != actual_execution_uid)
    {
        return Err("execution UID does not match the registered node identity".into());
    }
    if matches!(node.transport, macluster_core::config::Transport::Local)
        && (node.machine_uuid.is_none() || node.execution_uid.is_none())
    {
        return Err("local node identity is missing from config".into());
    }
    Ok(())
}

fn validate_current_node_identity(node: &NodeConfig) -> Result<(), String> {
    let machine_uuid = if node.machine_uuid.is_some()
        || matches!(node.transport, macluster_core::config::Transport::Local)
    {
        Some(local_machine_uuid()?)
    } else {
        None
    };
    let uid = unsafe { libc::geteuid() };
    if let Some(machine_uuid) = machine_uuid {
        validate_node_identity(node, &machine_uuid, uid)?;
    } else if node.execution_uid.is_some_and(|expected| expected != uid) {
        return Err("execution UID does not match the registered node identity".into());
    }
    Ok(())
}

fn local_machine_uuid() -> Result<String, String> {
    let output = Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|error| format!("could not read local machine identity: {error}"))?;
    if !output.status.success() {
        return Err("ioreg failed while reading local machine identity".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| line.rsplit_once('=').map(|(_, value)| value.trim()))
        .map(|value| value.trim_matches('"').trim())
        .ok_or_else(|| "IOPlatformUUID was not present in ioreg output".to_owned())?;
    Id128::parse(value).map_err(|error| format!("invalid IOPlatformUUID: {error}"))?;
    Ok(value.to_ascii_lowercase())
}

fn node_health(config: &ClusterConfig, local_node_id: &str) -> Result<NodeHealth, AgentError> {
    let machine_uuid = local_machine_uuid().map_err(|message| {
        AgentError::State(format!("could not read local identity: {message}"))
    })?;
    let shares = config
        .shares
        .iter()
        .map(|(id, share)| {
            (
                id.clone(),
                verify_named_share(config, local_node_id, share).is_ok(),
            )
        })
        .collect();
    Ok(NodeHealth {
        machine_uuid,
        execution_uid: unsafe { libc::geteuid() },
        execution_digest: config
            .execution_digest()
            .map_err(|error| AgentError::State(error.to_string()))?,
        primary_share_ready: verify_share(config, local_node_id).is_ok(),
        shares,
        features: vec![
            INTERACTIVE_PTY_FEATURE.to_owned(),
            macluster_protocol::types::NAMESPACED_JOBS_FEATURE.to_owned(),
        ],
    })
}

fn verify_named_share(
    config: &ClusterConfig,
    local_node_id: &str,
    share: &macluster_core::config::ShareConfig,
) -> Result<(), AgentError> {
    let Some(server) = config.nodes.get(share.server.as_str()) else {
        return Err(AgentError::SharedStorage);
    };
    let named_share = AgentNamedShare {
        share_uuid: share.share_uuid.clone(),
        server_node_id: share.server.to_string(),
        server_host: server.host.clone(),
        source_root: share.source_root.to_string_lossy().into_owned(),
        mount_root: share.mount_root.to_string_lossy().into_owned(),
    };
    verify_agent_named_share(local_node_id, &named_share).map(|_| ())
}

fn verify_agent_named_share(
    local_node_id: &str,
    share: &AgentNamedShare,
) -> Result<PathBuf, AgentError> {
    let source_root = Path::new(&share.source_root);
    let mount_root = Path::new(&share.mount_root);
    let is_server = local_node_id == share.server_node_id;
    let root = if is_server && source_root != mount_root {
        let link = fs::read_link(mount_root)?;
        if link != source_root {
            return Err(AgentError::SharedStorage);
        }
        source_root
    } else {
        mount_root
    };
    let marker = read_share_marker(&root.join(".macluster-share-id"))?;
    if marker.trim() != share.share_uuid {
        return Err(AgentError::SharedStorage);
    }
    let (filesystem, flags) = filesystem_info(root)?;
    if is_server {
        if flags & (libc::MNT_LOCAL as u32) != 0 {
            return root.canonicalize().map_err(AgentError::Io);
        }
        return Err(AgentError::SharedStorage);
    }
    let mounts = Command::new("/sbin/mount").output()?;
    let output = String::from_utf8_lossy(&mounts.stdout);
    let expected = format!(
        "{}:{} on {} (nfs",
        share.server_host, share.source_root, share.mount_root
    );
    if filesystem == "nfs" && output.lines().any(|line| line.starts_with(&expected)) {
        root.canonicalize().map_err(AgentError::Io)
    } else {
        Err(AgentError::SharedStorage)
    }
}

fn start_job(
    controller: ControllerEpoch,
    start_token: StartToken,
    job_id: u64,
    spec: JobSpec,
    config: &ClusterConfig,
    state_dir: &Path,
    local_node_id: &str,
) -> Result<StartResult, ProtocolError> {
    config
        .nodes
        .get(local_node_id)
        .ok_or(ProtocolError::NotPermitted)?;
    verify_share(config, local_node_id).map_err(|_| ProtocolError::StorageUnavailable)?;
    for share in config.shares.values() {
        verify_named_share(config, local_node_id, share)
            .map_err(|_| ProtocolError::StorageUnavailable)?;
    }
    if spec
        .storage_namespace
        .is_some_and(|namespace| Id128::parse(&config.share_uuid).ok() != Some(namespace))
    {
        return Err(ProtocolError::Conflict);
    }
    let shared_script = spec
        .shared_job_dir(&config.shared_root, job_id)
        .join("script.sh");
    if let Some(snapshot) = spec.snapshot.as_ref() {
        verify_file(&shared_script, snapshot).map_err(|_| ProtocolError::StorageUnavailable)?;
    } else if spec.mode == JobMode::Batch {
        return Err(ProtocolError::InvalidRequest);
    }

    let _lock = StateLock::acquire(state_dir).map_err(protocol_failed)?;
    let mut store = read_store(state_dir).map_err(protocol_failed)?;
    admit_epoch(&mut store, controller).map_err(ProtocolError::Failed)?;
    if store.log_sync_shutdown.is_some() {
        return Err(ProtocolError::Busy);
    }
    if let Some(record) = store
        .active
        .as_ref()
        .filter(|record| record.start_token == start_token)
    {
        if record.job_id != job_id || record.spec != spec {
            return Err(ProtocolError::Conflict);
        }
        return Ok(StartResult {
            start_token,
            accepted: true,
            runner_pid: record.runner_pid,
        });
    }
    if let Some(record) = store
        .tombstones
        .iter()
        .find(|record| record.start_token == start_token)
    {
        if record.job_id != job_id || record.spec != spec {
            return Err(ProtocolError::Conflict);
        }
        return Ok(StartResult {
            start_token,
            accepted: true,
            runner_pid: record.runner_pid,
        });
    }
    if let Some(mut receipt) =
        read_execution_receipt(state_dir, job_id, start_token).map_err(protocol_failed)?
    {
        validate_receipt(&receipt, controller, start_token, job_id, local_node_id)?;
        if receipt.spec != spec {
            return Err(ProtocolError::Conflict);
        }
        let runner_pid = receipt.runner_pid;
        if store.active.is_none() {
            receipt.controller = controller;
            store.active = Some(receipt);
            write_store(state_dir, &store).map_err(protocol_failed)?;
        }
        return Ok(StartResult {
            start_token,
            accepted: true,
            runner_pid,
        });
    }
    if store
        .active
        .as_ref()
        .is_some_and(|record| !record.terminal() || record.log_sync_pending)
    {
        return Err(ProtocolError::Busy);
    }

    let local_job_dir = state_dir.join("jobs").join(job_id.to_string());
    fs::create_dir_all(&local_job_dir).map_err(protocol_failed)?;
    fs::set_permissions(&local_job_dir, fs::Permissions::from_mode(0o700))
        .map_err(protocol_failed)?;
    let local_script = local_job_dir.join("script.sh");
    if let Some(snapshot) = spec.snapshot.as_ref() {
        copy_snapshot(&shared_script, &local_script, snapshot).map_err(protocol_failed)?;
    }

    let storage_node = config
        .nodes
        .get(config.storage_server.as_str())
        .ok_or(ProtocolError::StorageUnavailable)?;
    let mut record = AgentRecord {
        controller,
        start_token,
        job_id,
        node_id: local_node_id.to_owned(),
        shared_root: config.shared_root.to_string_lossy().into_owned(),
        tool_paths: config
            .shares
            .values()
            .flat_map(|share| {
                [
                    share.mount_root.to_string_lossy().into_owned(),
                    share.mount_root.join("bin").to_string_lossy().into_owned(),
                ]
            })
            .collect(),
        named_shares: config
            .shares
            .values()
            .map(|share| {
                let server = config
                    .nodes
                    .get(share.server.as_str())
                    .expect("validated share server is present");
                AgentNamedShare {
                    share_uuid: share.share_uuid.clone(),
                    server_node_id: share.server.to_string(),
                    server_host: server.host.clone(),
                    source_root: share.source_root.to_string_lossy().into_owned(),
                    mount_root: share.mount_root.to_string_lossy().into_owned(),
                }
            })
            .collect(),
        spec,
        phase: RuntimePhase::Launching,
        authorized: false,
        runner_pid: None,
        runner_start_id: None,
        child_pid: None,
        child_start_id: None,
        task_start_gated: true,
        share_uuid: Some(config.share_uuid.clone()),
        storage_node_id: Some(config.storage_server.to_string()),
        storage_host: Some(storage_node.host.clone()),
        storage_source_root: Some(config.primary_source_root().to_string_lossy().into_owned()),
        terminal_state: None,
        exit_code: None,
        end_reason: None,
        termination_cause: None,
        cancel_requested: false,
        force_cancel: false,
        boot_id: boot_id(),
        log_sync_pending: false,
        log_sync_retry_after_unix_ms: None,
        started_unix_ms: now_ms(),
    };
    store.controller = Some(controller);
    if let Some(previous) = store.active.take() {
        store.tombstones.push(previous);
    }
    store.active = Some(record.clone());
    write_store(state_dir, &store).map_err(protocol_failed)?;

    let executable = std::env::current_exe().map_err(protocol_failed)?;
    let mut runner = Command::new(executable);
    runner
        .args(["internal", "runner", "--state-dir"])
        .arg(state_dir)
        .arg("--job-id")
        .arg(job_id.to_string())
        .arg("--start-token")
        .arg(start_token.to_string())
        .current_dir(state_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_vendor = "apple")]
    use std::os::unix::process::CommandExt;
    #[cfg(target_vendor = "apple")]
    runner.process_group(0);
    let mut child = match runner.spawn() {
        Ok(child) => child,
        Err(error) => {
            record.terminal_state = Some(JobState::Failed);
            record.end_reason = Some(format!("could not launch runner: {error}"));
            store.active = Some(record);
            let _ = write_store(state_dir, &store);
            return Err(ProtocolError::Failed(error.to_string()));
        }
    };
    let runner_pid = child.id();
    let Some(runner_start_id) = wait_for_process_start_identity(runner_pid) else {
        let _ = child.kill();
        let _ = child.wait();
        record.terminal_state = Some(JobState::Failed);
        record.end_reason = Some("could not verify detached runner process identity".into());
        store.active = Some(record);
        let _ = write_store(state_dir, &store);
        return Err(ProtocolError::Failed(
            "could not verify detached runner process identity".into(),
        ));
    };
    record.runner_pid = Some(runner_pid);
    record.runner_start_id = Some(runner_start_id);
    record.authorized = true;
    store.active = Some(record.clone());
    write_store(state_dir, &store).map_err(protocol_failed)?;
    Ok(StartResult {
        start_token,
        accepted: true,
        runner_pid: record.runner_pid,
    })
}

fn cancel_job(
    controller: ControllerEpoch,
    token: StartToken,
    job_id: u64,
    force: bool,
    state_dir: &Path,
) -> Result<(), ProtocolError> {
    let _lock = StateLock::acquire(state_dir).map_err(protocol_failed)?;
    let mut store = read_store(state_dir).map_err(protocol_failed)?;
    admit_epoch(&mut store, controller).map_err(ProtocolError::Failed)?;
    let record = store
        .active
        .as_mut()
        .filter(|record| record.start_token == token && record.job_id == job_id)
        .ok_or(ProtocolError::NotFound)?;
    if record.terminal() {
        return Ok(());
    }
    record.cancel_requested = true;
    if record.termination_cause.is_none() {
        record.termination_cause = Some(JobState::Cancelled);
        record.end_reason = Some("cancelled by user".into());
        record.force_cancel = force;
    } else if record.termination_cause == Some(JobState::Cancelled) {
        record.force_cancel |= force;
    }
    store.controller = Some(controller);
    write_store(state_dir, &store).map_err(protocol_failed)
}

fn fence(controller: ControllerEpoch, state_dir: &Path) -> Result<(), ProtocolError> {
    let _lock = StateLock::acquire(state_dir).map_err(protocol_failed)?;
    let mut store = read_store(state_dir).map_err(protocol_failed)?;
    admit_epoch(&mut store, controller).map_err(ProtocolError::Failed)?;
    store.controller = Some(controller);
    write_store(state_dir, &store).map_err(protocol_failed)
}

fn validate_receipt(
    record: &AgentRecord,
    controller: ControllerEpoch,
    token: StartToken,
    job_id: u64,
    node_id: &str,
) -> Result<(), ProtocolError> {
    if record.controller.controller_uuid != controller.controller_uuid
        || record.controller.epoch > controller.epoch
    {
        return Err(ProtocolError::Failed(
            "execution receipt belongs to another controller or a newer epoch".into(),
        ));
    }
    if record.start_token != token || record.job_id != job_id || record.node_id != node_id {
        return Err(ProtocolError::Conflict);
    }
    Ok(())
}

fn recover_job(
    controller: ControllerEpoch,
    token: StartToken,
    job_id: u64,
    _config: &ClusterConfig,
    state_dir: &Path,
    node_id: &str,
) -> Result<ExecutionStatus, ProtocolError> {
    {
        let _lock = StateLock::acquire_existing(state_dir).map_err(protocol_failed)?;
        let mut store = read_store(state_dir).map_err(protocol_failed)?;
        admit_epoch(&mut store, controller).map_err(ProtocolError::Failed)?;
        if store.log_sync_shutdown.is_some() {
            return Err(ProtocolError::Busy);
        }
        match store.active.as_ref() {
            Some(active) => validate_receipt(active, controller, token, job_id, node_id)?,
            None => {
                let mut receipt = read_execution_receipt(state_dir, job_id, token)
                    .map_err(protocol_failed)?
                    .ok_or(ProtocolError::NotFound)?;
                validate_receipt(&receipt, controller, token, job_id, node_id)?;
                receipt.controller = controller;
                store.active = Some(receipt);
            }
        }
        write_store(state_dir, &store).map_err(protocol_failed)?;
    }
    status(state_dir)
}

fn status(state_dir: &Path) -> Result<ExecutionStatus, ProtocolError> {
    let current_boot = boot_id();
    let recovery = {
        let _lock = StateLock::acquire(state_dir).map_err(protocol_failed)?;
        let mut store = read_store(state_dir).map_err(protocol_failed)?;
        let Some(record) = store.active.as_mut() else {
            return Err(ProtocolError::NotFound);
        };
        if record.terminal() {
            None
        } else if record.boot_id != current_boot
            && record.boot_id != "unknown"
            && current_boot != "unknown"
        {
            mark_lost_execution(
                record,
                "node rebooted while task was active; the task process no longer exists",
            );
            write_store(state_dir, &store).map_err(protocol_failed)?;
            None
        } else if record.task_start_gated
            && record.phase == RuntimePhase::Launching
            && !record.authorized
        {
            // start_job persists an unauthorized launch record before it
            // creates the runner. If the controller process dies in that
            // window, the runner cannot pass its authorization gate and no
            // user task can have started.
            mark_lost_execution(
                record,
                "controller disappeared before authorizing the runner; user code was not started",
            );
            write_store(state_dir, &store).map_err(protocol_failed)?;
            None
        } else {
            let runner = match (record.runner_pid, record.runner_start_id.as_deref()) {
                (Some(pid), Some(start_id)) => process_identity(pid, start_id),
                _ => ProcessIdentity::Unverifiable,
            };
            match runner {
                ProcessIdentity::Match => None,
                ProcessIdentity::Gone | ProcessIdentity::Reused => {
                    match (record.child_pid, record.child_start_id.as_deref()) {
                        (Some(pid), Some(start_id)) => {
                            Some((record.job_id, record.start_token, pid, start_id.to_owned()))
                        }
                        _ if record.task_start_gated
                            && matches!(
                                record.phase,
                                RuntimePhase::Launching | RuntimePhase::Unknown
                            )
                            && record.child_pid.is_none()
                            && record.child_start_id.is_none() =>
                        {
                            mark_lost_execution(
                                record,
                                "runner disappeared before releasing the task start gate; user code was not started",
                            );
                            write_store(state_dir, &store).map_err(protocol_failed)?;
                            None
                        }
                        _ => {
                            record.phase = RuntimePhase::Unknown;
                            record.end_reason = Some("runner disappeared before the task process identity was saved; manual reconciliation is required".into());
                            write_store(state_dir, &store).map_err(protocol_failed)?;
                            None
                        }
                    }
                }
                ProcessIdentity::Unverifiable => {
                    record.phase = RuntimePhase::Unknown;
                    record.end_reason = Some(
                        "runner process identity could not be verified; the node remains reserved"
                            .into(),
                    );
                    write_store(state_dir, &store).map_err(protocol_failed)?;
                    None
                }
            }
        }
    };

    if let Some((job_id, token, child_pid, child_start_id)) = recovery {
        let stopped = runner::stop_orphan_task_group(child_pid, &child_start_id);
        let _lock = StateLock::acquire(state_dir).map_err(protocol_failed)?;
        let mut store = read_store(state_dir).map_err(protocol_failed)?;
        if let Some(record) = store.active.as_mut().filter(|record| {
            record.job_id == job_id && record.start_token == token && !record.terminal()
        }) {
            if stopped {
                mark_lost_execution(
                    record,
                    "runner disappeared; its task process group was stopped during recovery",
                );
            } else {
                record.phase = RuntimePhase::Unknown;
                record.end_reason = Some("runner disappeared, but the task process group could not be safely verified or stopped; manual reconciliation is required".into());
            }
        }
        write_store(state_dir, &store).map_err(protocol_failed)?;
    }

    let _lock = StateLock::acquire(state_dir).map_err(protocol_failed)?;
    let store = read_store(state_dir).map_err(protocol_failed)?;
    store
        .active
        .map(|record| record.status())
        .ok_or(ProtocolError::NotFound)
}

fn mark_lost_execution(record: &mut AgentRecord, reason: &str) {
    let user_code_never_started = record.task_start_gated
        && matches!(
            record.phase,
            RuntimePhase::Launching | RuntimePhase::Unknown
        )
        && record.child_pid.is_none()
        && record.child_start_id.is_none();
    let cancelled_or_timed_out = record.termination_cause;
    if cancelled_or_timed_out.is_none() {
        record.end_reason = Some(reason.to_owned());
    }
    record.terminal_state = Some(cancelled_or_timed_out.unwrap_or(JobState::NodeLost));
    record.phase = RuntimePhase::Idle;
    record.child_pid = None;
    record.child_start_id = None;
    record.log_sync_pending = !user_code_never_started;
    record.log_sync_retry_after_unix_ms = None;
}

fn commit_log_sync_result(
    state_dir: &Path,
    snapshot: AgentRecord,
    sync: io::Result<()>,
) -> Result<(), ProtocolError> {
    let _lock = match StateLock::acquire_existing(state_dir) {
        Ok(lock) => lock,
        Err(AgentError::Io(error)) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(protocol_failed(error)),
    };
    let mut store = read_store(state_dir).map_err(protocol_failed)?;
    let Some(record) = store.active.as_mut().filter(|record| {
        record.job_id == snapshot.job_id && record.start_token == snapshot.start_token
    }) else {
        return Ok(());
    };
    record.share_uuid = snapshot.share_uuid;
    record.storage_node_id = snapshot.storage_node_id;
    record.storage_host = snapshot.storage_host;
    record.storage_source_root = snapshot.storage_source_root;
    match sync {
        Ok(()) => {
            record.log_sync_pending = false;
            record.log_sync_retry_after_unix_ms = None;
        }
        Err(_) => {
            // Another publisher may have succeeded after this attempt took
            // its snapshot. Completion is monotonic for one execution token.
            record.log_sync_retry_after_unix_ms = record
                .log_sync_pending
                .then(|| now_ms().saturating_add(LOG_SYNC_RETRY_DELAY_MS));
        }
    }
    write_store(state_dir, &store).map_err(protocol_failed)
}

fn hydrate_record_storage_identity(record: &mut AgentRecord, config: &ClusterConfig) {
    if record.share_uuid.is_some()
        && record.storage_node_id.is_some()
        && record.storage_host.is_some()
        && record.storage_source_root.is_some()
    {
        // A completed task retains its output locally while NFS endpoints move.
        // Only rebind the host when the storage namespace and paths are unchanged.
        if record.terminal()
            && record.log_sync_pending
            && record
                .share_uuid
                .as_deref()
                .is_some_and(|uuid| uuid.eq_ignore_ascii_case(&config.share_uuid))
            && record.storage_node_id.as_deref() == Some(config.storage_server.as_str())
            && Path::new(&record.shared_root) == config.shared_root
            && record.storage_source_root.as_deref().map(Path::new)
                == Some(config.primary_source_root())
            && let Some(storage) = config.nodes.get(config.storage_server.as_str())
        {
            record.storage_host = Some(storage.host.clone());
        }
        return;
    }
    if Path::new(&record.shared_root) != config.shared_root {
        return;
    }
    let Some(storage) = config.nodes.get(config.storage_server.as_str()) else {
        return;
    };
    record.share_uuid = Some(config.share_uuid.clone());
    record.storage_node_id = Some(config.storage_server.to_string());
    record.storage_host = Some(storage.host.clone());
    record.storage_source_root = Some(config.primary_source_root().to_string_lossy().into_owned());
}

pub fn run_runner(state_dir: &Path, job_id: u64, token: StartToken) -> i32 {
    match runner::run(state_dir, job_id, token) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("runner error: {error}");
            1
        }
    }
}

/// Attach the current terminal to an authorized interactive task on this node.
pub fn serve_attach_stdio<R, W>(
    input: &mut R,
    output: &mut W,
    state_dir: &Path,
    node_id: &str,
    job_id: u64,
    start_token: StartToken,
) -> Result<(), AgentError>
where
    R: Read + std::os::fd::AsRawFd,
    W: Write + std::os::fd::AsRawFd,
{
    runner::serve_attach_stdio(input, output, state_dir, node_id, job_id, start_token)
}

pub(crate) fn load_active(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
) -> Result<AgentRecord, AgentError> {
    let _lock = StateLock::acquire(state_dir)?;
    let store = read_store(state_dir)?;
    store
        .active
        .filter(|record| record.job_id == job_id && record.start_token == token)
        .ok_or_else(|| AgentError::State("active execution identity changed".into()))
}

pub(crate) fn write_active(state_dir: &Path, record: AgentRecord) -> Result<(), AgentError> {
    let _lock = StateLock::acquire(state_dir)?;
    let mut store = read_store(state_dir)?;
    if !store.active.as_ref().is_some_and(|current| {
        current.job_id == record.job_id && current.start_token == record.start_token
    }) {
        return Err(AgentError::State(
            "active execution identity changed".into(),
        ));
    }
    let mut record = record;
    if let Some(current) = store.active.as_ref() {
        record.cancel_requested |= current.cancel_requested;
        record.force_cancel |= current.force_cancel;
        if record.termination_cause.is_none() {
            record.termination_cause = current.termination_cause;
        }
        if record.end_reason.is_none() {
            record.end_reason = current.end_reason.clone();
        }
        record.log_sync_pending &= current.log_sync_pending;
        if record.log_sync_pending {
            record.log_sync_retry_after_unix_ms = record
                .log_sync_retry_after_unix_ms
                .or(current.log_sync_retry_after_unix_ms);
        } else {
            record.log_sync_retry_after_unix_ms = None;
        }
    }
    store.active = Some(record);
    write_store(state_dir, &store)
}

pub(crate) fn mark_termination_cause(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    state: JobState,
    reason: &str,
) -> Result<(), AgentError> {
    let _lock = StateLock::acquire(state_dir)?;
    let mut store = read_store(state_dir)?;
    let record = store
        .active
        .as_mut()
        .filter(|record| record.job_id == job_id && record.start_token == token)
        .ok_or_else(|| AgentError::State("active execution identity changed".into()))?;
    if record.terminal() {
        return Ok(());
    }
    if record.termination_cause.is_none() {
        record.termination_cause = Some(state);
        record.end_reason = Some(reason.to_owned());
        record.cancel_requested = true;
    }
    write_store(state_dir, &store)
}

pub(crate) fn finalize_active(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    state: JobState,
    exit_code: Option<i32>,
    reason: Option<String>,
) -> Result<AgentRecord, AgentError> {
    let _lock = StateLock::acquire(state_dir)?;
    let mut store = read_store(state_dir)?;
    let record = store
        .active
        .as_mut()
        .filter(|record| record.job_id == job_id && record.start_token == token)
        .ok_or_else(|| AgentError::State("active execution identity changed".into()))?;
    let final_state = record.termination_cause.unwrap_or(state);
    if record.termination_cause.is_none() {
        record.end_reason = reason;
    }
    record.terminal_state = Some(final_state);
    record.exit_code = exit_code;
    record.phase = RuntimePhase::Idle;
    record.child_pid = None;
    record.child_start_id = None;
    record.log_sync_pending = true;
    record.log_sync_retry_after_unix_ms = None;
    let output = record.clone();
    write_store(state_dir, &store)?;
    Ok(output)
}

pub(crate) fn active_record(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
) -> Result<AgentRecord, AgentError> {
    load_active(state_dir, job_id, token)
}

pub(crate) fn wait_for_active_execution(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    timeout: std::time::Duration,
) -> Result<AgentRecord, AgentError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        {
            let _lock = StateLock::acquire(state_dir)?;
            let store = read_store(state_dir)?;
            match store.active {
                Some(record) if record.job_id == job_id && record.start_token == token => {
                    return Ok(record);
                }
                Some(record) if !record.terminal() => {
                    return Err(AgentError::State(
                        "a different execution identity is active".into(),
                    ));
                }
                _ => {}
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(AgentError::State(
                "active execution identity did not become ready for attachment".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

pub(crate) fn local_script_path(state_dir: &Path, job_id: u64) -> PathBuf {
    state_dir
        .join("jobs")
        .join(job_id.to_string())
        .join("script.sh")
}

fn admit_epoch(store: &mut AgentStore, request: ControllerEpoch) -> Result<(), String> {
    if store.reset_fence || store.pending_archive.is_some() || store.pending_handoff.is_some() {
        return Err(
            "agent administrative transition must be resumed before controller requests".into(),
        );
    }
    if store.controller.is_none() && !store.retired_controllers.is_empty() {
        return Err("retired agent requires an explicit idle claim".into());
    }
    if let Some(current) = store.controller {
        if current.controller_uuid != request.controller_uuid {
            return Err(
                "a different controller owns this agent; explicit recovery is required".into(),
            );
        }
        if request.epoch < current.epoch {
            return Err(format!(
                "request epoch {} is older than accepted epoch {}",
                request.epoch, current.epoch
            ));
        }
    }
    if store
        .controller
        .is_none_or(|current| request.epoch > current.epoch)
    {
        store.controller = Some(request);
    }
    Ok(())
}

fn verify_share(config: &ClusterConfig, local_node_id: &str) -> Result<(), AgentError> {
    let marker = read_share_marker(&config.shared_root.join(".macluster-share-id"))?;
    if marker.trim() != config.share_uuid {
        return Err(AgentError::SharedStorage);
    }
    let Some(storage) = config.nodes.get(config.storage_server.as_str()) else {
        return Err(AgentError::SharedStorage);
    };
    let mounts = Command::new("/sbin/mount").output()?;
    let mount_output = String::from_utf8_lossy(&mounts.stdout);
    let expected_nfs_mount = primary_nfs_mount_matches(
        &mount_output,
        &storage.host,
        config.primary_source_root(),
        &config.shared_root,
    );
    let (filesystem, flags) = filesystem_info(&config.shared_root)?;
    if share_mount_valid(
        local_node_id,
        config.storage_server.as_str(),
        &filesystem,
        flags,
        expected_nfs_mount,
    ) {
        Ok(())
    } else {
        Err(AgentError::SharedStorage)
    }
}

fn verify_record_primary_share(record: &AgentRecord) -> Result<(), AgentError> {
    let Some(share_uuid) = record.share_uuid.as_deref() else {
        return Err(AgentError::SharedStorage);
    };
    let Some(storage_node_id) = record.storage_node_id.as_deref() else {
        return Err(AgentError::SharedStorage);
    };
    let Some(storage_host) = record.storage_host.as_deref() else {
        return Err(AgentError::SharedStorage);
    };
    let Some(source_root) = record.storage_source_root.as_deref() else {
        return Err(AgentError::SharedStorage);
    };
    let root = Path::new(&record.shared_root);
    let marker = read_share_marker(&root.join(".macluster-share-id"))?;
    if marker.trim() != share_uuid {
        return Err(AgentError::SharedStorage);
    }
    let mounts = Command::new("/sbin/mount").output()?;
    let mount_output = String::from_utf8_lossy(&mounts.stdout);
    let expected_nfs_mount =
        primary_nfs_mount_matches(&mount_output, storage_host, Path::new(source_root), root);
    let (filesystem, flags) = filesystem_info(root)?;
    if share_mount_valid(
        &record.node_id,
        storage_node_id,
        &filesystem,
        flags,
        expected_nfs_mount,
    ) {
        Ok(())
    } else {
        Err(AgentError::SharedStorage)
    }
}

fn primary_nfs_mount_matches(
    mount_output: &str,
    storage_host: &str,
    source_root: &Path,
    mount_root: &Path,
) -> bool {
    let expected = format!(
        "{storage_host}:{} on {} (nfs",
        source_root.display(),
        mount_root.display()
    );
    mount_output.lines().any(|line| line.starts_with(&expected))
}

fn read_share_marker(path: &Path) -> Result<String, AgentError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AgentError::SharedStorage);
    }
    Ok(fs::read_to_string(path)?)
}

#[cfg(target_vendor = "apple")]
fn filesystem_info(path: &Path) -> io::Result<(String, u32)> {
    use std::mem::MaybeUninit;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut info = MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(path.as_ptr(), info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    let filesystem = unsafe { CStr::from_ptr(info.f_fstypename.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    Ok((filesystem, info.f_flags))
}

#[cfg(not(target_vendor = "apple"))]
fn filesystem_info(_path: &Path) -> io::Result<(String, u32)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "macOS filesystem metadata is unavailable",
    ))
}

fn share_mount_valid(
    local_node_id: &str,
    storage_node_id: &str,
    filesystem: &str,
    flags: u32,
    expected_nfs_mount: bool,
) -> bool {
    if filesystem == "nfs" {
        expected_nfs_mount
    } else {
        local_node_id == storage_node_id && flags & (libc::MNT_LOCAL as u32) != 0
    }
}

fn verify_file(path: &Path, snapshot: &SnapshotRef) -> Result<(), AgentError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() != snapshot.size_bytes || metadata.len() > MAX_SNAPSHOT_BYTES {
        return Err(AgentError::SnapshotMismatch);
    }
    let bytes = fs::read(path)?;
    if sha256_hex(&bytes).map_err(|error| AgentError::State(error.to_string()))? != snapshot.sha256
    {
        return Err(AgentError::SnapshotMismatch);
    }
    Ok(())
}

fn copy_snapshot(source: &Path, target: &Path, snapshot: &SnapshotRef) -> Result<(), AgentError> {
    if target.exists() {
        verify_file(target, snapshot)?;
        return Ok(());
    }
    verify_file(source, snapshot)?;
    let temp = target.with_extension(format!("{}.tmp", Id128::random()));
    let result = (|| -> io::Result<()> {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        fs::rename(&temp, target)?;
        File::open(target.parent().expect("job dir exists"))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    verify_file(target, snapshot)
}

fn read_store(state_dir: &Path) -> Result<AgentStore, AgentError> {
    let path = state_dir.join("agent-state.json");
    if !path.exists() {
        return Ok(AgentStore::default());
    }
    serde_json::from_slice(&fs::read(path)?).map_err(|error| AgentError::State(error.to_string()))
}

fn write_store(state_dir: &Path, store: &AgentStore) -> Result<(), AgentError> {
    fs::create_dir_all(state_dir)?;
    fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))?;
    // The receipt is durable before a Running/authorized main record can be
    // committed and before the runner releases its user-code start gate.
    if let Some(active) = &store.active {
        write_execution_receipt(state_dir, active)?;
    }
    let bytes = serde_json::to_vec(store).map_err(|error| AgentError::State(error.to_string()))?;
    let path = state_dir.join("agent-state.json");
    let temp = state_dir.join(format!(".agent-state-{}.tmp", Id128::random()));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        File::open(state_dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result?;
    Ok(())
}

fn execution_receipt_path(state: &Path, job_id: u64, token: StartToken) -> PathBuf {
    state
        .join("jobs")
        .join(job_id.to_string())
        .join(format!("execution-{token}.json"))
}

fn read_execution_receipt(
    state: &Path,
    job_id: u64,
    token: StartToken,
) -> Result<Option<AgentRecord>, AgentError> {
    let path = execution_receipt_path(state, job_id, token);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > macluster_protocol::framing::MAX_FRAME_BYTES as u64
    {
        return Err(AgentError::State("invalid execution receipt file".into()));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| AgentError::State(error.to_string()))
}

fn write_execution_receipt(state: &Path, record: &AgentRecord) -> Result<(), AgentError> {
    let path = execution_receipt_path(state, record.job_id, record.start_token);
    let parent = path.parent().expect("job directory");
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(".execution-{}.tmp", Id128::random()));
    let result = (|| -> Result<(), AgentError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(
            &serde_json::to_vec(record).map_err(|error| AgentError::State(error.to_string()))?,
        )?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
        File::open(parent)?.sync_all()?;
        // Persist the job-directory entry before a task can pass its start gate.
        File::open(parent.parent().expect("jobs directory"))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

struct StateLock(File);
impl StateLock {
    fn acquire_existing(state_dir: &Path) -> Result<Self, AgentError> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(state_dir.join("agent.lock"))?;
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(lock))
    }

    fn acquire(state_dir: &Path) -> Result<Self, AgentError> {
        fs::create_dir_all(state_dir)?;
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(state_dir.join("agent.lock"))?;
        let result = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(lock))
    }
}
impl Drop for StateLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}

fn protocol_failed(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::Failed(error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessIdentity {
    Match,
    Gone,
    Reused,
    Unverifiable,
}

#[cfg(target_vendor = "apple")]
fn process_start_identity(pid: u32) -> Option<String> {
    use std::mem::{MaybeUninit, size_of};

    #[repr(C)]
    #[allow(dead_code)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
        comm: [libc::c_char; 16],
        name: [libc::c_char; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        nice: i32,
        start_sec: u64,
        start_usec: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
    }
    const PROC_PIDTBSDINFO: i32 = 3;
    let mut info = MaybeUninit::<ProcBsdInfo>::uninit();
    let returned = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size_of::<ProcBsdInfo>() as i32,
        )
    };
    if returned != size_of::<ProcBsdInfo>() as i32 {
        return None;
    }
    let info = unsafe { info.assume_init() };
    (info.pid == pid).then(|| format!("{}:{}", info.start_sec, info.start_usec))
}

#[cfg(not(target_vendor = "apple"))]
fn process_start_identity(_pid: u32) -> Option<String> {
    None
}

fn wait_for_process_start_identity(pid: u32) -> Option<String> {
    for _ in 0..100 {
        if let Some(identity) = process_start_identity(pid) {
            return Some(identity);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    None
}

fn process_identity(pid: u32, expected_start_id: &str) -> ProcessIdentity {
    match process_start_identity(pid) {
        Some(actual) if actual == expected_start_id => ProcessIdentity::Match,
        Some(_) => ProcessIdentity::Reused,
        None if unsafe { libc::kill(pid as i32, 0) } == 0
            || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) =>
        {
            ProcessIdentity::Unverifiable
        }
        None => ProcessIdentity::Gone,
    }
}

fn boot_id() -> String {
    Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.boottime"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

pub fn default_state_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Users/unknown"))
        .join("Library/Application Support/macluster/agent")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use macluster_protocol::identifiers::{ControllerUuid, QueueName};
    use std::collections::BTreeMap;
    #[cfg(target_vendor = "apple")]
    use std::os::unix::process::CommandExt;

    const TEST_SHARE_UUID: &str = "00000000-0000-4000-8000-000000000001";

    pub(super) fn status_fixture(
        label: &str,
        boot_id: &str,
        terminal_state: Option<JobState>,
        log_sync_pending: bool,
    ) -> (PathBuf, PathBuf, StartToken, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "macluster-agent-status-{label}-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let state_dir = root.join("agent");
        let shared = root.join("shared");
        let local_job_dir = state_dir.join("jobs/1");
        let shared_job_dir = shared.join("jobs/1");
        fs::create_dir_all(&local_job_dir).unwrap();
        fs::create_dir_all(&shared_job_dir).unwrap();
        fs::write(
            shared.join(".macluster-share-id"),
            format!("{TEST_SHARE_UUID}\n"),
        )
        .unwrap();
        fs::write(local_job_dir.join("stdout.log"), b"saved stdout\n").unwrap();
        fs::write(local_job_dir.join("stderr.log"), b"saved stderr\n").unwrap();
        let shared = shared.canonicalize().unwrap();
        let token = StartToken(Id128::random());
        let spec = JobSpec {
            storage_namespace: None,
            queue: QueueName::new("mini01").unwrap(),
            node: None,
            name: "status-recovery".into(),
            cwd: shared.to_string_lossy().into_owned(),
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
            snapshot: None,
        };
        let record = AgentRecord {
            controller: ControllerEpoch {
                controller_uuid: ControllerUuid(Id128::random()),
                epoch: 1,
            },
            start_token: token,
            job_id: 1,
            node_id: "mini01-a".into(),
            shared_root: shared.to_string_lossy().into_owned(),
            tool_paths: Vec::new(),
            named_shares: Vec::new(),
            spec,
            phase: if terminal_state.is_some() {
                RuntimePhase::Idle
            } else {
                RuntimePhase::Running
            },
            authorized: true,
            runner_pid: Some(999_999),
            runner_start_id: Some("old-runner".into()),
            child_pid: None,
            child_start_id: None,
            task_start_gated: true,
            share_uuid: Some(TEST_SHARE_UUID.into()),
            storage_node_id: Some("mini01-a".into()),
            storage_host: Some("127.0.0.1".into()),
            storage_source_root: Some(shared.to_string_lossy().into_owned()),
            terminal_state,
            termination_cause: None,
            exit_code: None,
            end_reason: None,
            cancel_requested: false,
            force_cancel: false,
            boot_id: boot_id.into(),
            log_sync_pending,
            log_sync_retry_after_unix_ms: None,
            started_unix_ms: 1,
        };
        write_store(
            &state_dir,
            &AgentStore {
                controller: Some(record.controller),
                active: Some(record),
                tombstones: Vec::new(),
                log_sync_shutdown: None,
                ..AgentStore::default()
            },
        )
        .unwrap();
        (root, state_dir, token, shared)
    }

    pub(super) fn status_config(shared_root: &Path) -> ClusterConfig {
        ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"mini01\"\nshared_root = \"{}\"\nshare_uuid = \"{}\"\nstorage_server = \"mini01-a\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"mini01-a\"]\nscheduler = \"fifo\"\n\n[nodes.mini01-a]\nhost = \"127.0.0.1\"\ntransport = \"ssh\"\n",
            shared_root.display(),
            TEST_SHARE_UUID
        ))
        .unwrap()
    }

    // Recovery and publication are deliberately separate now. These tests
    // exercise a completed publication in-process; the CLI integration tests
    // cover actual asynchronous scheduling and watchdog behavior.
    fn status_with_publication_for_test(
        state_dir: &Path,
        config: &ClusterConfig,
        local_node_id: &str,
    ) -> Result<ExecutionStatus, ProtocolError> {
        let response = status(state_dir)?;
        if response.terminal_state.is_some() && response.log_sync_pending {
            let mut snapshot = read_store(state_dir).unwrap().active.unwrap();
            hydrate_record_storage_identity(&mut snapshot, config);
            let result = verify_share(config, local_node_id)
                .map_err(|error| io::Error::other(error.to_string()))
                .and_then(|()| runner::sync_pending_logs(state_dir, &snapshot, || {}));
            commit_log_sync_result(state_dir, snapshot, result)?;
        }
        status(state_dir)
    }

    #[test]
    fn terminal_log_identity_follows_storage_address_only_with_the_same_namespace() {
        let (root, state_dir, _, shared) = status_fixture(
            "readdress-storage",
            &boot_id(),
            Some(JobState::Completed),
            true,
        );
        let original = read_store(&state_dir).unwrap().active.unwrap();
        let mut config = status_config(&shared);
        config.nodes.get_mut("mini01-a").unwrap().host = "192.0.2.20".into();
        let mut migrated = original.clone();
        hydrate_record_storage_identity(&mut migrated, &config);
        assert_eq!(migrated.storage_host.as_deref(), Some("192.0.2.20"));
        assert!(migrated.log_sync_pending);
        assert_eq!(migrated.start_token, original.start_token);
        let mut running = original.clone();
        running.terminal_state = None;
        running.phase = RuntimePhase::Running;
        hydrate_record_storage_identity(&mut running, &config);
        assert_eq!(running.storage_host.as_deref(), Some("127.0.0.1"));
        config.share_uuid = "00000000-0000-4000-8000-000000000099".into();
        let mut wrong_cluster = original;
        hydrate_record_storage_identity(&mut wrong_cluster, &config);
        assert_eq!(wrong_cluster.storage_host.as_deref(), Some("127.0.0.1"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_identity_requires_the_registered_machine_and_execution_user() {
        let node = ClusterConfig::parse(
            r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "/Users/Shared/macluster"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "login"
protocol_version = 1

[queues.mini01]
nodes = ["login"]
scheduler = "fifo"

[nodes.login]
host = "192.168.2.3"
transport = "local"
machine_uuid = "00000000-0000-4000-8000-000000000003"
execution_uid = 501
"#,
        )
        .unwrap()
        .nodes["login"]
            .clone();

        assert!(validate_node_identity(&node, "00000000-0000-4000-8000-000000000003", 501).is_ok());
        assert!(
            validate_node_identity(&node, "00000000-0000-4000-8000-000000000004", 501).is_err()
        );
        assert!(
            validate_node_identity(&node, "00000000-0000-4000-8000-000000000003", 502).is_err()
        );
    }

    #[test]
    fn runner_identity_rejects_a_reused_pid() {
        let pid = std::process::id();
        let start_id =
            process_start_identity(pid).expect("proc_pidinfo must identify this process");
        assert_eq!(process_identity(pid, &start_id), ProcessIdentity::Match);
        assert_eq!(process_identity(pid, "0:0"), ProcessIdentity::Reused);
    }

    #[test]
    fn execution_receipt_recovers_lost_main_state_without_restarting_user_code() {
        let (root, state, token, shared) =
            status_fixture("receipt-recovery", "previous-boot", None, false);
        let controller = read_store(&state).unwrap().active.unwrap().controller;
        fs::remove_file(state.join("agent-state.json")).unwrap();
        let result = handle_operation(
            Operation::RecoverJob {
                controller,
                start_token: token,
                job_id: 1,
            },
            &status_config(&shared),
            &state,
            "mini01-a",
        )
        .unwrap();
        let ResponseBody::Execution(status) = result else {
            panic!("expected recovered execution");
        };
        assert_eq!(status.terminal_state, Some(JobState::NodeLost));
        assert!(status.log_sync_pending);
        assert_eq!(
            read_store(&state).unwrap().active.unwrap().start_token,
            token
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn receipt_recovery_refuses_an_unrelated_controller() {
        let (root, state, token, shared) =
            status_fixture("receipt-controller", "previous-boot", None, false);
        let mut controller = read_store(&state).unwrap().active.unwrap().controller;
        controller.controller_uuid = ControllerUuid(Id128::random());
        fs::remove_file(state.join("agent-state.json")).unwrap();
        assert!(
            handle_operation(
                Operation::RecoverJob {
                    controller,
                    start_token: token,
                    job_id: 1
                },
                &status_config(&shared),
                &state,
                "mini01-a"
            )
            .is_err()
        );
        assert!(read_store(&state).unwrap().active.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn receipt_recovery_stops_a_verified_orphan_after_main_state_is_deleted() {
        let (root, state, token, shared) =
            status_fixture("receipt-orphan", &boot_id(), None, false);
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let mut store = read_store(&state).unwrap();
        let record = store.active.as_mut().unwrap();
        record.child_pid = Some(child.id());
        record.child_start_id = Some(wait_for_process_start_identity(child.id()).unwrap());
        let controller = record.controller;
        write_store(&state, &store).unwrap();
        fs::remove_file(state.join("agent-state.json")).unwrap();
        let result = recover_job(
            controller,
            token,
            1,
            &status_config(&shared),
            &state,
            "mini01-a",
        )
        .unwrap();
        assert_eq!(result.terminal_state, Some(JobState::NodeLost));
        assert!(result.log_sync_pending);
        assert!(child.wait().is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_recovers_a_previous_boot_and_publishes_surviving_logs() {
        let (root, state_dir, _token, shared) =
            status_fixture("previous-boot", "old-boot", None, false);

        let config = status_config(&shared);
        let status = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();

        assert_eq!(status.terminal_state, Some(JobState::NodeLost));
        assert!(!status.log_sync_pending);
        assert_eq!(
            fs::read(shared.join("jobs/1/stdout.log")).unwrap(),
            b"saved stdout\n"
        );
        assert_eq!(
            fs::read(shared.join("jobs/1/stderr.log")).unwrap(),
            b"saved stderr\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_failed_retry_cannot_resurrect_successful_log_sync() {
        let (root, state_dir, _token, _shared) = status_fixture(
            "sync-commit-race",
            &boot_id(),
            Some(JobState::Completed),
            true,
        );
        let mut store = read_store(&state_dir).unwrap();
        let snapshot = store.active.clone().unwrap();
        store.active.as_mut().unwrap().log_sync_pending = false;
        write_store(&state_dir, &store).unwrap();

        commit_log_sync_result(
            &state_dir,
            snapshot,
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another publisher holds the lock",
            )),
        )
        .unwrap();

        let record = read_store(&state_dir).unwrap().active.unwrap();
        assert!(!record.log_sync_pending);
        assert!(record.log_sync_retry_after_unix_ms.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_retries_pending_log_sync_idempotently() {
        let current_boot = boot_id();
        let (root, state_dir, _token, shared) = status_fixture(
            "pending-logs",
            &current_boot,
            Some(JobState::Completed),
            true,
        );
        let config = status_config(&shared);

        let first = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();
        let second = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();

        assert!(!first.log_sync_pending);
        assert!(!second.log_sync_pending);
        assert_eq!(
            fs::read(shared.join("jobs/1/stdout.log")).unwrap(),
            b"saved stdout\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn status_keeps_sync_pending_when_the_shared_root_is_not_the_nfs_mount() {
        let current_boot = boot_id();
        let (root, state_dir, _token, shared) = status_fixture(
            "missing-nfs",
            &current_boot,
            Some(JobState::Completed),
            true,
        );
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"mini01\"\nshared_root = \"{}\"\nshare_uuid = \"{}\"\nstorage_server = \"mini01-b\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"mini01-a\", \"mini01-b\"]\nscheduler = \"fifo\"\n\n[nodes.mini01-a]\nhost = \"127.0.0.1\"\ntransport = \"ssh\"\n\n[nodes.mini01-b]\nhost = \"127.0.0.2\"\ntransport = \"ssh\"\n",
            shared.display(),
            TEST_SHARE_UUID
        ))
        .unwrap();

        let status = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();

        assert!(status.log_sync_pending);
        assert!(!shared.join("jobs/1/stdout.log").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn status_recovers_a_dead_runner_and_stops_its_task_group() {
        let current_boot = boot_id();
        let (root, state_dir, _token, shared) =
            status_fixture("orphaned-task", &current_boot, None, false);
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let child_pid = child.id();
        let child_start_id = wait_for_process_start_identity(child_pid).unwrap();
        let mut store = read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.child_pid = Some(child_pid);
        record.child_start_id = Some(child_start_id);
        write_store(&state_dir, &store).unwrap();

        let config = status_config(&shared);
        let status = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();

        assert_eq!(status.terminal_state, Some(JobState::NodeLost));
        assert!(!status.log_sync_pending);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while child.try_wait().unwrap().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "orphaned task is still running"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lost_gated_launch_does_not_require_logs_from_unstarted_user_code() {
        let (root, state_dir, _token, _shared) =
            status_fixture("unstarted-output", &boot_id(), None, false);
        let mut record = read_store(&state_dir).unwrap().active.unwrap();
        record.phase = RuntimePhase::Launching;
        record.child_pid = None;
        mark_lost_execution(&mut record, "runner disappeared before task start");
        assert!(!record.log_sync_pending);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn status_resolves_a_gated_launch_when_the_runner_dies_before_pid_persist() {
        let current_boot = boot_id();
        let (root, state_dir, _token, shared) =
            status_fixture("gated-launch", &current_boot, None, false);
        let mut store = read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.phase = RuntimePhase::Launching;
        record.task_start_gated = true;
        record.child_pid = None;
        record.child_start_id = None;
        write_store(&state_dir, &store).unwrap();

        let config = status_config(&shared);
        let status = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();

        assert_eq!(status.terminal_state, Some(JobState::NodeLost));
        assert!(!status.log_sync_pending);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn gated_launch_recovers_after_a_transient_unknown_observation() {
        let (root, state_dir, _token, shared) =
            status_fixture("unknown-gated-launch", &boot_id(), None, false);
        let mut store = read_store(&state_dir).unwrap();
        store.active.as_mut().unwrap().phase = RuntimePhase::Unknown;
        write_store(&state_dir, &store).unwrap();
        fs::remove_file(state_dir.join("jobs/1/stdout.log")).unwrap();
        fs::remove_file(state_dir.join("jobs/1/stderr.log")).unwrap();

        let result =
            status_with_publication_for_test(&state_dir, &status_config(&shared), "mini01-a")
                .unwrap();

        fs::remove_dir_all(root).unwrap();
        assert_eq!(result.terminal_state, Some(JobState::NodeLost));
        assert!(!result.log_sync_pending);
    }

    #[test]
    fn status_resolves_an_uncommitted_unauthorized_runner_launch() {
        let current_boot = boot_id();
        let (root, state_dir, _token, shared) =
            status_fixture("unauthorized-launch", &current_boot, None, false);
        let mut store = read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.phase = RuntimePhase::Launching;
        record.authorized = false;
        record.runner_pid = None;
        record.runner_start_id = None;
        record.task_start_gated = true;
        record.child_pid = None;
        record.child_start_id = None;
        write_store(&state_dir, &store).unwrap();

        let config = status_config(&shared);
        let status = status_with_publication_for_test(&state_dir, &config, "mini01-a").unwrap();

        assert_eq!(status.terminal_state, Some(JobState::NodeLost));
        assert!(!status.log_sync_pending);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn share_validation_accepts_local_storage_and_exact_nfs_clients() {
        let local = libc::MNT_LOCAL as u32;
        assert!(share_mount_valid(
            "mini01-a", "mini01-a", "apfs", local, false
        ));
        assert!(!share_mount_valid(
            "login", "mini01-a", "apfs", local, false
        ));
        assert!(share_mount_valid("login", "mini01-a", "nfs", 0, true));
        assert!(!share_mount_valid("login", "mini01-a", "nfs", 0, false));
    }

    #[test]
    fn primary_mount_validation_uses_server_source_and_client_mount_paths() {
        let output = "192.168.2.1:/Volumes/Storage/macluster on /Users/Shared/macluster (nfs, nodev, nosuid)\n";
        assert!(primary_nfs_mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!primary_nfs_mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Users/Shared/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!primary_nfs_mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/other"),
        ));
    }

    #[test]
    fn accepted_epoch_rejects_delayed_old_controller_mutations() {
        let root = std::env::temp_dir().join(format!(
            "macluster-fence-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let controller = ControllerEpoch {
            controller_uuid: macluster_protocol::identifiers::ControllerUuid::random(),
            epoch: 4,
        };
        fence(controller, &root).unwrap();
        let stale = ControllerEpoch {
            epoch: 3,
            ..controller
        };
        assert!(matches!(fence(stale, &root), Err(ProtocolError::Failed(_))));
        let unrelated = ControllerEpoch {
            controller_uuid: macluster_protocol::identifiers::ControllerUuid::random(),
            epoch: 5,
        };
        assert!(matches!(
            fence(unrelated, &root),
            Err(ProtocolError::Failed(_))
        ));
        assert_eq!(read_store(&root).unwrap().controller, Some(controller));
        fs::remove_dir_all(root).unwrap();
    }
}
