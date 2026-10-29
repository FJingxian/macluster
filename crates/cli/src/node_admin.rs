//! SSH based enrollment and removal of compute nodes.

mod addresses;
mod primary_reuse;

pub(crate) use addresses::{
    address_migration_has_active_jobs, address_migration_pending, prepare_node_address_migration,
    refresh_node_addresses, watch_node_addresses,
};

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use macluster_controller::ssh::{ConnectionKey, SshPool};
use macluster_controller::transport::{ClusterTransport, NodeTransport};
use macluster_core::{
    config::{ClusterConfig, NodeConfig, ShareConfig, Transport},
    maintenance::{MaintenanceLock, maintenance_barrier_path, read_maintenance_barrier},
    service::ServiceBinding,
    storage::{ReadOnlyJobStore, Storage},
};
use macluster_protocol::{
    control::{
        ControlCommand, ControlErrorCode, ControlPayload, MaintenancePhase, MaintenanceScope,
        MaintenanceTicket,
    },
    framing::sha256_hex,
    identifiers::{Id128, NodeId, QueueName},
    types::{
        ControllerEpoch, ExecutionStatus, INTERACTIVE_PTY_FEATURE, METRICS_FAN_SPEED_FEATURE,
        NodeHealth, Operation, ProtocolError, ResponseBody, RuntimePhase,
    },
};
use serde::{Deserialize, Serialize};

use crate::control_client::{ControlClient, ControlClientError};

pub(crate) type AppResult<T> = Result<T, (i32, String)>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const NFS_EXPORTS_PATH: &str = "/etc/exports";
const NFS_EXPORTS_TEMP_PATH: &str = "/etc/exports.macluster.tmp";
const NFS_EXPORTS_BACKUP_PATH: &str = "/etc/exports.macluster.bak";
const NFS_DAEMON_PATH: &str = "/sbin/nfsd";
const POWER_HELPER_PATH: &str = "/Library/PrivilegedHelperTools/org.macluster.power";
const POWER_LAUNCHD_PATH: &str = "/Library/LaunchDaemons/org.macluster.power.plist";
const POWER_LAUNCHD_LABEL: &str = "org.macluster.power";
const SSH_OPTIONS: &[&str] = &[
    "-T",
    "-oLogLevel=ERROR",
    "-oBatchMode=yes",
    "-oStrictHostKeyChecking=yes",
    "-oConnectTimeout=5",
    "-oServerAliveInterval=5",
    "-oServerAliveCountMax=1",
];
const INTERACTIVE_SSH_OPTIONS: &[&str] = &[
    "-tt",
    "-oLogLevel=ERROR",
    "-oBatchMode=no",
    "-oStrictHostKeyChecking=yes",
    "-oConnectTimeout=5",
    "-oServerAliveInterval=5",
    "-oServerAliveCountMax=1",
];
const ADMIN_COMMAND_LIMIT: Duration = Duration::from_secs(300);
const ADMIN_TIMEOUT: &str = "administrator command timed out";

const MAINTENANCE_WAIT_LIMIT: Duration = Duration::from_secs(300);

struct NodeMaintenanceGuard {
    _maintenance: Option<MaintenanceLock>,
    _barrier_lock: Option<File>,
    _client_lock: Option<File>,
    barrier_path: Option<PathBuf>,
    controller_was_running: bool,
    recovered: bool,
    live: Option<LiveMaintenance>,
}

struct LiveMaintenance {
    operation: String,
    client: ControlClient,
    ticket: MaintenanceTicket,
    config_path: PathBuf,
    state_path: PathBuf,
    journal_path: PathBuf,
    initial_config_digest: Option<String>,
    initial_journal_digest: Option<String>,
    client_state: MaintenanceClientState,
    finished: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MaintenanceClientState {
    version: u32,
    binding_digest: String,
    operation: String,
    scope: MaintenanceScope,
    operation_id: Id128,
    #[serde(default)]
    initial_config_digest: Option<String>,
    #[serde(default)]
    initial_journal_digest: Option<String>,
    #[serde(default)]
    candidate_config_digest: Option<String>,
    #[serde(default)]
    candidate_journal_digest: Option<String>,
}

impl Drop for NodeMaintenanceGuard {
    fn drop(&mut self) {
        if let Some(barrier_path) = self.barrier_path.as_ref()
            && let Err(error) = fs::remove_file(barrier_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "macluster: could not remove maintenance barrier {}: {error}; rerun the interrupted cluster command to recover maintenance",
                barrier_path.display()
            );
        }
        if let Some(live) = self.live.as_ref()
            && !live.finished
        {
            eprintln!(
                "macluster: maintenance for '{}' remains active; rerun the same command to resume it",
                live.operation
            );
        }
    }
}

impl NodeMaintenanceGuard {
    fn complete(&mut self) -> AppResult<()> {
        let Some(live) = self.live.as_mut() else {
            return Ok(());
        };
        let bytes = fs::read(&live.config_path).map_err(io_error)?;
        let digest = sha256_hex(&bytes).map_err(|error| (1, error.to_string()))?;
        let journal_bytes = match fs::read(&live.journal_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(io_error(error)),
        };
        let journal_digest = sha256_hex(&journal_bytes).map_err(|error| (1, error.to_string()))?;
        let mut client_state = live.client_state.clone();
        client_state.candidate_config_digest = Some(digest.clone());
        client_state.candidate_journal_digest = Some(journal_digest.clone());
        write_maintenance_client_state(&live.state_path, &client_state)?;
        live.client_state = client_state;
        let operation = live.operation.clone();
        retry_maintenance_completion(&operation, || {
            reconnect_live_maintenance(live)?;
            if complete_maintenance_ticket(
                &mut live.client,
                &live.ticket,
                &live.config_path,
                &live.journal_path,
            )? {
                return Ok(true);
            }
            wait_for_live_maintenance(
                &mut live.client,
                &live.ticket,
                &live.client_state.scope,
                &live.operation,
                &live.config_path,
                &live.journal_path,
            )
        })?;
        remove_maintenance_client_state(&live.state_path)?;
        live.finished = true;
        Ok(())
    }

    fn reconcile_after_error(&mut self) -> AppResult<()> {
        let Some(live) = self.live.as_mut() else {
            return Ok(());
        };
        let current_config = fs::read(&live.config_path)
            .ok()
            .and_then(|bytes| sha256_hex(&bytes).ok());
        let current_journal = fs::read(&live.journal_path)
            .ok()
            .and_then(|bytes| sha256_hex(&bytes).ok())
            .or_else(|| {
                (!live.journal_path.exists())
                    .then(|| sha256_hex(&[]).expect("empty byte digest is infallible"))
            });
        let inputs_unchanged = maintenance_inputs_unchanged(
            live.initial_config_digest.as_deref(),
            live.initial_journal_digest.as_deref(),
            current_config.as_deref(),
            current_journal.as_deref(),
        );
        let config_digest = current_config.as_deref().ok_or_else(|| {
            (
                1,
                "cannot verify cluster config while recovering maintenance".into(),
            )
        })?;
        let journal_digest = current_journal.as_deref().ok_or_else(|| {
            (
                1,
                "cannot verify node admin journal while recovering maintenance".into(),
            )
        })?;
        reconnect_live_maintenance(live)?;
        let active = live
            .client
            .request(ControlCommand::InspectMaintenance)
            .map_err(control_client_error)?;
        let ControlPayload::Maintenance(active) = active else {
            return Err((
                1,
                "controller returned an invalid maintenance status during recovery".into(),
            ));
        };
        let Some(active) = active else {
            remove_maintenance_client_state(&live.state_path)?;
            live.finished = true;
            return Ok(());
        };
        if active.ticket != live.ticket || active.scope != live.client_state.scope {
            return Err((
                1,
                "a different controller maintenance ticket is active; refusing to alter it".into(),
            ));
        }

        let applying = matches!(
            active.phase,
            MaintenancePhase::Applying | MaintenancePhase::RecoveryRequired
        );
        if applying
            && (live.client_state.candidate_config_digest.as_deref() != Some(config_digest)
                || live.client_state.candidate_journal_digest.as_deref() != Some(journal_digest))
        {
            return Err((
                1,
                "controller maintenance entered config application with a different candidate; rerun the original operation to recover it".into(),
            ));
        }

        if inputs_unchanged && !applying {
            match live.client.request(ControlCommand::AbortMaintenance {
                ticket: live.ticket.clone(),
            }) {
                Ok(ControlPayload::Maintenance(None)) => {
                    remove_maintenance_client_state(&live.state_path)?;
                    live.finished = true;
                    return Ok(());
                }
                Ok(_) => {
                    return Err((
                        1,
                        "controller returned an invalid maintenance abort response".into(),
                    ));
                }
                Err(error) => return Err(control_client_error(error)),
            }
        }

        // The command changed its recovery journal or config before failing.
        // Finalize that exact on-disk candidate through the controller so a
        // later mnode operation can safely acquire a fresh maintenance ticket.
        self.complete()
    }
}

fn reconnect_live_maintenance(live: &mut LiveMaintenance) -> AppResult<()> {
    let state_dir = live
        .state_path
        .parent()
        .ok_or_else(|| (1, "invalid maintenance state directory".into()))?;
    let binding = ServiceBinding::load(&live.config_path, state_dir)
        .map_err(|error| (1, error.to_string()))?;
    live.client =
        ControlClient::connect(&binding, Duration::from_secs(5)).map_err(control_client_error)?;
    Ok(())
}

fn finish_node_maintenance<T>(guard: NodeMaintenanceGuard, result: AppResult<T>) -> AppResult<T> {
    finish_node_maintenance_with_success_notice(guard, result, true)
}

fn finish_node_maintenance_with_success_notice<T>(
    mut guard: NodeMaintenanceGuard,
    result: AppResult<T>,
    show_restart_notice: bool,
) -> AppResult<T> {
    match result {
        Ok(value) => {
            guard.complete()?;
            if guard.controller_was_running && show_restart_notice {
                println!(
                    "Restart the controller with `macluster controller run` after this command exits."
                );
            }
            Ok(value)
        }
        Err(error) => {
            let mut error = error;
            if !error.1.contains(ADMIN_TIMEOUT)
                && let Err((_, recovery_error)) = guard.reconcile_after_error()
            {
                error.1 = format!(
                    "{}; controller maintenance recovery also failed: {recovery_error}",
                    error.1
                );
            }
            if guard.controller_was_running {
                eprintln!(
                    "The controller was stopped for maintenance. After resolving the error, run `macluster controller run` to resume scheduling."
                );
            }
            Err(error)
        }
    }
}

pub fn ensure_no_node_maintenance_in_progress(
    config_path: &Path,
    state_dir: &Path,
) -> Result<(), String> {
    if address_migration_pending(state_dir) {
        return Err("node address/NFS migration is pending; rerun the command to complete migration before submitting work".into());
    }
    let config_path = config_path
        .canonicalize()
        .map_err(|error| format!("cannot resolve cluster config: {error}"))?;
    let barrier = maintenance_barrier_path(&config_path);
    match read_maintenance_barrier(&barrier, &config_path, state_dir) {
        Ok(true) => Err(format!(
            "node maintenance is draining the controller; wait for it to finish before submitting or starting another controller"
        )),
        Ok(false) => Ok(()),
        Err(error) => Err(format!(
            "maintenance barrier {} is invalid: {error}; rerun the interrupted cluster command to recover maintenance",
            barrier.display()
        )),
    }
}

fn acquire_node_maintenance(
    config_path: &Path,
    state_dir: &Path,
    operation: &str,
) -> AppResult<NodeMaintenanceGuard> {
    acquire_node_maintenance_with_confirmation(config_path, state_dir, operation, false)
}

fn acquire_node_maintenance_scoped(
    config_path: &Path,
    state_dir: &Path,
    operation: &str,
    scope: MaintenanceScope,
) -> AppResult<NodeMaintenanceGuard> {
    crate::init::reset::ensure_no_reset_in_progress(config_path, state_dir)?;
    let config_path = config_path.canonicalize().map_err(io_error)?;
    fs::create_dir_all(state_dir).map_err(io_error)?;
    let state_dir = state_dir.canonicalize().map_err(io_error)?;
    if let Some(guard) = try_acquire_live_maintenance(&config_path, &state_dir, operation, scope)? {
        return Ok(guard);
    }
    acquire_node_maintenance(&config_path, &state_dir, operation)
}

fn try_acquire_live_maintenance(
    config_path: &Path,
    state_dir: &Path,
    operation: &str,
    mut scope: MaintenanceScope,
) -> AppResult<Option<NodeMaintenanceGuard>> {
    let binding = ServiceBinding::load(config_path, state_dir).map_err(|error| {
        (
            1,
            format!("cannot resolve the controller service binding: {error}"),
        )
    })?;
    let mut client = match ControlClient::connect(&binding, Duration::from_secs(1)) {
        Ok(client) => client,
        Err(_) => return Ok(None),
    };
    if !client
        .hello()
        .capabilities
        .iter()
        .any(|capability| capability == "maintenance.v1")
    {
        return Ok(None);
    }
    // Keep discovery fast, but allow maintenance requests the server's full
    // processing deadline while health reconciliation is in progress.
    client
        .set_timeouts(Duration::from_secs(5))
        .map_err(control_client_error)?;
    let client_lock = acquire_maintenance_client_lock(state_dir)?;
    let config = read_config(config_path)?;
    if let MaintenanceScope::Nodes(nodes) = &mut scope {
        nodes.sort();
        nodes.dedup();
        if nodes.is_empty() {
            return Err((1, "node maintenance scope cannot be empty".into()));
        }
        for node in nodes.iter() {
            if !config.nodes.contains_key(node.as_str()) {
                return Err((
                    2,
                    format!("maintenance scope refers to unconfigured node '{node}'"),
                ));
            }
        }
    }
    let config_bytes = fs::read(config_path).map_err(io_error)?;
    let current_config_digest =
        sha256_hex(&config_bytes).map_err(|error| (1, error.to_string()))?;
    let journal_path = state_dir.join("node-admin.json");
    let journal_bytes = match fs::read(&journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(io_error(error)),
    };
    let current_journal_digest =
        sha256_hex(&journal_bytes).map_err(|error| (1, error.to_string()))?;
    let state_path = state_dir.join("maintenance-client.json");
    let state = match read_maintenance_client_state(&state_path)? {
        Some(state)
            if state.binding_digest == binding.binding_digest()
                && state.operation == operation
                && state.scope == scope =>
        {
            state
        }
        Some(previous) => {
            let active = client
                .request(ControlCommand::InspectMaintenance)
                .map_err(control_client_error)?;
            if let ControlPayload::Maintenance(Some(active)) = active {
                if previous.binding_digest != binding.binding_digest()
                    || previous.operation_id != active.ticket.operation_id
                    || previous.scope != active.scope
                {
                    return Err((
                        1,
                        format!(
                            "controller maintenance {} for {:?} does not match the saved maintenance record; refusing to alter it",
                            active.ticket.operation_id, active.scope
                        ),
                    ));
                }
                let unchanged = previous.binding_digest == binding.binding_digest()
                    && previous.operation_id == active.ticket.operation_id
                    && previous.scope == active.scope
                    && previous.candidate_config_digest.is_none()
                    && previous.candidate_journal_digest.is_none()
                    && maintenance_inputs_unchanged(
                        previous.initial_config_digest.as_deref(),
                        previous.initial_journal_digest.as_deref(),
                        Some(&current_config_digest),
                        Some(&current_journal_digest),
                    );
                if unchanged {
                    if matches!(
                        active.phase,
                        MaintenancePhase::Applying | MaintenancePhase::RecoveryRequired
                    ) {
                        retry_maintenance_completion(&previous.operation, || {
                            if complete_maintenance_ticket(
                                &mut client,
                                &active.ticket,
                                config_path,
                                &journal_path,
                            )? {
                                return Ok(true);
                            }
                            wait_for_live_maintenance(
                                &mut client,
                                &active.ticket,
                                &active.scope,
                                &previous.operation,
                                config_path,
                                &journal_path,
                            )
                        })?;
                    } else {
                        match client
                            .request(ControlCommand::AbortMaintenance {
                                ticket: active.ticket.clone(),
                            })
                            .map_err(control_client_error)?
                        {
                            ControlPayload::Maintenance(None) => {}
                            _ => {
                                return Err((
                                    1,
                                    "controller did not retire unchanged maintenance".into(),
                                ));
                            }
                        }
                    }
                    // Completing the old ticket can advance the generation.
                    client = ControlClient::connect(&binding, Duration::from_secs(5))
                        .map_err(control_client_error)?;
                    eprintln!(
                        "Recovered unchanged interrupted maintenance for {}.",
                        previous.operation
                    );
                } else {
                    let applying = matches!(
                        active.phase,
                        MaintenancePhase::Applying | MaintenancePhase::RecoveryRequired
                    );
                    if applying
                        && (previous.candidate_config_digest.as_deref()
                            != Some(current_config_digest.as_str())
                            || previous.candidate_journal_digest.as_deref()
                                != Some(current_journal_digest.as_str()))
                    {
                        return Err((
                            1,
                            format!(
                                "controller maintenance {} is applying a different config/journal candidate; rerun '{}' to recover it before starting '{operation}'",
                                active.ticket.operation_id, previous.operation
                            ),
                        ));
                    }
                    retry_maintenance_completion(&previous.operation, || {
                        if complete_maintenance_ticket(
                            &mut client,
                            &active.ticket,
                            config_path,
                            &journal_path,
                        )? {
                            return Ok(true);
                        }
                        wait_for_live_maintenance(
                            &mut client,
                            &active.ticket,
                            &active.scope,
                            &previous.operation,
                            config_path,
                            &journal_path,
                        )
                    })?;
                    client = ControlClient::connect(&binding, Duration::from_secs(5))
                        .map_err(control_client_error)?;
                    eprintln!(
                        "Recovered interrupted maintenance for {} before starting {operation}.",
                        previous.operation
                    );
                }
            }
            remove_maintenance_client_state(&state_path)?;
            MaintenanceClientState {
                version: 1,
                binding_digest: binding.binding_digest().to_owned(),
                operation: operation.to_owned(),
                scope: scope.clone(),
                operation_id: Id128::random(),
                initial_config_digest: Some(current_config_digest.clone()),
                initial_journal_digest: Some(current_journal_digest.clone()),
                candidate_config_digest: None,
                candidate_journal_digest: None,
            }
        }
        None => MaintenanceClientState {
            version: 1,
            binding_digest: binding.binding_digest().to_owned(),
            operation: operation.to_owned(),
            scope: scope.clone(),
            operation_id: Id128::random(),
            initial_config_digest: Some(current_config_digest.clone()),
            initial_journal_digest: Some(current_journal_digest.clone()),
            candidate_config_digest: None,
            candidate_journal_digest: None,
        },
    };

    if state.candidate_config_digest.as_deref() == Some(current_config_digest.as_str())
        && state.candidate_journal_digest.as_deref() == Some(current_journal_digest.as_str())
        && matches!(
            client
                .request(ControlCommand::InspectMaintenance)
                .map_err(control_client_error)?,
            ControlPayload::Maintenance(None)
        )
    {
        remove_maintenance_client_state(&state_path)?;
        eprintln!("Recovered completed controller maintenance for {operation}.");
        return Ok(Some(NodeMaintenanceGuard {
            _maintenance: None,
            _barrier_lock: None,
            _client_lock: Some(client_lock),
            barrier_path: None,
            controller_was_running: false,
            recovered: true,
            live: None,
        }));
    }

    write_maintenance_client_state(&state_path, &state)?;
    let begin = client.request(ControlCommand::BeginMaintenance {
        operation_id: state.operation_id,
        scope: scope.clone(),
        journal_digest: current_journal_digest,
    });
    let ticket = match begin {
        Ok(ControlPayload::Maintenance(Some(status))) => status.ticket,
        Ok(_) => {
            return Err((
                1,
                "controller returned an invalid maintenance ticket".into(),
            ));
        }
        Err(error) => {
            let active = client
                .request(ControlCommand::InspectMaintenance)
                .map_err(control_client_error)?;
            match active {
                ControlPayload::Maintenance(Some(status))
                    if status.ticket.operation_id == state.operation_id
                        && status.scope == scope =>
                {
                    status.ticket
                }
                _ => return Err(control_client_error(error)),
            }
        }
    };
    if wait_for_live_maintenance(
        &mut client,
        &ticket,
        &scope,
        operation,
        config_path,
        &journal_path,
    )? {
        remove_maintenance_client_state(&state_path)?;
        eprintln!("Recovered interrupted controller maintenance for {operation}.");
        return Ok(Some(NodeMaintenanceGuard {
            _maintenance: None,
            _barrier_lock: None,
            _client_lock: Some(client_lock),
            barrier_path: None,
            controller_was_running: false,
            recovered: true,
            live: None,
        }));
    }
    Ok(Some(NodeMaintenanceGuard {
        _maintenance: None,
        _barrier_lock: None,
        _client_lock: Some(client_lock),
        barrier_path: None,
        controller_was_running: false,
        recovered: false,
        live: Some(LiveMaintenance {
            operation: operation.to_owned(),
            client,
            ticket,
            config_path: config_path.to_path_buf(),
            state_path,
            journal_path: state_dir.join("node-admin.json"),
            initial_config_digest: state.initial_config_digest.clone(),
            initial_journal_digest: state.initial_journal_digest.clone(),
            client_state: state,
            finished: false,
        }),
    }))
}

fn wait_for_live_maintenance(
    client: &mut ControlClient,
    ticket: &MaintenanceTicket,
    scope: &MaintenanceScope,
    operation: &str,
    config_path: &Path,
    journal_path: &Path,
) -> AppResult<bool> {
    let started = Instant::now();
    let mut last_message = Instant::now();
    let mut next_epoch_check = Instant::now();
    let mut epoch_recovered = false;
    loop {
        match client
            .request(ControlCommand::InspectMaintenance)
            .map_err(control_client_error)?
        {
            ControlPayload::Maintenance(Some(status))
                if status.ticket == *ticket && status.scope == *scope =>
            {
                if matches!(
                    status.phase,
                    MaintenancePhase::Ready | MaintenancePhase::Draining
                ) && !epoch_recovered
                    && Instant::now() >= next_epoch_check
                {
                    next_epoch_check = Instant::now() + Duration::from_secs(5);
                    if recover_stale_maintenance_controller(client, config_path, journal_path)? {
                        epoch_recovered = true;
                        continue;
                    }
                }
                match status.phase {
                    MaintenancePhase::Ready => return Ok(false),
                    MaintenancePhase::RecoveryRequired => {
                        if status.blockers.is_empty() {
                            if complete_maintenance_ticket(
                                client,
                                ticket,
                                config_path,
                                journal_path,
                            )? {
                                return Ok(true);
                            }
                        }
                    }
                    MaintenancePhase::Applying => {
                        if status.blockers.is_empty() {
                            if complete_maintenance_ticket(
                                client,
                                ticket,
                                config_path,
                                journal_path,
                            )? {
                                return Ok(true);
                            }
                        }
                    }
                    MaintenancePhase::Draining => {
                        if last_message.elapsed() >= Duration::from_secs(5) {
                            let reason = status
                                .blockers
                                .first()
                                .map(String::as_str)
                                .unwrap_or("waiting for scoped nodes to become idle");
                            eprintln!("Waiting for controller maintenance {operation}: {reason}");
                            last_message = Instant::now();
                        }
                    }
                }
            }
            ControlPayload::Maintenance(None) => {
                return Err((
                    1,
                    "controller maintenance ticket disappeared before the operation could start"
                        .into(),
                ));
            }
            _ => {
                return Err((
                    1,
                    "controller returned an invalid maintenance status".into(),
                ));
            }
        }
        if started.elapsed() >= MAINTENANCE_WAIT_LIMIT {
            return Err((
                1,
                format!(
                    "controller maintenance did not drain within five minutes; ticket {} remains recorded, rerun '{operation}' to resume",
                    ticket.operation_id
                ),
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn recover_stale_controller_epoch_with(
    running: ControllerEpoch,
    persisted: Option<ControllerEpoch>,
    has_active_execution: bool,
    restart: impl FnOnce() -> AppResult<()>,
) -> AppResult<bool> {
    let Some(persisted) = persisted else {
        return Ok(false);
    };
    if persisted.controller_uuid != running.controller_uuid {
        return Err((
            1,
            "controller identity changed during maintenance; refusing automatic restart".into(),
        ));
    }
    if persisted.epoch <= running.epoch {
        return Ok(false);
    }
    if has_active_execution {
        return Err((1, "controller fencing epoch changed while executions are active; automatic restart is blocked to preserve running work".into()));
    }
    restart()?;
    Ok(true)
}

fn recover_stale_maintenance_controller(
    client: &mut ControlClient,
    config_path: &Path,
    journal_path: &Path,
) -> AppResult<bool> {
    let state_dir = journal_path
        .parent()
        .ok_or((1, "maintenance state directory is missing".into()))?;
    if !state_dir.join("controller.sqlite3").is_file() {
        return Ok(false);
    }
    let storage = ReadOnlyJobStore::open(state_dir).map_err(|error| (1, error.to_string()))?;
    let persisted = storage
        .current_controller_epoch()
        .map_err(|error| (1, error.to_string()))?;
    let running = client.hello().controller_epoch;
    if persisted.is_none_or(|epoch| epoch == running) {
        return Ok(false);
    }
    let active = storage
        .list_active_jobs()
        .map_err(|error| (1, error.to_string()))?
        .iter()
        .any(|job| {
            matches!(
                job.state,
                macluster_protocol::types::JobState::Starting
                    | macluster_protocol::types::JobState::Running
                    | macluster_protocol::types::JobState::Cancelling
            )
        });
    recover_stale_controller_epoch_with(running, persisted, active, || {
        eprintln!(
            "Controller was fenced by an earlier maintenance handoff; restarting the idle controller and resuming maintenance."
        );
        let binding =
            ServiceBinding::load(config_path, state_dir).map_err(|error| (1, error.to_string()))?;
        crate::service::ServiceManager::current(binding.clone())
            .map_err(|error| (1, error.to_string()))?
            .restart(Duration::from_secs(5))
            .map_err(|error| (1, error.to_string()))?;
        let next = ControlClient::connect(&binding, Duration::from_secs(5))
            .map_err(control_client_error)?;
        if next.hello().controller_epoch.controller_uuid != running.controller_uuid
            || next.hello().controller_epoch.epoch
                <= persisted.map_or(running.epoch, |epoch| epoch.epoch)
        {
            return Err((
                1,
                "controller restart did not establish a newer matching fencing epoch".into(),
            ));
        }
        *client = next;
        Ok(())
    })
}

fn complete_maintenance_ticket(
    client: &mut ControlClient,
    ticket: &MaintenanceTicket,
    config_path: &Path,
    journal_path: &Path,
) -> AppResult<bool> {
    let config_bytes = fs::read(config_path).map_err(io_error)?;
    let candidate_config_digest =
        sha256_hex(&config_bytes).map_err(|error| (1, error.to_string()))?;
    let journal_bytes = match fs::read(journal_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(io_error(error)),
    };
    let candidate_journal_digest =
        sha256_hex(&journal_bytes).map_err(|error| (1, error.to_string()))?;
    let response = match client.request(ControlCommand::CompleteMaintenance {
        ticket: ticket.clone(),
        candidate_config_digest,
        candidate_journal_digest,
    }) {
        Ok(response) => response,
        Err(ControlClientError::Remote {
            code: ControlErrorCode::Maintenance,
            message,
        }) if message.contains("still has active jobs")
            || message.contains("maintenance is still draining") =>
        {
            return Ok(false);
        }
        Err(error) => return Err(control_client_error(error)),
    };
    if matches!(response, ControlPayload::Maintenance(None)) {
        Ok(true)
    } else {
        Err((
            1,
            "controller returned an invalid maintenance recovery response".into(),
        ))
    }
}

fn retry_maintenance_completion(
    operation: &str,
    mut attempt: impl FnMut() -> AppResult<bool>,
) -> AppResult<()> {
    let started = Instant::now();
    let mut last_message = Instant::now();
    loop {
        if attempt()? {
            return Ok(());
        }
        if started.elapsed() >= MAINTENANCE_WAIT_LIMIT {
            return Err((
                1,
                format!(
                    "controller maintenance did not complete within five minutes; ticket remains recorded, rerun the command for '{operation}' to resume"
                ),
            ));
        }
        if last_message.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "Waiting for controller maintenance {operation} to become quiescent before finalizing…"
            );
            last_message = Instant::now();
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn control_client_error(error: ControlClientError) -> (i32, String) {
    match error {
        ControlClientError::Remote { message, .. } => (1, message),
        other => (1, format!("controller maintenance request failed: {other}")),
    }
}

pub(crate) fn acquire_maintenance_client_lock(state_dir: &Path) -> AppResult<File> {
    let path = state_dir.join("maintenance-client.lock");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(&path).map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err((
            1,
            format!(
                "maintenance client lock {} has unsafe ownership or permissions",
                path.display()
            ),
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err((
                1,
                "another node maintenance command is preparing or applying an operation".into(),
            ));
        }
        return Err((1, format!("cannot lock maintenance client state: {error}")));
    }
    Ok(file)
}

fn maintenance_inputs_unchanged(
    initial_config: Option<&str>,
    initial_journal: Option<&str>,
    current_config: Option<&str>,
    current_journal: Option<&str>,
) -> bool {
    matches!(
        (initial_config, initial_journal, current_config, current_journal),
        (Some(a), Some(b), Some(c), Some(d)) if a == c && b == d
    )
}

fn read_maintenance_client_state(path: &Path) -> AppResult<Option<MaintenanceClientState>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(error)),
    };
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 4096
    {
        return Err((
            1,
            "maintenance client state has unsafe ownership or permissions".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(io_error)?;
    let state: MaintenanceClientState = serde_json::from_slice(&bytes)
        .map_err(|error| (1, format!("maintenance client state is invalid: {error}")))?;
    if state.version != 1 {
        return Err((1, "unsupported maintenance client state version".into()));
    }
    Ok(Some(state))
}

fn write_maintenance_client_state(path: &Path, state: &MaintenanceClientState) -> AppResult<()> {
    let bytes = serde_json::to_vec(state).map_err(|error| (1, error.to_string()))?;
    let temporary = path.with_file_name(format!(".maintenance-client-{}.tmp", Id128::random()));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(io_error)
}

fn remove_maintenance_client_state(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            fs::remove_file(path).map_err(io_error)
        }
        Ok(_) => Err((
            1,
            "refusing to remove unsafe maintenance client state".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn acquire_node_maintenance_with_confirmation(
    config_path: &Path,
    state_dir: &Path,
    operation: &str,
    shutdown_preconfirmed: bool,
) -> AppResult<NodeMaintenanceGuard> {
    acquire_node_maintenance_with_confirmation_using(
        config_path,
        state_dir,
        operation,
        shutdown_preconfirmed,
        |state_dir| {
            let _ = macluster_controller::wake::notify_controller(state_dir);
        },
        confirm_controller_shutdown,
        find_controller_process,
        stop_controller_process,
    )
}

fn acquire_node_maintenance_with_confirmation_using(
    config_path: &Path,
    state_dir: &Path,
    operation: &str,
    shutdown_preconfirmed: bool,
    notify_controller: impl FnMut(&Path),
    mut confirm_shutdown: impl FnMut(&str) -> AppResult<()>,
    find_controller: impl FnMut(&Path, &Path) -> AppResult<Option<libc::pid_t>>,
    stop_controller: impl FnMut(&Path, &Path, libc::pid_t, &str) -> AppResult<MaintenanceLock>,
) -> AppResult<NodeMaintenanceGuard> {
    acquire_node_maintenance_with(
        config_path,
        state_dir,
        operation,
        notify_controller,
        |operation| {
            if shutdown_preconfirmed {
                Ok(())
            } else {
                confirm_shutdown(operation)
            }
        },
        find_controller,
        stop_controller,
    )
}

fn acquire_node_maintenance_with(
    config_path: &Path,
    state_dir: &Path,
    operation: &str,
    mut notify_controller: impl FnMut(&Path),
    mut confirm_shutdown: impl FnMut(&str) -> AppResult<()>,
    mut find_controller: impl FnMut(&Path, &Path) -> AppResult<Option<libc::pid_t>>,
    mut stop_controller: impl FnMut(&Path, &Path, libc::pid_t, &str) -> AppResult<MaintenanceLock>,
) -> AppResult<NodeMaintenanceGuard> {
    crate::init::reset::ensure_no_reset_in_progress(config_path, state_dir)?;
    let config_path = config_path.canonicalize().map_err(io_error)?;
    fs::create_dir_all(state_dir).map_err(io_error)?;
    let state_dir = state_dir.canonicalize().map_err(io_error)?;
    let mut controller_pid = None;
    let initial_maintenance = match MaintenanceLock::exclusive(&config_path) {
        Ok(lock) => Some(lock),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            controller_pid = find_controller(&config_path, &state_dir)?;
            None
        }
        Err(error) => {
            return Err((1, format!("cannot acquire node maintenance lock: {error}")));
        }
    };
    let barrier_path = maintenance_barrier_path(&config_path);
    let barrier_lock = acquire_barrier_lock(&barrier_path, &config_path, &state_dir)?;
    let mut guard = NodeMaintenanceGuard {
        _maintenance: initial_maintenance,
        _barrier_lock: Some(barrier_lock),
        _client_lock: None,
        barrier_path: Some(barrier_path),
        controller_was_running: false,
        recovered: false,
        live: None,
    };
    if guard._maintenance.is_some() {
        ensure_maintenance_jobs_drained(&state_dir, operation, false)?;
        return Ok(guard);
    }
    if let Some(pid) = controller_pid.take() {
        ensure_maintenance_jobs_drained(&state_dir, operation, false)?;
        confirm_shutdown(operation)?;
        guard._maintenance = Some(stop_controller(&config_path, &state_dir, pid, operation)?);
        guard.controller_was_running = true;
        eprintln!("Controller stopped for {operation}.");
        ensure_maintenance_jobs_drained(&state_dir, operation, true)?;
        return Ok(guard);
    }
    notify_controller(&state_dir);
    let started = Instant::now();
    let mut last_message = Instant::now();
    loop {
        match MaintenanceLock::exclusive(&config_path) {
            Ok(lock) => {
                guard._maintenance = Some(lock);
                if guard.controller_was_running {
                    eprintln!("Controller has drained and stopped for {operation}.");
                }
                ensure_maintenance_jobs_drained(
                    &state_dir,
                    operation,
                    guard.controller_was_running,
                )?;
                return Ok(guard);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(pid) = find_controller(&config_path, &state_dir)? {
                    ensure_maintenance_jobs_drained(&state_dir, operation, false)?;
                    confirm_shutdown(operation)?;
                    ensure_maintenance_jobs_drained(&state_dir, operation, false)?;
                    guard._maintenance =
                        Some(stop_controller(&config_path, &state_dir, pid, operation)?);
                    guard.controller_was_running = true;
                    eprintln!("Controller stopped for {operation}.");
                    ensure_maintenance_jobs_drained(&state_dir, operation, true)?;
                    return Ok(guard);
                }
                if last_message.elapsed() >= Duration::from_secs(5) {
                    eprintln!(
                        "Waiting for another cluster command to release the config lock before {operation}…"
                    );
                    last_message = Instant::now();
                }
                if started.elapsed() >= MAINTENANCE_WAIT_LIMIT {
                    return Err((
                        1,
                        format!(
                            "the config lock stayed busy for five minutes and no verified controller process was found to stop; maintenance was cancelled and the barrier removed. Finish the other cluster command, then retry {operation}."
                        ),
                    ));
                }
                thread::sleep(Duration::from_millis(250));
            }
            Err(error) => {
                return Err((1, format!("cannot acquire node maintenance lock: {error}")));
            }
        }
    }
}

fn confirm_controller_shutdown(operation: &str) -> AppResult<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err((
            2,
            format!("controller is running; rerun {operation} in Terminal to confirm stopping it"),
        ));
    }
    eprint!(
        "Controller is running. Stop it for {operation} now? Running jobs will not be killed, but maintenance will stop if jobs or output sync remain. [y/N] "
    );
    io::stderr().flush().map_err(io_error)?;
    let mut response = String::new();
    io::stdin().read_line(&mut response).map_err(io_error)?;
    if shutdown_confirmation_accepted(&response) {
        Ok(())
    } else {
        Err((
            1,
            format!("{operation} cancelled; the controller was not stopped"),
        ))
    }
}

fn shutdown_confirmation_accepted(response: &str) -> bool {
    matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

pub(crate) fn find_controller_process(
    config_path: &Path,
    state_dir: &Path,
) -> AppResult<Option<libc::pid_t>> {
    let config_lock = maintenance_lock_path(config_path);
    let controller_lock = state_dir.join("controller.lock");
    let config_holders = lock_holders(&config_lock, "config")?;
    let controller_holders = lock_holders(&controller_lock, "controller")?;
    let mut controllers = Vec::new();
    for pid in config_holders.intersection(&controller_holders).copied() {
        if verified_controller_process(pid)? {
            controllers.push(pid);
        }
    }
    match controllers.as_slice() {
        [pid] => Ok(Some(*pid)),
        [] if config_holders.is_empty() || controller_holders.is_empty() => Ok(None),
        [] => Err((
            1,
            "the config and controller locks are held, but their common owner is not a verified `macluster controller run` process; no process was stopped".into(),
        )),
        _ => Err((
            1,
            format!(
                "multiple controller processes hold the config and controller locks for {}; no process was stopped",
                config_path.display()
            ),
        )),
    }
}

fn maintenance_lock_path(config_path: &Path) -> PathBuf {
    let config_path = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".macluster.lock");
    config_path.with_file_name(name)
}

fn lock_holders(path: &Path, kind: &str) -> AppResult<BTreeSet<libc::pid_t>> {
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let output = Command::new("/usr/sbin/lsof")
        .args(["-t", "--"])
        .arg(path)
        .output()
        .map_err(|error| (1, format!("cannot identify {kind} lock owner: {error}")))?;
    if output.stdout.is_empty() {
        if output.status.success() || output.status.code() == Some(1) {
            return Ok(BTreeSet::new());
        }
        return Err((
            1,
            format!(
                "cannot inspect {kind} lock owner: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    if !output.status.success() {
        return Err((
            1,
            format!(
                "cannot inspect {kind} lock owner: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    let mut holders = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let pid = line.trim().parse::<libc::pid_t>().map_err(|error| {
            (
                1,
                format!("lsof returned an invalid {kind} lock PID '{line}': {error}"),
            )
        })?;
        if pid > 0 {
            holders.insert(pid);
        }
    }
    Ok(holders)
}

fn verified_controller_process(pid: libc::pid_t) -> AppResult<bool> {
    let pid_text = pid.to_string();
    let executable = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid_text, "-d", "txt", "-Fn"])
        .output()
        .map_err(|error| {
            (
                1,
                format!("cannot verify controller process {pid}: {error}"),
            )
        })?;
    if !executable.status.success() {
        return Ok(false);
    }
    let executable_output = String::from_utf8_lossy(&executable.stdout);
    let executable_path = executable_output
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .map(Path::new)
        .find(|path| path.file_name().is_some_and(|name| name == "macluster"));
    let Some(executable_path) = executable_path else {
        return Ok(false);
    };

    let process = Command::new("/bin/ps")
        .args(["-p", &pid_text, "-o", "uid=", "-o", "command="])
        .output()
        .map_err(|error| {
            (
                1,
                format!("cannot verify controller process {pid}: {error}"),
            )
        })?;
    if !process.status.success() {
        return Ok(false);
    }
    let output = String::from_utf8_lossy(&process.stdout);
    let Some((uid, command)) = output.trim().split_once(char::is_whitespace) else {
        return Ok(false);
    };
    let Ok(uid) = uid.trim().parse::<libc::uid_t>() else {
        return Ok(false);
    };
    Ok(controller_command_matches(
        executable_path,
        uid,
        unsafe { libc::geteuid() },
        command.trim_start(),
    ))
}

fn controller_command_matches(
    executable_path: &Path,
    process_uid: libc::uid_t,
    current_uid: libc::uid_t,
    command_line: &str,
) -> bool {
    executable_path
        .file_name()
        .is_some_and(|name| name == "macluster")
        && process_uid == current_uid
        && command_line
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|arguments| arguments == ["controller", "run"])
}

pub(crate) fn stop_controller_process(
    config_path: &Path,
    state_dir: &Path,
    pid: libc::pid_t,
    operation: &str,
) -> AppResult<MaintenanceLock> {
    let identity_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match MaintenanceLock::exclusive(config_path) {
            Ok(lock) => return Ok(lock),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err((1, format!("cannot acquire node maintenance lock: {error}")));
            }
        }
        match find_controller_process(config_path, state_dir)? {
            Some(current) if current == pid => break,
            Some(_) => {
                return Err((
                    1,
                    format!(
                        "controller process changed before it could be stopped for {operation}; no process was signaled"
                    ),
                ));
            }
            None if Instant::now() < identity_deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            None => {
                return Err((
                    1,
                    format!(
                        "controller process changed before it could be stopped for {operation}; no process was signaled"
                    ),
                ));
            }
        }
    }
    eprintln!("Stopping controller process {pid} for {operation}…");
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err((
                1,
                format!("could not stop controller process {pid}: {error}"),
            ));
        }
    }

    let term_deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match MaintenanceLock::exclusive(config_path) {
            Ok(lock) => return Ok(lock),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= term_deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err((1, format!("cannot acquire node maintenance lock: {error}")));
            }
        }
    }

    if find_controller_process(config_path, state_dir)? == Some(pid) {
        eprintln!("Controller did not exit after SIGTERM; stopping the verified process.");
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err((
                    1,
                    format!("could not stop controller process {pid}: {error}"),
                ));
            }
        }
    }
    let kill_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match MaintenanceLock::exclusive(config_path) {
            Ok(lock) => return Ok(lock),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= kill_deadline {
                    return Err((
                        1,
                        format!(
                            "controller process {pid} did not release the config lock; no cluster changes were made"
                        ),
                    ));
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err((1, format!("cannot acquire node maintenance lock: {error}")));
            }
        }
    }
}

fn acquire_barrier_lock(
    barrier_path: &Path,
    config_path: &Path,
    state_dir: &Path,
) -> AppResult<File> {
    if let Some(parent) = barrier_path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    match fs::symlink_metadata(barrier_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(barrier_path)
                .map_err(io_error)?;
            lock_maintenance_barrier(&file).map_err(|error| {
                if error.kind() == io::ErrorKind::WouldBlock {
                    (
                        1,
                        "another node maintenance command is already running; wait for it to finish".into(),
                    )
                } else {
                    (1, format!("cannot lock maintenance barrier: {error}"))
                }
            })?;
            read_maintenance_barrier(barrier_path, config_path, state_dir).map_err(|error| {
                (
                    1,
                    format!(
                        "cannot recover maintenance barrier {}: {error}; inspect it before retrying",
                        barrier_path.display()
                    ),
                )
            })?;
            Ok(file)
        }
        Ok(_) => Err((
            1,
            format!(
                "maintenance barrier {} is not a regular file; inspect it before retrying",
                barrier_path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = barrier_path.parent().expect("barrier path has a parent");
            let temporary = parent.join(format!(
                ".{}.{}.tmp",
                barrier_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy(),
                Id128::random()
            ));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
                .map_err(io_error)?;
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = io::Error::last_os_error();
                let _ = fs::remove_file(&temporary);
                return Err((1, format!("cannot lock maintenance barrier: {error}")));
            }
            let record = serde_json::json!({
                "version": 1,
                "config_path": config_path,
                "state_dir": state_dir,
                "owner_pid": std::process::id(),
            });
            let result = (|| -> io::Result<()> {
                let mut writer = &file;
                serde_json::to_writer(&mut writer, &record).map_err(io::Error::other)?;
                writer.flush()?;
                file.sync_all()?;
                fs::hard_link(&temporary, barrier_path)?;
                fs::remove_file(&temporary)?;
                File::open(parent)?.sync_all()?;
                Ok(())
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(&temporary);
                return Err((1, format!("cannot create maintenance barrier: {error}")));
            }
            Ok(file)
        }
        Err(error) => Err((1, format!("cannot inspect maintenance barrier: {error}"))),
    }
}

fn lock_maintenance_barrier(file: &File) -> io::Result<()> {
    let started = Instant::now();
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock
            || started.elapsed() >= Duration::from_millis(250)
        {
            return Err(error);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn ensure_maintenance_jobs_drained(
    state_dir: &Path,
    operation: &str,
    controller_stopped: bool,
) -> AppResult<()> {
    if !state_dir.join("controller.sqlite3").exists() {
        return Ok(());
    }
    let storage = Storage::open(state_dir).map_err(|error| (1, error.to_string()))?;
    let jobs = storage
        .list_jobs(None)
        .map_err(|error| (1, error.to_string()))?;
    let pending: Vec<_> = jobs
        .iter()
        .filter(|job| {
            matches!(
                job.state,
                macluster_protocol::types::JobState::Starting
                    | macluster_protocol::types::JobState::Running
                    | macluster_protocol::types::JobState::Cancelling
            ) || operation != addresses::MAINTENANCE_OPERATION
                && (job.snapshot_sync_pending || job.log_sync_pending)
        })
        .map(|job| format!("job {} ({:?})", job.id, job.state))
        .collect();
    if pending.is_empty() {
        Ok(())
    } else {
        let controller = if controller_stopped {
            "Restart the controller with `macluster controller run` after the work drains."
        } else {
            "The controller remains running."
        };
        Err((
            1,
            format!(
                "active jobs or output sync remain before {operation}: {}. No node changes were made. {controller} Let the work finish, then retry.",
                pending.join(", "),
            ),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NodeEndpoint {
    user: String,
    host: Ipv4Addr,
    port: u16,
    source_path: Option<String>,
}

impl NodeEndpoint {
    fn parse(value: &str) -> Result<Self, String> {
        let (user, address) = value
            .split_once('@')
            .ok_or_else(|| "endpoint must be USER@IPv4[:PORT]".to_owned())?;
        if user.is_empty()
            || user.len() > 64
            || !user.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                }
            })
        {
            return Err("SSH user is invalid; use letters, digits, '_', '.', or '-'".into());
        }
        let mut parts = address.splitn(3, ':');
        let host = parts.next().unwrap_or_default();
        let second = parts.next();
        let third = parts.next();
        let (port, source_path) = match second {
            None => (22, None),
            Some(value) if value.bytes().all(|byte| byte.is_ascii_digit()) => {
                let port = value
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or_else(|| "SSH port must be in 1..=65535".to_owned())?;
                (port, third.map(str::to_owned))
            }
            Some(value) if looks_like_source_path(value) && third.is_none() => {
                (22, Some(value.to_owned()))
            }
            _ => return Err("SSH port must be in 1..=65535 before an optional source path".into()),
        };
        let host = host
            .parse::<Ipv4Addr>()
            .map_err(|_| "node address must be an IPv4 address".to_owned())?;
        if host.is_unspecified() || host.is_multicast() || host == Ipv4Addr::BROADCAST {
            return Err("node address must be a unicast IPv4 address".into());
        }
        Ok(Self {
            user: user.into(),
            host,
            port,
            source_path,
        })
    }

    fn canonical(&self) -> String {
        let base = format!("{}@{}:{}", self.user, self.host, self.port);
        self.source_path
            .as_ref()
            .map_or(base.clone(), |path| format!("{base}:{path}"))
    }

    fn ssh_identity_endpoint(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }

    fn node_config(&self, remote_binary: String, remote_config: Option<String>) -> NodeConfig {
        NodeConfig {
            host: self.host.to_string(),
            transport: Transport::Ssh,
            remote_binary,
            ssh_user: Some(self.user.clone()),
            ssh_port: Some(self.port),
            ssh_identity_file: None,
            remote_config,
            machine_uuid: None,
            execution_uid: None,
        }
    }
}

fn looks_like_source_path(value: &str) -> bool {
    value.starts_with('/') || value.starts_with("./") || value.starts_with("~/")
}

#[derive(Clone, Debug)]
enum AddTarget {
    Ssh(NodeEndpoint),
    Local {
        source_path: Option<String>,
        host: Option<Ipv4Addr>,
    },
}

#[derive(Clone, Debug)]
struct AddOptions {
    target: AddTarget,
    queue: Option<String>,
    share_id: Option<String>,
    mount_root: Option<String>,
}

#[derive(Debug)]
enum Action {
    Add(AddOptions),
    List,
    Failures,
    Remove {
        target: String,
        connect: Option<NodeEndpoint>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentStagePurpose {
    Enrollment,
    Share,
    Update,
}

impl AgentStagePurpose {
    fn installs_power_helper(self) -> bool {
        self == Self::Enrollment
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminState {
    version: u32,
    config_path: String,
    state_dir: String,
    reserved_node_ids: BTreeSet<String>,
    machine_uuids: BTreeMap<String, String>,
    operations: BTreeMap<String, NodeOperation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct NodeOperation {
    id: String,
    action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_config_path: Option<String>,
    node_id: String,
    endpoint: String,
    machine_uuid: Option<String>,
    phase: String,
    old_config_sha256: Option<String>,
    candidate_config_sha256: Option<String>,
    managed_export: bool,
    #[serde(default)]
    managed_shares: BTreeSet<String>,
    #[serde(default)]
    client_setup_attempted: Option<bool>,
    detail: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResetAdminOperation {
    pub(crate) id: String,
    pub(crate) action: String,
    pub(crate) connection_endpoint: Option<String>,
    pub(crate) remote_config_path: Option<String>,
    pub(crate) node_id: String,
    pub(crate) endpoint: String,
    pub(crate) machine_uuid: Option<String>,
    pub(crate) phase: String,
    pub(crate) old_config_sha256: Option<String>,
    pub(crate) candidate_config_sha256: Option<String>,
    pub(crate) client_setup_may_have_run: bool,
}

#[derive(Debug, Deserialize)]
struct NodeCheck {
    node: String,
    machine_uuid: Option<String>,
    shared_storage_ready: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoteFacts {
    pub(crate) os: String,
    pub(crate) arch: String,
    pub(crate) version: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) home: String,
    pub(crate) free_kb: u64,
}

#[derive(Deserialize)]
struct CapabilityReport {
    features: Vec<String>,
}

const REQUIRED_AGENT_FEATURES: &[&str] = &[
    "agent.idle-handoff.v1",
    INTERACTIVE_PTY_FEATURE,
    "config.local-transport.v1",
    "config.named-shares.v1",
    "agent.node-health.v1",
    "config.execution-digest.v1",
    "config.primary-storage-source.v1",
    macluster_protocol::types::NAMESPACED_JOBS_FEATURE,
    "metrics.cpu-temperature.v1",
    METRICS_FAN_SPEED_FEATURE,
];

pub fn run(config_path: PathBuf, state_dir: PathBuf, args: &[String]) -> AppResult<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err((
            1,
            "run mnode as your normal cluster account, without sudo; it prompts through the terminal when local or remote NFS administration needs sudo".into(),
        ));
    }
    if args.is_empty() || args.iter().any(|value| value == "-h" || value == "--help") {
        print_help(args.iter().any(|value| value == "--help"));
        return Ok(());
    }
    let action = parse_action(args)?;
    match action {
        Action::List => list_nodes(&config_path, &state_dir),
        Action::Failures => list_failed_operations(&config_path, &state_dir),
        Action::Add(options) => add_node(&config_path, &state_dir, options),
        Action::Remove { target, connect } => {
            if let Some(share_id) = target.strip_prefix("share:") {
                remove_pending_share(&config_path, &state_dir, share_id)
            } else {
                remove_node(&config_path, &state_dir, &target, connect.as_ref())
            }
        }
    }
}

pub fn ensure_controller_recovery_clean(
    config_path: &Path,
    state_dir: &Path,
) -> Result<(), String> {
    let canonical = config_path
        .canonicalize()
        .map_err(|error| format!("cannot resolve cluster config: {error}"))?;
    let path = state_dir.join("node-admin.json");
    if !path.exists() {
        return Ok(());
    }
    let state = read_admin_state(&path, &canonical, state_dir).map_err(|(_, error)| error)?;
    if let Some(operation) = state.operations.values().find(|operation| {
        matches!(
            operation.phase.as_str(),
            "ADD_COMMITTING" | "REMOVAL_COMMITTING" | "UPDATE_COMMITTING"
        )
    }) {
        let recovery_command = if operation.action == "update" {
            "rerun the command that triggered the Agent update"
        } else {
            "rerun its mnode command"
        };
        return Err(format!(
            "node operation {} for {} is at an uncertain config commit; {recovery_command} before starting the controller",
            operation.id, operation.node_id,
        ));
    }
    Ok(())
}

pub fn dispatch_sync_pending(config_path: &Path, state_dir: &Path) -> Result<bool, String> {
    let canonical = config_path
        .canonicalize()
        .map_err(|error| format!("cannot resolve cluster config: {error}"))?;
    let journal_path = state_dir.join("node-admin.json");
    if !journal_path.exists() {
        return Ok(false);
    }
    let state =
        read_admin_state(&journal_path, &canonical, state_dir).map_err(|(_, error)| error)?;
    let source = fs::read(&canonical)
        .map_err(|error| format!("cannot read cluster config for sync barrier: {error}"))?;
    let digest = sha256_hex(&source).map_err(|error| error.to_string())?;
    Ok(state.operations.values().any(|operation| {
        operation.phase == "SYNC_PENDING"
            && operation.candidate_config_sha256.as_deref() == Some(digest.as_str())
    }))
}

pub(crate) fn agent_update_recovery_pending(
    config_path: &Path,
    state_dir: &Path,
) -> Result<bool, String> {
    let canonical = config_path
        .canonicalize()
        .map_err(|error| format!("cannot resolve cluster config: {error}"))?;
    let journal_path = state_dir.join("node-admin.json");
    if !journal_path.exists() {
        return Ok(false);
    }
    let state =
        read_admin_state(&journal_path, &canonical, state_dir).map_err(|(_, error)| error)?;
    Ok(state.operations.values().any(|operation| {
        operation.action == "update"
            && !matches!(operation.phase.as_str(), "READY" | "REMOVED" | "ABORTED")
    }))
}

pub(crate) fn agent_helper_refresh_pending(state_dir: &Path) -> Result<bool, String> {
    let path = state_dir.join(HELPER_REFRESH_PENDING_FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("cannot inspect helper refresh marker: {error}")),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "helper refresh marker {} has unsafe ownership or permissions",
            path.display()
        ));
    }
    Ok(true)
}

fn set_agent_helper_refresh_pending(state_dir: &Path, pending: bool) {
    let path = state_dir.join(HELPER_REFRESH_PENDING_FILE);
    if pending {
        if let Err((_, error)) = atomic_write(&path, b"pending\n") {
            eprintln!("macluster: could not preserve pending helper refresh state: {error}");
        }
    } else if let Err(error) = fs::remove_file(&path)
        && error.kind() != io::ErrorKind::NotFound
    {
        eprintln!("macluster: could not clear helper refresh marker: {error}");
    }
}

pub(crate) fn agent_update_blocked_by_work(state_dir: &Path) -> Result<bool, String> {
    if !state_dir.join("controller.sqlite3").is_file() {
        return Ok(false);
    }
    ReadOnlyJobStore::open(state_dir)
        .and_then(|store| store.has_maintenance_work())
        .map_err(|error| format!("cannot inspect active jobs or output synchronization: {error}"))
}

fn is_uncommitted_enrollment(config: &ClusterConfig, operation: &NodeOperation) -> bool {
    operation.action == "add"
        && matches!(
            operation.phase.as_str(),
            "SETUP_PENDING" | "CANDIDATE_INSTALLED"
        )
        && !config.nodes.contains_key(&operation.node_id)
}

pub(crate) fn node_admin_recovery_pending(
    config_path: &Path,
    state_dir: &Path,
) -> Result<bool, String> {
    let canonical = config_path
        .canonicalize()
        .map_err(|error| format!("cannot resolve cluster config: {error}"))?;
    let journal_path = state_dir.join("node-admin.json");
    if !journal_path.exists() {
        return Ok(false);
    }
    let state =
        read_admin_state(&journal_path, &canonical, state_dir).map_err(|(_, error)| error)?;
    // An uncommitted candidate is a private enrollment draft, not a cluster
    // member or a reason to fence updates to the active configuration.
    // Invalid configs retain the conservative recovery behavior.
    let config = read_config(&canonical).ok();
    Ok(state.operations.values().any(|operation| {
        operation.action != "update"
            && !config
                .as_ref()
                .is_some_and(|config| is_uncommitted_enrollment(config, operation))
            && !matches!(operation.phase.as_str(), "READY" | "REMOVED" | "ABORTED")
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateRecovery {
    Fresh,
    Stage,
    Sync,
    AbandonUncommittedFailure,
}

fn update_recovery(
    operation: Option<&NodeOperation>,
    current_digest: &str,
) -> Result<UpdateRecovery, String> {
    let Some(operation) = operation else {
        return Ok(UpdateRecovery::Fresh);
    };
    if operation.action != "update" {
        return Err("the all-node update journal entry has an unexpected action".into());
    }
    match operation.phase.as_str() {
        "READY" => Ok(UpdateRecovery::Fresh),
        "UPDATE_STAGING" | "UPDATE_FAILED"
            if operation.old_config_sha256.as_deref() == Some(current_digest) =>
        {
            Ok(UpdateRecovery::Stage)
        }
        "UPDATE_COMMITTING"
            if operation.candidate_config_sha256.as_deref() == Some(current_digest) =>
        {
            Ok(UpdateRecovery::Sync)
        }
        "UPDATE_COMMITTING" if operation.old_config_sha256.as_deref() == Some(current_digest) => {
            Ok(UpdateRecovery::Stage)
        }
        "SYNC_PENDING" if operation.candidate_config_sha256.as_deref() == Some(current_digest) => {
            Ok(UpdateRecovery::Sync)
        }
        "UPDATE_FAILED"
            if operation.candidate_config_sha256.is_none()
                && operation.old_config_sha256.as_deref() != Some(current_digest) =>
        {
            // No candidate config was activated. A later, independently
            // committed config change supersedes this failed staging attempt;
            // preserve the journal as aborted and stage a fresh update.
            Ok(UpdateRecovery::AbandonUncommittedFailure)
        }
        phase => Err(format!(
            "all-node update {} is in phase {phase}, but the active config matches neither its old nor candidate digest; inspect {} before retrying",
            operation.id, "node-admin.json"
        )),
    }
}

fn ensure_no_pending_admin_operation_for_config(
    state: &AdminState,
    config: &ClusterConfig,
) -> AppResult<()> {
    let mut active = state.clone();
    active
        .operations
        .retain(|_, op| !is_uncommitted_enrollment(config, op));
    ensure_no_pending_admin_operation(&active)
}

fn ensure_no_pending_admin_operation(state: &AdminState) -> AppResult<()> {
    for (key, operation) in &state.operations {
        if key == "update:all"
            || matches!(operation.phase.as_str(), "READY" | "REMOVED" | "ABORTED")
        {
            continue;
        }
        return Err((
            1,
            format!(
                "node admin operation {} for {} is still in phase {}; finish or resolve it with mnode before retrying the Agent update",
                operation.id, operation.node_id, operation.phase
            ),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentBuildState {
    Current,
    Stale,
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct AgentBuildCompatibility {
    pub(crate) current: Vec<String>,
    pub(crate) stale: Vec<String>,
    pub(crate) unknown: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) missing_required_features: Vec<String>,
}

impl AgentBuildCompatibility {
    pub(crate) fn requires_update(&self) -> bool {
        !self.stale.is_empty() || !self.missing_required_features.is_empty()
    }
}

struct AgentBuildProbe {
    version: String,
    sha256: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct AgentValidationCache {
    schema: u32,
    key: String,
    checked_unix_ms: u64,
    compatibility: AgentBuildCompatibility,
}

const AGENT_VALIDATION_CACHE_TTL_MS: u64 = 60_000;
const AGENT_VALIDATION_CACHE_SCHEMA: u32 = 3;
const AGENT_VALIDATION_CACHE_MAX_BYTES: u64 = 64 * 1024;
const HELPER_REFRESH_PENDING_FILE: &str = "agent-helper-refresh.pending";

pub(crate) fn current_agent_sha256() -> AppResult<String> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let executable = executable.canonicalize().map_err(io_error)?;
    local_sha256(&executable)
}

pub(crate) fn configured_agent_build_compatibility(
    config: &ClusterConfig,
) -> AppResult<AgentBuildCompatibility> {
    let current_digest = current_agent_sha256()?;
    let mut legacy_ssh = Vec::new();
    let mut compatibility = classify_configured_agents(config, |node_id, node| {
        if node.transport == Transport::Ssh && managed_binary_digest(&node.remote_binary).is_none()
        {
            legacy_ssh.push((node_id.to_owned(), node.clone()));
            AgentBuildState::Unknown
        } else {
            inspect_configured_agent_build(node, &current_digest)
        }
    });

    // A legacy path has no digest in the config. Probe all such nodes in
    // parallel so one offline host does not delay a blocked submission by
    // one SSH timeout per queue member.
    let probed = bounded_legacy_agent_probes(legacy_ssh, &current_digest);
    for (node_id, state) in probed {
        compatibility.record(node_id, state);
    }
    compatibility.missing_required_features = bounded_agent_feature_probes(config);
    Ok(compatibility)
}

/// Check locally available build evidence without contacting any node.
pub(crate) fn configured_agent_build_mismatch_local(config: &ClusterConfig) -> AppResult<bool> {
    let digest = current_agent_sha256()?;
    Ok(config
        .nodes
        .values()
        .any(|node| inspect_configured_agent_build(node, &digest) == AgentBuildState::Stale))
}

pub(crate) fn configured_agent_build_compatibility_cached(
    config: &ClusterConfig,
    cache_root: &Path,
) -> AppResult<AgentBuildCompatibility> {
    configured_agent_build_compatibility_cached_with_age(config, cache_root)
        .map(|(compatibility, _)| compatibility)
}

pub(crate) fn configured_agent_build_compatibility_cached_with_age(
    config: &ClusterConfig,
    cache_root: &Path,
) -> AppResult<(AgentBuildCompatibility, u64)> {
    let key = agent_validation_cache_key(config)?;
    let cache_path = cache_root.join("mtop-agent-validation.json");
    if let Some((cache, age_ms)) = read_agent_validation_cache(&cache_path, &key) {
        return Ok((cache, age_ms));
    }

    let compatibility = configured_agent_build_compatibility(config)?;
    if agent_validation_cache_key(config).is_ok_and(|after| after == key) {
        write_agent_validation_cache(
            &cache_path,
            AgentValidationCache {
                schema: AGENT_VALIDATION_CACHE_SCHEMA,
                key,
                checked_unix_ms: validation_now_ms(),
                compatibility: compatibility.clone(),
            },
        );
    }
    Ok((compatibility, 0))
}

fn bounded_legacy_agent_probes(
    nodes: Vec<(String, NodeConfig)>,
    current_digest: &str,
) -> Vec<(String, AgentBuildState)> {
    const MAX_PROBES: usize = 4;
    let queue = Mutex::new(VecDeque::from(nodes));
    let worker_count = MAX_PROBES.min(queue.lock().map_or(0, |queue| queue.len()));
    std::thread::scope(|scope| {
        let handles = (0..worker_count)
            .map(|_| {
                let queue = &queue;
                let current_digest = current_digest.to_owned();
                scope.spawn(move || {
                    let mut results = Vec::new();
                    loop {
                        let task = queue.lock().ok().and_then(|mut queue| queue.pop_front());
                        let Some((node_id, node)) = task else {
                            break;
                        };
                        let state = probe_configured_agent_build(&node, &current_digest);
                        results.push((node_id, state));
                    }
                    results
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .flatten()
            .collect()
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentFeatureState {
    Current,
    Missing,
    Unknown,
}

fn missing_required_agent_features(features: &[String]) -> Vec<&'static str> {
    REQUIRED_AGENT_FEATURES
        .iter()
        .filter(|feature| !features.iter().any(|actual| actual == **feature))
        .copied()
        .collect()
}

fn probe_configured_agent_features(node: &NodeConfig) -> AgentFeatureState {
    let output = if node.transport == Transport::Local {
        let mut command = Command::new(&node.remote_binary);
        command.args(["internal", "capabilities", "--json"]);
        match run_child(command, None, Duration::from_secs(5)) {
            Ok(output) => output,
            Err(_) => return AgentFeatureState::Unknown,
        }
    } else {
        let command = shell_join(&[&node.remote_binary, "internal", "capabilities", "--json"]);
        match ssh_output(node, &command, None) {
            Ok(output) => output,
            Err(_) => return AgentFeatureState::Unknown,
        }
    };
    if !output.status.success() {
        return if node.transport == Transport::Ssh && output.status.code() == Some(255) {
            AgentFeatureState::Unknown
        } else {
            AgentFeatureState::Missing
        };
    }
    let Ok(report) = serde_json::from_slice::<CapabilityReport>(&output.stdout) else {
        return AgentFeatureState::Missing;
    };
    if missing_required_agent_features(&report.features).is_empty() {
        AgentFeatureState::Current
    } else {
        AgentFeatureState::Missing
    }
}

fn bounded_agent_feature_probes(config: &ClusterConfig) -> Vec<String> {
    const MAX_PROBES: usize = 4;
    let queue = Mutex::new(
        config
            .nodes
            .iter()
            .map(|(node_id, node)| (node_id.clone(), node.clone()))
            .collect::<VecDeque<_>>(),
    );
    let worker_count = MAX_PROBES.min(queue.lock().map_or(0, |queue| queue.len()));
    std::thread::scope(|scope| {
        let handles = (0..worker_count)
            .map(|_| {
                let queue = &queue;
                scope.spawn(move || {
                    let mut missing = Vec::new();
                    loop {
                        let task = queue.lock().ok().and_then(|mut queue| queue.pop_front());
                        let Some((node_id, node)) = task else {
                            break;
                        };
                        if probe_configured_agent_features(&node) == AgentFeatureState::Missing {
                            missing.push(node_id);
                        }
                    }
                    missing
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .flatten()
            .collect()
    })
}

fn agent_validation_cache_key(config: &ClusterConfig) -> AppResult<String> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut identity = format!(
        "schema={AGENT_VALIDATION_CACHE_SCHEMA};uid={};config={config:?};exe={}",
        unsafe { libc::geteuid() },
        file_identity_fingerprint(&executable)
    );
    for (node_id, node) in &config.nodes {
        if node.transport == Transport::Local {
            identity.push_str(&format!(
                ";local={node_id}:{}",
                file_identity_fingerprint(Path::new(&node.remote_binary))
            ));
        } else {
            let connection = ConnectionKey::for_node(&config.share_uuid, node_id, node)
                .map_err(|error| (1, error.to_string()))?;
            let digest = connection
                .cache_fingerprint()
                .map_err(|error| (1, error.to_string()))?;
            identity.push_str(&format!(";ssh={node_id}:{digest}"));
        }
    }
    sha256_hex(identity.as_bytes()).map_err(|error| (1, error.to_string()))
}

fn file_identity_fingerprint(path: &Path) -> String {
    let canonical = path.canonicalize().ok();
    let Some(canonical) = canonical else {
        return format!("{}:missing", path.display());
    };
    let Ok(metadata) = fs::metadata(&canonical) else {
        return format!("{}:missing", canonical.display());
    };
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        canonical.display(),
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.mode()
    )
}

fn read_agent_validation_cache(path: &Path, key: &str) -> Option<(AgentBuildCompatibility, u64)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > AGENT_VALIDATION_CACHE_MAX_BYTES
    {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(AGENT_VALIDATION_CACHE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > AGENT_VALIDATION_CACHE_MAX_BYTES {
        return None;
    }
    let cache: AgentValidationCache = serde_json::from_slice(&bytes).ok()?;
    let age = validation_now_ms().checked_sub(cache.checked_unix_ms)?;
    (cache.schema == AGENT_VALIDATION_CACHE_SCHEMA
        && cache.key == key
        && age <= AGENT_VALIDATION_CACHE_TTL_MS)
        .then_some((cache.compatibility, age))
}

pub(crate) fn invalidate_agent_validation_cache(cache_root: &Path) {
    let _ = fs::remove_file(cache_root.join("mtop-agent-validation.json"));
}

fn write_agent_validation_cache(path: &Path, cache: AgentValidationCache) {
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    let Ok(metadata) = fs::symlink_metadata(parent) else {
        return;
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return;
    }
    if fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).is_err() {
        return;
    }
    let temp_path = parent.join(format!(
        ".mtop-agent-validation-{}-{}.tmp",
        std::process::id(),
        validation_now_ms()
    ));
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
    else {
        return;
    };
    let result = serde_json::to_vec(&cache)
        .map_err(io::Error::other)
        .and_then(|bytes| file.write_all(&bytes))
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp_path, path));
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
}

fn validation_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn classify_configured_agents(
    config: &ClusterConfig,
    mut inspect: impl FnMut(&str, &NodeConfig) -> AgentBuildState,
) -> AgentBuildCompatibility {
    let mut compatibility = AgentBuildCompatibility::default();
    for (node_id, node) in &config.nodes {
        compatibility.record(node_id.clone(), inspect(node_id, node));
    }
    compatibility
}

impl AgentBuildCompatibility {
    fn record(&mut self, node_id: String, state: AgentBuildState) {
        match state {
            AgentBuildState::Current => self.current.push(node_id),
            AgentBuildState::Stale => self.stale.push(node_id),
            AgentBuildState::Unknown => self.unknown.push(node_id),
        }
    }
}

fn managed_binary_digest(binary: &str) -> Option<String> {
    let path = Path::new(binary);
    if path.file_name()? != "macluster" {
        return None;
    }
    let digest = path.parent()?.file_name()?.to_str()?;
    valid_sha256(digest).then(|| digest.to_ascii_lowercase())
}

fn is_expected_managed_agent_path(binary: &str, expected_digest: &str) -> bool {
    managed_binary_digest(binary).is_some_and(|digest| digest.eq_ignore_ascii_case(expected_digest))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn inspect_configured_agent_build(node: &NodeConfig, current_digest: &str) -> AgentBuildState {
    if node.transport == Transport::Local {
        return local_sha256(Path::new(&node.remote_binary))
            .map(|digest| compare_agent_digest(&digest, current_digest))
            .unwrap_or(AgentBuildState::Unknown);
    }
    let Some(digest) = managed_binary_digest(&node.remote_binary) else {
        return AgentBuildState::Unknown;
    };
    compare_agent_digest(&digest, current_digest)
}

fn compare_agent_digest(digest: &str, current_digest: &str) -> AgentBuildState {
    if digest.eq_ignore_ascii_case(current_digest) {
        AgentBuildState::Current
    } else {
        AgentBuildState::Stale
    }
}

fn probe_configured_agent_build(node: &NodeConfig, current_digest: &str) -> AgentBuildState {
    let binary = shell_quote(&node.remote_binary);
    let command = format!(
        "set -e; version=$({binary} --version); digest=$(/usr/bin/shasum -a 256 -- {binary}); digest=${{digest%% *}}; printf 'VERSION=%s\\nSHA256=%s\\n' \"$version\" \"$digest\""
    );
    let Ok(output) = ssh_output(node, &command, None) else {
        return AgentBuildState::Unknown;
    };
    if !output.status.success() {
        return AgentBuildState::Unknown;
    }
    let Some(probe) = parse_agent_build_probe(&String::from_utf8_lossy(&output.stdout)) else {
        return AgentBuildState::Unknown;
    };
    if let Some(digest) = probe.sha256 {
        return compare_agent_digest(&digest, current_digest);
    }
    let expected_version = format!("macluster {}", env!("CARGO_PKG_VERSION"));
    if probe.version.starts_with(&expected_version) {
        AgentBuildState::Current
    } else if probe.version.starts_with("macluster ") {
        AgentBuildState::Stale
    } else {
        AgentBuildState::Unknown
    }
}

fn parse_agent_build_probe(output: &str) -> Option<AgentBuildProbe> {
    let mut version = None;
    let mut sha256 = None;
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("VERSION=") {
            version = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("SHA256=") {
            let value = value.trim();
            if valid_sha256(value) {
                sha256 = Some(value.to_ascii_lowercase());
            }
        }
    }
    let version = version.filter(|version| version.starts_with("macluster "))?;
    Some(AgentBuildProbe { version, sha256 })
}

fn verify_registered_node_identities(config: &ClusterConfig) -> AppResult<()> {
    for (node_id, node) in &config.nodes {
        let (machine_uuid, execution_uid) = if node.transport == Transport::Local {
            (local_platform_uuid()?, unsafe { libc::geteuid() })
        } else {
            let facts = read_remote_facts(node)
                .map_err(|(_, error)| (1, format!("cannot inspect node {node_id}: {error}")))?;
            let machine_uuid = remote_machine_uuid(node).map_err(|(_, error)| {
                (1, format!("cannot verify node {node_id} identity: {error}"))
            })?;
            (machine_uuid, facts.uid)
        };
        if node
            .machine_uuid
            .as_deref()
            .is_some_and(|expected| !expected.eq_ignore_ascii_case(&machine_uuid))
            || node
                .execution_uid
                .is_some_and(|expected| expected != execution_uid)
        {
            return Err((
                1,
                format!(
                    "node {node_id} no longer matches its registered machine UUID or execution UID"
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn update_all_agents_for_preflight(
    config_path: &Path,
    state_dir: &Path,
) -> AppResult<bool> {
    update_all_agents_impl(config_path, state_dir)
}

fn update_all_agents_impl(config_path: &Path, state_dir: &Path) -> AppResult<bool> {
    if unsafe { libc::geteuid() } == 0 {
        return Err((
            1,
            "run the Agent update as your normal cluster account, without sudo".into(),
        ));
    }
    let maintenance = acquire_node_maintenance_scoped(
        config_path,
        state_dir,
        "Agent update",
        MaintenanceScope::Cluster,
    )?;
    if maintenance.recovered {
        return Ok(false);
    }
    let mut helper_refresh_deferred = None;
    let result = (|| -> AppResult<bool> {
        MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(|error| {
            (
                1,
                format!("cluster config/state directory binding failed: {error}"),
            )
        })?;
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let config_path = config_path.canonicalize().map_err(io_error)?;
        let source = fs::read_to_string(&config_path).map_err(io_error)?;
        let config = ClusterConfig::parse(&source).map_err(|error| (2, error.to_string()))?;
        let old_digest = sha256_hex(source.as_bytes()).map_err(|error| (1, error.to_string()))?;
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, state_dir)?;
        ensure_no_pending_admin_operation_for_config(&state, &config)?;

        let operation_key = "update:all";
        let mut recovery = update_recovery(state.operations.get(operation_key), &old_digest)
            .map_err(|error| (1, error))?;
        if recovery == UpdateRecovery::AbandonUncommittedFailure {
            let mut obsolete = state
                .operations
                .get(operation_key)
                .expect("superseded update recovery has an operation")
                .clone();
            obsolete.phase = "ABORTED".into();
            obsolete.detail = Some(
            "failed update had no committed candidate config and was superseded by a later cluster config change; unreferenced staging files were preserved".into(),
        );
            state.operations.insert(operation_key.to_owned(), obsolete);
            save_admin_state(&journal_path, &state)?;
            recovery = UpdateRecovery::Fresh;
        }
        if recovery == UpdateRecovery::Sync {
            let mut operation = state
                .operations
                .get(operation_key)
                .expect("sync recovery has an update operation")
                .clone();
            operation.phase = "SYNC_PENDING".into();
            operation.detail = None;
            state
                .operations
                .insert(operation_key.to_owned(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            verify_registered_node_identities(&config).map_err(|(code, error)| {
                (
                    code,
                    format!("cannot verify node identities before Agent update: {error}"),
                )
            })?;
            finish_update_sync(
                &mut state,
                &journal_path,
                operation_key,
                operation,
                &config,
                &source,
                state_dir,
            )?;
            println!("Recovered the all-node update and peer config synchronization.");
            return Ok(maintenance.controller_was_running);
        }

        let mut operation = if recovery == UpdateRecovery::Stage {
            state
                .operations
                .get(operation_key)
                .expect("stage recovery has an update operation")
                .clone()
        } else {
            NodeOperation {
                id: Id128::random().to_string(),
                action: "update".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: "all".into(),
                endpoint: "cluster".into(),
                machine_uuid: None,
                phase: "UPDATE_STAGING".into(),
                old_config_sha256: Some(old_digest.clone()),
                candidate_config_sha256: None,
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: Some(false),
                detail: None,
            }
        };
        operation.phase = "UPDATE_STAGING".into();
        operation.old_config_sha256 = Some(old_digest.clone());
        operation.candidate_config_sha256 = None;
        operation.detail =
            Some("staging and verifying the current Agent on every configured node".into());
        state
            .operations
            .insert(operation_key.to_owned(), operation.clone());
        save_admin_state(&journal_path, &state)?;

        if let Err((code, error)) = verify_registered_node_identities(&config) {
            operation.phase = "UPDATE_FAILED".into();
            operation.detail = Some(error.clone());
            state.operations.insert(operation_key.to_owned(), operation);
            save_admin_state(&journal_path, &state)?;
            return Err((
                code,
                format!(
                    "Agent update stopped because node identity verification failed: {error}. Correct the registered node identity, then rerun the requested command to resume the update."
                ),
            ));
        }

        let (candidate, candidate_config) = match stage_current_agents(
            &config,
            &source,
            &operation.id,
            AgentStagePurpose::Update,
        ) {
            Ok(candidate) => candidate,
            Err((code, error)) => {
                operation.phase = "UPDATE_FAILED".into();
                operation.detail = Some(error.clone());
                state.operations.insert(operation_key.to_owned(), operation);
                save_admin_state(&journal_path, &state)?;
                return Err((
                    code,
                    format!(
                        "Agent update stopped before config activation: {error}. Rerun the requested command to resume."
                    ),
                ));
            }
        };

        let current_source = fs::read(&config_path).map_err(io_error)?;
        let current_digest = sha256_hex(&current_source).map_err(|error| (1, error.to_string()))?;
        if current_digest != old_digest {
            operation.phase = "UPDATE_FAILED".into();
            operation.detail =
                Some("cluster config changed while Agent binaries were staged".into());
            state.operations.insert(operation_key.to_owned(), operation);
            save_admin_state(&journal_path, &state)?;
            return Err((
            1,
            "cluster config changed during Agent update; refusing to activate the staged paths. Inspect the node admin journal before retrying the requested command".into(),
        ));
        }

        operation.detail =
            Some("checking privileged helper versions and refreshing only changed services".into());
        state
            .operations
            .insert(operation_key.to_owned(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        match refresh_agent_helpers_for_update(&candidate_config, &operation.id) {
            Ok(deferred) => helper_refresh_deferred = Some(deferred),
            Err((code, error)) => {
                operation.phase = "UPDATE_FAILED".into();
                operation.detail = Some(error.clone());
                state.operations.insert(operation_key.to_owned(), operation);
                save_admin_state(&journal_path, &state)?;
                return Err((
                    code,
                    format!(
                        "Agent binaries were staged, but privileged helper refresh failed before config activation: {error}. Rerun the requested command to resume."
                    ),
                ));
            }
        }

        let current_source = fs::read(&config_path).map_err(io_error)?;
        let current_digest = sha256_hex(&current_source).map_err(|error| (1, error.to_string()))?;
        if current_digest != old_digest {
            operation.phase = "UPDATE_FAILED".into();
            operation.detail =
                Some("cluster config changed while privileged helpers were refreshed".into());
            state.operations.insert(operation_key.to_owned(), operation);
            save_admin_state(&journal_path, &state)?;
            return Err((
                1,
                "cluster config changed during Agent helper refresh; refusing to activate staged paths. Inspect the node admin journal before retrying the requested command".into(),
            ));
        }

        let candidate_digest =
            sha256_hex(candidate.as_bytes()).map_err(|error| (1, error.to_string()))?;
        operation.candidate_config_sha256 = Some(candidate_digest.clone());
        if candidate == source {
            operation.phase = "SYNC_PENDING".into();
            operation.detail =
                Some("verifying peer config copies for the active Agent paths".into());
            state
                .operations
                .insert(operation_key.to_owned(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            finish_update_sync(
                &mut state,
                &journal_path,
                operation_key,
                operation,
                &candidate_config,
                &candidate,
                state_dir,
            )?;
            println!("All configured nodes already use the current Agent.");
            return Ok(maintenance.controller_was_running);
        }

        operation.phase = "UPDATE_COMMITTING".into();
        operation.detail = Some("activating verified Agent paths in the cluster config".into());
        state
            .operations
            .insert(operation_key.to_owned(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        backup_config(&config_path, &operation.id)?;
        atomic_write(&config_path, candidate.as_bytes())?;
        operation.phase = "SYNC_PENDING".into();
        operation.detail = None;
        state
            .operations
            .insert(operation_key.to_owned(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        finish_update_sync(
            &mut state,
            &journal_path,
            operation_key,
            operation,
            &candidate_config,
            &candidate,
            state_dir,
        )?;
        println!(
            "Updated Agent on {} configured node(s).",
            config.nodes.len()
        );
        Ok(maintenance.controller_was_running)
    })();
    if result.is_ok()
        && let Some(deferred) = helper_refresh_deferred
    {
        set_agent_helper_refresh_pending(state_dir, deferred);
    }
    finish_node_maintenance_with_success_notice(maintenance, result, false)
}

fn finish_update_sync(
    state: &mut AdminState,
    journal_path: &Path,
    operation_key: &str,
    mut operation: NodeOperation,
    config: &ClusterConfig,
    source: &str,
    state_dir: &Path,
) -> AppResult<()> {
    // Keep private drafts anchored to this cluster when an Agent-only update
    // changes binary paths. Reset can still recognize and clean their exact
    // managed resources, and a later explicit add can reuse the draft.
    let current_digest = sha256_hex(source.as_bytes()).map_err(|error| (1, error.to_string()))?;
    if operation.candidate_config_sha256.as_deref() == Some(current_digest.as_str()) {
        for draft in state.operations.values_mut() {
            if is_uncommitted_enrollment(config, draft)
                && draft.old_config_sha256 == operation.old_config_sha256
            {
                draft.old_config_sha256 = Some(current_digest.clone());
            }
        }
        save_admin_state(journal_path, state)?;
    }
    if let Err(error) = sync_remote_configs(config, source, state_dir, &operation.id, None) {
        operation.phase = "SYNC_PENDING".into();
        operation.detail = Some(error.clone());
        state.operations.insert(operation_key.to_owned(), operation);
        save_admin_state(journal_path, state)?;
        return Err((
            1,
            format!(
                "Agent paths are active locally, but peer config sync is pending: {error}. Rerun the requested command to resume the update."
            ),
        ));
    }
    operation.phase = "READY".into();
    operation.detail = None;
    state.operations.insert(operation_key.to_owned(), operation);
    save_admin_state(journal_path, state)?;
    Ok(())
}

fn parse_action(args: &[String]) -> AppResult<Action> {
    if args.is_empty() || args.iter().any(|value| value == "-h" || value == "--help") {
        print_help(args.iter().any(|value| value == "--help"));
        return Err((0, String::new()));
    }
    let (key, inline) = args[0]
        .split_once('=')
        .map_or((args[0].as_str(), None), |(key, value)| (key, Some(value)));
    if key == "--failed" {
        if args.len() != 1 || inline.is_some() {
            return Err((2, "mnode --failed does not accept a value".into()));
        }
        return Ok(Action::Failures);
    }
    if key == "-l" || key == "--list" {
        if args.len() != 1 {
            return Err((2, "mnode --list does not accept a value".into()));
        }
        return Ok(Action::List);
    }
    match key {
        "-a" | "--add" => {
            let endpoint = if let Some(value) = inline {
                value.to_owned()
            } else {
                args.get(1)
                    .cloned()
                    .ok_or_else(|| (2, format!("{key} requires an endpoint")))?
            };
            let mut queue = None;
            let mut share_id = None;
            let mut mount_root = None;
            let mut host = None;
            let mut index = if inline.is_some() { 1 } else { 2 };
            while index < args.len() {
                let option = args[index].as_str();
                let value = args
                    .get(index + 1)
                    .cloned()
                    .ok_or_else(|| (2, format!("{option} requires a value")))?;
                match option {
                    "--queue" => {
                        QueueName::new(value.clone()).map_err(|error| (2, error.to_string()))?;
                        queue = Some(value);
                    }
                    "--share-id" => {
                        NodeId::new(value.clone()).map_err(|error| (2, error.to_string()))?;
                        share_id = Some(value);
                    }
                    "--mount-root" => {
                        let value = value.trim_end_matches('/').to_owned();
                        if !safe_absolute_remote_path(&value) {
                            return Err((
                                2,
                                "--mount-root must be a normalized absolute path containing only ASCII letters, digits, '/', '.', '_' or '-'".into(),
                            ));
                        }
                        mount_root = Some(value);
                    }
                    "--host" => {
                        host = Some(
                            value
                                .parse::<Ipv4Addr>()
                                .map_err(|_| (2, "--host must be an IPv4 address".into()))?,
                        );
                    }
                    _ => return Err((2, format!("unknown mnode add option '{option}'"))),
                }
                index += 2;
            }
            let target = if let Some(local_source) = endpoint.strip_prefix("local") {
                let source_path = if local_source.is_empty() {
                    None
                } else if let Some(path) = local_source.strip_prefix(':') {
                    Some(path.to_owned())
                } else {
                    return Err((2, "local endpoint syntax is local[:SOURCE_PATH]".into()));
                };
                AddTarget::Local { source_path, host }
            } else {
                let parsed = NodeEndpoint::parse(&endpoint).map_err(|error| (2, error))?;
                if parsed.host.is_loopback() {
                    let current_user = std::env::var("USER").unwrap_or_default();
                    if parsed.host != Ipv4Addr::LOCALHOST
                        || parsed.user != current_user
                        || parsed.port != 22
                    {
                        return Err((
                            2,
                            "only the current user at 127.0.0.1:22 may be registered as local"
                                .into(),
                        ));
                    }
                    AddTarget::Local {
                        source_path: parsed.source_path,
                        host,
                    }
                } else {
                    if host.is_some() {
                        return Err((2, "--host is only valid with mnode -a local".into()));
                    }
                    AddTarget::Ssh(parsed)
                }
            };
            let source_path = match &target {
                AddTarget::Ssh(endpoint) => endpoint.source_path.as_ref(),
                AddTarget::Local { source_path, .. } => source_path.as_ref(),
            };
            if mount_root.is_some() && (source_path.is_none() || share_id.is_none()) {
                return Err((2, "--mount-root requires SOURCE_PATH and --share-id".into()));
            }
            if source_path.is_some() && share_id.is_none() {
                return Err((
                    2,
                    "SOURCE_PATH registers an additional named NFS share and requires --share-id; to mount the configured primary share on this Mac, use `mnode -a local` without :SOURCE_PATH".into(),
                ));
            }
            if source_path.is_none() && share_id.is_some() {
                return Err((
                    2,
                    "--share-id is only valid when SOURCE_PATH is provided".into(),
                ));
            }
            if let (Some(source), Some(mount)) = (source_path, mount_root.as_deref())
                && Path::new(source).is_absolute()
            {
                validate_share_alias_paths(Path::new(source), Path::new(mount))?;
            }
            Ok(Action::Add(AddOptions {
                target,
                queue,
                share_id,
                mount_root,
            }))
        }
        "-rm" | "--remove" => {
            if inline.is_some() || !matches!(args.len(), 2 | 4) {
                return Err((
                    2,
                    format!(
                        "{key} requires a node ID or pending share ID, optionally followed by --connect USER@IPv4[:PORT]"
                    ),
                ));
            }
            let value = args[1].clone();
            let identifier = value.strip_prefix("share:").unwrap_or(&value);
            NodeId::new(identifier.to_owned()).map_err(|error| (2, error.to_string()))?;
            let connect = if args.len() == 4 {
                if args[2] != "--connect" {
                    return Err((2, format!("unknown mnode remove option '{}'", args[2])));
                }
                if value.starts_with("share:") {
                    return Err((
                        2,
                        "--connect is only supported when removing a configured node".into(),
                    ));
                }
                let endpoint = NodeEndpoint::parse(&args[3]).map_err(|error| (2, error))?;
                if endpoint.source_path.is_some() {
                    return Err((
                        2,
                        "--connect accepts USER@IPv4[:PORT], without a source path".into(),
                    ));
                }
                Some(endpoint)
            } else {
                None
            };
            Ok(Action::Remove {
                target: value,
                connect,
            })
        }
        _ => Err((2, format!("unknown mnode option '{key}'"))),
    }
}

fn print_help(full: bool) {
    println!("{}", node_help(full));
}

fn node_help(full: bool) -> &'static str {
    if !full {
        return "Usage: mnode -a USER@IPv4[:PORT] [OPTIONS]\n       mnode -a local[:SOURCE_PATH] [OPTIONS]\n       mnode -l | --list\n       mnode --failed\n       mnode -rm NODE_ID [--connect USER@IPv4[:PORT]]\n       mnode -rm share:SHARE_ID\n\nOptions: --queue QUEUE, --host IPv4, --share-id ID, --mount-root PATH\nSSH nodes join the default compute queue. `local` enrolls this Mac as the login node. Use --help for SSH setup, shares, removal, and controller maintenance.";
    }

    "Usage: mnode -a USER@IPv4[:PORT][:SOURCE_PATH] [--queue QUEUE] [--share-id ID] [--mount-root PATH]\n       mnode -a local[:SOURCE_PATH] [--host IPv4] [--queue QUEUE] [--share-id ID] [--mount-root PATH]\n       mnode -l | --list\n       mnode --failed\n       mnode -rm NODE_ID [--connect USER@IPv4[:PORT]] | --remove NODE_ID\n       mnode -rm share:SHARE_ID\n\nAdd nodes\n  Nodes enter the configured cluster after setup verification. Failed attempts stay outside the node list; use --failed to inspect their errors and retry the original command. Registered nodes show READY or OFFLINE. SSH-added Macs join the default compute queue unless --queue selects another queue. If key login is not configured, mnode can install a dedicated SSH key after you accept the host fingerprint and enter the remote account password once. Administrator prompts identify the Mac and operation; a separate administrator password may be needed on each affected Mac. The configured login Mac stays outside compute queues.\n\nShares\n  `local` adds this Mac without SSH. SOURCE_PATH registers an additional named share and requires --share-id. --mount-root selects its path on every client; without it the path is /Users/Shared/macluster-shares/<share-id>. Use `mnode -a local` without SOURCE_PATH to enroll this Mac as the login node and mount the configured primary share.\n\nRemove nodes and shares\n  `mnode -rm NODE_ID --connect USER@IPv4[:PORT]` reaches a moved node at its current address, verifies its registered machine UUID before cleanup, and retains the original NFS client address for export cleanup. The connection is saved for interrupted-removal retries; host-key verification remains enabled. `mnode -rm share:SHARE_ID` cancels an incomplete named-share setup and removes only exact macluster-managed resources.\n\nController maintenance\n  Add/remove and share changes fence submissions. If the controller is running, mnode asks before stopping it; y stops it immediately, n cancels. Running jobs are not killed, but mnode stops if active jobs or output sync remain. Restart it with `macluster controller run` after the command exits."
}

fn read_config(path: &Path) -> AppResult<ClusterConfig> {
    let source = fs::read_to_string(path)
        .map_err(|error| (1, format!("cannot read config {}: {error}", path.display())))?;
    ClusterConfig::parse(&source).map_err(|error| (2, error.to_string()))
}

fn read_admin_state(path: &Path, config_path: &Path, state_dir: &Path) -> AppResult<AdminState> {
    let config_identity =
        fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf());
    let state_identity = fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    if path.exists() {
        let bytes = fs::read(path).map_err(io_error)?;
        let state: AdminState = serde_json::from_slice(&bytes).map_err(|error| {
            (
                1,
                format!("invalid node admin journal {}: {error}", path.display()),
            )
        })?;
        if state.version != 1
            || state.config_path != config_identity.to_string_lossy()
            || state.state_dir != state_identity.to_string_lossy()
        {
            return Err((
                1,
                "node admin journal belongs to a different config or state directory".into(),
            ));
        }
        Ok(state)
    } else {
        Ok(AdminState {
            version: 1,
            config_path: config_identity.to_string_lossy().into_owned(),
            state_dir: state_identity.to_string_lossy().into_owned(),
            reserved_node_ids: BTreeSet::new(),
            machine_uuids: BTreeMap::new(),
            operations: BTreeMap::new(),
        })
    }
}

fn save_admin_state(path: &Path, state: &AdminState) -> AppResult<()> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| (1, error.to_string()))?;
    atomic_write(path, &bytes)
}

fn allocate_node_id(queue: &str, reserved: &BTreeSet<String>) -> AppResult<String> {
    if queue.len() + 4 > 64 {
        return Err((
            2,
            format!(
                "queue name '{queue}' is too long to form a node ID within the 64-character limit"
            ),
        ));
    }
    for index in 1..=999 {
        let candidate = format!("{queue}-{index:03}");
        if !reserved.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err((
        2,
        format!("no node IDs remain in queue '{queue}' (suffixes 001 through 999 are reserved)"),
    ))
}

fn config_path_candidate(
    config: &ClusterConfig,
    source: &str,
    node_id: &str,
    queue_name: &str,
    include_in_queue: bool,
    endpoint: &NodeEndpoint,
    remote_binary: &str,
    remote_config: &str,
    ssh_identity_file: Option<&str>,
    machine_uuid: &str,
    execution_uid: u32,
) -> AppResult<String> {
    let mut members = config
        .queues
        .get(queue_name)
        .ok_or_else(|| (2, format!("queue '{queue_name}' is not configured")))?
        .nodes
        .clone();
    if include_in_queue && !members.iter().any(|member| member == node_id) {
        members.push(node_id.to_owned());
    }
    let mut candidate = replace_queue_members(source, queue_name, &members)?;
    candidate.push_str("\n[nodes.");
    candidate.push_str(node_id);
    candidate.push_str("]\nhost = \"");
    candidate.push_str(&endpoint.host.to_string());
    candidate.push_str("\"\ntransport = \"ssh\"\nremote_binary = \"");
    candidate.push_str(remote_binary);
    candidate.push_str("\"\nssh_user = \"");
    candidate.push_str(&endpoint.user);
    candidate.push_str("\"\nssh_port = ");
    candidate.push_str(&endpoint.port.to_string());
    candidate.push_str("\nremote_config = \"");
    candidate.push_str(remote_config);
    candidate.push_str("\"\n");
    if let Some(identity_file) = ssh_identity_file {
        candidate.push_str("ssh_identity_file = ");
        candidate.push_str(&toml_quote(identity_file));
        candidate.push('\n');
    }
    candidate.push_str("machine_uuid = \"");
    candidate.push_str(machine_uuid);
    candidate.push_str("\"\nexecution_uid = ");
    candidate.push_str(&execution_uid.to_string());
    candidate.push('\n');
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

fn toml_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

fn replace_queue_members(source: &str, queue: &str, members: &[String]) -> AppResult<String> {
    let section = format!("[queues.{queue}]");
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == section)
        .ok_or_else(|| (2, format!("config is missing {section}")))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    let key = (start + 1..end)
        .find(|index| {
            lines[*index]
                .split_once('=')
                .is_some_and(|(key, _)| key.trim() == "nodes")
        })
        .ok_or_else(|| (2, format!("{section} has no nodes array")))?;
    let value = members
        .iter()
        .map(|member| format!("\"{member}\""))
        .collect::<Vec<_>>()
        .join(", ");
    lines[key] = format!("nodes = [{value}]");
    Ok(lines.join("\n") + if source.ends_with('\n') { "\n" } else { "" })
}

fn queue_candidate_with_node(
    config: &ClusterConfig,
    source: &str,
    queue_name: &str,
    node_id: &str,
) -> AppResult<String> {
    if config.is_login_node(node_id) {
        let mut candidate = source.to_owned();
        for (name, queue) in &config.queues {
            let members = queue
                .nodes
                .iter()
                .filter(|member| member.as_str() != node_id)
                .cloned()
                .collect::<Vec<_>>();
            candidate = replace_queue_members(&candidate, name, &members)?;
        }
        return Ok(candidate);
    }
    let mut members = config
        .queues
        .get(queue_name)
        .ok_or_else(|| (2, format!("queue '{queue_name}' is not configured")))?
        .nodes
        .clone();
    if !members.iter().any(|member| member == node_id) {
        members.push(node_id.to_owned());
    }
    replace_queue_members(source, queue_name, &members)
}

fn remove_node_from_config(
    source: &str,
    config: &ClusterConfig,
    node_id: &str,
) -> AppResult<String> {
    let mut candidate = source.to_owned();
    for (queue_name, queue) in &config.queues {
        let members: Vec<_> = queue
            .nodes
            .iter()
            .filter(|member| member.as_str() != node_id)
            .cloned()
            .collect();
        candidate = replace_queue_members(&candidate, queue_name, &members)?;
    }
    let section = format!("[nodes.{node_id}]");
    let mut lines: Vec<String> = candidate.lines().map(str::to_owned).collect();
    let Some(start) = lines.iter().position(|line| line.trim() == section) else {
        return Err((2, format!("config has no node section for {node_id}")));
    };
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    lines.drain(start..end);
    let mut result = lines.join("\n");
    if candidate.ends_with('\n') {
        result.push('\n');
    }
    ClusterConfig::parse(&result).map_err(|error| (2, error.to_string()))?;
    Ok(result)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| (1, "managed file has no parent directory".into()))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("macluster"),
        Id128::random()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(io_error)
}

fn backup_config(path: &Path, operation_id: &str) -> AppResult<()> {
    let backup = path.with_file_name(format!(
        "{}.macluster-{operation_id}.bak",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config")
    ));
    if !backup.exists() {
        fs::copy(path, &backup).map_err(io_error)?;
        let file = OpenOptions::new()
            .read(true)
            .open(&backup)
            .map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
    }
    Ok(())
}

fn remote_node_check(node: &NodeConfig, node_id: &str) -> AppResult<NodeCheck> {
    let mut args = vec![node.remote_binary.as_str()];
    if let Some(config_path) = node.remote_config.as_deref() {
        args.extend(["--config", config_path]);
    }
    args.extend(["internal", "node-check", "--node", node_id]);
    let command = shell_join(&args);
    let output = ssh_output(node, &command, None)?;
    if !output.status.success() {
        return Err((1, command_error("remote node check failed", &output)));
    }
    let report: NodeCheck = serde_json::from_slice(&output.stdout).map_err(|error| {
        (
            1,
            format!("remote node check returned invalid JSON: {error}"),
        )
    })?;
    if report.node != node_id {
        return Err((1, "remote node check returned a different node ID".into()));
    }
    Ok(report)
}

pub(crate) fn read_remote_facts(node: &NodeConfig) -> AppResult<RemoteFacts> {
    let command = "printf 'OS='; /usr/bin/uname -s; printf 'ARCH='; /usr/bin/uname -m; printf 'VERSION='; /usr/bin/sw_vers -productVersion; printf 'UID='; /usr/bin/id -u; printf 'GID='; /usr/bin/id -g; printf 'HOME='; /usr/bin/printenv HOME; printf 'FREE_KB='; /bin/df -Pk \"$HOME\" | /usr/bin/tail -1 | /usr/bin/awk '{print $4}'";
    let output = ssh_output(node, command, None)?;
    if !output.status.success() {
        return Err((1, command_error("SSH preflight failed", &output)));
    }
    let mut facts = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((key, value)) = line.split_once('=') {
            facts.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    let get = |key: &str| {
        facts
            .get(key)
            .cloned()
            .ok_or_else(|| (1, format!("remote preflight omitted {key}")))
    };
    Ok(RemoteFacts {
        os: get("OS")?,
        arch: get("ARCH")?,
        version: get("VERSION")?,
        uid: get("UID")?
            .parse()
            .map_err(|_| (1, "remote UID was not numeric".into()))?,
        gid: get("GID")?
            .parse()
            .map_err(|_| (1, "remote GID was not numeric".into()))?,
        home: get("HOME")?,
        free_kb: get("FREE_KB")?
            .parse()
            .map_err(|_| (1, "remote free disk size was not numeric".into()))?,
    })
}

fn remote_route_ipv4(node: &NodeConfig, destination: &str) -> AppResult<Ipv4Addr> {
    let route = shell_join(&["/sbin/route", "-n", "get", destination]);
    let output = ssh_output(node, &route, None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("cannot inspect route to NFS server", &output),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let interface = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .ok_or_else(|| (1, "route output did not include an interface".into()))?;
    let command = shell_join(&["/sbin/ifconfig", interface]);
    let output = ssh_output(node, &command, None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("cannot inspect selected network interface", &output),
        ));
    }
    parse_ifconfig_ipv4(&String::from_utf8_lossy(&output.stdout))
        .into_iter()
        .next()
        .ok_or_else(|| {
            (
                1,
                "selected network interface has no usable IPv4 address".into(),
            )
        })
}

pub(crate) fn ensure_agent_capabilities(node: &NodeConfig) -> AppResult<()> {
    let output = if node.transport == Transport::Local {
        let mut command = Command::new(&node.remote_binary);
        command.args(["internal", "capabilities", "--json"]);
        run_child(command, None, Duration::from_secs(5))?
    } else {
        let command = shell_join(&[&node.remote_binary, "internal", "capabilities", "--json"]);
        ssh_output(node, &command, None)?
    };
    if !output.status.success() {
        return Err((1, command_error("agent capability check failed", &output)));
    }
    let report: CapabilityReport = serde_json::from_slice(&output.stdout).map_err(|error| {
        (
            1,
            format!("agent capability report was invalid JSON: {error}"),
        )
    })?;
    let missing = missing_required_agent_features(&report.features);
    if !missing.is_empty() {
        return Err((
            1,
            format!(
                "agent on {} does not support required feature(s): {}; upgrade it with the current macluster binary before changing cluster config",
                node.host,
                missing.join(", ")
            ),
        ));
    }
    Ok(())
}

pub(crate) fn stage_current_agents(
    config: &ClusterConfig,
    source: &str,
    operation_id: &str,
    purpose: AgentStagePurpose,
) -> AppResult<(String, ClusterConfig)> {
    let mut candidate = source.to_owned();
    let local_binary = std::env::current_exe()
        .map_err(io_error)?
        .canonicalize()
        .map_err(io_error)?;
    let local_binary_text = local_binary
        .to_str()
        .ok_or_else(|| (1, "current macluster binary path is not UTF-8".into()))?;
    if !safe_absolute_remote_path(local_binary_text) {
        return Err((
            1,
            "current macluster binary path cannot be stored safely in TOML".into(),
        ));
    }
    for (node_id, node) in &config.nodes {
        let (destination, machine_uuid, execution_uid, remote_arch) = if node.transport
            == Transport::Local
        {
            let machine_uuid = local_platform_uuid()?;
            let execution_uid = unsafe { libc::geteuid() };
            if node
                .machine_uuid
                .as_deref()
                .is_some_and(|expected| !expected.eq_ignore_ascii_case(&machine_uuid))
                || node
                    .execution_uid
                    .is_some_and(|expected| expected != execution_uid)
            {
                return Err((
                    1,
                    format!(
                        "local node {node_id} no longer matches its registered machine UUID or execution UID"
                    ),
                ));
            }
            ensure_agent_capabilities(&NodeConfig {
                remote_binary: local_binary_text.into(),
                ..node.clone()
            })
            .map_err(|(_, error)| (1, format!("node {node_id}: {error}")))?;
            (
                local_binary_text.to_owned(),
                machine_uuid,
                execution_uid,
                std::env::consts::ARCH.to_owned(),
            )
        } else {
            let facts = read_remote_facts(node)
                .map_err(|(_, error)| (1, format!("cannot inspect node {node_id}: {error}")))?;
            let machine_uuid = remote_machine_uuid(node).map_err(|(_, error)| {
                (1, format!("cannot verify node {node_id} identity: {error}"))
            })?;
            if node
                .machine_uuid
                .as_deref()
                .is_some_and(|expected| !expected.eq_ignore_ascii_case(&machine_uuid))
                || node
                    .execution_uid
                    .is_some_and(|expected| expected != facts.uid)
            {
                return Err((
                    1,
                    format!(
                        "node {node_id} no longer matches its registered machine UUID or execution UID"
                    ),
                ));
            }
            let binary = select_local_binary(&facts.arch)?;
            let digest = local_sha256(&binary)?;
            let home = checked_remote_path(&facts.home)?;
            let path = format!(
                "{home}/.local/share/macluster/clusters/{}/bin/{digest}/macluster",
                config.share_uuid
            );
            let mut staged = node.clone();
            staged.remote_binary = path.clone();
            ensure_remote_binary(&staged, &binary, &facts.version, operation_id).map_err(
                |(_, error)| {
                    (
                        1,
                        format!("cannot stage current agent on {node_id}: {error}"),
                    )
                },
            )?;
            ensure_agent_capabilities(&staged)
                .map_err(|(_, error)| (1, format!("node {node_id}: {error}")))?;
            (path, machine_uuid, facts.uid, facts.arch)
        };
        if purpose.installs_power_helper() {
            if let Err(error) = ensure_power_helper(node, execution_uid, &remote_arch, operation_id)
            {
                eprintln!("Power sampler setup for {node_id} was skipped: {error}");
            }
        }
        candidate = replace_node_string_key(&candidate, node_id, "remote_binary", &destination)?;
        candidate = replace_node_string_key(&candidate, node_id, "machine_uuid", &machine_uuid)?;
        candidate = replace_node_integer_key(&candidate, node_id, "execution_uid", execution_uid)?;
    }
    let candidate_config =
        ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok((candidate, candidate_config))
}

fn replace_node_string_key(
    source: &str,
    node_id: &str,
    key: &str,
    value: &str,
) -> AppResult<String> {
    let section = format!("[nodes.{node_id}]");
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == section)
        .ok_or_else(|| (2, format!("config is missing {section}")))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    if let Some(index) = (start + 1..end).find(|index| {
        lines[*index]
            .split_once('=')
            .is_some_and(|(existing, _)| existing.trim() == key)
    }) {
        lines[index] = format!("{key} = \"{value}\"");
    } else {
        lines.insert(end, format!("{key} = \"{value}\""));
    }
    Ok(lines.join("\n") + if source.ends_with('\n') { "\n" } else { "" })
}

fn replace_node_integer_key(
    source: &str,
    node_id: &str,
    key: &str,
    value: u32,
) -> AppResult<String> {
    let section = format!("[nodes.{node_id}]");
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == section)
        .ok_or_else(|| (2, format!("config is missing {section}")))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    if let Some(index) = (start + 1..end).find(|index| {
        lines[*index]
            .split_once('=')
            .is_some_and(|(existing, _)| existing.trim() == key)
    }) {
        lines[index] = format!("{key} = {value}");
    } else {
        lines.insert(end, format!("{key} = {value}"));
    }
    Ok(lines.join("\n") + if source.ends_with('\n') { "\n" } else { "" })
}

pub(crate) fn remote_machine_uuid(node: &NodeConfig) -> AppResult<String> {
    let output = ssh_output(node, "/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice", None)?;
    if !output.status.success() {
        return Err((1, command_error("could not read machine identity", &output)));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| line.rsplit_once('=').map(|(_, value)| value.trim()))
        .map(|value| value.trim_matches('"').trim())
        .ok_or_else(|| (1, "remote IOPlatformUUID was not present".into()))?;
    Id128::parse(value).map_err(|error| (1, format!("invalid remote platform UUID: {error}")))?;
    Ok(value.to_ascii_lowercase())
}

pub(crate) fn checked_remote_path(path: &str) -> AppResult<String> {
    if !safe_absolute_remote_path(path) {
        return Err((
            2,
            "remote HOME must be a normalized absolute path containing only ASCII letters, digits, '/', '.', '_' or '-'".into(),
        ));
    }
    Ok(path.to_owned())
}

pub(crate) fn reset_admin_operations(
    config_path: &Path,
    state_dir: &Path,
) -> AppResult<Vec<ResetAdminOperation>> {
    let canonical_config = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let canonical_state = state_dir
        .canonicalize()
        .unwrap_or_else(|_| state_dir.to_path_buf());
    let state = read_admin_state(
        &state_dir.join("node-admin.json"),
        &canonical_config,
        &canonical_state,
    )?;
    Ok(state
        .operations
        .into_values()
        .map(|operation| {
            let client_setup_may_have_run = pending_add_may_have_client_state(&operation);
            ResetAdminOperation {
                id: operation.id,
                action: operation.action,
                connection_endpoint: operation.connection_endpoint,
                remote_config_path: operation.remote_config_path,
                node_id: operation.node_id,
                endpoint: operation.endpoint,
                machine_uuid: operation.machine_uuid,
                phase: operation.phase,
                old_config_sha256: operation.old_config_sha256,
                candidate_config_sha256: operation.candidate_config_sha256,
                client_setup_may_have_run,
            }
        })
        .collect())
}

pub(crate) fn reset_node_from_endpoint(
    endpoint: &str,
    machine_uuid: Option<String>,
) -> AppResult<NodeConfig> {
    let parsed = NodeEndpoint::parse(endpoint).map_err(|error| {
        (
            1,
            format!("cannot identify pending node endpoint '{endpoint}': {error}"),
        )
    })?;
    if parsed.source_path.is_some() {
        return Err((
            1,
            format!("pending node endpoint '{endpoint}' unexpectedly contains a source path"),
        ));
    }
    let local = parsed.user == "local";
    let ssh_identity_file = if local {
        None
    } else {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            (
                1,
                "cannot find the login account's HOME to resume SSH access".to_owned(),
            )
        })?;
        crate::ssh_bootstrap::existing_ssh_identity_file(&home, &parsed.ssh_identity_endpoint())
            .map_err(|error| (1, error))?
            .map(|path| path.to_string_lossy().into_owned())
    };
    Ok(NodeConfig {
        host: parsed.host.to_string(),
        transport: if local {
            Transport::Local
        } else {
            Transport::Ssh
        },
        remote_binary: "/usr/local/bin/macluster".into(),
        ssh_user: (!local).then_some(parsed.user),
        ssh_port: (!local).then_some(parsed.port),
        ssh_identity_file,
        remote_config: None,
        machine_uuid,
        execution_uid: None,
    })
}

fn cleanup_node_from_endpoint(
    endpoint: &str,
    machine_uuid: Option<String>,
) -> AppResult<NodeConfig> {
    let parsed = NodeEndpoint::parse(endpoint).map_err(|error| {
        (
            1,
            format!("cannot identify pending node endpoint '{endpoint}': {error}"),
        )
    })?;
    let local = parsed.user == "local";
    let ssh_identity_file = if local {
        None
    } else {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            (
                1,
                "cannot find the login account's HOME to resume SSH access".to_owned(),
            )
        })?;
        crate::ssh_bootstrap::existing_ssh_identity_file(&home, &parsed.ssh_identity_endpoint())
            .map_err(|error| (1, error))?
            .map(|path| path.to_string_lossy().into_owned())
    };
    Ok(NodeConfig {
        host: parsed.host.to_string(),
        transport: if local {
            Transport::Local
        } else {
            Transport::Ssh
        },
        remote_binary: "/usr/local/bin/macluster".into(),
        ssh_user: (!local).then_some(parsed.user),
        ssh_port: (!local).then_some(parsed.port),
        ssh_identity_file,
        remote_config: None,
        machine_uuid,
        execution_uid: None,
    })
}

fn safe_absolute_remote_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && path
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn normalize_binary_path(path: &Path) -> AppResult<String> {
    let canonical = path.canonicalize().map_err(io_error)?;
    let binary = canonical
        .to_str()
        .ok_or_else(|| (1, "current macluster binary path is not UTF-8".into()))?;
    if !safe_absolute_remote_path(binary) {
        return Err((
            1,
            "current macluster binary path cannot be stored safely in TOML".into(),
        ));
    }
    Ok(binary.to_owned())
}

fn select_local_binary(remote_arch: &str) -> AppResult<PathBuf> {
    let wanted = match remote_arch {
        "arm64" | "aarch64" => "arm64",
        "x86_64" => "x86_64",
        value => return Err((2, format!("unsupported macOS architecture '{value}'"))),
    };
    let path = std::env::current_exe()
        .map_err(io_error)?
        .canonicalize()
        .map_err(io_error)?;
    let output = Command::new("/usr/bin/lipo")
        .arg("-archs")
        .arg(&path)
        .output()
        .map_err(|error| {
            (
                1,
                format!("cannot inspect current macluster binary: {error}"),
            )
        })?;
    if !output.status.success() {
        return Err((
            1,
            command_error("lipo could not inspect the current binary", &output),
        ));
    }
    let architectures = String::from_utf8_lossy(&output.stdout);
    if !architectures.split_whitespace().any(|arch| arch == wanted) {
        return Err((
            2,
            format!(
                "current macluster binary does not include {wanted}; build and run the matching architecture binary first"
            ),
        ));
    }
    Ok(path)
}

pub(crate) struct PowerHelperSetup {
    pub(crate) script: String,
    staged_binary: String,
    staged_plist: String,
}

pub(crate) fn prepare_power_helper(
    node: &NodeConfig,
    execution_uid: u32,
    remote_arch: &str,
    operation_id: &str,
) -> Result<Option<PowerHelperSetup>, String> {
    if execution_uid == 0 {
        return Err("the cluster execution account must not be root".into());
    }
    let helper = crate::embedded_power::ExtractedHelper::new()?;
    let wanted_arch = match remote_arch {
        "arm64" | "aarch64" => "arm64",
        "x86_64" => "x86_64",
        value => return Err(format!("unsupported macOS architecture '{value}'")),
    };
    let architectures = Command::new("/usr/bin/lipo")
        .args(["-archs"])
        .arg(helper.path())
        .output()
        .map_err(|error| format!("cannot inspect macluster-power architecture: {error}"))?;
    if !architectures.status.success()
        || !String::from_utf8_lossy(&architectures.stdout)
            .split_whitespace()
            .any(|arch| arch == wanted_arch)
    {
        return Err(format!(
            "macluster-power does not contain the {wanted_arch} architecture"
        ));
    }
    let digest = crate::embedded_power::digest()?;
    let plist = power_launch_daemon_plist(execution_uid);
    let installed_digest = ssh_output(
        node,
        &shell_join(&["/usr/bin/shasum", "-a", "256", POWER_HELPER_PATH]),
        None,
    )
    .map_err(|(_, error)| error)?;
    let installed_plist = ssh_output(node, &shell_join(&["/bin/cat", POWER_LAUNCHD_PATH]), None)
        .map_err(|(_, error)| error)?;
    let socket_ready = ssh_output(
        node,
        &shell_join(&["test", "-S", "/var/run/org.macluster.power.sock"]),
        None,
    )
    .map_err(|(_, error)| error)?;
    let installed = String::from_utf8_lossy(&installed_digest.stdout)
        .split_whitespace()
        .next()
        == Some(digest.as_str());
    if installed
        && installed_plist.status.success()
        && installed_plist.stdout == plist.as_bytes()
        && socket_ready.status.success()
    {
        return Ok(None);
    }

    let operation_id = operation_id
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect::<String>();
    let staged_binary = format!("/tmp/macluster-power-{operation_id}.bin");
    let staged_plist = format!("/tmp/macluster-power-{operation_id}.plist");
    let local_plist = std::env::temp_dir().join(format!("macluster-power-{operation_id}.plist"));
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&local_plist)?;
        file.write_all(plist.as_bytes())?;
        file.sync_all()
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&local_plist);
        return Err(format!("could not stage LaunchDaemon plist: {error}"));
    }
    let stage_result = (|| -> AppResult<PowerHelperSetup> {
        scp_to_node(node, helper.path(), &staged_binary)?;
        scp_to_node(node, &local_plist, &staged_plist)?;
        let script = power_helper_install_script(&staged_binary, &staged_plist, &digest);
        Ok(PowerHelperSetup {
            script,
            staged_binary: staged_binary.clone(),
            staged_plist: staged_plist.clone(),
        })
    })();
    let _ = fs::remove_file(&local_plist);
    match stage_result {
        Ok(setup) => Ok(Some(setup)),
        Err((_, error)) => {
            let _ = ssh_output(
                node,
                &shell_join(&["/bin/rm", "-f", &staged_binary, &staged_plist]),
                None,
            );
            Err(error)
        }
    }
}

pub(crate) fn cleanup_power_helper_stage(node: &NodeConfig, setup: &PowerHelperSetup) {
    let _ = ssh_output(
        node,
        &shell_join(&["/bin/rm", "-f", &setup.staged_binary, &setup.staged_plist]),
        None,
    );
}

pub(crate) fn local_power_sampler_needs_setup() -> Result<bool, String> {
    use std::os::unix::fs::FileTypeExt;
    let socket = fs::symlink_metadata("/var/run/org.macluster.power.sock")
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false);
    if !socket {
        return Ok(true);
    }
    let expected = crate::embedded_power::digest()?;
    if local_sha256(Path::new(POWER_HELPER_PATH)).ok().as_deref() != Some(expected.as_str()) {
        return Ok(true);
    }
    let plist = power_launch_daemon_plist(unsafe { libc::geteuid() });
    Ok(fs::read(POWER_LAUNCHD_PATH).ok().as_deref() != Some(plist.as_bytes()))
}

pub(crate) fn ensure_local_power_sampler(config: &ClusterConfig) -> Result<(), String> {
    let login = config
        .login_node
        .as_ref()
        .and_then(|id| config.nodes.get(id.as_str()))
        .filter(|node| node.transport == Transport::Local)
        .ok_or_else(|| {
            "power sampler setup requires this Mac to be the local login node".to_owned()
        })?;
    let uid = unsafe { libc::geteuid() };
    if login.execution_uid != Some(uid)
        || login.machine_uuid.as_deref()
            != Some(local_platform_uuid().map_err(|(_, error)| error)?.as_str())
    {
        return Err(
            "local login identity does not match this Mac/account; power setup was skipped".into(),
        );
    }
    ensure_power_helper(
        login,
        uid,
        std::env::consts::ARCH,
        &Id128::random().to_string(),
    )
}

fn ensure_power_helper(
    node: &NodeConfig,
    execution_uid: u32,
    remote_arch: &str,
    operation_id: &str,
) -> Result<(), String> {
    let Some(setup) = prepare_power_helper(node, execution_uid, remote_arch, operation_id)? else {
        return Ok(());
    };
    let result = run_interactive_admin_with_reason(
        node,
        "install or refresh the system mtop power sampler",
        &setup.script,
    );
    cleanup_power_helper_stage(node, &setup);
    result
}

fn prepare_power_helpers_for_nodes(
    config: &ClusterConfig,
    operation_id: &str,
    excluded_machine_uuid: Option<&str>,
) -> BTreeMap<String, PowerHelperSetup> {
    let mut setups = BTreeMap::new();
    for (node_id, node) in &config.nodes {
        if excluded_machine_uuid.is_some_and(|expected| {
            node.machine_uuid
                .as_deref()
                .is_some_and(|known| known.eq_ignore_ascii_case(expected))
        }) {
            continue;
        }
        let (uid, arch) = if node.transport == Transport::Local {
            (
                unsafe { libc::geteuid() },
                std::env::consts::ARCH.to_owned(),
            )
        } else {
            match read_remote_facts(node) {
                Ok(facts) => (facts.uid, facts.arch),
                Err((_, error)) => {
                    eprintln!("Power sampler setup for {node_id} was skipped: {error}");
                    continue;
                }
            }
        };
        match prepare_power_helper(node, uid, &arch, operation_id) {
            Ok(Some(setup)) => {
                setups.insert(node_id.clone(), setup);
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("Power sampler setup for {node_id} was skipped: {error}");
            }
        }
    }
    setups
}

fn power_helper_install_script(staged_binary: &str, staged_plist: &str, digest: &str) -> String {
    let staged_binary = shell_quote(staged_binary);
    let staged_plist = shell_quote(staged_plist);
    let digest = shell_quote(digest);
    format!(
        "set -e\nif [ ! -f {staged_binary} ] || [ -L {staged_binary} ]; then echo 'power helper staging file is not a regular file' >&2; exit 1; fi\nactual=$(/usr/bin/shasum -a 256 {staged_binary})\nif [ \"${{actual%% *}}\" != {digest} ]; then echo 'power helper checksum mismatch; installation cancelled' >&2; exit 1; fi\n/bin/mkdir -p /Library/PrivilegedHelperTools /Library/LaunchDaemons\n/usr/bin/install -o root -g wheel -m 755 {staged_binary} {POWER_HELPER_PATH}\n/usr/bin/install -o root -g wheel -m 644 {staged_plist} {POWER_LAUNCHD_PATH}\n/bin/launchctl bootout system/{POWER_LAUNCHD_LABEL} >/dev/null 2>&1 || true\n/bin/rm -f {staged_binary} {staged_plist}\nattempt=0\nwhile ! bootstrap_error=$(/bin/launchctl bootstrap system {POWER_LAUNCHD_PATH} 2>&1); do\n  attempt=$((attempt + 1))\n  if [ \"$attempt\" -ge 20 ]; then printf '%s\\n' \"$bootstrap_error\" >&2; exit 1; fi\n  /bin/sleep 0.25\ndone\n/bin/launchctl kickstart -k system/{POWER_LAUNCHD_LABEL}\n"
    )
}

fn admin_shell_command(sudo_path: &str, script: &str) -> String {
    format!(
        "{} /bin/sh -c {}",
        shell_quote(sudo_path),
        shell_quote(script)
    )
}

fn candidate_admin_script(
    power_script: Option<&str>,
    mount_command: Option<&str>,
) -> Option<String> {
    if power_script.is_none() && mount_command.is_none() {
        return None;
    }
    let mut script = String::from("set -e\n");
    if let Some(power_script) = power_script {
        script.push_str(&format!(
            "if ! /bin/sh -c {}; then echo 'power sampler setup failed; continuing with NFS setup' >&2; fi\n",
            shell_quote(power_script)
        ));
    }
    if let Some(mount_command) = mount_command {
        script.push_str(mount_command);
        script.push('\n');
    }
    Some(script)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientMountRequest {
    source: String,
    mount_root: PathBuf,
    source_alias: Option<PathBuf>,
    needs_privileged_mkdir: bool,
    needs_mount: bool,
    allow_existing_contents: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientUnmountRequest {
    source: String,
    mount_root: PathBuf,
    share_uuid: String,
    label: String,
}

pub(crate) fn client_mount_status_awk_script() -> &'static str {
    r#"{
    separator = index($0, " on ");
    if (!separator) next;
    actual_source = substr($0, 1, separator - 1);
    rest = substr($0, separator + 4);
    open = index(rest, " (");
    if (!open) next;
    actual_mount = substr(rest, 1, open - 1);
    filesystem = substr(rest, open + 2);
    sub(/,.*/, "", filesystem);
    sub(/\).*/, "", filesystem);
    if (actual_mount != mount) next;
    matches++;
    if (matches == 1 && actual_source == source && filesystem == "nfs") result = "expected";
    else result = "other";
}
END {
    if (matches == 0) print "none";
    else if (matches == 1 && result == "expected") print "expected";
    else print "other";
}"#
}

fn client_nfs_cleanup_batch_script(
    requests: &[ClientUnmountRequest],
    aliases: &[(PathBuf, PathBuf)],
) -> String {
    let awk = shell_quote(client_mount_status_awk_script());
    let mut script = String::from("set -eu\n");
    for request in requests {
        script.push_str(&crate::nfs_recovery::cleanup_script(
            &request.source,
            &request.mount_root,
            &request.share_uuid,
        ));
    }
    if !requests.is_empty() {
        script.push_str("mounts=$(/sbin/mount)\n");
        for request in requests {
            append_client_mount_status(&mut script, &awk, request);
            script.push_str(&format!(
                "case \"$mount_status\" in expected) ;; other) echo {} >&2; exit 1 ;; none) ;; esac\n",
                shell_quote(&format!(
                    "mount {} for {} changed; refusing cleanup",
                    request.mount_root.display(),
                    request.label
                ))
            ));
            append_client_mount_marker_check(&mut script, request);
        }
        for request in requests {
            script.push_str("mounts=$(/sbin/mount)\n");
            append_client_mount_status(&mut script, &awk, request);
            script.push_str(&format!(
                "case \"$mount_status\" in other) echo {} >&2; exit 1 ;; esac\nif [ \"$mount_status\" = expected ]; then\n",
                shell_quote(&format!(
                    "mount {} for {} changed during cleanup; refusing to unmount it",
                    request.mount_root.display(),
                    request.label
                ))
            ));
            append_client_mount_marker_check(&mut script, request);
            script.push_str(&format!(
                "/sbin/umount {}\n",
                shell_quote(&request.mount_root.to_string_lossy())
            ));
            script.push_str("fi\n");
        }
        for request in requests {
            let probe = primary_restore_probe(&request.mount_root, &request.share_uuid);
            let restore = primary_restore_script(&request.mount_root, &request.share_uuid);
            script.push_str(&format!("if ( {probe} ); then\n{restore}\nfi\n"));
        }
    }
    for (alias, target) in aliases {
        if alias == target {
            continue;
        }
        script.push_str(&client_alias_cleanup_snippet(alias, target));
    }
    for (alias, target) in aliases {
        if alias == target {
            continue;
        }
        script.push_str(&client_alias_verification_snippet(alias, target));
    }
    script
}

fn client_alias_cleanup_snippet(alias: &Path, target: &Path) -> String {
    let alias = shell_quote(&alias.to_string_lossy());
    let target = shell_quote(&target.to_string_lossy());
    format!(
        "alias_path={alias}; target_path={target}; if alias_type=$(/usr/bin/stat -f '%HT' \"$alias_path\" 2>&1); then if [ \"$alias_type\" = 'Symbolic Link' ]; then if alias_target=$(/usr/bin/readlink \"$alias_path\" 2>&1); then if [ \"$alias_target\" = \"$target_path\" ]; then /bin/rm \"$alias_path\"; fi; else echo \"$alias_target\" >&2; exit 1; fi; fi; else case \"$alias_type\" in *'Permission denied'*|*'Operation not permitted'*) echo \"$alias_type\" >&2; exit 1 ;; *'No such file or directory'*) : ;; *) echo \"cannot inspect source alias $alias_path: $alias_type\" >&2; exit 1 ;; esac; fi\n"
    )
}

fn client_alias_verification_snippet(alias: &Path, target: &Path) -> String {
    let alias = shell_quote(&alias.to_string_lossy());
    let target = shell_quote(&target.to_string_lossy());
    format!(
        "alias_path={alias}; target_path={target}; if alias_type=$(/usr/bin/stat -f '%HT' \"$alias_path\" 2>&1); then if [ \"$alias_type\" = 'Symbolic Link' ]; then if alias_target=$(/usr/bin/readlink \"$alias_path\" 2>&1); then if [ \"$alias_target\" = \"$target_path\" ]; then echo 'managed source alias remains after cleanup' >&2; exit 1; fi; else echo \"$alias_target\" >&2; exit 1; fi; fi; else case \"$alias_type\" in *'Permission denied'*|*'Operation not permitted'*) echo \"$alias_type\" >&2; exit 1 ;; *'No such file or directory'*) : ;; *) echo \"cannot verify source alias $alias_path: $alias_type\" >&2; exit 1 ;; esac; fi\n"
    )
}

fn client_nfs_cleanup_plan(
    config: &ClusterConfig,
    node_id: &str,
) -> (Vec<ClientUnmountRequest>, Vec<(PathBuf, PathBuf)>) {
    let mut requests = Vec::new();
    let mut aliases = Vec::new();
    let storage_id = config.storage_server.as_str();
    if node_id != storage_id {
        let storage = &config.nodes[storage_id];
        requests.push(ClientUnmountRequest {
            source: format!(
                "{}:{}",
                storage.host,
                config.primary_source_root().to_string_lossy()
            ),
            mount_root: config.shared_root.clone(),
            share_uuid: config.share_uuid.clone(),
            label: "primary shared root".into(),
        });
    }
    for (share_id, share) in &config.shares {
        let server_id = share.server.as_str();
        if node_id == server_id {
            continue;
        }
        let server = &config.nodes[server_id];
        requests.push(ClientUnmountRequest {
            source: format!("{}:{}", server.host, share.source_root.to_string_lossy()),
            mount_root: share.mount_root.clone(),
            share_uuid: share.share_uuid.clone(),
            label: format!("NFS share {share_id}"),
        });
        if share.source_root != share.mount_root {
            aliases.push((share.source_root.clone(), share.mount_root.clone()));
        }
    }
    (requests, aliases)
}

fn pending_add_may_have_client_state(operation: &NodeOperation) -> bool {
    operation.action == "add"
        && !operation.endpoint.starts_with("queue:")
        && (operation.client_setup_attempted != Some(false)
            || operation.managed_export
            || !operation.managed_shares.is_empty()
            || matches!(
                operation.phase.as_str(),
                "CANDIDATE_INSTALLED" | "ADD_COMMITTING"
            ))
}

fn validate_pending_node_identity(
    node_id: &str,
    expected_uuid: Option<&str>,
    actual_uuid: &str,
) -> Result<(), String> {
    let expected_uuid = expected_uuid.ok_or_else(|| {
        format!(
            "cannot safely clean pending node {node_id}; its journal has no recorded machine UUID"
        )
    })?;
    if expected_uuid.eq_ignore_ascii_case(actual_uuid) {
        Ok(())
    } else {
        Err(format!(
            "node {node_id} reports machine UUID {actual_uuid}, different from its recorded identity {expected_uuid}; refusing cleanup"
        ))
    }
}

pub(crate) fn pending_managed_export_cleanup_plan(
    config: &ClusterConfig,
    node_id: &str,
    client_ip: &str,
) -> BTreeMap<String, Vec<(Option<String>, NfsExportRequest)>> {
    let mut groups = BTreeMap::new();
    let storage_id = config.storage_server.as_str();
    if node_id != storage_id {
        groups
            .entry(storage_id.to_owned())
            .or_insert_with(Vec::new)
            .push((
                None,
                NfsExportRequest {
                    root: config.primary_source_root().to_string_lossy().into_owned(),
                    client_ip: client_ip.to_owned(),
                    share_uuid: config.share_uuid.clone(),
                    node_id: node_id.to_owned(),
                },
            ));
    }
    for (share_id, share) in &config.shares {
        let server_id = share.server.as_str();
        if node_id == server_id {
            continue;
        }
        groups
            .entry(server_id.to_owned())
            .or_insert_with(Vec::new)
            .push((
                Some(share_id.clone()),
                NfsExportRequest {
                    root: share.source_root.to_string_lossy().into_owned(),
                    client_ip: client_ip.to_owned(),
                    share_uuid: share.share_uuid.clone(),
                    node_id: node_id.to_owned(),
                },
            ));
    }
    groups
}

fn cleanup_client_nfs_resources(
    config: &ClusterConfig,
    node_id: &str,
    node: &NodeConfig,
) -> AppResult<()> {
    let (requests, aliases) = client_nfs_cleanup_plan(config, node_id);
    if requests.is_empty() && aliases.is_empty() {
        return Ok(());
    }

    let output = ssh_output(node, "/sbin/mount", None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error(&format!("cannot inspect NFS mounts on {node_id}"), &output),
        ));
    }
    let mount_output = String::from_utf8_lossy(&output.stdout);
    for request in &requests {
        match named_share_mount_status(
            &mount_output,
            &request.source,
            &request.mount_root.to_string_lossy(),
        ) {
            NamedShareMountStatus::NotMounted | NamedShareMountStatus::Expected => {}
            NamedShareMountStatus::MountedElsewhere(source) => {
                return Err((
                    1,
                    format!(
                        "cannot remove {node_id}; {} is mounted from unexpected source {source}, refusing to unmount it",
                        request.mount_root.display()
                    ),
                ));
            }
        }
    }

    let script = client_nfs_cleanup_batch_script(&requests, &aliases);
    let output = ssh_output(node, &script, None)?;
    if !output.status.success() {
        let detail = command_error("client NFS cleanup failed", &output);
        if mount_point_permission_error(&detail) {
            run_interactive_admin_with_reason(
                node,
                &format!("unmount managed NFS paths and remove source aliases from {node_id}"),
                &script,
            )
            .map_err(|error| {
                (
                    1,
                    format!("cannot clean client NFS resources on {node_id}: {error}"),
                )
            })?;
        } else {
            return Err((
                1,
                format!("cannot clean client NFS resources on {node_id}: {detail}"),
            ));
        }
    }

    let output = ssh_output(node, "/sbin/mount", None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error(
                &format!("cannot verify client NFS cleanup on {node_id}"),
                &output,
            ),
        ));
    }
    let mount_output = String::from_utf8_lossy(&output.stdout);
    for request in &requests {
        match named_share_mount_status(
            &mount_output,
            &request.source,
            &request.mount_root.to_string_lossy(),
        ) {
            NamedShareMountStatus::NotMounted => {}
            NamedShareMountStatus::Expected => {
                return Err((
                    1,
                    format!(
                        "managed NFS mount {} is still active on {node_id}; retry removal",
                        request.mount_root.display()
                    ),
                ));
            }
            NamedShareMountStatus::MountedElsewhere(source) => {
                return Err((
                    1,
                    format!(
                        "mount {} changed to {source} during cleanup on {node_id}; refusing further changes",
                        request.mount_root.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn append_client_mount_status(script: &mut String, awk: &str, request: &ClientUnmountRequest) {
    script.push_str(&format!(
        "mount_status=$(printf '%s\\n' \"$mounts\" | /usr/bin/awk -v source={} -v mount={} {})\n",
        shell_quote(&request.source),
        shell_quote(&request.mount_root.to_string_lossy()),
        awk
    ));
}

fn append_client_mount_marker_check(script: &mut String, request: &ClientUnmountRequest) {
    let marker = request.mount_root.join(".macluster-share-id");
    script.push_str(&format!(
        "if [ \"$mount_status\" = expected ]; then marker={}; expected_uuid={}; if marker_type=$(/usr/bin/stat -f '%HT' \"$marker\" 2>&1); then if [ \"$marker_type\" != 'Regular File' ]; then echo {} >&2; exit 1; fi; else case \"$marker_type\" in *'Permission denied'*|*'Operation not permitted'*) echo \"$marker_type\" >&2; exit 1 ;; *) echo {} >&2; exit 1 ;; esac; fi; if marker_contents=$(/bin/cat \"$marker\" 2>&1); then if [ \"$marker_contents\" != \"$expected_uuid\" ]; then echo {} >&2; exit 1; fi; else echo \"$marker_contents\" >&2; exit 1; fi; fi\n",
        shell_quote(&marker.to_string_lossy()),
        shell_quote(&request.share_uuid),
        shell_quote(&format!(
            "share marker on {} is not a regular file; refusing to unmount",
            request.mount_root.display()
        )),
        shell_quote(&format!(
            "share marker on {} does not match; refusing to unmount",
            request.mount_root.display()
        )),
        shell_quote(&format!(
            "share marker on {} does not match; refusing to unmount",
            request.mount_root.display()
        ))
    ));
}

fn client_mount_batch_script(requests: &[ClientMountRequest]) -> Option<String> {
    let mut script = String::new();
    for request in requests {
        let mount_root = shell_quote(&request.mount_root.to_string_lossy());
        if request.needs_mount {
            if request.needs_privileged_mkdir {
                script.push_str(&format!("/bin/mkdir -p {mount_root}\n"));
            }
            if request.allow_existing_contents {
                script.push_str(
                    "# Existing local files remain underneath this explicitly configured NFS share.\n",
                );
            } else {
                script.push_str(&format!(
                    "entries=$(/bin/ls -A {mount_root}) || exit 1\n[ -z \"$entries\" ] || {{ echo 'mount point is not empty after preflight' >&2; exit 1; }}\n"
                ));
            }
            script.push_str(&format!(
                "/sbin/mount_nfs -o resvport {} {mount_root}\n",
                shell_quote(&request.source)
            ));
        }
        if let Some(alias) = request
            .source_alias
            .as_deref()
            .filter(|alias| *alias != request.mount_root)
        {
            script.push_str(&client_share_alias_script(alias, &request.mount_root));
        }
    }
    (!script.is_empty()).then_some(script)
}

fn persistent_mount_batch_script(
    node: &NodeConfig,
    requests: &[ClientMountRequest],
) -> Option<String> {
    let mut script = client_mount_batch_script(requests).unwrap_or_default();
    for request in requests {
        script.push_str(&crate::nfs_recovery::install_script(
            &node.remote_binary,
            &request.source,
            &request.mount_root,
            node.execution_uid,
        ));
    }
    (!script.is_empty()).then_some(script)
}

fn client_nfs_recovery_version_probe_script(mounts: &[ClientUnmountRequest]) -> Option<String> {
    if mounts.is_empty() {
        return None;
    }
    let mut script = String::from("set -e\n");
    for (index, mount) in mounts.iter().enumerate() {
        let check = crate::nfs_recovery::installation_probe_script(&mount.mount_root);
        script.push_str(&format!(
            "if ! ( {check} ); then printf '%s\\n' '{index}'; fi\n"
        ));
    }
    Some(script)
}

fn client_nfs_recovery_refresh_script(
    config: &ClusterConfig,
    node_id: &str,
    stale_mounts: &BTreeSet<usize>,
) -> Result<Option<String>, String> {
    let Some(node) = config.nodes.get(node_id) else {
        return Err(format!("unknown node {node_id}"));
    };
    let (mounts, _) = client_nfs_cleanup_plan(config, node_id);
    let digest = if node.transport == Transport::Local {
        local_sha256(Path::new(&node.remote_binary)).map_err(|(_, error)| error)?
    } else {
        managed_binary_digest(&node.remote_binary)
            .ok_or_else(|| format!("Agent path for {node_id} is not managed by digest"))?
    };
    let execution_uid = node.execution_uid;
    let mut script = String::new();
    for (index, mount) in mounts.iter().enumerate() {
        if stale_mounts.contains(&index) {
            script.push_str(&crate::nfs_recovery::refresh_script(
                &node.remote_binary,
                &digest,
                &mount.source,
                &mount.mount_root,
                &mount.share_uuid,
                execution_uid,
            ));
        }
    }
    Ok((!script.is_empty()).then_some(script))
}

fn prepare_nfs_recovery_refresh_for_update(
    config: &ClusterConfig,
    node_id: &str,
) -> Result<Option<String>, String> {
    let Some(node) = config.nodes.get(node_id) else {
        return Err(format!("unknown node {node_id}"));
    };
    let (mounts, _) = client_nfs_cleanup_plan(config, node_id);
    let Some(probe) = client_nfs_recovery_version_probe_script(&mounts) else {
        return Ok(None);
    };
    let output = ssh_output(node, &probe, None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(command_error(
            "cannot inspect NFS recovery helper versions",
            &output,
        ));
    }
    let mut stale_mounts = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let index = line
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("invalid NFS recovery version probe response: {line}"))?;
        if index >= mounts.len() {
            return Err("NFS recovery version probe returned an invalid mount index".into());
        }
        stale_mounts.insert(index);
    }
    client_nfs_recovery_refresh_script(config, node_id, &stale_mounts)
}

fn agent_update_admin_script(
    power_script: Option<&str>,
    nfs_recovery_script: Option<&str>,
) -> Option<String> {
    if power_script.is_none() && nfs_recovery_script.is_none() {
        return None;
    }
    let mut script = String::from("set -e\n");
    for command in [power_script, nfs_recovery_script].into_iter().flatten() {
        script.push_str(command);
        if !command.ends_with('\n') {
            script.push('\n');
        }
    }
    Some(script)
}

fn prepare_node_power_helper_for_update(
    node: &NodeConfig,
    operation_id: &str,
) -> Result<Option<PowerHelperSetup>, String> {
    let (uid, arch) = if node.transport == Transport::Local {
        (
            node.execution_uid
                .unwrap_or_else(|| unsafe { libc::geteuid() }),
            std::env::consts::ARCH.to_owned(),
        )
    } else {
        let facts = read_remote_facts(node).map_err(|(_, error)| error)?;
        (facts.uid, facts.arch)
    };
    prepare_power_helper(node, uid, &arch, operation_id)
}

fn refresh_agent_helpers_for_update(config: &ClusterConfig, operation_id: &str) -> AppResult<bool> {
    refresh_agent_helpers_for_update_with(
        config,
        operation_id,
        prepare_node_power_helper_for_update,
        prepare_nfs_recovery_refresh_for_update,
    )
}

fn refresh_agent_helpers_for_update_with(
    config: &ClusterConfig,
    operation_id: &str,
    prepare_power: impl FnMut(&NodeConfig, &str) -> Result<Option<PowerHelperSetup>, String>,
    prepare_nfs: impl FnMut(&ClusterConfig, &str) -> Result<Option<String>, String>,
) -> AppResult<bool> {
    refresh_agent_helpers_with_admin(
        config,
        operation_id,
        prepare_power,
        prepare_nfs,
        run_interactive_admin_with_reason,
    )
}

fn refresh_agent_helpers_with_admin(
    config: &ClusterConfig,
    operation_id: &str,
    mut prepare_power: impl FnMut(&NodeConfig, &str) -> Result<Option<PowerHelperSetup>, String>,
    mut prepare_nfs: impl FnMut(&ClusterConfig, &str) -> Result<Option<String>, String>,
    mut execute: impl FnMut(&NodeConfig, &str, &str) -> Result<(), String>,
) -> AppResult<bool> {
    let mut deferred = false;
    for (node_id, node) in &config.nodes {
        let power_setup = match prepare_power(node, operation_id) {
            Ok(setup) => setup,
            Err(error) => {
                deferred = true;
                eprintln!("Power sampler refresh on {node_id} is pending: {error}");
                None
            }
        };
        let nfs_recovery_script = match prepare_nfs(config, node_id) {
            Ok(script) => script,
            Err(error) => {
                deferred = true;
                eprintln!("NFS recovery helper refresh on {node_id} is pending: {error}");
                None
            }
        };
        let admin_script = agent_update_admin_script(
            power_setup.as_ref().map(|setup| setup.script.as_str()),
            nfs_recovery_script.as_deref(),
        );
        let Some(admin_script) = admin_script else {
            continue;
        };
        let purpose = match (power_setup.is_some(), nfs_recovery_script.is_some()) {
            (true, true) => "refresh the power sampler and NFS recovery service",
            (true, false) => "refresh the mtop power sampler",
            (false, true) => "refresh the NFS recovery service",
            (false, false) => unreachable!(),
        };
        let result = execute(node, purpose, &admin_script);
        if let Some(setup) = &power_setup {
            cleanup_power_helper_stage(node, setup);
        }
        if !io::stdin().is_terminal()
            && result
                .as_ref()
                .err()
                .is_some_and(|error| admin_authorization_required(error))
        {
            deferred = true;
            eprintln!(
                "Privileged helper refresh on {node_id} awaits administrator authorization; rerun from Terminal."
            );
            continue;
        }
        result.map_err(|error| {
            (
                1,
                format!("could not refresh privileged helpers on {node_id}: {error}"),
            )
        })?;
    }
    Ok(deferred)
}

fn power_launch_daemon_plist(execution_uid: u32) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{label}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{helper}</string>\n    <string>--serve</string>\n    <string>{execution_uid}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n  <key>StandardOutPath</key>\n  <string>/var/log/macluster-power.out.log</string>\n  <key>StandardErrorPath</key>\n  <string>/var/log/macluster-power.err.log</string>\n</dict>\n</plist>\n",
        label = POWER_LAUNCHD_LABEL,
        helper = POWER_HELPER_PATH,
    )
}

fn ensure_remote_binary(
    node: &NodeConfig,
    local_binary: &Path,
    remote_macos_version: &str,
    operation_id: &str,
) -> AppResult<()> {
    let destination = &node.remote_binary;
    let expected_digest = local_sha256(local_binary)?;
    let replaceable_managed_path = is_expected_managed_agent_path(destination, &expected_digest);
    let test = ssh_output(node, &shell_join(&["test", "-x", destination]), None)?;
    if test.status.success() {
        let installed = ssh_output(node, &shell_join(&[destination, "--version"]), None)?;
        let installed_version = String::from_utf8_lossy(&installed.stdout);
        let expected = format!("macluster {}", env!("CARGO_PKG_VERSION"));
        if installed.status.success()
            && !installed_version.trim().starts_with(&expected)
            && !replaceable_managed_path
        {
            return Err((
                1,
                format!(
                    "remote binary {destination} already exists with a different version; refusing to overwrite it"
                ),
            ));
        }
        let remote_digest_output = ssh_output(
            node,
            &shell_join(&["/usr/bin/shasum", "-a", "256", destination]),
            None,
        )?;
        let remote_digest = String::from_utf8_lossy(&remote_digest_output.stdout)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        if installed.status.success()
            && remote_digest_output.status.success()
            && remote_digest == expected_digest
        {
            return Ok(());
        }
        if !replaceable_managed_path {
            return Err((1, "existing remote binary has the same version label but a different digest; refusing to overwrite it".into()));
        }
    }
    let existing = ssh_output(node, &shell_join(&["test", "-e", destination]), None)?;
    if existing.status.success() {
        let regular = ssh_output(node, &shell_join(&["test", "-f", destination]), None)?;
        let not_symlink = ssh_output(node, &shell_join(&["test", "!", "-L", destination]), None)?;
        if !replaceable_managed_path || !regular.status.success() || !not_symlink.status.success() {
            return Err((
                1,
                format!(
                    "remote path {destination} already exists but is not a trusted managed Agent file; refusing to overwrite it"
                ),
            ));
        }
    } else if existing.status.code() != Some(1) {
        return Err((
            1,
            command_error("could not inspect the remote binary destination", &existing),
        ));
    }

    let parent = Path::new(destination)
        .parent()
        .ok_or_else(|| (1, "remote binary path has no parent".into()))?;
    remote_run(
        node,
        &shell_join(&["/bin/mkdir", "-p", &parent.to_string_lossy()]),
        None,
    )?;
    let temp = format!("{destination}.macluster-{operation_id}.tmp");
    scp_to_node(node, local_binary, &temp)?;
    remote_run(node, &shell_join(&["/bin/chmod", "755", &temp]), None)?;
    let temp_digest_output = ssh_output(
        node,
        &shell_join(&["/usr/bin/shasum", "-a", "256", &temp]),
        None,
    )?;
    if !temp_digest_output.status.success()
        || String::from_utf8_lossy(&temp_digest_output.stdout)
            .split_whitespace()
            .next()
            != Some(expected_digest.as_str())
    {
        let _ = ssh_output(node, &shell_join(&["/bin/rm", "-f", &temp]), None);
        return Err((
            1,
            "uploaded temporary binary digest did not match; install was not changed".into(),
        ));
    }
    let temp_version = ssh_output(node, &shell_join(&[&temp, "--version"]), None)?;
    if !temp_version.status.success()
        || !String::from_utf8_lossy(&temp_version.stdout)
            .trim()
            .starts_with(&format!("macluster {}", env!("CARGO_PKG_VERSION")))
    {
        let _ = ssh_output(node, &shell_join(&["/bin/rm", "-f", &temp]), None);
        return Err((
            1,
            "uploaded temporary binary failed its version check; install was not changed".into(),
        ));
    }
    remote_run(
        node,
        &shell_join(&["/bin/mv", "-f", &temp, destination]),
        None,
    )?;
    let installed = ssh_output(node, &shell_join(&[destination, "--version"]), None)?;
    let installed_version = String::from_utf8_lossy(&installed.stdout);
    if !installed.status.success()
        || !installed_version
            .trim()
            .starts_with(&format!("macluster {}", env!("CARGO_PKG_VERSION")))
    {
        return Err((
            1,
            format!(
                "remote binary did not report the expected version (remote macOS {remote_macos_version})"
            ),
        ));
    }
    let remote_digest_output = ssh_output(
        node,
        &shell_join(&["/usr/bin/shasum", "-a", "256", destination]),
        None,
    )?;
    if !remote_digest_output.status.success()
        || String::from_utf8_lossy(&remote_digest_output.stdout)
            .split_whitespace()
            .next()
            != Some(expected_digest.as_str())
    {
        return Err((1, "uploaded remote binary digest did not match".into()));
    }
    Ok(())
}

fn ensure_remote_config(
    node: &NodeConfig,
    path: &str,
    candidate: &str,
    operation_id: &str,
    state_dir: &Path,
) -> AppResult<()> {
    ensure_remote_config_with_idle_check(
        node,
        path,
        candidate,
        operation_id,
        state_dir,
        check_remote_idle,
    )
}

pub(crate) fn remote_agent_config_path(
    home: &str,
    cluster_uuid: &str,
    machine_uuid: &str,
) -> String {
    format!("{home}/.config/macluster/clusters/{cluster_uuid}/agents/{machine_uuid}/config.toml")
}

fn enrollment_config_node_id(config: &ClusterConfig, node: &NodeConfig) -> AppResult<String> {
    let uuid = node
        .machine_uuid
        .as_deref()
        .ok_or_else(|| (1, "enrollment requires a verified machine UUID".into()))?;
    let matches = config
        .nodes
        .iter()
        .filter(|(_, configured)| {
            configured
                .machine_uuid
                .as_deref()
                .is_some_and(|known| known.eq_ignore_ascii_case(uuid))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1
        || node.execution_uid.is_none()
        || matches[0].1.execution_uid != node.execution_uid
    {
        return Err((1, "existing remote cluster config does not unambiguously identify this machine UUID and execution UID; refusing to replace it".into()));
    }
    Ok(matches[0].0.clone())
}

fn ensure_remote_config_with_idle_check(
    node: &NodeConfig,
    path: &str,
    candidate: &str,
    operation_id: &str,
    state_dir: &Path,
    mut check_idle: impl FnMut(&NodeConfig, &str, &Path) -> AppResult<()>,
) -> AppResult<()> {
    let candidate = compatible_agent_config(candidate)?;
    let expected = ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    enrollment_config_node_id(&expected, node)?;
    if !safe_absolute_remote_path(path) {
        return Err((2, "remote config path is not a safe absolute path".into()));
    }
    let quoted = shell_quote(path);
    let current = ssh_output(
        node,
        &format!(
            "if [ -L {quoted} ]; then exit 2; elif [ -f {quoted} ]; then /bin/cat {quoted}; elif [ -e {quoted} ]; then exit 3; else exit 4; fi"
        ),
        None,
    )?;
    let mut sync_operation = operation_id.to_owned();
    let mut enrollment_baseline = "absent".to_owned();
    if current.status.success() {
        let existing =
            ClusterConfig::parse(&String::from_utf8_lossy(&current.stdout)).map_err(|error| {
                (
                    1,
                    format!("remote cluster config {path} is invalid; preserving it: {error}"),
                )
            })?;
        if !remote_config_belongs_to_cluster(&existing, &expected, None) {
            return Err((
                1,
                format!(
                    "remote cluster config {path} belongs to another cluster or storage namespace; preserving it"
                ),
            ));
        }
        let existing_node_id = enrollment_config_node_id(&existing, node)?;
        let compatible = compatible_agent_config(&String::from_utf8_lossy(&current.stdout))?;
        if ClusterConfig::parse(&compatible).map_err(|error| (2, error.to_string()))? == expected {
            return Ok(());
        }
        let mut connection = node.clone();
        connection.remote_config = Some(path.to_owned());
        check_idle(&connection, &existing_node_id, Path::new(path)).map_err(|(_, error)| {
            (1, format!("cannot refresh existing remote config {path} until this node is idle and its output is synchronized: {error}"))
        })?;
        // An interrupted enrollment may be retried after another binary
        // upgrade. Retain each previous config without reusing its backup name.
        let digest = sha256_hex(&current.stdout).map_err(|error| (1, error.to_string()))?;
        sync_operation = format!("{operation_id}-enroll-{}", &digest[..16]);
        enrollment_baseline = digest;
    } else if current.status.code() == Some(4) {
        let parent = Path::new(path)
            .parent()
            .ok_or_else(|| (2, "remote config path has no parent".into()))?;
        remote_run(
            node,
            &format!(
                "{} && {}",
                shell_join(&["/bin/mkdir", "-p", &parent.to_string_lossy()]),
                shell_join(&["/bin/chmod", "700", &parent.to_string_lossy()])
            ),
            None,
        )?;
    } else {
        return Err((
            1,
            command_error(
                "remote cluster config is not a readable regular file; preserving it",
                &current,
            ),
        ));
    }
    sync_one_remote_config(
        node,
        path,
        &candidate,
        &expected,
        &sync_operation,
        state_dir,
        None,
        Some(&enrollment_baseline),
    )
}

fn remote_config_belongs_to_cluster(
    existing: &ClusterConfig,
    expected: &ClusterConfig,
    previous: Option<&ClusterConfig>,
) -> bool {
    let old_host = existing
        .nodes
        .get(existing.storage_server.as_str())
        .map(|node| &node.host);
    let new_host = expected
        .nodes
        .get(expected.storage_server.as_str())
        .map(|node| &node.host);
    let same_storage_machine = existing
        .nodes
        .get(existing.storage_server.as_str())
        .zip(expected.nodes.get(expected.storage_server.as_str()))
        .is_some_and(|(old, new)| {
            old.machine_uuid
                .as_deref()
                .zip(new.machine_uuid.as_deref())
                .is_some_and(|(old, new)| old.eq_ignore_ascii_case(new))
                && old.execution_uid.is_some()
                && old.execution_uid == new.execution_uid
        });
    existing.name == expected.name
        && existing.share_uuid == expected.share_uuid
        && existing.shared_root == expected.shared_root
        && existing.primary_source_root() == expected.primary_source_root()
        && existing.login_node == expected.login_node
        && existing.storage_server == expected.storage_server
        && (old_host == new_host
            || same_storage_machine
            || previous.is_some_and(|config| {
                config
                    .execution_digest()
                    .ok()
                    .zip(existing.execution_digest().ok())
                    .is_some_and(|(wanted, actual)| wanted == actual)
            }))
}

pub(crate) fn sync_remote_configs(
    config: &ClusterConfig,
    source: &str,
    state_dir: &Path,
    operation_id: &str,
    skip_node: Option<&str>,
) -> Result<(), String> {
    let candidate = compatible_agent_config(source).map_err(|(_, error)| error)?;
    let mut failures = Vec::new();
    for (node_id, node) in &config.nodes {
        if skip_node == Some(node_id.as_str()) {
            continue;
        }
        if node.transport == Transport::Local {
            continue;
        }
        let result = (|| -> AppResult<()> {
            let facts = read_remote_facts(node)
                .map_err(|(_, error)| (1, format!("cannot inspect {node_id}: {error}")))?;
            let home = checked_remote_path(&facts.home)?;
            let destination = node
                .remote_config
                .clone()
                .unwrap_or_else(|| format!("{home}/.config/macluster/config.toml"));
            sync_one_remote_config(
                node,
                &destination,
                &candidate,
                config,
                operation_id,
                state_dir,
                None,
                None,
            )
        })();
        if let Err((_, error)) = result {
            failures.push(format!("{node_id}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "remote config sync is pending on {}",
            failures.join("; ")
        ))
    }
}

fn compatible_agent_config(source: &str) -> AppResult<String> {
    let mut in_nodes = false;
    let mut lines = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_nodes = trimmed.starts_with("[nodes.");
        }
        if in_nodes
            && trimmed.split_once('=').is_some_and(|(key, _)| {
                matches!(key.trim(), "ssh_user" | "ssh_port" | "remote_config")
            })
        {
            continue;
        }
        lines.push(line);
    }
    let candidate = lines.join("\n") + if source.ends_with('\n') { "\n" } else { "" };
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

fn sync_one_remote_config(
    node: &NodeConfig,
    destination: &str,
    candidate: &str,
    expected_config: &ClusterConfig,
    operation_id: &str,
    state_dir: &Path,
    previous_config: Option<&ClusterConfig>,
    enrollment_baseline: Option<&str>,
) -> AppResult<()> {
    if !safe_absolute_remote_path(destination) {
        return Err((
            1,
            format!("remote config path '{destination}' is not safe for atomic sync"),
        ));
    }
    let exists = ssh_output(node, &shell_join(&["test", "-f", destination]), None)?;
    if enrollment_baseline.is_some_and(|digest| (digest == "absent") == exists.status.success()) {
        return Err((
            1,
            "remote config changed while checking enrollment; rerun mnode -a".into(),
        ));
    }
    if exists.status.success() {
        let current = ssh_output(node, &shell_join(&["/bin/cat", destination]), None)?;
        if !current.status.success() {
            return Err((
                1,
                command_error("cannot read existing remote config", &current),
            ));
        }
        if let Some(expected) = enrollment_baseline
            && sha256_hex(&current.stdout).map_err(|error| (1, error.to_string()))? != expected
        {
            return Err((
                1,
                "remote config changed while checking enrollment; rerun mnode -a".into(),
            ));
        }
        if current.stdout == candidate.as_bytes() {
            return Ok(());
        }
        let existing =
            ClusterConfig::parse(&String::from_utf8_lossy(&current.stdout)).map_err(|error| {
                (
                    1,
                    format!(
                        "refusing to overwrite unrecognized remote config {destination}: {error}"
                    ),
                )
            })?;
        if !remote_config_belongs_to_cluster(&existing, expected_config, previous_config) {
            return Err((
                1,
                format!(
                    "remote config {destination} does not belong to the same cluster; refusing to replace it"
                ),
            ));
        }
        let backup = format!("{destination}.macluster-{operation_id}.bak");
        let backup_exists = ssh_output(node, &shell_join(&["test", "-f", &backup]), None)?;
        if backup_exists.status.success() {
            let original = ssh_output(node, &shell_join(&["/bin/cat", &backup]), None)?;
            if !original.status.success() {
                return Err((
                    1,
                    command_error("cannot read previous remote config backup", &original),
                ));
            }
            if original.stdout != current.stdout {
                return Err((
                    1,
                    format!(
                        "remote config {destination} changed after this sync began; refusing to overwrite the new contents"
                    ),
                ));
            }
        }
    }
    let parent = Path::new(destination)
        .parent()
        .ok_or_else(|| (1, "remote config path has no parent".into()))?;
    remote_run(
        node,
        &shell_join(&["/bin/mkdir", "-p", &parent.to_string_lossy()]),
        None,
    )?;
    if exists.status.success() {
        let backup = format!("{destination}.macluster-{operation_id}.bak");
        let backup_exists = ssh_output(node, &shell_join(&["test", "-f", &backup]), None)?;
        if !backup_exists.status.success() {
            remote_run(
                node,
                &shell_join(&["/bin/cp", "-p", destination, &backup]),
                None,
            )?;
        }
    }
    let local_temp = state_dir.join(format!(".node-config-{}.toml", Id128::random()));
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&local_temp)?;
        file.write_all(candidate.as_bytes())?;
        file.sync_all()
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&local_temp);
        return Err(io_error(error));
    }
    let remote_temp = format!("{destination}.macluster-{operation_id}.tmp");
    let result = (|| {
        scp_to_node(node, &local_temp, &remote_temp)?;
        if let Some(baseline) = enrollment_baseline {
            if node.transport == Transport::Local {
                commit_enrollment_config(
                    Path::new(destination),
                    Path::new(&remote_temp),
                    baseline,
                )?;
            } else {
                remote_run(
                    node,
                    &shell_join(&[
                        &node.remote_binary,
                        "internal",
                        "commit-enrollment-config",
                        "--destination",
                        destination,
                        "--staged",
                        &remote_temp,
                        "--baseline",
                        baseline,
                    ]),
                    None,
                )?;
            }
        } else {
            remote_run(
                node,
                &format!(
                    "{} && {}",
                    shell_join(&["/bin/chmod", "600", &remote_temp]),
                    shell_join(&["/bin/mv", "-f", &remote_temp, destination])
                ),
                None,
            )?;
        }
        let installed = ssh_output(node, &shell_join(&["/bin/cat", destination]), None)?;
        if !installed.status.success() || installed.stdout != candidate.as_bytes() {
            return Err((
                1,
                format!("remote config verification failed after installing {destination}"),
            ));
        }
        Ok(())
    })();
    let _ = fs::remove_file(local_temp);
    result
}

pub(crate) fn commit_enrollment_config(
    destination: &Path,
    staged: &Path,
    baseline: &str,
) -> AppResult<()> {
    if destination
        .canonicalize()
        .ok()
        .zip(staged.canonicalize().ok())
        .is_some_and(|(destination, staged)| destination == staged)
    {
        return Err((
            2,
            "staged enrollment config must be a different file".into(),
        ));
    }
    let _lock = MaintenanceLock::exclusive_for_creation(destination).map_err(|error| (1,
        format!("remote config is in use by a controller or another command; stop that controller before retrying enrollment: {error}")))?;
    let current = match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            Some(fs::read(destination).map_err(io_error)?)
        }
        Ok(_) => {
            return Err((
                1,
                "remote config is no longer a regular file; preserving it".into(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(io_error(error)),
    };
    let actual = current
        .as_ref()
        .map(|bytes| sha256_hex(bytes))
        .transpose()
        .map_err(|error| (1, error.to_string()))?;
    if actual.as_deref().unwrap_or("absent") != baseline {
        return Err((
            1,
            "remote config changed during enrollment; preserving it; rerun mnode -a".into(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(staged)
        .map_err(io_error)?;
    if !file.metadata().map_err(io_error)?.is_file() {
        return Err((1, "staged enrollment config is not a regular file".into()));
    }
    let mut candidate = String::new();
    file.read_to_string(&mut candidate).map_err(io_error)?;
    ClusterConfig::parse(&candidate).map_err(|error| (1, error.to_string()))?;
    atomic_write(destination, candidate.as_bytes())?;
    fs::remove_file(staged).map_err(io_error)
}

fn local_sha256(path: &Path) -> AppResult<String> {
    hash_file_sha256(path)
}

#[cfg(target_vendor = "apple")]
#[repr(C, align(4))]
struct CommonCryptoSha256Context {
    words: [u32; 26],
}

#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn CC_SHA256_Init(context: *mut CommonCryptoSha256Context) -> i32;
    fn CC_SHA256_Update(
        context: *mut CommonCryptoSha256Context,
        data: *const libc::c_void,
        len: u32,
    ) -> i32;
    fn CC_SHA256_Final(digest: *mut u8, context: *mut CommonCryptoSha256Context) -> *mut u8;
}

#[cfg(target_vendor = "apple")]
fn hash_file_sha256(path: &Path) -> AppResult<String> {
    use std::fmt::Write as _;

    let path = path.canonicalize().map_err(io_error)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(io_error)?;
    let before = file.metadata().map_err(io_error)?;
    if !before.is_file() {
        return Err((1, format!("{} is not a regular file", path.display())));
    }
    let mut context = CommonCryptoSha256Context { words: [0; 26] };
    if unsafe { CC_SHA256_Init(&mut context) } != 1 {
        return Err((1, "CommonCrypto could not initialize SHA-256".into()));
    }
    let mut buffer = [0_u8; 256 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(io_error)?;
        if count == 0 {
            break;
        }
        if unsafe {
            CC_SHA256_Update(
                &mut context,
                buffer.as_ptr().cast(),
                u32::try_from(count).unwrap_or(u32::MAX),
            )
        } != 1
        {
            return Err((1, "CommonCrypto could not update SHA-256".into()));
        }
    }
    let after = file.metadata().map_err(io_error)?;
    if file_metadata_identity(&before) != file_metadata_identity(&after) {
        return Err((
            1,
            format!(
                "{} changed while its SHA-256 was being read",
                path.display()
            ),
        ));
    }
    let mut digest = [0_u8; 32];
    if unsafe { CC_SHA256_Final(digest.as_mut_ptr(), &mut context) }.is_null() {
        return Err((1, "CommonCrypto could not finalize SHA-256".into()));
    }
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

#[cfg(not(target_vendor = "apple"))]
fn hash_file_sha256(path: &Path) -> AppResult<String> {
    let bytes = fs::read(path).map_err(io_error)?;
    sha256_hex(&bytes).map_err(|error| (1, error.to_string()))
}

#[cfg(target_vendor = "apple")]
fn file_metadata_identity(metadata: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn scp_to_node(node: &NodeConfig, local_path: &Path, remote_path: &str) -> AppResult<()> {
    if node.transport == Transport::Local {
        let target = Path::new(remote_path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        fs::copy(local_path, target).map_err(io_error)?;
        return Ok(());
    }
    let mut command = Command::new("/usr/bin/scp");
    node.add_pinned_host_key_args(&mut command);
    add_node_admin_ssh_pool_args(node, &mut command);
    command.args(["-q", "-P"]);
    command.arg(node.ssh_port.unwrap_or(22).to_string());
    for option in [
        "LogLevel=ERROR",
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "ConnectTimeout=5",
    ] {
        command.arg("-o").arg(option);
    }
    if let Some(identity_file) = &node.ssh_identity_file {
        command
            .arg("-i")
            .arg(identity_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes");
    }
    command.arg(local_path);
    let user = node.ssh_user.as_deref().unwrap_or("");
    let host = if user.is_empty() {
        node.host.clone()
    } else {
        format!("{user}@{}", node.host)
    };
    command.arg(format!("{host}:{remote_path}"));
    let output = run_child(command, None, CONNECT_TIMEOUT)?;
    if output.status.success() {
        Ok(())
    } else {
        Err((
            1,
            command_error(
                "scp failed (verify host key and SSH key authentication)",
                &output,
            ),
        ))
    }
}

fn remote_run(node: &NodeConfig, script: &str, input: Option<&[u8]>) -> AppResult<Output> {
    let output = ssh_output(node, script, input)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err((1, command_error("remote command failed", &output)))
    }
}

pub(crate) fn ssh_output(
    node: &NodeConfig,
    script: &str,
    input: Option<&[u8]>,
) -> AppResult<Output> {
    if node.transport == Transport::Local {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        return run_child(command, input, CONNECT_TIMEOUT);
    }
    let mut command = Command::new("/usr/bin/ssh");
    command.args(SSH_OPTIONS);
    node.add_ssh_identity_args(&mut command);
    add_node_admin_ssh_pool_args(node, &mut command);
    command.arg(&node.host).arg(script);
    run_child(command, input, CONNECT_TIMEOUT)
}

fn add_node_admin_ssh_pool_args(node: &NodeConfig, command: &mut Command) {
    let namespace = node
        .remote_config
        .as_deref()
        .map(|path| format!("node-admin:{path}"))
        .unwrap_or_else(|| "node-admin:unscoped".into());
    let pool = SshPool::new(namespace);
    let node_id = node
        .machine_uuid
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(&node.host);
    if let Ok(key) = ConnectionKey::for_node(pool.namespace(), node_id, node) {
        // SSH pooling only saves repeat handshakes. If its private socket path
        // cannot be established, preserve the original one-shot SSH behavior.
        let _ = pool.append_args(&key, command);
    }
}

pub(crate) fn run_interactive(node: &NodeConfig, script: &str) -> Result<(), String> {
    if unsafe { libc::isatty(0) } != 1 {
        return Err("interactive sudo requires a terminal; rerun mnode from Terminal".into());
    }
    let mut command = if node.transport == Transport::Local {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        command
    } else {
        let mut command = Command::new("/usr/bin/ssh");
        command.args(INTERACTIVE_SSH_OPTIONS);
        node.add_ssh_identity_args(&mut command);
        add_node_admin_ssh_pool_args(node, &mut command);
        command.arg(&node.host).arg(script);
        command
    };
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = wait_admin_child(command, ADMIN_COMMAND_LIMIT)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "interactive admin command exited with {status}; see terminal output above"
        ))
    }
}

// Keep the caller's foreground process group so sudo can read the terminal.
fn wait_admin_child(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start administrator command: {error}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
            result => {
                // SIGTERM lets sudo forward termination to its command before escalation.
                unsafe {
                    libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
                }
                let grace = Instant::now() + Duration::from_millis(500);
                while Instant::now() < grace {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                let _ = child.kill();
                thread::spawn(move || {
                    let _ = child.wait();
                });
                return Err(match result {
                    Err(error) => format!("could not observe administrator command: {error}"),
                    _ => format!(
                        "{ADMIN_TIMEOUT} after {} seconds; remote changes may be incomplete. Maintenance recovery is preserved; inspect the node and rerun the original command.",
                        timeout.as_secs()
                    ),
                });
            }
        }
    }
}

fn admin_authorization_required(error: &str) -> bool {
    [
        "sudo: a password is required",
        "sudo: a terminal is required",
        "not allowed to execute",
    ]
    .iter()
    .any(|message| error.contains(message))
}

fn noninteractive_admin_script(sudo_path: &str, script: &str) -> String {
    format!(
        "exec /usr/bin/env LC_ALL=C {} -n /bin/sh -c {}",
        shell_quote(sudo_path),
        shell_quote(script)
    )
}

fn run_noninteractive_admin(node: &NodeConfig, script: &str) -> Result<(), String> {
    let script = noninteractive_admin_script("/usr/bin/sudo", script);
    let mut command = if node.transport == Transport::Local {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        command
    } else {
        let mut command = Command::new("/usr/bin/ssh");
        command.args(SSH_OPTIONS);
        node.add_ssh_identity_args(&mut command);
        add_node_admin_ssh_pool_args(node, &mut command);
        command.arg(&node.host).arg(script);
        command
    };
    command.stdin(Stdio::null());
    let output = run_child(command, None, ADMIN_COMMAND_LIMIT).map_err(|(_, error)| {
        if error.to_lowercase().contains("timed out") || error.to_lowercase().contains("timeout") {
            format!("{ADMIN_TIMEOUT}; inspect the node and rerun the original operation: {error}")
        } else {
            error
        }
    })?;
    if output.status.success() {
        return Ok(());
    }
    let reason = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "non-interactive administrator command failed ({}): {}; if authorization is required, rerun from Terminal for this node's administrator approval",
        output.status,
        reason.trim()
    ))
}

fn run_child(command: Command, input: Option<&[u8]>, timeout: Duration) -> AppResult<Output> {
    macluster_controller::transport::run_child_bounded(
        command,
        input.map(|value| value.to_vec()),
        timeout,
    )
    .map_err(|error| (1, error.to_string()))
}

fn shell_join(args: &[&str]) -> String {
    args.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn nfs_exports_read_command(path: &str) -> String {
    let path = shell_quote(path);
    format!("if [ -e {path} ]; then /bin/cat {path}; else :; fi")
}

pub(crate) fn read_nfs_exports(node: &NodeConfig) -> AppResult<String> {
    let command = nfs_exports_read_command(NFS_EXPORTS_PATH);
    let output = ssh_output(node, &command, None)?;
    if !output.status.success() {
        return Err((1, command_error("could not read /etc/exports", &output)));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn nfs_exports_update_baseline_read_command(exports_path: &str, backup_path: &str) -> String {
    let exports_path_raw = exports_path.to_owned();
    let exports_path = shell_quote(exports_path);
    let backup_path_raw = backup_path.to_owned();
    let backup_path = shell_quote(backup_path);
    let state_path = shell_quote(&format!("{backup_path_raw}.txn"));
    let legacy_prefix = shell_quote(&format!("{exports_path_raw}.macluster-"));
    let legacy_backups = format!("{legacy_prefix}*.bak");
    let legacy_temporaries = format!("{legacy_prefix}*.tmp");
    let empty_hash =
        shell_quote("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let script = format!(
        "if [ -L {state_path} ]; then echo 'NFS transaction state is a symlink' >&2; exit 1; fi\nif [ -f {state_path} ]; then\n  IFS='|' read -r version had_original had_enabled had_running baseline_hash accepted_before accepted_candidate < {state_path} || exit 1\n  if [ \"$version\" != MACLUSTER_NFS_TXN_V1 ]; then echo 'NFS transaction state has an unsupported format' >&2; exit 1; fi\n  printf 'MACLUSTER_PENDING_V1\\n'\n  case \"$had_original\" in\n    yes) [ -f {backup_path} ] || {{ echo 'NFS transaction backup is missing' >&2; exit 1; }}; /bin/cat {backup_path} ;;\n    no) : ;;\n    *) echo 'NFS transaction state is malformed' >&2; exit 1 ;;\n  esac\nelse\n  legacy_count=0; legacy_backup=\n  for possible_backup in {legacy_backups}; do [ -e \"$possible_backup\" ] || continue; legacy_count=$((legacy_count + 1)); legacy_backup=$possible_backup; done\n  if [ \"$legacy_count\" -gt 1 ]; then echo 'multiple legacy NFS transactions need manual recovery; no exports were changed' >&2; exit 1; fi\n  if [ \"$legacy_count\" -eq 1 ]; then\n    legacy_temp=${{legacy_backup%.bak}}.tmp\n    if [ -e {exports_path} ]; then actual=$(/usr/bin/shasum -a 256 {exports_path}); actual=${{actual%% *}}; else actual={empty_hash}; fi\n    saved=$(/usr/bin/shasum -a 256 \"$legacy_backup\"); saved=${{saved%% *}}\n    if [ \"$actual\" != \"$saved\" ]; then\n      if [ ! -f \"$legacy_temp\" ]; then echo 'legacy NFS transaction backup does not match exports; manual recovery is required' >&2; exit 1; fi\n      candidate=$(/usr/bin/shasum -a 256 \"$legacy_temp\"); candidate=${{candidate%% *}}\n      if [ \"$actual\" != \"$candidate\" ]; then echo 'legacy NFS transaction exports do not match its backup or candidate; manual recovery is required' >&2; exit 1; fi\n    fi\n    printf 'MACLUSTER_PENDING_V1\\n'; /bin/cat \"$legacy_backup\"\n  else\n    if [ -e {exports_path} ]; then actual=$(/usr/bin/shasum -a 256 {exports_path}); actual=${{actual%% *}}; else actual={empty_hash}; fi\n    for possible_temp in {legacy_temporaries}; do\n      [ -e \"$possible_temp\" ] || continue\n      candidate=$(/usr/bin/shasum -a 256 \"$possible_temp\"); candidate=${{candidate%% *}}\n      if [ \"$actual\" = \"$candidate\" ]; then echo 'legacy NFS candidate has no original backup; manual recovery is required' >&2; exit 1; fi\n    done\n    printf 'MACLUSTER_CLEAN_V1\\n'; if [ -e {exports_path} ]; then /bin/cat {exports_path}; fi\n  fi\nfi"
    );
    format!("/bin/sh -c {}", shell_quote(&script))
}

pub(crate) fn read_nfs_exports_update_baseline(node: &NodeConfig) -> AppResult<(String, bool)> {
    let command =
        nfs_exports_update_baseline_read_command(NFS_EXPORTS_PATH, NFS_EXPORTS_BACKUP_PATH);
    let output = ssh_output(node, &command, None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("could not inspect NFS exports transaction", &output),
        ));
    }
    let output = String::from_utf8_lossy(&output.stdout);
    parse_nfs_exports_update_baseline(&output).map_err(|error| (1, error))
}

fn parse_nfs_exports_update_baseline(output: &str) -> Result<(String, bool), String> {
    let Some((marker, contents)) = output.split_once('\n') else {
        return Err("NFS exports transaction response was malformed".into());
    };
    match marker {
        "MACLUSTER_PENDING_V1" => Ok((contents.to_owned(), true)),
        "MACLUSTER_CLEAN_V1" => Ok((contents.to_owned(), false)),
        _ => Err("NFS exports transaction response was malformed".into()),
    }
}

pub(crate) fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
        })
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn command_error(context: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if stderr.is_empty() {
        format!("{context}: process exited with {}", output.status)
    } else {
        format!("{context}: {stderr}")
    }
}

fn io_error(error: io::Error) -> (i32, String) {
    (1, error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NfsExportRequest {
    pub(crate) root: String,
    pub(crate) client_ip: String,
    pub(crate) share_uuid: String,
    pub(crate) node_id: String,
}

fn group_nfs_export_requests(
    requests: impl IntoIterator<Item = (String, NfsExportRequest)>,
) -> BTreeMap<String, Vec<NfsExportRequest>> {
    let mut grouped = BTreeMap::new();
    for (server_id, request) in requests {
        grouped
            .entry(server_id)
            .or_insert_with(Vec::new)
            .push(request);
    }
    grouped
}

pub(crate) fn ensure_nfs_exports(
    storage_node: &NodeConfig,
    requests: &[NfsExportRequest],
    operation_id: &str,
) -> (Vec<bool>, Result<(), String>) {
    ensure_nfs_exports_with_setup(storage_node, requests, operation_id, None)
}

pub(crate) fn ensure_nfs_exports_with_setup(
    storage_node: &NodeConfig,
    requests: &[NfsExportRequest],
    operation_id: &str,
    setup_script: Option<&str>,
) -> (Vec<bool>, Result<(), String>) {
    let (original, transaction_pending) = match read_nfs_exports_update_baseline(storage_node) {
        Ok(state) => state,
        Err((_, error)) => {
            return (
                vec![false; requests.len()],
                Err(format!(
                    "cannot inspect NFS exports on {}: {error}\n{}",
                    storage_node.host,
                    nfs_admin_steps_for_requests(requests)
                )),
            );
        }
    };
    let (candidate, managed, changed) = match plan_ensure_nfs_exports(&original, requests) {
        Ok(plan) => plan,
        Err(error) => {
            return (
                vec![false; requests.len()],
                Err(format!(
                    "{error}\n{}",
                    nfs_admin_steps_for_requests(requests)
                )),
            );
        }
    };
    if !changed && !transaction_pending && setup_script.is_none() {
        return (managed, Ok(()));
    }
    let purpose = requests
        .iter()
        .map(|request| format!("{} for {}", request.root, request.client_ip))
        .collect::<Vec<_>>()
        .join(", ");
    let export_update = if changed || transaction_pending {
        match nfs_exports_update_commands(&candidate, &original, operation_id) {
            Ok(script) => Some(script),
            Err(error) => return (managed, Err(error)),
        }
    } else {
        None
    };
    let Some(script) = candidate_admin_script(setup_script, export_update.as_deref()) else {
        return (managed, Ok(()));
    };
    let admin_purpose = match (setup_script.is_some(), changed || transaction_pending) {
        (true, true) => format!(
            "install or refresh the mtop power sampler and authorize NFS clients/reload exports: {purpose}"
        ),
        (true, false) => "install or refresh the mtop power sampler".to_owned(),
        (false, true) => format!("authorize NFS clients and reload exports: {purpose}"),
        (false, false) => unreachable!("empty administrative batch was filtered above"),
    };
    match run_interactive_admin_with_reason(storage_node, &admin_purpose, &script) {
        Ok(()) => (managed, Ok(())),
        Err(error) => (
            managed,
            Err(format!(
                "could not configure NFS exports on {}: {error}\nResolve the server error shown above, then rerun the same mnode --add command to resume",
                storage_node.host
            )),
        ),
    }
}

fn nfs_admin_steps_for_requests(requests: &[NfsExportRequest]) -> String {
    requests
        .iter()
        .map(|request| nfs_admin_steps(&request.root, &request.client_ip))
        .collect::<Vec<_>>()
        .join("\n")
}

fn plan_ensure_nfs_exports(
    original: &str,
    requests: &[NfsExportRequest],
) -> Result<(String, Vec<bool>, bool), String> {
    let mut candidate = original.to_owned();
    let mut managed = Vec::with_capacity(requests.len());
    let mut changed = false;
    for request in requests {
        if !nfs_token_safe(&request.root) {
            return Err(format!(
                "NFS export path {} contains characters unsupported by the automatic /etc/exports editor",
                request.root
            ));
        }
        request.client_ip.parse::<Ipv4Addr>().map_err(|_| {
            format!(
                "NFS export client {} is not an IPv4 address",
                request.client_ip
            )
        })?;
        let marker = format!(
            "# macluster-managed {} {}",
            request.share_uuid, request.node_id
        );
        match exports_authorize(&candidate, &request.root, &request.client_ip, Some(&marker)) {
            ExportAccess::Authorized => managed.push(false),
            ExportAccess::Managed => managed.push(true),
            ExportAccess::Conflicting => {
                return Err(format!(
                    "NFS has an export for {} with custom host/options rules; refusing to rewrite it automatically",
                    request.root
                ));
            }
            ExportAccess::Absent | ExportAccess::OtherClientsOnly => {
                if !candidate.is_empty() && !candidate.ends_with('\n') {
                    candidate.push('\n');
                }
                candidate.push_str(&format!(
                    "{marker}\n{} {}\n",
                    request.root, request.client_ip
                ));
                managed.push(true);
                changed = true;
            }
        }
    }
    Ok((candidate, managed, changed))
}

enum ExportAccess {
    Authorized,
    Managed,
    OtherClientsOnly,
    Conflicting,
    Absent,
}

fn exports_authorize(
    exports: &str,
    root: &str,
    client_ip: &str,
    expected_marker: Option<&str>,
) -> ExportAccess {
    let marker_suffix = format!(" {client_ip}");
    let mut lines = exports.lines().peekable();
    let mut found_path = false;
    let mut found_restricted_path = false;
    let mut found_conflicting_path = false;
    while let Some(line) = lines.next() {
        if line.starts_with("# macluster-managed ") {
            if let Some(next) = lines.peek() {
                if expected_marker == Some(line) && next.trim() == format!("{root}{marker_suffix}")
                {
                    return ExportAccess::Managed;
                }
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let tokens: Vec<_> = trimmed.split_whitespace().collect();
        if !tokens
            .iter()
            .take_while(|token| !token.starts_with('-'))
            .any(|token| *token == root)
        {
            continue;
        }
        found_path = true;
        let mut network_address: Option<Ipv4Addr> = None;
        let mut network_mask: Option<Ipv4Addr> = None;
        let mut hosts = Vec::new();
        let options_index = tokens
            .iter()
            .position(|token| token.starts_with('-'))
            .unwrap_or(tokens.len());
        // macOS accepts the common per-host form `path client` without an
        // options field. In that syntax, hosts are the non-path tokens before
        // any option. Previously this parser started at the first option and
        // mistook the empty suffix for an unrestricted export.
        hosts.extend(
            tokens[..options_index]
                .iter()
                .copied()
                .filter(|token| *token != root && !token.starts_with('/')),
        );
        let mut index = options_index;
        while index < tokens.len() {
            let token = tokens[index];
            if let Some(value) = token.strip_prefix("-network=") {
                let Ok(value) = value.parse::<Ipv4Addr>() else {
                    return ExportAccess::Conflicting;
                };
                if network_address.replace(value).is_some() {
                    return ExportAccess::Conflicting;
                }
                index += 1;
                continue;
            }
            if token == "-network" {
                if let Some(value) = tokens
                    .get(index + 1)
                    .and_then(|value| value.parse::<Ipv4Addr>().ok())
                {
                    if network_address.replace(value).is_some() {
                        return ExportAccess::Conflicting;
                    }
                    index += 2;
                    continue;
                }
                return ExportAccess::Conflicting;
            }
            if let Some(value) = token.strip_prefix("-mask=") {
                let Ok(value) = value.parse::<Ipv4Addr>() else {
                    return ExportAccess::Conflicting;
                };
                if network_mask.replace(value).is_some() {
                    return ExportAccess::Conflicting;
                }
                index += 1;
                continue;
            }
            if token == "-mask" {
                let Some(value) = tokens
                    .get(index + 1)
                    .and_then(|value| value.parse::<Ipv4Addr>().ok())
                else {
                    return ExportAccess::Conflicting;
                };
                if network_mask.replace(value).is_some() {
                    return ExportAccess::Conflicting;
                }
                index += 2;
                continue;
            }
            if matches!(
                token,
                "-maproot" | "-mapall" | "-sec" | "-anon" | "-uid" | "-gid" | "-index"
            ) {
                if tokens.get(index + 1).is_none() {
                    return ExportAccess::Conflicting;
                }
                index += 2;
                continue;
            }
            if token.starts_with('-') {
                index += 1;
                continue;
            }
            hosts.push(token);
            index += 1;
        }
        if hosts.iter().any(|host| *host == client_ip) {
            return ExportAccess::Authorized;
        }
        if network_address.is_some() || network_mask.is_some() {
            let network = if let Some(network) = network_address {
                network
            } else if hosts.len() == 1 {
                let Ok(network) = hosts[0].parse::<Ipv4Addr>() else {
                    return ExportAccess::Conflicting;
                };
                hosts.clear();
                network
            } else {
                return ExportAccess::Conflicting;
            };
            let mask = network_mask.unwrap_or_else(|| classful_mask(network));
            let client = client_ip
                .parse::<Ipv4Addr>()
                .expect("caller passes parsed IPv4");
            if u32::from(client) & u32::from(mask) == u32::from(network) & u32::from(mask) {
                return ExportAccess::Authorized;
            }
            found_restricted_path = true;
        } else if !hosts.is_empty() {
            if hosts.iter().all(|host| host.parse::<Ipv4Addr>().is_ok()) {
                found_restricted_path = true;
            } else {
                found_conflicting_path = true;
            }
        } else {
            // No host restriction is an export for all clients.
            return ExportAccess::Authorized;
        }
    }
    if found_conflicting_path {
        ExportAccess::Conflicting
    } else if found_restricted_path {
        ExportAccess::OtherClientsOnly
    } else if found_path {
        ExportAccess::Conflicting
    } else {
        ExportAccess::Absent
    }
}

fn classful_mask(address: Ipv4Addr) -> Ipv4Addr {
    match address.octets()[0] {
        0..=127 => Ipv4Addr::new(255, 0, 0, 0),
        128..=191 => Ipv4Addr::new(255, 255, 0, 0),
        _ => Ipv4Addr::new(255, 255, 255, 0),
    }
}

fn nfs_token_safe(value: &str) -> bool {
    value.starts_with('/')
        && value != "/"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && !Path::new(value).components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

pub(crate) fn verify_storage_root(
    node: &NodeConfig,
    source_root: &Path,
    share_uuid: &str,
    expected_uid: u32,
    expected_gid: u32,
) -> AppResult<()> {
    let root = source_root.to_string_lossy();
    if !nfs_token_safe(&root) {
        return Err((
            1,
            "shared_root cannot be safely used as an NFS export path".into(),
        ));
    }
    let stat = ssh_output(
        node,
        &format!("/usr/bin/stat -f '%T %u %g' {}", shell_quote(&root)),
        None,
    )?;
    if !stat.status.success() {
        return Err((
            1,
            command_error("cannot inspect storage export path", &stat),
        ));
    }
    let fields: Vec<_> = String::from_utf8_lossy(&stat.stdout)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if fields.len() != 3 {
        return Err((1, "storage export path metadata was malformed".into()));
    }
    if fields[0].eq_ignore_ascii_case("nfs") {
        return Err((
            1,
            "configured storage path on the storage server is itself an NFS mount".into(),
        ));
    }
    let owner_uid = fields[1]
        .parse::<u32>()
        .map_err(|_| (1, "storage path owner UID was invalid".into()))?;
    let owner_gid = fields[2]
        .parse::<u32>()
        .map_err(|_| (1, "storage path owner GID was invalid".into()))?;
    // A different directory group is safe when the storage account itself has
    // effective read/write/traverse access; the primary group need not own it.
    let account_access = ssh_output(
        node,
        &format!(
            "test -r {} && test -w {} && test -x {}",
            shell_quote(&root),
            shell_quote(&root),
            shell_quote(&root)
        ),
        None,
    )?;
    validate_storage_root_access(
        owner_uid,
        owner_gid,
        expected_uid,
        expected_gid,
        account_access.status.success(),
    )
    .map_err(|error| (1, error))?;
    let physical = ssh_output(
        node,
        &format!("cd {} && /bin/pwd -P", shell_quote(&root)),
        None,
    )?;
    if !physical.status.success() || String::from_utf8_lossy(&physical.stdout).trim() != root {
        return Err((
            1,
            "primary storage source resolves through a symlink or is not available on the storage server"
                .into(),
        ));
    }
    let marker = format!("{root}/.macluster-share-id");
    let marker_output = ssh_output(node, &shell_join(&["/bin/cat", &marker]), None)?;
    if !marker_output.status.success()
        || String::from_utf8_lossy(&marker_output.stdout).trim() != share_uuid
    {
        return Err((
            1,
            "storage server share marker does not match the configured UUID".into(),
        ));
    }
    Ok(())
}

fn validate_storage_root_access(
    owner_uid: u32,
    owner_gid: u32,
    expected_uid: u32,
    expected_gid: u32,
    account_can_access: bool,
) -> Result<(), String> {
    if owner_uid != expected_uid {
        return Err(format!(
            "storage export path owner is {owner_uid}:{owner_gid}, storage SSH account is {expected_uid}:{expected_gid}; the owner UID must match, and macluster will not change ownership automatically"
        ));
    }
    if !account_can_access {
        return Err(format!(
            "storage SSH account {expected_uid}:{expected_gid} cannot read, write, and traverse the export directory owned by {owner_uid}:{owner_gid}; grant that account access manually; macluster will not change permissions automatically"
        ));
    }
    Ok(())
}

fn nfs_admin_steps(root: &str, client_ip: &str) -> String {
    format!(
        "On the NFS server, preserve existing export options and authorize this client IP (create /etc/exports if this is the first export):\n  export: {root}\n  client: {client_ip}\nThen run `sudo {NFS_DAEMON_PATH} enable`, `sudo {NFS_DAEMON_PATH} start`, `sudo {NFS_DAEMON_PATH} checkexports`, and `sudo {NFS_DAEMON_PATH} update`. Rerun the same mnode --add command afterward."
    )
}

#[cfg(test)]
fn nfs_exports_update_script(
    candidate: &str,
    exports_path: &str,
    temporary_path: &str,
    backup_path: &str,
    sudo_path: &str,
    nfsd_path: &str,
) -> String {
    let expected_original = fs::read_to_string(exports_path).unwrap_or_default();
    let body = nfs_exports_update_body(
        candidate,
        &expected_original,
        exports_path,
        temporary_path,
        backup_path,
        nfsd_path,
    )
    .expect("hash expected NFS exports");
    format!(
        "{} /bin/sh -c {}",
        shell_quote(sudo_path),
        shell_quote(&body)
    )
}

#[cfg(test)]
fn nfs_exports_update_script_for_expected(
    candidate: &str,
    expected_original: &str,
    exports_path: &str,
    temporary_path: &str,
    backup_path: &str,
    sudo_path: &str,
    nfsd_path: &str,
) -> String {
    let body = nfs_exports_update_body(
        candidate,
        expected_original,
        exports_path,
        temporary_path,
        backup_path,
        nfsd_path,
    )
    .expect("hash expected NFS exports");
    format!(
        "{} /bin/sh -c {}",
        shell_quote(sudo_path),
        shell_quote(&body)
    )
}

fn nfs_exports_update_body(
    candidate: &str,
    expected_original: &str,
    exports_path: &str,
    temporary_path: &str,
    backup_path: &str,
    nfsd_path: &str,
) -> Result<String, String> {
    let exports_path_raw = exports_path.to_owned();
    let state_path_raw = format!("{backup_path}.txn");
    let state_new_path_raw = format!("{state_path_raw}.new");
    let exports_path = shell_quote(exports_path);
    let temporary_path = shell_quote(temporary_path);
    let backup_path = shell_quote(backup_path);
    let state_path = shell_quote(&state_path_raw);
    let state_new_path = shell_quote(&state_new_path_raw);
    let nfsd_path = shell_quote(nfsd_path);
    let legacy_prefix = shell_quote(&format!("{exports_path_raw}.macluster-"));
    let legacy_backups = format!("{legacy_prefix}*.bak");
    let legacy_temporaries = format!("{legacy_prefix}*.tmp");
    let lock_path = shell_quote(&format!("{exports_path_raw}.macluster.lock"));
    let expected_hash =
        shell_quote(&sha256_hex(expected_original.as_bytes()).map_err(|error| error.to_string())?);
    let empty_hash = shell_quote(&sha256_hex(b"").map_err(|error| error.to_string())?);
    let candidate_hash =
        shell_quote(&sha256_hex(candidate.as_bytes()).map_err(|error| error.to_string())?);

    let mut script = String::from("set -eu\n");
    script.push_str(&format!(
        r#"had_original=no
had_enabled=no
had_running=no
transaction_active=no
legacy_backup=
legacy_temp=
legacy_recovered=no
check_nfs_exports() {{
  if nfs_check_output=$({nfsd_path} "$@" checkexports 2>&1); then
    if [ -n "$nfs_check_output" ]; then printf '%s\n' "$nfs_check_output" >&2; fi
  else
    nfs_check_status=$?
    printf '%s\n' "$nfs_check_output" >&2
    case "$nfs_check_output" in
      *"sandbox_check failed"*"nfsd has no read access"*)
        echo 'macOS privacy protection blocks nfsd on this NFS server. In System Settings > Privacy & Security > Full Disk Access, add /sbin/nfsd and enable it. sudo cannot grant this permission.' >&2
        echo 'After authorizing nfsd, run sudo /sbin/nfsd restart on this server, then rerun the same mnode --add command. A full Mac restart is not the first step.' >&2
        ;;
      *"NFS exporting not supported by fstype"*)
        echo 'This volume cannot be exported by macOS NFS. Choose a directory on an NFS-capable volume, such as APFS; sudo and export options cannot add filesystem support.' >&2
        ;;
    esac
    return "$nfs_check_status"
  fi
}}
rollback_nfs_transaction() {{
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$transaction_active" = yes ]; then
    rollback_ok=yes
    if [ "$had_original" = yes ]; then
      if ! /bin/cat {backup_path} > {exports_path}; then rollback_ok=no; fi
    else
      if ! /bin/rm -f {exports_path}; then rollback_ok=no; fi
    fi
    if [ "$rollback_ok" = yes ] && ! {nfsd_path} update; then rollback_ok=no; fi
    if [ "$had_running" = no ] && ! {nfsd_path} stop; then rollback_ok=no; fi
    if [ "$had_enabled" = no ] && ! {nfsd_path} disable; then rollback_ok=no; fi
    if [ "$rollback_ok" = yes ]; then
      /bin/rm -f {state_path} {state_new_path} {backup_path} {temporary_path} {legacy_backups} {legacy_temporaries} || true
    else
      echo 'NFS rollback is incomplete; transaction files were preserved for retry' >&2
    fi
  fi
  exit "$result"
}}
trap rollback_nfs_transaction EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -L {exports_path} ] || [ -L {temporary_path} ] || [ -L {backup_path} ] || [ -L {state_path} ] || [ -L {state_new_path} ]; then
  echo 'NFS exports transaction path became a symlink' >&2
  exit 1
fi
if [ -e {exports_path} ]; then actual=$(/usr/bin/shasum -a 256 {exports_path}); actual=${{actual%% *}}; else actual={empty_hash}; fi
if [ -f {state_path} ]; then
  IFS='|' read -r version had_original had_enabled had_running baseline_hash accepted_before accepted_candidate < {state_path} || {{ echo 'NFS transaction state is unreadable' >&2; exit 1; }}
  if [ "$version" != MACLUSTER_NFS_TXN_V1 ]; then echo 'NFS transaction state has an unsupported format' >&2; exit 1; fi
  case "$had_original:$had_enabled:$had_running" in yes:yes:yes|yes:yes:no|yes:no:yes|yes:no:no|no:yes:yes|no:yes:no|no:no:yes|no:no:no) ;; *) echo 'NFS transaction state is malformed' >&2; exit 1 ;; esac
  if [ "$had_original" = yes ]; then
    if [ ! -f {backup_path} ]; then echo 'NFS transaction backup is missing' >&2; exit 1; fi
    stored_baseline=$(/usr/bin/shasum -a 256 {backup_path}); stored_baseline=${{stored_baseline%% *}}
    if [ "$stored_baseline" != "$baseline_hash" ] || [ "$baseline_hash" != {expected_hash} ]; then echo 'NFS transaction backup changed; refusing to overwrite exports' >&2; exit 1; fi
  elif [ "$baseline_hash" != {empty_hash} ] || [ "$expected_hash" != {empty_hash} ] || [ -e {backup_path} ]; then
    echo 'NFS transaction baseline is inconsistent; refusing to overwrite exports' >&2
    exit 1
  fi
  if [ "$actual" != "$baseline_hash" ] && [ "$actual" != "$accepted_before" ] && [ "$actual" != "$accepted_candidate" ]; then
    if [ -f {temporary_path} ] && [ -e {exports_path} ]; then
      stored_candidate=$(/usr/bin/shasum -a 256 {temporary_path}); stored_candidate=${{stored_candidate%% *}}
      actual_length=$(/usr/bin/wc -c < {exports_path} | /usr/bin/tr -d '[:space:]')
      candidate_length=$(/usr/bin/wc -c < {temporary_path} | /usr/bin/tr -d '[:space:]')
      partial_match=no
      if [ "$stored_candidate" = "$accepted_candidate" ] && [ "$actual_length" -le "$candidate_length" ] && /usr/bin/head -c "$actual_length" {temporary_path} | /usr/bin/cmp - {exports_path} >/dev/null 2>&1; then partial_match=yes; fi
      if [ "$partial_match" = no ] && [ "$had_original" = yes ]; then
        baseline_length=$(/usr/bin/wc -c < {backup_path} | /usr/bin/tr -d '[:space:]')
        if [ "$actual_length" -le "$baseline_length" ] && /usr/bin/head -c "$actual_length" {backup_path} | /usr/bin/cmp - {exports_path} >/dev/null 2>&1; then partial_match=yes; fi
      fi
      if [ "$partial_match" = yes ]; then
        echo 'recovering a partial /etc/exports write from the saved original' >&2
        transaction_active=yes
        if [ "$had_original" = yes ]; then /bin/cat {backup_path} > {exports_path}; else /bin/rm -f {exports_path}; fi
        actual=$baseline_hash
      else
        echo 'NFS exports changed during a pending transaction; transaction files were preserved' >&2
        exit 1
      fi
    else
      echo 'NFS exports changed during a pending transaction; transaction files were preserved' >&2
      exit 1
    fi
  fi
  transaction_active=yes
else
  legacy_count=0
  for possible_backup in {legacy_backups}; do [ -e "$possible_backup" ] || continue; legacy_count=$((legacy_count + 1)); legacy_backup=$possible_backup; done
  if [ "$legacy_count" -gt 1 ]; then echo 'multiple legacy NFS transactions need manual recovery; no exports were changed' >&2; exit 1; fi
  if [ "$legacy_count" -eq 1 ]; then
    legacy_temp=${{legacy_backup%.bak}}.tmp
    stored_baseline=$(/usr/bin/shasum -a 256 "$legacy_backup"); stored_baseline=${{stored_baseline%% *}}
    if [ "$stored_baseline" != {expected_hash} ]; then echo 'legacy NFS backup does not match the planning baseline' >&2; exit 1; fi
    if [ "$actual" != "$stored_baseline" ]; then
      if [ ! -f "$legacy_temp" ]; then echo 'legacy NFS transaction backup does not match exports; manual recovery is required' >&2; exit 1; fi
      candidate_actual=$(/usr/bin/shasum -a 256 "$legacy_temp"); candidate_actual=${{candidate_actual%% *}}
      if [ "$actual" != "$candidate_actual" ]; then echo 'legacy NFS exports do not match its backup or candidate; manual recovery is required' >&2; exit 1; fi
    fi
    had_original=yes
    /bin/cp -p "$legacy_backup" {backup_path}
    legacy_recovered=yes
  else
    if [ "$actual" != {expected_hash} ]; then echo 'NFS exports changed after preflight; refusing to overwrite them' >&2; exit 1; fi
    for possible_temp in {legacy_temporaries}; do
      [ -e "$possible_temp" ] || continue
      candidate_actual=$(/usr/bin/shasum -a 256 "$possible_temp"); candidate_actual=${{candidate_actual%% *}}
      if [ "$actual" = "$candidate_actual" ]; then echo 'legacy NFS candidate has no original backup; manual recovery is required' >&2; exit 1; fi
    done
    if [ -e {exports_path} ]; then had_original=yes; fi
  fi
  nfsd_status=$({nfsd_path} status 2>&1 || true)
  case "$nfsd_status" in *"service is enabled"*) had_enabled=yes ;; *) had_enabled=no ;; esac
  case "$nfsd_status" in *"nfsd is running"*) had_running=yes ;; *) had_running=no ;; esac
fi
printf '%s' {candidate} > {temporary_path}
check_nfs_exports -F {temporary_path}
"#,
        candidate = shell_quote(candidate),
    ));
    script.push_str(&format!(
        r#"if [ "$transaction_active" = no ]; then
  if [ "$legacy_recovered" = no ]; then
    /bin/rm -f {backup_path}
    if [ "$had_original" = yes ]; then /bin/cp -p {exports_path} {backup_path}; fi
  fi
  baseline_hash={expected_hash}
  accepted_before=$actual
else
  accepted_before=$actual
fi
printf 'MACLUSTER_NFS_TXN_V1|%s|%s|%s|%s|%s|%s\n' "$had_original" "$had_enabled" "$had_running" "$baseline_hash" "$accepted_before" {candidate_hash} > {state_new_path}
/bin/mv -f {state_new_path} {state_path}
transaction_active=yes
"#
    ));
    // Write through the existing inode: atomically renaming over macOS's
    // /etc/exports can block in the kernel while leaving NFS setup hung.
    script.push_str(&format!(
        r#"/bin/cat {temporary_path} > {exports_path}
if [ "$had_enabled" = no ]; then {nfsd_path} enable; fi
if [ "$had_running" = no ]; then {nfsd_path} start; fi
check_nfs_exports
{nfsd_path} update
transaction_active=no
/bin/rm -f {state_path}
/bin/rm -f {state_new_path} {backup_path} {temporary_path} {legacy_backups} {legacy_temporaries} || true
"#
    ));
    Ok(format!(
        "/usr/bin/lockf -t 0 -k -w {} /bin/sh -c {}\n",
        lock_path,
        shell_quote(&script)
    ))
}

pub(crate) fn nfs_exports_update_commands(
    candidate: &str,
    expected_original: &str,
    _operation_id: &str,
) -> Result<String, String> {
    nfs_exports_update_body(
        candidate,
        expected_original,
        NFS_EXPORTS_PATH,
        NFS_EXPORTS_TEMP_PATH,
        NFS_EXPORTS_BACKUP_PATH,
        NFS_DAEMON_PATH,
    )
}

pub(crate) fn run_interactive_admin(node: &NodeConfig, script: &str) -> Result<(), String> {
    if io::stdin().is_terminal() {
        run_interactive(
            node,
            &format!("exec {}", admin_shell_command("/usr/bin/sudo", script)),
        )
    } else {
        run_noninteractive_admin(node, script)
    }
}

fn run_interactive_admin_with_reason(
    node: &NodeConfig,
    purpose: &str,
    script: &str,
) -> Result<(), String> {
    announce_admin_authorization(node, purpose);
    run_interactive_admin(node, script)
}

fn announce_admin_authorization(node: &NodeConfig, purpose: &str) {
    static ANNOUNCER: OnceLock<Mutex<AdminAuthorizationAnnouncer>> = OnceLock::new();
    let mut announcer = ANNOUNCER
        .get_or_init(|| Mutex::new(AdminAuthorizationAnnouncer::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for message in announcer.messages_for(node, purpose) {
        eprintln!("{message}");
    }
}

#[derive(Default)]
struct AdminAuthorizationAnnouncer {
    guidance_printed: bool,
}

impl AdminAuthorizationAnnouncer {
    fn messages_for(&mut self, node: &NodeConfig, purpose: &str) -> Vec<String> {
        let account = match node.transport {
            Transport::Local => std::env::var("USER").unwrap_or_else(|_| "current account".into()),
            Transport::Ssh => node
                .ssh_user
                .clone()
                .unwrap_or_else(|| "default SSH account".into()),
        };
        let mut messages = Vec::new();
        if !self.guidance_printed {
            messages.push(
                "Administrator authorization may be requested. If sudo prompts, use the administrator password for the listed account on that Mac; it is separate from the SSH login password.".into(),
            );
            self.guidance_printed = true;
        }
        messages.push(format!("  {} ({account}): {purpose}", node.host));
        messages
    }
}

pub(crate) fn update_nfs_exports(
    node: &NodeConfig,
    candidate: &str,
    expected_original: &str,
    operation_id: &str,
    purpose: &str,
) -> Result<(), String> {
    let script = nfs_exports_update_commands(candidate, expected_original, operation_id)?;
    run_interactive_admin_with_reason(node, purpose, &script)
}

pub(crate) fn remove_managed_nfs_exports(
    node: &NodeConfig,
    requests: &[NfsExportRequest],
    operation_id: &str,
) -> Result<Vec<(bool, bool)>, String> {
    let (contents, transaction_pending) = read_nfs_exports_update_baseline(node)
        .map_err(|(_, error)| format!("cannot inspect NFS exports before removal: {error}"))?;
    let (candidate, statuses, changed) = plan_remove_nfs_exports(&contents, requests)?;
    if changed || transaction_pending {
        let purpose = requests
            .iter()
            .map(|request| format!("{} for {}", request.root, request.client_ip))
            .collect::<Vec<_>>()
            .join(", ");
        update_nfs_exports(
            node,
            &candidate,
            &contents,
            operation_id,
            &format!("remove managed NFS authorizations and reload exports: {purpose}"),
        )?;
    }
    Ok(statuses)
}

fn plan_remove_nfs_exports(
    original: &str,
    requests: &[NfsExportRequest],
) -> Result<(String, Vec<(bool, bool)>, bool), String> {
    let mut candidate = original.to_owned();
    let mut statuses = Vec::with_capacity(requests.len());
    let mut changed_any = false;
    for request in requests {
        request.client_ip.parse::<Ipv4Addr>().map_err(|_| {
            format!(
                "NFS export client {} is not an IPv4 address",
                request.client_ip
            )
        })?;
        let marker = format!(
            "# macluster-managed {} {}",
            request.share_uuid, request.node_id
        );
        let lines: Vec<&str> = candidate.lines().collect();
        let mut retained = Vec::with_capacity(lines.len());
        let mut removed = false;
        let mut index = 0;
        while index < lines.len() {
            if lines[index] == marker {
                let entry = lines.get(index + 1).copied().unwrap_or_default();
                if entry.trim() != format!("{} {}", request.root, request.client_ip) {
                    return Err(format!(
                        "managed NFS marker for {} was present but its export line did not match; refusing to edit /etc/exports",
                        request.node_id
                    ));
                }
                removed = true;
                index += 2;
                continue;
            }
            retained.push(lines[index]);
            index += 1;
        }
        if removed {
            candidate = if retained.is_empty() {
                String::new()
            } else {
                retained.join("\n") + "\n"
            };
            changed_any = true;
        }
        let still_authorized = matches!(
            exports_authorize(&candidate, &request.root, &request.client_ip, None),
            ExportAccess::Authorized
        );
        statuses.push((removed, still_authorized));
    }
    Ok((candidate, statuses, changed_any))
}

pub(crate) fn mount_candidate_with_power(
    node: &NodeConfig,
    storage_node: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
    power_setup: Option<PowerHelperSetup>,
) -> Result<(), String> {
    let mount_request = match candidate_mount_command(node, storage_node, source_root, mount_root) {
        Ok(command) => command,
        Err(error) => {
            if let Some(setup) = &power_setup {
                cleanup_power_helper_stage(node, setup);
            }
            return Err(error);
        }
    };
    let mount_requests = mount_request.into_iter().collect::<Vec<_>>();
    let mount_script = persistent_mount_batch_script(node, &mount_requests);
    let script = candidate_admin_script(
        power_setup.as_ref().map(|setup| setup.script.as_str()),
        mount_script.as_deref(),
    );
    if let Some(script) = script {
        let installing_power = power_setup.is_some();
        let mounting_share = !mount_requests.is_empty();
        let purpose = match (installing_power, mounting_share) {
            (true, true) => "install the mtop power sampler and mount the primary NFS share",
            (true, false) => "install or refresh the mtop power sampler",
            (false, true) => "mount the primary NFS share",
            (false, false) => unreachable!("an empty admin batch is not generated"),
        };
        let result = run_interactive_admin_with_reason(node, purpose, &script);
        if let Some(setup) = &power_setup {
            cleanup_power_helper_stage(node, setup);
        }
        if let Err(error) = result {
            if mounting_share {
                return Err(format!(
                    "could not mount shared storage on {}: {error}",
                    node.host,
                ));
            }
            eprintln!("Power sampler setup for {} was skipped: {error}", node.host);
            return Ok(());
        }
    }
    if !mount_requests.is_empty() {
        verify_candidate_mount(node, storage_node, source_root, mount_root)?;
    }
    Ok(())
}

pub(crate) fn preflight_primary_mount(
    node: &NodeConfig,
    storage_node: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
) -> Result<(), String> {
    candidate_mount_command(node, storage_node, source_root, mount_root).map(|_| ())
}

fn candidate_mount_command(
    node: &NodeConfig,
    storage_node: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
) -> Result<Option<ClientMountRequest>, String> {
    let root = mount_root.to_string_lossy();
    let source = nfs_mount_source(storage_node, source_root);
    let output = ssh_output(node, "/sbin/mount", None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(command_error("cannot inspect candidate mounts", &output));
    }
    let mount_output = String::from_utf8_lossy(&output.stdout).into_owned();
    let path_check = format!(
        "root={}; current=''; old_ifs=$IFS; IFS='/'; set -- ${{root#/}}; IFS=$old_ifs; for part do current=\"$current/$part\"; if [ -L \"$current\" ]; then echo \"symlink mount path component: $current\" >&2; exit 1; fi; if [ -e \"$current\" ] && [ ! -d \"$current\" ]; then echo \"mount path component is not a directory: $current\" >&2; exit 1; fi; done",
        shell_quote(&root)
    );
    let output = ssh_output(node, &path_check, None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(command_error("unsafe primary mount path", &output));
    }
    match named_share_mount_status(&mount_output, &source, &root) {
        NamedShareMountStatus::Expected => {
            return Ok(Some(ClientMountRequest {
                source,
                mount_root: mount_root.to_path_buf(),
                source_alias: None,
                needs_privileged_mkdir: false,
                needs_mount: false,
                allow_existing_contents: false,
            }));
        }
        NamedShareMountStatus::MountedElsewhere(other) => {
            return Err(format!(
                "mount point {root} is already mounted from {other}; refusing to mount {source}"
            ));
        }
        NamedShareMountStatus::NotMounted => {}
    }
    let path_check = format!(
        "root={}; current=''; old_ifs=$IFS; IFS='/'; set -- ${{root#/}}; IFS=$old_ifs; for part do current=\"$current/$part\"; if [ -L \"$current\" ]; then echo \"symlink mount path component: $current\" >&2; exit 1; fi; if [ -e \"$current\" ] && [ ! -d \"$current\" ]; then echo \"mount path component is not a directory: $current\" >&2; exit 1; fi; done",
        shell_quote(&root)
    );
    let output = ssh_output(node, &path_check, None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(command_error("unsafe primary mount path", &output));
    }
    let mkdir = shell_join(&["/bin/mkdir", "-p", &root]);
    let output = ssh_output(node, &mkdir, None).map_err(|(_, error)| error)?;
    let needs_privileged_mkdir = if output.status.success() {
        false
    } else if mount_point_permission_error(&String::from_utf8_lossy(&output.stderr)) {
        true
    } else {
        return Err(format!(
            "cannot prepare mount point {root}: {}",
            command_error("mkdir failed", &output)
        ));
    };
    if !needs_privileged_mkdir {
        let list = format!("/bin/ls -A {}", shell_quote(&root));
        let output = ssh_output(node, &list, None).map_err(|(_, error)| error)?;
        if !output.status.success()
            && !mount_point_permission_error(&String::from_utf8_lossy(&output.stderr))
        {
            return Err(command_error("cannot inspect NFS mount point", &output));
        }
        if output.status.success() && !output.stdout.is_empty() {
            return Err(format!(
                "mount point {root} is not empty and is not mounted from {}",
                storage_node.host
            ));
        }
    }
    Ok(Some(ClientMountRequest {
        source,
        mount_root: mount_root.to_path_buf(),
        source_alias: None,
        needs_privileged_mkdir,
        needs_mount: true,
        allow_existing_contents: false,
    }))
}

fn verify_candidate_mount(
    node: &NodeConfig,
    storage_node: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
) -> Result<(), String> {
    let root = mount_root.to_string_lossy();
    let source = nfs_mount_source(storage_node, source_root);
    let expected = format!("{source} on {root} (nfs");
    let output = ssh_output(node, "/sbin/mount", None).map_err(|(_, error)| error)?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.starts_with(&expected))
    {
        return Err(format!(
            "mount command returned, but {root} is not mounted from {source}"
        ));
    }
    Ok(())
}

fn nfs_mount_source(storage_node: &NodeConfig, source_root: &Path) -> String {
    format!("{}:{}", storage_node.host, source_root.display())
}

fn verify_cross_node_write(
    shared_root: &Path,
    node: &NodeConfig,
    operation_id: &str,
) -> AppResult<()> {
    let probe_name = format!(".macluster-write-check-{operation_id}");
    let probe_path = shared_root.join(&probe_name);
    let payload = format!("macluster:{operation_id}\n");
    let digest = sha256_hex(payload.as_bytes()).map_err(|error| (1, error.to_string()))?;
    let remote_probe = format!(
        "/usr/bin/tee {} >/dev/null",
        shell_quote(&probe_path.to_string_lossy())
    );
    let result = (|| -> AppResult<()> {
        let output = ssh_output(node, &remote_probe, Some(payload.as_bytes()))?;
        if !output.status.success() {
            return Err((
                1,
                command_error("remote shared-storage write failed", &output),
            ));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match verify_local_file_child(&probe_path, &digest) {
                Ok(true) => return Ok(()),
                Ok(false) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(100));
                }
                Ok(false) => {
                    return Err((1, "login node did not observe the remote NFS write".into()));
                }
                Err((_, error)) => {
                    return Err((1, format!("login node NFS probe failed: {error}")));
                }
            }
        }
    })();
    let cleanup = shell_join(&["/bin/rm", "-f", &probe_path.to_string_lossy()]);
    let _ = ssh_output(node, &cleanup, None);
    result
}

fn verify_login_share(config_path: &Path) -> AppResult<()> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut command = Command::new(executable);
    command.arg0("macluster").args([
        "--config",
        config_path.to_string_lossy().as_ref(),
        "internal",
        "local-share-check",
    ]);
    let output = run_child(command, None, Duration::from_secs(10))?;
    if output.status.success() {
        Ok(())
    } else {
        Err((
            1,
            command_error("login node NFS verification failed", &output),
        ))
    }
}

fn verify_local_file_child(path: &Path, digest: &str) -> AppResult<bool> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut command = Command::new(executable);
    command.arg0("macluster").args([
        "internal",
        "verify-file",
        "--path",
        path.to_string_lossy().as_ref(),
        "--sha256",
        digest,
    ]);
    let output = run_child(command, None, Duration::from_secs(5))?;
    Ok(output.status.success())
}

fn abort_pending_enrollment(
    state: &mut AdminState,
    journal_path: &Path,
    config: &ClusterConfig,
    node_id: &str,
) -> AppResult<bool> {
    let Some((key, mut operation)) = state
        .operations
        .iter()
        .find(|(_, operation)| {
            operation.action == "add"
                && operation.node_id == node_id
                && !matches!(operation.phase.as_str(), "READY" | "ABORTED")
        })
        .map(|(key, operation)| (key.clone(), operation.clone()))
    else {
        return Ok(false);
    };
    let client_cleanup_needed = pending_add_may_have_client_state(&operation);
    let endpoint = if operation.managed_export
        || !operation.managed_shares.is_empty()
        || client_cleanup_needed
    {
        Some(NodeEndpoint::parse(&operation.endpoint).map_err(|error| {
            (
                1,
                format!("cannot resume NFS cleanup for {node_id}: {error}"),
            )
        })?)
    } else {
        None
    };
    if client_cleanup_needed {
        let node = cleanup_node_from_endpoint(&operation.endpoint, operation.machine_uuid.clone())?;
        operation.detail = Some("verifying pending node identity before NFS cleanup".into());
        state.operations.insert(key.clone(), operation.clone());
        save_admin_state(journal_path, state)?;
        let identity_result = (|| -> Result<String, String> {
            let actual_uuid = remote_machine_uuid(&node).map_err(|(_, error)| error)?;
            let recorded_uuid = operation
                .machine_uuid
                .as_deref()
                .or_else(|| state.machine_uuids.get(node_id).map(String::as_str));
            validate_pending_node_identity(node_id, recorded_uuid, &actual_uuid)?;
            if let Some(state_uuid) = state.machine_uuids.get(node_id) {
                validate_pending_node_identity(node_id, Some(state_uuid), &actual_uuid)?;
            }
            Ok(actual_uuid)
        })();
        let actual_uuid = match identity_result {
            Ok(actual_uuid) => actual_uuid,
            Err(error) => {
                operation.detail = Some(error.clone());
                state.operations.insert(key.clone(), operation.clone());
                save_admin_state(journal_path, state)?;
                return Err((
                    1,
                    format!(
                        "cannot abort {node_id} while its recorded machine identity is unresolved: {error}"
                    ),
                ));
            }
        };
        operation.machine_uuid = Some(actual_uuid.clone());
        state.machine_uuids.insert(node_id.to_owned(), actual_uuid);
        operation.detail = Some("cleaning exact client NFS mounts and aliases before abort".into());
        state.operations.insert(key.clone(), operation.clone());
        save_admin_state(journal_path, state)?;
        if let Err((_, error)) = cleanup_client_nfs_resources(config, node_id, &node) {
            operation.detail = Some(error.clone());
            state.operations.insert(key.clone(), operation.clone());
            save_admin_state(journal_path, state)?;
            return Err((
                1,
                format!(
                    "cannot abort {node_id} while client NFS cleanup is unresolved: {error}. Rerun `mnode -rm {node_id}` after resolving it."
                ),
            ));
        }
    }
    let export_requests_by_server = endpoint.as_ref().map_or_else(BTreeMap::new, |endpoint| {
        pending_managed_export_cleanup_plan(config, node_id, &endpoint.host.to_string())
    });
    for (server_id, labelled_requests) in export_requests_by_server {
        let server = &config.nodes[&server_id];
        let requests = labelled_requests
            .iter()
            .map(|(_, request)| request.clone())
            .collect::<Vec<_>>();
        let statuses = remove_managed_nfs_exports(server, &requests, &operation.id).map_err(
            |error| {
                let subject = labelled_requests
                    .iter()
                    .find_map(|(share_id, _)| share_id.as_deref())
                    .map_or_else(|| "primary NFS export".to_owned(), |id| format!("NFS share {id}"));
                (
                    1,
                    format!("cannot abort {node_id} while {subject} cleanup on {} is unresolved: {error}", server.host),
                )
            },
        )?;
        for ((share_id, request), (removed, still_authorized)) in
            labelled_requests.iter().zip(statuses)
        {
            if share_id.is_none() {
                if removed {
                    println!("Removed the pending enrollment's managed NFS export entry.");
                } else if still_authorized {
                    println!(
                        "An operator-managed NFS export still authorizes {}; it was left unchanged.",
                        request.client_ip
                    );
                }
            }
        }
    }
    operation.phase = "ABORTED".into();
    operation.detail =
        Some("pending enrollment was explicitly cancelled with mnode --remove".into());
    state.operations.insert(key, operation);
    save_admin_state(journal_path, state)?;
    println!("Cancelled pending enrollment {node_id}; its ID remains permanently reserved.");
    Ok(true)
}

fn remove_pending_share(config_path: &Path, state_dir: &Path, share_id: &str) -> AppResult<()> {
    let maintenance = acquire_node_maintenance_scoped(
        config_path,
        state_dir,
        "mnode --remove share",
        MaintenanceScope::Cluster,
    )?;
    if maintenance.recovered {
        return Ok(());
    }
    let result = (|| -> AppResult<()> {
        MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(|error| {
            (
                1,
                format!("cluster config/state directory binding failed: {error}"),
            )
        })?;
        let config_path = config_path.canonicalize().map_err(io_error)?;
        let config_source = fs::read_to_string(&config_path).map_err(io_error)?;
        let config =
            ClusterConfig::parse(&config_source).map_err(|error| (2, error.to_string()))?;
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, state_dir)?;
        let key = format!("share:{share_id}");
        let Some(mut operation) = state.operations.get(&key).cloned() else {
            return Err((
                2,
                format!("no pending named-share operation exists for '{share_id}'"),
            ));
        };
        if config.shares.contains_key(share_id) || operation.phase == "READY" {
            return Err((
                1,
                format!(
                    "share {share_id} is already configured; `mnode -rm share:{share_id}` only cancels an incomplete setup"
                ),
            ));
        }
        if operation.phase == "ABORTED" {
            println!("Pending named share {share_id} was already cancelled.");
            return Ok(());
        }
        if operation.action != "share" || operation.phase != "SETUP_PENDING" {
            return Err((
                1,
                format!(
                    "share operation {} is in phase {}; rerun its original mnode add command or use `macluster init` to reset the cluster",
                    operation.id, operation.phase
                ),
            ));
        }
        let digest =
            sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
        if operation.old_config_sha256.as_deref() != Some(digest.as_str()) {
            return Err((
                1,
                format!(
                    "cluster config changed during setup of share {share_id}; inspect node-admin.json before cancelling"
                ),
            ));
        }
        let (endpoint_share_id, server_id, source_root, mount_root) =
            parse_pending_named_share_endpoint(&operation.endpoint)?;
        if endpoint_share_id != share_id || operation.node_id != server_id {
            return Err((
                1,
                format!(
                    "share operation {} does not match the requested share or configured NFS server",
                    operation.id
                ),
            ));
        }
        let share_uuid = operation.machine_uuid.as_deref().ok_or_else(|| {
            (
                1,
                format!("pending share {share_id} has no recorded share UUID"),
            )
        })?;
        Id128::parse(share_uuid).map_err(|error| {
            (
                1,
                format!("pending share {share_id} has an invalid share UUID: {error}"),
            )
        })?;
        let pending_share = ShareConfig {
            server: NodeId::new(server_id.clone()).map_err(|error| (1, error.to_string()))?,
            source_root: source_root.clone(),
            mount_root: mount_root.clone(),
            share_uuid: share_uuid.to_owned(),
        };
        let replaced = replaced_child_shares(&config, &pending_share);
        if !replaced.is_empty() {
            return Err((
                1,
                format!(
                    "pending share {share_id} is migrating nested share(s) {}; rerun its original mnode add command to finish or use `macluster init` to reset safely",
                    replaced.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ));
        }
        let server = config.nodes.get(&server_id).ok_or_else(|| {
            (
                1,
                format!("NFS server {server_id} for pending share {share_id} is missing"),
            )
        })?;

        // Validate every endpoint before removing any share resource. A pending
        // share is cluster-wide, so its clients must still be the registered Macs.
        for (node_id, node) in &config.nodes {
            verify_registered_node_identity(node_id, node, &state)?;
            check_remote_idle(node, node_id, &config_path)?;
        }

        let source = format!("{}:{}", server.host, source_root.display());
        let mut clients = Vec::new();
        for (node_id, node) in &config.nodes {
            if node_id == &server_id {
                continue;
            }
            let mounts = ssh_output(node, "/sbin/mount", None).map_err(|(_, error)| {
            (
                1,
                format!(
                    "cannot inspect NFS mounts on {node_id} before cancelling {share_id}: {error}"
                ),
            )
        })?;
            if !mounts.status.success() {
                return Err((
                    1,
                    format!(
                        "cannot inspect NFS mounts on {node_id} before cancelling {share_id}: {}",
                        command_error("mount inspection failed", &mounts)
                    ),
                ));
            }
            let mount_text = String::from_utf8_lossy(&mounts.stdout);
            let _mounted =
                pending_share_mount_present(&mount_text, &source, &mount_root.to_string_lossy())
                    .map_err(|error| {
                        (
                            1,
                            format!("cannot safely cancel share {share_id} on {node_id}: {error}"),
                        )
                    })?;
            let request = Some(ClientUnmountRequest {
                source: source.clone(),
                mount_root: mount_root.clone(),
                share_uuid: share_uuid.to_owned(),
                label: format!("pending NFS share {share_id}"),
            });
            clients.push((node_id.clone(), node.clone(), request));
        }

        operation.detail = Some(
            "cancelling pending named-share setup and removing exact managed resources".into(),
        );
        state.operations.insert(key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;

        for (node_id, node, request) in &clients {
            let requests = request.iter().cloned().collect::<Vec<_>>();
            let aliases = if source_root != mount_root {
                vec![(source_root.clone(), mount_root.clone())]
            } else {
                Vec::new()
            };
            let script = client_nfs_cleanup_batch_script(&requests, &aliases);
            if requests.is_empty() && aliases.is_empty() {
                continue;
            }
            run_pending_share_cleanup(
                node,
                &script,
                &format!("remove exact pending NFS share {share_id} mount and alias on {node_id}"),
            )
            .map_err(|error| {
                (
                    1,
                    format!("cannot cancel pending share {share_id} on {node_id}: {error}"),
                )
            })?;
        }

        let export_requests = config
            .nodes
            .iter()
            .filter(|(node_id, _)| node_id.as_str() != server_id)
            .map(|(node_id, node)| NfsExportRequest {
                root: source_root.to_string_lossy().into_owned(),
                client_ip: node.host.to_string(),
                share_uuid: share_uuid.to_owned(),
                node_id: node_id.clone(),
            })
            .collect::<Vec<_>>();
        if !export_requests.is_empty() {
            remove_managed_nfs_exports(server, &export_requests, &operation.id).map_err(
                |error| {
                    (
                        1,
                        format!("cannot remove pending NFS exports for share {share_id}: {error}"),
                    )
                },
            )?;
        }

        if source_root != mount_root {
            remove_pending_share_alias(server, &mount_root, &source_root, share_id)?;
            for (node_id, node, _) in &clients {
                remove_pending_share_alias(node, &source_root, &mount_root, share_id).map_err(
                    |(_, error)| {
                        (
                            1,
                            format!("cannot remove pending share alias on {node_id}: {error}"),
                        )
                    },
                )?;
            }
        }
        remove_pending_share_marker(server, &source_root, share_uuid, share_id)?;

        operation.phase = "ABORTED".into();
        operation.detail = Some("pending named-share setup was explicitly cancelled".into());
        state.operations.insert(key, operation);
        save_admin_state(&journal_path, &state)?;
        println!(
            "Cancelled pending named share {share_id}; exact managed NFS resources were removed."
        );
        Ok(())
    })();
    finish_node_maintenance(maintenance, result)
}

fn parse_pending_named_share_endpoint(
    endpoint: &str,
) -> AppResult<(String, String, PathBuf, PathBuf)> {
    let fields = endpoint
        .strip_prefix("share:")
        .map(|endpoint| endpoint.splitn(4, ':').collect::<Vec<_>>())
        .unwrap_or_default();
    let [share_id, server_id, source, mount_root] = fields.as_slice() else {
        return Err((
            1,
            format!("pending named-share endpoint '{endpoint}' has an invalid format"),
        ));
    };
    NodeId::new((*share_id).to_owned()).map_err(|error| (1, error.to_string()))?;
    NodeId::new((*server_id).to_owned()).map_err(|error| (1, error.to_string()))?;
    for (path, label) in [(*source, "source"), (*mount_root, "mount root")] {
        if !safe_absolute_remote_path(path) || path == "/" {
            return Err((
                1,
                format!("pending named-share {label} path is invalid: {path}"),
            ));
        }
    }
    let source_root = PathBuf::from(source);
    let mount_root = PathBuf::from(mount_root);
    validate_share_alias_paths(&source_root, &mount_root)?;
    Ok((
        (*share_id).to_owned(),
        (*server_id).to_owned(),
        source_root,
        mount_root,
    ))
}

fn pending_share_mount_present(
    output: &str,
    source: &str,
    mount_root: &str,
) -> Result<bool, String> {
    let mut mounts_at_path = 0;
    let mut expected_mounts = 0;
    for line in output.lines() {
        let Some((actual_source, destination)) = line.split_once(" on ") else {
            continue;
        };
        let Some((actual_mount, filesystem)) = destination.split_once(" (") else {
            continue;
        };
        if actual_mount != mount_root {
            continue;
        }
        mounts_at_path += 1;
        let filesystem = filesystem.split(',').next().unwrap_or_default();
        if actual_source == source && filesystem == "nfs" {
            expected_mounts += 1;
        }
    }
    match (expected_mounts, mounts_at_path) {
        (0, _) => Ok(false),
        (1, 1) => Ok(true),
        _ => Err(format!(
            "the expected share mount is stacked with another filesystem at {mount_root}"
        )),
    }
}

fn verify_registered_node_identity(
    node_id: &str,
    node: &NodeConfig,
    state: &AdminState,
) -> AppResult<()> {
    let actual = if node.transport == Transport::Local {
        local_platform_uuid()?
    } else {
        remote_machine_uuid(node).map_err(|(_, error)| {
            (
                1,
                format!("cannot verify registered node {node_id} identity: {error}"),
            )
        })?
    };
    let configured = node.machine_uuid.as_deref();
    let journal = state.machine_uuids.get(node_id).map(String::as_str);
    let expected = configured.or(journal).ok_or_else(|| {
        (
            1,
            format!(
                "cannot cancel pending share: no recorded machine UUID is available for node {node_id}; restore its recorded identity or run `macluster init` to reset safely"
            ),
        )
    })?;
    if !expected.eq_ignore_ascii_case(&actual)
        || configured
            .zip(journal)
            .is_some_and(|(configured, journal)| !configured.eq_ignore_ascii_case(journal))
    {
        return Err((
            1,
            format!(
                "cannot cancel pending share: registered identity for {node_id} does not match the recorded Mac"
            ),
        ));
    }
    Ok(())
}

fn run_pending_share_cleanup(node: &NodeConfig, script: &str, purpose: &str) -> Result<(), String> {
    let output = ssh_output(node, script, None).map_err(|(_, error)| error)?;
    if output.status.success() {
        return Ok(());
    }
    let detail = command_error(purpose, &output);
    if mount_point_permission_error(&detail) {
        run_interactive_admin_with_reason(node, purpose, script)
    } else {
        Err(detail)
    }
}

fn remove_pending_share_alias(
    node: &NodeConfig,
    alias: &Path,
    target: &Path,
    share_id: &str,
) -> AppResult<()> {
    let alias_text = shell_quote(&alias.to_string_lossy());
    let target_text = shell_quote(&target.to_string_lossy());
    let script = format!(
        "set -eu\nalias_path={alias_text}\ntarget_path={target_text}\nif alias_type=$(/usr/bin/stat -f '%HT' \"$alias_path\" 2>&1); then if [ \"$alias_type\" = 'Symbolic Link' ]; then actual=$(/usr/bin/readlink \"$alias_path\"); if [ \"$actual\" = \"$target_path\" ]; then /bin/rm \"$alias_path\"; fi; fi; else case \"$alias_type\" in *'No such file or directory'*) : ;; *) echo \"$alias_type\" >&2; exit 1 ;; esac; fi\n"
    );
    run_pending_share_cleanup(
        node,
        &script,
        &format!("remove exact alias for pending NFS share {share_id}"),
    )
    .map_err(|error| (1, error))
}

fn remove_pending_share_marker(
    node: &NodeConfig,
    source_root: &Path,
    share_uuid: &str,
    share_id: &str,
) -> AppResult<()> {
    let marker = shell_quote(&source_root.join(".macluster-share-id").to_string_lossy());
    let uuid = shell_quote(share_uuid);
    let script = format!(
        "set -eu\nmarker={marker}\nexpected={uuid}\nif marker_type=$(/usr/bin/stat -f '%HT' \"$marker\" 2>&1); then [ \"$marker_type\" = 'Regular File' ] || {{ echo 'share marker is not a regular file' >&2; exit 1; }}; actual=$(/bin/cat \"$marker\"); [ \"$actual\" = \"$expected\" ] || {{ echo 'share marker UUID changed' >&2; exit 1; }}; /bin/rm \"$marker\"; else case \"$marker_type\" in *'No such file or directory'*) : ;; *) echo \"$marker_type\" >&2; exit 1 ;; esac; fi\n"
    );
    run_pending_share_cleanup(
        node,
        &script,
        &format!("remove exact marker for pending NFS share {share_id}"),
    )
    .map_err(|error| (1, error))
}

fn removal_connection_node(
    node_id: &str,
    registered: &NodeConfig,
    connect: Option<&NodeEndpoint>,
    saved_endpoint: Option<&str>,
    recorded_uuid: Option<&str>,
) -> AppResult<NodeConfig> {
    if registered.transport != Transport::Ssh {
        if connect.is_some() {
            return Err((2, "--connect requires a registered SSH node".into()));
        }
        return Ok(registered.clone());
    }
    let saved = if connect.is_none() {
        saved_endpoint
            .map(NodeEndpoint::parse)
            .transpose()
            .map_err(|error| (1, format!("cannot resume removal of {node_id}: {error}")))?
    } else {
        None
    };
    let Some(endpoint) = connect.or(saved.as_ref()) else {
        return Ok(registered.clone());
    };
    if registered.ssh_user.as_deref() != Some(endpoint.user.as_str()) {
        return Err((
            2,
            format!("--connect must use the registered SSH account for {node_id}"),
        ));
    }
    let mut connection = registered.clone();
    connection.host = endpoint.host.to_string();
    connection.ssh_port = Some(endpoint.port);
    if (connection.host != registered.host
        || connection.ssh_port.unwrap_or(22) != registered.ssh_port.unwrap_or(22))
        && registered.machine_uuid.is_none()
        && recorded_uuid.is_none()
    {
        return Err((
            1,
            format!(
                "cannot redirect removal of {node_id}; no registered machine UUID is available to verify its new address"
            ),
        ));
    }
    Ok(connection)
}

fn validate_removal_address(
    node_id: &str,
    node: &NodeConfig,
    local_addresses: &[Ipv4Addr],
) -> AppResult<()> {
    if node.transport == Transport::Ssh
        && node
            .host
            .parse::<Ipv4Addr>()
            .is_ok_and(|host| host.is_loopback() || local_addresses.contains(&host))
    {
        return Err((
            1,
            format!(
                "cannot remove {node_id}: its SSH address {} now belongs to this login Mac. The node address has changed; rerun `mnode -rm {node_id} --connect {}@CURRENT_IP:{}`. The destination machine UUID will be verified before cleanup; SSH host-key verification remains enabled",
                node.host,
                node.ssh_user.as_deref().unwrap_or("USER"),
                node.ssh_port.unwrap_or(22)
            ),
        ));
    }
    Ok(())
}

fn validate_removal_identity(
    node_id: &str,
    node: &NodeConfig,
    recorded_uuid: Option<&str>,
    actual_uuid: &str,
) -> AppResult<()> {
    for expected in [node.machine_uuid.as_deref(), recorded_uuid]
        .into_iter()
        .flatten()
    {
        validate_pending_node_identity(node_id, Some(expected), actual_uuid)
            .map_err(|error| (1, error))?;
    }
    Ok(())
}

fn removal_connection_error(node_id: &str, node: &NodeConfig, error: String) -> (i32, String) {
    let lower = error.to_ascii_lowercase();
    let advice = if lower.contains("remote host identification has changed")
        || lower.contains("host key verification failed")
        || lower.contains("host key is known")
    {
        "SSH host-key verification failed. Check whether the node IP was reassigned; keep existing known_hosts entries until you have verified the destination fingerprint."
    } else {
        "The registered node could not be reached or authenticated. Check its current address and SSH access."
    };
    (
        1,
        format!(
            "cannot verify removal destination for {node_id} at {}: {advice} If its address changed, use `mnode -rm {node_id} --connect {}@CURRENT_IP:{}`. No remote cleanup was performed.\n{error}",
            node.host,
            node.ssh_user.as_deref().unwrap_or("USER"),
            node.ssh_port.unwrap_or(22)
        ),
    )
}

fn removal_connection_from_state(
    node_id: &str,
    node: &NodeConfig,
    connect: Option<&NodeEndpoint>,
    state: &AdminState,
) -> AppResult<NodeConfig> {
    let saved_endpoint = state
        .operations
        .get(&format!("remove:{node_id}"))
        .filter(|operation| operation.action == "remove")
        .and_then(|operation| operation.connection_endpoint.as_deref());
    removal_connection_node(
        node_id,
        node,
        connect,
        saved_endpoint,
        state.machine_uuids.get(node_id).map(String::as_str),
    )
}

pub(crate) fn pending_removal_connection(
    node_id: &str,
    node: &NodeConfig,
    endpoint: Option<&str>,
    recorded_uuid: Option<&str>,
) -> AppResult<NodeConfig> {
    removal_connection_node(node_id, node, None, endpoint, recorded_uuid)
}

fn remove_node(
    config_path: &Path,
    state_dir: &Path,
    node_id: &str,
    connect: Option<&NodeEndpoint>,
) -> AppResult<()> {
    // Reject a stale address that now identifies this Mac before asking to
    // stop the controller or creating any maintenance state. Recheck under lock.
    let initial_config = read_config(config_path)?;
    if let Some(node) = initial_config.nodes.get(node_id) {
        let initial_state =
            read_admin_state(&state_dir.join("node-admin.json"), config_path, state_dir)?;
        let connection = removal_connection_from_state(node_id, node, connect, &initial_state)?;
        validate_removal_address(node_id, &connection, &local_ipv4_addresses()?)?;
    }
    let maintenance_scope = if initial_config.nodes.contains_key(node_id) {
        MaintenanceScope::Nodes(vec![
            NodeId::new(node_id.to_owned()).map_err(|error| (2, error.to_string()))?,
        ])
    } else {
        MaintenanceScope::Cluster
    };
    let maintenance = acquire_node_maintenance_scoped(
        config_path,
        state_dir,
        "mnode --remove",
        maintenance_scope,
    )?;
    if maintenance.recovered {
        return Ok(());
    }
    let result = (|| -> AppResult<()> {
        MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(|error| {
            (
                1,
                format!("cluster config/state directory binding failed: {error}"),
            )
        })?;
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let config_path = config_path.canonicalize().map_err(io_error)?;
        let config_source = fs::read_to_string(&config_path).map_err(io_error)?;
        let config =
            ClusterConfig::parse(&config_source).map_err(|error| (2, error.to_string()))?;
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, state_dir)?;
        let operation_key = format!("remove:{node_id}");
        if !config.nodes.contains_key(node_id) {
            if let Some(mut operation) = state.operations.get(&operation_key).cloned() {
                if operation.phase == "REMOVED" {
                    println!("Node {node_id} has already been removed.");
                    return Ok(());
                }
                let current_digest =
                    sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
                if matches!(
                    operation.phase.as_str(),
                    "REMOVAL_COMMITTING" | "SYNC_PENDING"
                ) && operation.candidate_config_sha256.as_deref()
                    == Some(current_digest.as_str())
                {
                    let final_config = ClusterConfig::parse(&config_source)
                        .map_err(|error| (2, error.to_string()))?;
                    operation.phase = "SYNC_PENDING".into();
                    operation.detail = None;
                    state
                        .operations
                        .insert(operation_key.clone(), operation.clone());
                    save_admin_state(&journal_path, &state)?;
                    if let Err(error) = sync_remote_configs(
                        &final_config,
                        &config_source,
                        state_dir,
                        &operation.id,
                        None,
                    ) {
                        operation.detail = Some(error.clone());
                        state
                            .operations
                            .insert(operation_key.clone(), operation.clone());
                        save_admin_state(&journal_path, &state)?;
                        return Err((
                            1,
                            format!(
                                "node {node_id} is removed locally, but peer config sync is pending: {error}. Rerun `mnode -rm {node_id}` to resume."
                            ),
                        ));
                    }
                    operation.phase = "REMOVED".into();
                    operation.detail = None;
                    state.operations.insert(operation_key, operation);
                    save_admin_state(&journal_path, &state)?;
                    println!(
                        "Recovered the completed removal and peer config sync for node {node_id}."
                    );
                    return Ok(());
                }
            }
            if let Some(operation) = state
                .operations
                .values()
                .find(|operation| operation.action == "add" && operation.node_id == node_id)
            {
                match operation.phase.as_str() {
                    "ABORTED" => {
                        println!(
                            "Enrollment for {node_id} was already cancelled; its ID remains reserved."
                        );
                        return Ok(());
                    }
                    "SETUP_PENDING" | "CANDIDATE_INSTALLED" | "ADD_COMMITTING" => {
                        let current_digest = sha256_hex(config_source.as_bytes())
                            .map_err(|error| (1, error.to_string()))?;
                        if operation.old_config_sha256.as_deref() != Some(current_digest.as_str()) {
                            return Err((
                                1,
                                format!(
                                    "cluster config changed during enrollment of {node_id}; refusing to cancel it automatically"
                                ),
                            ));
                        }
                        if abort_pending_enrollment(&mut state, &journal_path, &config, node_id)? {
                            return Ok(());
                        }
                        return Err((
                            1,
                            format!(
                                "node {node_id} is reserved by a pending enrollment but is not schedulable; rerun its original mnode --add command or inspect the node admin journal"
                            ),
                        ));
                    }
                    "SYNC_PENDING" => {
                        return Err((
                            1,
                            format!(
                                "the enrollment of {node_id} was committed locally but its node config is missing; inspect the config and node-admin journal before cancelling"
                            ),
                        ));
                    }
                    _ => {}
                }
            }
            return Err((2, format!("node '{node_id}' is not configured")));
        }
        if config
            .login_node
            .as_ref()
            .is_some_and(|login| login.as_str() == node_id)
        {
            return Err((
            1,
            "cannot remove the configured login node; reinitialize the cluster with the intended login Mac first".into(),
        ));
        }
        if config.storage_server.as_str() == node_id {
            return Err((
                1,
                "cannot remove the configured NFS storage server; migrate storage first".into(),
            ));
        }
        let served_shares: Vec<_> = config
            .shares
            .iter()
            .filter(|(_, share)| share.server.as_str() == node_id)
            .map(|(id, _)| id.as_str())
            .collect();
        if !served_shares.is_empty() {
            return Err((
                1,
                format!(
                    "cannot remove node {node_id}; it serves additional NFS share(s): {}",
                    served_shares.join(", ")
                ),
            ));
        }
        let node = config
            .nodes
            .get(node_id)
            .cloned()
            .ok_or_else(|| (2, format!("node '{node_id}' is not configured")))?;
        let storage = Storage::open(state_dir).map_err(|error| (1, error.to_string()))?;
        let blockers = storage
            .jobs_preventing_node_removal(node_id)
            .map_err(|error| (1, error.to_string()))?;
        if !blockers.is_empty() {
            let details = blockers
                .iter()
                .map(|job| format!("{}:{:?}", job.id, job.state))
                .collect::<Vec<_>>()
                .join(", ");
            return Err((
                1,
                format!("cannot remove {node_id}; local jobs still reference it: {details}"),
            ));
        }
        let connection_node = removal_connection_from_state(node_id, &node, connect, &state)?;
        validate_removal_address(node_id, &connection_node, &local_ipv4_addresses()?)?;
        let machine_uuid = remote_machine_uuid(&connection_node)
            .map_err(|(_, error)| removal_connection_error(node_id, &connection_node, error))?;
        validate_removal_identity(
            node_id,
            &node,
            state.machine_uuids.get(node_id).map(String::as_str),
            &machine_uuid,
        )?;
        check_remote_idle(&connection_node, node_id, &config_path)?;
        state.machine_uuids.insert(node_id.to_owned(), machine_uuid);

        state.reserved_node_ids.insert(node_id.to_owned());
        let mut operation = state
            .operations
            .get(&operation_key)
            .cloned()
            .unwrap_or_else(|| {
                let add_record = state
                    .operations
                    .values()
                    .find(|record| record.action == "add" && record.node_id == node_id);
                NodeOperation {
                    id: Id128::random().to_string(),
                    action: "remove".into(),
                    connection_endpoint: None,
                    remote_config_path: node.remote_config.clone(),
                    node_id: node_id.to_owned(),
                    endpoint: format!(
                        "{}@{}:{}",
                        if node.transport == Transport::Local {
                            "local"
                        } else {
                            node.ssh_user.as_deref().unwrap_or("unknown")
                        },
                        node.host,
                        node.ssh_port.unwrap_or(22)
                    ),
                    machine_uuid: state.machine_uuids.get(node_id).cloned(),
                    phase: "REMOVAL_PENDING".into(),
                    old_config_sha256: sha256_hex(config_source.as_bytes()).ok(),
                    candidate_config_sha256: None,
                    managed_export: add_record.is_some_and(|record| record.managed_export),
                    managed_shares: add_record
                        .map(|record| record.managed_shares.clone())
                        .unwrap_or_default(),
                    client_setup_attempted: add_record
                        .and_then(|record| record.client_setup_attempted),
                    detail: None,
                }
            });
        if operation.remote_config_path.is_none() {
            operation.remote_config_path = node.remote_config.clone();
        }
        if connection_node.transport == Transport::Ssh {
            operation.connection_endpoint = Some(format!(
                "{}@{}:{}",
                connection_node.ssh_user.as_deref().unwrap_or("unknown"),
                connection_node.host,
                connection_node.ssh_port.unwrap_or(22)
            ));
        }
        let current_digest =
            sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
        let matches_old = operation.old_config_sha256.as_deref() == Some(current_digest.as_str());
        let matches_pending_candidate =
            operation.candidate_config_sha256.as_deref() == Some(current_digest.as_str());
        if !matches_old && !matches_pending_candidate {
            return Err((
            1,
            "cluster config changed since this node removal began; refusing to overwrite it. Inspect the config and node-admin journal before retrying".into(),
        ));
        }
        if matches_pending_candidate && !matches_old {
            operation.old_config_sha256 = Some(current_digest.clone());
        }
        operation.phase = "REMOVAL_PENDING".into();
        operation.detail = Some("node removal is pending; checking queue and NFS state".into());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        if config
            .queues
            .values()
            .any(|queue| queue.nodes.iter().any(|id| id == node_id))
        {
            let detached = detach_node_from_queues(&config_source, &config, node_id)?;
            operation.candidate_config_sha256 =
                Some(sha256_hex(detached.as_bytes()).map_err(|error| (1, error.to_string()))?);
            operation.detail =
                Some("node is being detached from scheduling; NFS cleanup remains".into());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            backup_config(&config_path, &operation.id)?;
            atomic_write(&config_path, detached.as_bytes())?;
            operation.old_config_sha256 = operation.candidate_config_sha256.clone();
            operation.detail = Some("node is detached from scheduling; NFS cleanup remains".into());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
        }

        if let Err((_, error)) = cleanup_client_nfs_resources(&config, node_id, &connection_node) {
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            return Err((
                1,
                format!(
                    "{node_id} is detached from queues but client NFS cleanup is pending: {error}. Rerun `mnode -rm {node_id}`."
                ),
            ));
        }

        let mut export_requests_by_server: BTreeMap<
            String,
            Vec<(Option<String>, NfsExportRequest)>,
        > = BTreeMap::new();
        export_requests_by_server
            .entry(config.storage_server.as_str().to_owned())
            .or_default()
            .push((
                None,
                NfsExportRequest {
                    root: config.primary_source_root().to_string_lossy().into_owned(),
                    client_ip: node.host.to_string(),
                    share_uuid: config.share_uuid.clone(),
                    node_id: node_id.to_owned(),
                },
            ));
        for (share_id, share) in &config.shares {
            export_requests_by_server
                .entry(share.server.as_str().to_owned())
                .or_default()
                .push((
                    Some(share_id.clone()),
                    NfsExportRequest {
                        root: share.source_root.to_string_lossy().into_owned(),
                        client_ip: node.host.to_string(),
                        share_uuid: share.share_uuid.clone(),
                        node_id: node_id.to_owned(),
                    },
                ));
        }
        let mut removed_export = false;
        let mut still_authorized = false;
        let mut removed_share_exports = Vec::new();
        for (server_id, labelled_requests) in export_requests_by_server {
            let export_server = &config.nodes[&server_id];
            let requests = labelled_requests
                .iter()
                .map(|(_, request)| request.clone())
                .collect::<Vec<_>>();
            let statuses = match remove_managed_nfs_exports(export_server, &requests, &operation.id)
            {
                Ok(statuses) => statuses,
                Err(error) => {
                    operation.detail = Some(error.clone());
                    state
                        .operations
                        .insert(operation_key.clone(), operation.clone());
                    save_admin_state(&journal_path, &state)?;
                    let subject = labelled_requests
                        .iter()
                        .find_map(|(share_id, _)| share_id.as_deref())
                        .map_or_else(
                            || "primary NFS export".to_owned(),
                            |id| format!("share {id}"),
                        );
                    return Err((
                        1,
                        format!(
                            "{node_id} is detached from queues but cleanup of {subject} on {} is pending: {error}. Rerun `mnode -rm {node_id}`.",
                            export_server.host
                        ),
                    ));
                }
            };
            for ((share_id, _), (removed, is_still_authorized)) in
                labelled_requests.iter().zip(statuses)
            {
                if let Some(share_id) = share_id {
                    if removed {
                        removed_share_exports.push(share_id.clone());
                    }
                } else {
                    removed_export = removed;
                    still_authorized = is_still_authorized;
                }
            }
        }

        let current_source = fs::read_to_string(&config_path).map_err(io_error)?;
        let current_digest =
            sha256_hex(current_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
        if operation.old_config_sha256.as_deref() != Some(current_digest.as_str())
            && operation.candidate_config_sha256.as_deref() != Some(current_digest.as_str())
        {
            return Err((
            1,
            "cluster config changed during node removal; refusing to overwrite it. Inspect the config and node-admin journal before retrying".into(),
        ));
        }
        let current_config =
            ClusterConfig::parse(&current_source).map_err(|error| (2, error.to_string()))?;
        let final_source = remove_node_from_config(&current_source, &current_config, node_id)?;
        backup_config(&config_path, &operation.id)?;
        operation.old_config_sha256 = Some(current_digest);
        operation.phase = "REMOVAL_COMMITTING".into();
        operation.candidate_config_sha256 =
            Some(sha256_hex(final_source.as_bytes()).map_err(|error| (1, error.to_string()))?);
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        atomic_write(&config_path, final_source.as_bytes())?;
        let final_config =
            ClusterConfig::parse(&final_source).map_err(|error| (2, error.to_string()))?;
        operation.phase = "SYNC_PENDING".into();
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        if let Err(error) =
            sync_remote_configs(&final_config, &final_source, state_dir, &operation.id, None)
        {
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            return Err((
                1,
                format!(
                    "node {node_id} was removed locally, but peer config sync is pending: {error}. Rerun `mnode -rm {node_id}` to resume."
                ),
            ));
        }
        operation.phase = "REMOVED".into();
        operation.detail = None;
        state.operations.insert(operation_key, operation);
        save_admin_state(&journal_path, &state)?;
        println!("Removed node {node_id} from the local cluster configuration.");
        if removed_export {
            println!("Removed its macluster-managed NFS export entry.");
        } else if still_authorized {
            println!(
                "Warning: an operator-managed NFS export still authorizes {}; it was left unchanged.",
                node.host
            );
        }
        if !removed_share_exports.is_empty() {
            println!(
                "Removed managed client exports for share(s): {}.",
                removed_share_exports.join(", ")
            );
        }
        Ok(())
    })();
    finish_node_maintenance(maintenance, result)
}

fn detach_node_from_queues(
    source: &str,
    config: &ClusterConfig,
    node_id: &str,
) -> AppResult<String> {
    let mut candidate = source.to_owned();
    for (queue_name, queue) in &config.queues {
        let members: Vec<_> = queue
            .nodes
            .iter()
            .filter(|member| member.as_str() != node_id)
            .cloned()
            .collect();
        candidate = replace_queue_members(&candidate, queue_name, &members)?;
    }
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

pub(crate) fn check_remote_idle(
    node: &NodeConfig,
    node_id: &str,
    local_config_path: &Path,
) -> AppResult<()> {
    let Some(status) = remote_execution_status(node, node_id, local_config_path)? else {
        return Ok(());
    };
    match status.phase {
        RuntimePhase::Idle => {}
        phase => {
            return Err((
                1,
                format!("cannot remove {node_id}; remote execution state is {phase:?}"),
            ));
        }
    }
    if status.log_sync_pending {
        return Err((
            1,
            format!("cannot remove {node_id}; remote job logs are still pending synchronization"),
        ));
    }
    Ok(())
}

fn enrollment_controller_epoch(state_dir: &Path) -> Result<ControllerEpoch, String> {
    // Enrollment can run under a live maintenance ticket. Advancing the epoch
    // here fences that still-running controller and prevents its next drain.
    migration_controller_epoch(state_dir)
}

fn migration_controller_epoch(state_dir: &Path) -> Result<ControllerEpoch, String> {
    let storage = Storage::open(state_dir)
        .map_err(|error| format!("cannot inspect node handoff identity: {error}"))?;
    if let Some(controller) = storage
        .current_controller_epoch()
        .map_err(|error| format!("cannot inspect node handoff identity: {error}"))?
    {
        return Ok(controller);
    }
    storage
        .begin_controller_epoch()
        .map_err(|error| format!("cannot prepare node handoff identity: {error}"))
}

fn claim_enrollment_agent(
    node: &NodeConfig,
    node_id: &str,
    config_path: &Path,
    namespace: &str,
    controller: ControllerEpoch,
) -> Result<(), String> {
    if node.transport == Transport::Local {
        let actual = local_platform_uuid().map_err(|(_, error)| error)?;
        macluster_agent::validate_node_identity(node, &actual, unsafe { libc::geteuid() })?;
        return macluster_agent::admin::claim_idle(
            &macluster_agent::default_state_dir(),
            controller,
            namespace,
        )
        .map_err(|error| error.to_string());
    }
    let selected_config = node
        .remote_config
        .as_deref()
        .unwrap_or_else(|| config_path.to_str().unwrap_or("/dev/null"));
    let command = shell_join(&[
        &node.remote_binary,
        "--config",
        selected_config,
        "internal",
        "claim-agent",
        "--node",
        node_id,
        "--controller",
        &controller.controller_uuid.to_string(),
        "--epoch",
        &controller.epoch.to_string(),
    ]);
    let output = ssh_output(node, &command, None).map_err(|(_, error)| error)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(
            "cannot hand this idle node to the current controller",
            &output,
        ))
    }
}

pub(crate) fn primary_restore_probe(root: &Path, namespace: &str) -> String {
    primary_reuse::presence_probe(root, namespace)
}

pub(crate) fn primary_restore_script(root: &Path, namespace: &str) -> String {
    primary_reuse::restore_script(root, namespace)
}

pub(crate) fn remote_execution_status(
    node: &NodeConfig,
    node_id: &str,
    local_config_path: &Path,
) -> AppResult<Option<ExecutionStatus>> {
    let id = NodeId::new(node_id.to_owned()).map_err(|error| (2, error.to_string()))?;
    let config_path = match node.transport {
        Transport::Local => local_config_path.to_path_buf(),
        Transport::Ssh => node
            .remote_config
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/dev/null")),
    };
    let namespace = read_config(local_config_path)
        .map(|config| config.share_uuid)
        .unwrap_or_else(|_| format!("config-path:{}", local_config_path.display()));
    let mut transport = ClusterTransport::new_with_namespace(config_path, namespace);
    transport.timeout = Duration::from_secs(12);
    let response = match transport.call(&id, node, Operation::Status) {
        Err(macluster_controller::transport::TransportError::Remote(ProtocolError::NotFound)) => {
            return Ok(None);
        }
        Ok(response) => response,
        Err(error) => {
            return Err((
                1,
                format!("cannot verify remote execution state for {node_id}: {error}"),
            ));
        }
    };
    let ResponseBody::Execution(status) = response else {
        return Err((
            1,
            format!("remote agent did not return execution status for {node_id}"),
        ));
    };
    Ok(Some(status))
}

struct NodeListRow {
    columns: [String; 6],
    mappings: Vec<NodeNfsMapping>,
}

#[derive(Debug, Clone)]
struct NodeNfsMapping {
    name: String,
    state: &'static str,
    kind: &'static str,
    source_node: String,
    target: String,
}

fn verified_node_health<'a>(
    config: &ClusterConfig,
    node_id: &str,
    health: Option<&'a NodeHealth>,
) -> Option<&'a NodeHealth> {
    let node = config.nodes.get(node_id)?;
    let digest = config.execution_digest().ok()?;
    health.filter(|health| {
        health.execution_digest == digest
            && node
                .machine_uuid
                .as_deref()
                .is_none_or(|uuid| uuid.eq_ignore_ascii_case(&health.machine_uuid))
            && node
                .execution_uid
                .is_none_or(|uid| uid == health.execution_uid)
    })
}

fn node_nfs_mappings(
    config: &ClusterConfig,
    node_id: &str,
    health: Option<&NodeHealth>,
) -> Vec<NodeNfsMapping> {
    let health = verified_node_health(config, node_id, health);
    let state = |ready| match ready {
        Some(true) => "READY",
        Some(false) => "PENDING",
        None => "UNKNOWN",
    };
    let mut mappings = vec![nfs_mapping(
        node_id,
        "primary",
        config.storage_server.as_str(),
        config.primary_source_root(),
        &config.shared_root,
        state(health.map(|health| health.primary_share_ready)),
    )];
    for (name, share) in &config.shares {
        mappings.push(nfs_mapping(
            node_id,
            if name == "primary" {
                "primary (named)"
            } else {
                name
            },
            share.server.as_str(),
            &share.source_root,
            &share.mount_root,
            state(health.and_then(|health| health.shares.get(name).copied())),
        ));
    }
    mappings
}

fn nfs_mapping(
    node_id: &str,
    name: &str,
    server_id: &str,
    source: &Path,
    target: &Path,
    state: &'static str,
) -> NodeNfsMapping {
    NodeNfsMapping {
        name: name.to_owned(),
        state,
        kind: if node_id != server_id {
            "MOUNT"
        } else if source == target {
            "LOCAL"
        } else {
            "ALIAS"
        },
        source_node: server_id.to_owned(),
        target: target.to_string_lossy().into_owned(),
    }
}

fn aggregate_nfs_mappings(rows: &[NodeListRow]) -> Vec<NodeNfsMapping> {
    let mut indexes: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut mappings: Vec<NodeNfsMapping> = Vec::new();
    for mapping in rows.iter().flat_map(|row| &row.mappings) {
        let key = (
            mapping.name.clone(),
            mapping.source_node.clone(),
            mapping.target.clone(),
        );
        if let Some(index) = indexes.get(&key).copied() {
            let current = &mut mappings[index];
            current.state = if current.state == "PENDING" || mapping.state == "PENDING" {
                "PENDING"
            } else if current.state == "UNKNOWN" || mapping.state == "UNKNOWN" {
                "UNKNOWN"
            } else {
                "READY"
            };
            current.kind = match (current.kind, mapping.kind) {
                (_, "MOUNT") | ("MOUNT", _) => "MOUNT",
                (_, "ALIAS") | ("ALIAS", _) => "ALIAS",
                _ => "LOCAL",
            };
        } else {
            indexes.insert(key, mappings.len());
            mappings.push(mapping.clone());
        }
    }
    mappings
}

fn format_node_list(rows: &[NodeListRow]) -> String {
    let headers = ["ID", "HOST", "SSH USER", "PORT", "QUEUE", "STATE"];
    let widths = std::array::from_fn::<_, 6, _>(|index| {
        rows.iter()
            .map(|row| row.columns[index].chars().count())
            .max()
            .unwrap_or(0)
            .max(headers[index].len())
    });
    let line = |cells: [&str; 6]| {
        cells
            .iter()
            .enumerate()
            .map(|(index, cell)| format!("{cell:<width$}", width = widths[index]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut output = line(headers);
    output.push('\n');
    for row in rows {
        output.push_str(&line(std::array::from_fn(|index| {
            row.columns[index].as_str()
        })));
        output.push('\n');
    }
    let mappings = aggregate_nfs_mappings(rows);
    if !mappings.is_empty() {
        output.push_str("\nNFS MAPPINGS\n");
        let name_width = mappings
            .iter()
            .map(|mapping| mapping.name.chars().count())
            .max()
            .unwrap_or(0);
        for mapping in mappings {
            output.push_str(&format!(
                "    {:<name_width$}  {:<7}  {:<7}  {} → {}\n",
                mapping.name, mapping.state, mapping.kind, mapping.source_node, mapping.target,
            ));
        }
    }
    output
}

fn probe_node_list(
    config_path: &Path,
    namespace: &str,
    id: &str,
    node: &NodeConfig,
) -> (Option<NodeHealth>, bool) {
    let Ok(node_id) = NodeId::new(id.to_owned()) else {
        return (None, false);
    };
    let mut transport =
        ClusterTransport::new_with_namespace(config_path.to_path_buf(), namespace.to_owned());
    transport.timeout = Duration::from_secs(8);
    match transport.call(&node_id, node, Operation::Health) {
        Ok(ResponseBody::Health(health)) => (Some(health), true),
        // An Agent rejection also proves the authenticated bridge answered.
        Ok(_) | Err(macluster_controller::transport::TransportError::Remote(_)) => (None, true),
        // Repeating Ping/node-check after a transport failure only repeats the timeout.
        Err(_) => (None, false),
    }
}

fn list_nodes(config_path: &Path, state_dir: &Path) -> AppResult<()> {
    if !config_path.is_file() {
        return Err((
            1,
            format!(
                "cluster is not initialized; config {} is missing. Run `macluster init` to configure a new cluster",
                config_path.display()
            ),
        ));
    }
    MaintenanceLock::verify_state_dir_binding(config_path, state_dir).map_err(|error| {
        (
            1,
            format!("cluster config/state directory binding failed: {error}"),
        )
    })?;
    let config = read_config(config_path)?;
    let canonical = config_path.canonicalize().map_err(io_error)?;
    let journal_path = state_dir.join("node-admin.json");
    let state = read_admin_state(&journal_path, &canonical, state_dir)?;
    let tasks = Mutex::new(VecDeque::from_iter(config.nodes.iter()));
    let observations = std::thread::scope(|scope| {
        let handles = (0..config.nodes.len().min(4))
            .map(|_| {
                let tasks = &tasks;
                let namespace = &config.share_uuid;
                scope.spawn(move || {
                    let mut results = Vec::new();
                    loop {
                        let Some((id, node)) =
                            tasks.lock().ok().and_then(|mut tasks| tasks.pop_front())
                        else {
                            break;
                        };
                        results.push((
                            id.clone(),
                            probe_node_list(config_path, namespace, id, node),
                        ));
                    }
                    results
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap_or_default())
            .collect::<BTreeMap<_, _>>()
    });
    let mut observations = observations;
    let mut rows = Vec::new();
    for (id, node) in &config.nodes {
        let queue_names = config
            .queues
            .iter()
            .filter(|(_, queue)| {
                queue.nodes.iter().any(|member| member == id) && !config.is_login_node(id)
            })
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let (health, bridge_online) = observations.remove(id).unwrap_or_default();
        let digest_matches = verified_node_health(&config, id, health.as_ref()).is_some();
        let all_shares_ready = health.as_ref().is_some_and(|health| {
            health.primary_share_ready
                && config
                    .shares
                    .keys()
                    .all(|share_id| health.shares.get(share_id).copied().unwrap_or(false))
        });
        let state_name = if digest_matches && all_shares_ready && bridge_online {
            "READY"
        } else {
            "OFFLINE"
        };
        let user = if node.transport == Transport::Local {
            "local"
        } else {
            node.ssh_user.as_deref().unwrap_or("OpenSSH")
        };
        let port = node.ssh_port.unwrap_or(22);
        rows.push(NodeListRow {
            columns: [
                id.clone(),
                node.host.clone(),
                user.to_owned(),
                port.to_string(),
                if queue_names.is_empty() {
                    "-".into()
                } else {
                    queue_names
                },
                state_name.to_owned(),
            ],
            mappings: node_nfs_mappings(&config, id, health.as_ref()),
        });
    }
    let drafts = state
        .operations
        .values()
        .filter(|op| is_uncommitted_enrollment(&config, op))
        .count();
    if drafts > 0 {
        eprintln!(
            "{drafts} enrollment attempt(s) did not complete; those nodes are not registered. Use `mnode --failed` for details and retry the original add command."
        );
    }
    print!("{}", format_node_list(&rows));
    Ok(())
}

fn list_failed_operations(config_path: &Path, state_dir: &Path) -> AppResult<()> {
    let canonical = config_path.canonicalize().map_err(io_error)?;
    MaintenanceLock::verify_state_dir_binding(&canonical, state_dir).map_err(io_error)?;
    let state = read_admin_state(&state_dir.join("node-admin.json"), &canonical, state_dir)?;
    let mut found = false;
    for operation in state.operations.values().filter(|op| {
        op.action != "update" && !matches!(op.phase.as_str(), "READY" | "REMOVED" | "ABORTED")
    }) {
        found = true;
        println!("{}  {}", operation.node_id, operation.endpoint);
        println!(
            "  {}",
            operation
                .detail
                .as_deref()
                .unwrap_or("Operation did not finish; retry its original mnode command.")
        );
    }
    if !found {
        println!("No unfinished node or share operations.");
    }
    Ok(())
}

fn existing_ssh_endpoint_matches(existing: &NodeConfig, endpoint: &NodeEndpoint) -> bool {
    existing.transport == Transport::Ssh
        && existing.ssh_user.as_deref() == Some(endpoint.user.as_str())
        && existing.ssh_port.unwrap_or(22) == endpoint.port
}

fn pending_combined_ssh_add(
    state: &AdminState,
    node_id: &str,
    endpoint: &NodeEndpoint,
    configured_digest: &str,
) -> AppResult<Option<String>> {
    let mut pending = state.operations.iter().filter(|(key, operation)| {
        key.starts_with("add:")
            && operation.action == "add"
            && operation.node_id == node_id
            && should_resume_add_operation(&operation.phase)
    });
    let Some((key, operation)) = pending.next() else {
        return Ok(None);
    };
    if pending.next().is_some()
        || operation.endpoint != endpoint.canonical()
        || !matches!(operation.phase.as_str(), "ADD_COMMITTING" | "SYNC_PENDING")
        || operation.candidate_config_sha256.as_deref() != Some(configured_digest)
    {
        return Err((
            1,
            format!(
                "node {node_id} has an incomplete enrollment that does not match this command or the active config; rerun the original enrollment command or inspect the node-admin journal before adding a share"
            ),
        ));
    }
    Ok(Some(key.clone()))
}

fn resume_existing_ssh_add_sync(
    state: &mut AdminState,
    journal_path: &Path,
    key: &str,
    endpoint: &NodeEndpoint,
    mut sync: impl FnMut(&NodeOperation) -> Result<(), String>,
) -> AppResult<()> {
    let mut operation = state.operations[key].clone();
    operation.phase = "SYNC_PENDING".into();
    operation.detail = None;
    state.operations.insert(key.to_owned(), operation.clone());
    save_admin_state(journal_path, state)?;
    if let Err(error) = sync(&operation) {
        operation.detail = Some(error.clone());
        let node_id = operation.node_id.clone();
        state.operations.insert(key.to_owned(), operation);
        save_admin_state(journal_path, state)?;
        return Err((
            1,
            format!(
                "node {node_id} is configured locally, but peer config sync is pending: {error}. Rerun the same `mnode -a {}` command to resume.",
                endpoint.canonical()
            ),
        ));
    }
    operation.phase = "READY".into();
    operation.detail = None;
    state.operations.insert(key.to_owned(), operation);
    save_admin_state(journal_path, state)
}

fn pending_local_share_retry_node(
    config: &ClusterConfig,
    operation: Option<&NodeOperation>,
    local_host: &Ipv4Addr,
    machine_uuid: &str,
    execution_uid: u32,
) -> AppResult<Option<String>> {
    let Some(operation) = operation.filter(|operation| {
        operation.action == "share" && should_resume_add_operation(&operation.phase)
    }) else {
        return Ok(None);
    };

    let host = local_host.to_string();
    let local_node = config.nodes.iter().find(|(_, node)| {
        node.transport == Transport::Local
            && node.host == host
            && node
                .machine_uuid
                .as_deref()
                .is_some_and(|registered| registered.eq_ignore_ascii_case(machine_uuid))
            && node.execution_uid == Some(execution_uid)
    });
    if let Some((node_id, _)) = local_node {
        return Ok(Some(node_id.clone()));
    }

    Err((
        1,
        format!(
            "cannot refresh local node configuration while share operation {} is pending; the current host, machine UUID, or execution UID does not match the registered local node. Inspect the node admin journal before retrying",
            operation.id
        ),
    ))
}

fn add_node(config_path: &Path, state_dir: &Path, options: AddOptions) -> AppResult<()> {
    match options.target {
        AddTarget::Ssh(endpoint) => {
            let source_path = endpoint.source_path.clone();
            add_ssh_node(
                config_path,
                state_dir,
                endpoint.clone(),
                options.queue.as_deref(),
                source_path.is_some(),
            )?;
            if let Some(source_path) = source_path {
                register_named_share(
                    config_path,
                    state_dir,
                    &endpoint.host.to_string(),
                    options.queue.as_deref(),
                    options
                        .share_id
                        .as_deref()
                        .expect("share ID validated with source path"),
                    &source_path,
                    options.mount_root.as_deref(),
                )?;
            }
            Ok(())
        }
        AddTarget::Local { source_path, host } => {
            let retry_local_id = if source_path.is_some() {
                let config = read_config(config_path)?;
                let journal =
                    read_admin_state(&state_dir.join("node-admin.json"), config_path, state_dir)?;
                let operation = options
                    .share_id
                    .as_deref()
                    .and_then(|share_id| journal.operations.get(&format!("share:{share_id}")));
                if operation.is_some_and(|operation| {
                    operation.action == "share" && should_resume_add_operation(&operation.phase)
                }) {
                    let local_host = resolve_local_host(&config, host)?;
                    let machine_uuid = local_platform_uuid()?;
                    let execution_uid = unsafe { libc::geteuid() };
                    pending_local_share_retry_node(
                        &config,
                        operation,
                        &local_host,
                        &machine_uuid,
                        execution_uid,
                    )?
                } else {
                    let local_host = resolve_local_host(&config, host)?;
                    let machine_uuid = local_platform_uuid()?;
                    let uid = unsafe { libc::geteuid() };
                    config
                        .nodes
                        .iter()
                        .find(|(_, node)| {
                            node.transport == Transport::Local
                                && node.host == local_host.to_string()
                                && node
                                    .machine_uuid
                                    .as_deref()
                                    .is_some_and(|id| id.eq_ignore_ascii_case(&machine_uuid))
                                && node.execution_uid == Some(uid)
                        })
                        .map(|(id, _)| id.clone())
                }
            } else {
                None
            };
            if retry_local_id.is_none() {
                add_local_node(
                    config_path,
                    state_dir,
                    options.queue.as_deref(),
                    host,
                    source_path.is_some(),
                )?;
            }
            if let Some(source_path) = source_path {
                let config = read_config(config_path)?;
                let local_id = retry_local_id
                    .or_else(|| {
                        config
                            .nodes
                            .iter()
                            .find(|(_, node)| node.transport == Transport::Local)
                            .map(|(id, _)| id.clone())
                    })
                    .ok_or_else(|| {
                        (
                            1,
                            "local node registration did not create a local node".into(),
                        )
                    })?;
                register_named_share(
                    config_path,
                    state_dir,
                    &local_id,
                    options.queue.as_deref(),
                    options
                        .share_id
                        .as_deref()
                        .expect("share ID validated with source path"),
                    &source_path,
                    options.mount_root.as_deref(),
                )?;
            }
            Ok(())
        }
    }
}

fn register_named_share(
    config_path: &Path,
    state_dir: &Path,
    server_key: &str,
    selected_queue: Option<&str>,
    share_id: &str,
    requested_source: &str,
    requested_mount_root: Option<&str>,
) -> AppResult<()> {
    let maintenance = acquire_node_maintenance_scoped(
        config_path,
        state_dir,
        "named-share setup",
        MaintenanceScope::Cluster,
    )?;
    if maintenance.recovered {
        return Ok(());
    }
    let result = (|| -> AppResult<()> {
        MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(|error| {
            (
                1,
                format!("cluster config/state directory binding failed: {error}"),
            )
        })?;
        let config_path = config_path.canonicalize().map_err(io_error)?;
        let source_text = fs::read_to_string(&config_path).map_err(io_error)?;
        let config = ClusterConfig::parse(&source_text).map_err(|error| (2, error.to_string()))?;
        let server_id = config
            .nodes
            .iter()
            .find(|(id, node)| id.as_str() == server_key || node.host == server_key)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| {
                (
                    2,
                    format!("share server '{server_key}' is not a registered node"),
                )
            })?;
        if let Some(queue) = selected_queue
            && !config.queues.contains_key(queue)
        {
            return Err((2, format!("queue '{queue}' is not configured")));
        }
        let queue_name = selected_queue.unwrap_or(config.default_queue.as_str());
        let server = config.nodes.get(&server_id).expect("server was located");
        let server_facts = read_remote_facts(server)?;
        for (node_id, node) in &config.nodes {
            let facts = read_remote_facts(node).map_err(|(_, error)| {
                (
                    1,
                    format!("cannot verify execution account on share client {node_id}: {error}"),
                )
            })?;
            if facts.uid != server_facts.uid || facts.gid != server_facts.gid {
                return Err((
                    2,
                    format!(
                        "UID/GID mismatch for share {share_id}: node {node_id} uses {}/{}, but server {server_id} uses {}/{}",
                        facts.uid, facts.gid, server_facts.uid, server_facts.gid
                    ),
                ));
            }
        }
        let home = checked_remote_path(&server_facts.home)?;
        let source_root = resolve_share_source(requested_source, &home)?;
        let mount_root = named_share_mount_root(share_id, requested_mount_root);
        validate_share_alias_paths(&source_root, &mount_root)?;
        let journal_path = state_dir.join("node-admin.json");
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let mut state = read_admin_state(&journal_path, &config_path, state_dir)?;
        let operation_key = format!("share:{share_id}");
        let endpoint_key =
            named_share_operation_endpoint(share_id, &server_id, &source_root, &mount_root);
        if let Some(existing) = config.shares.get(share_id) {
            if !named_share_request_matches(existing, &server_id, &source_root, &mount_root) {
                return Err((
                    2,
                    format!(
                        "share ID '{share_id}' is already configured for a different server, source path, or mount path"
                    ),
                ));
            }
            return repair_named_share(
                &config_path,
                state_dir,
                &config,
                &source_text,
                share_id,
                existing,
                &mut state,
                &journal_path,
            );
        }
        let marker_uuid = match state.operations.get(&operation_key) {
            Some(existing)
                if named_share_operation_matches(
                    &existing,
                    share_id,
                    &server_id,
                    &source_root,
                    &mount_root,
                ) && existing.phase != "READY" =>
            {
                existing
                    .machine_uuid
                    .clone()
                    .ok_or_else(|| (1, "share operation journal has no UUID".into()))?
            }
            Some(existing) if existing.phase != "READY" => {
                return Err((
                    1,
                    format!(
                        "share {share_id} has an incomplete operation for a different server, source path, or mount path; inspect node-admin journal {}",
                        existing.id
                    ),
                ));
            }
            _ => Id128::random().to_string(),
        };
        let share = macluster_core::config::ShareConfig {
            server: NodeId::new(server_id.clone()).map_err(|error| (2, error.to_string()))?,
            source_root: source_root.clone(),
            mount_root: mount_root.clone(),
            share_uuid: marker_uuid.clone(),
        };
        let queued_source =
            queue_candidate_with_node(&config, &source_text, queue_name, &server_id)?;
        let candidate = append_share_config(&queued_source, share_id, &share)?;
        let _preliminary_candidate_config =
            ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
        // Reject alias conflicts before recording an operation, writing a source
        // marker, or exporting anything. Replacing child shares has its own checks
        // because their managed alias directories are removed during migration.
        if replaced_child_shares(&config, &share).is_empty() {
            preflight_server_alias(server, &source_root, &mount_root)?;
        }
        preflight_share_clients(&config, &share)?;
        for (node_id, node) in &config.nodes {
            check_remote_idle(node, node_id, &config_path)?;
        }

        let old_digest =
            sha256_hex(source_text.as_bytes()).map_err(|error| (1, error.to_string()))?;
        let mut operation = match state.operations.get(&operation_key).cloned() {
            Some(existing) if existing.machine_uuid.as_deref() == Some(marker_uuid.as_str()) => {
                existing
            }
            Some(existing) if existing.phase != "READY" => {
                return Err((
                    1,
                    format!(
                        "share {share_id} has an incomplete prior operation {}; rerun its original mnode command using the same server and source path",
                        existing.id
                    ),
                ));
            }
            _ => NodeOperation {
                id: Id128::random().to_string(),
                action: "share".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: server_id.clone(),
                endpoint: endpoint_key,
                machine_uuid: Some(marker_uuid.clone()),
                phase: "SETUP_PENDING".into(),
                old_config_sha256: Some(old_digest.clone()),
                candidate_config_sha256: Some(
                    sha256_hex(candidate.as_bytes()).map_err(|error| (1, error.to_string()))?,
                ),
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: Some(false),
                detail: None,
            },
        };
        if operation.old_config_sha256.as_deref() != Some(old_digest.as_str()) {
            return Err((
                1,
                format!(
                    "cluster config changed while share {share_id} was being prepared; refusing to overwrite it"
                ),
            ));
        }
        operation.phase = "SETUP_PENDING".into();
        operation.detail =
            Some("share source, exports and client mounts are being prepared".into());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;

        let (staged_source, staged_config) = stage_current_agents(
            &config,
            &source_text,
            &operation.id,
            AgentStagePurpose::Share,
        )?;
        let queued_source =
            queue_candidate_with_node(&staged_config, &staged_source, queue_name, &server_id)?;
        let candidate = append_share_config(&queued_source, share_id, &share)?;
        let candidate_config =
            ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
        operation.candidate_config_sha256 =
            Some(sha256_hex(candidate.as_bytes()).map_err(|error| (1, error.to_string()))?);
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        let staged_server = candidate_config
            .nodes
            .get(&server_id)
            .expect("share server remains in candidate config");
        if staged_server.transport == Transport::Ssh {
            let handoff = enrollment_controller_epoch(state_dir).map_err(|error| (1, error))?;
            claim_enrollment_agent(
                staged_server,
                &server_id,
                &config_path,
                &config.share_uuid,
                handoff,
            )
            .map_err(|error| (1, error))?;
        }
        migrate_child_shares(&config, &share, &operation.id)?;
        prepare_share_source(staged_server, &source_root, &marker_uuid)?;
        let export_requests = config
            .nodes
            .iter()
            .filter(|(node_id, _)| node_id.as_str() != server_id)
            .map(|(node_id, node)| NfsExportRequest {
                root: source_root.to_string_lossy().into_owned(),
                client_ip: node.host.to_string(),
                share_uuid: marker_uuid.clone(),
                node_id: node_id.clone(),
            })
            .collect::<Vec<_>>();
        let (managed, export_result) = ensure_nfs_exports(server, &export_requests, &operation.id);
        operation.managed_export |= managed.iter().any(|managed| *managed);
        if let Err(error) = export_result {
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            return Err((1, error));
        }
        prepare_server_alias(server, &source_root, &mount_root)?;
        for (node_id, node) in &config.nodes {
            if node_id == &server_id {
                continue;
            }
            mount_share_candidate(node, server, &source_root, &mount_root).map_err(|error| {
                (
                    1,
                    format!("could not mount share {share_id} on {node_id}: {error}"),
                )
            })?;
        }
        verify_named_share_mount(
            server,
            &server_id,
            &server_id,
            &server.host,
            &source_root,
            &mount_root,
            &marker_uuid,
        )?;
        for (node_id, node) in &config.nodes {
            if node_id != &server_id {
                verify_named_share_mount(
                    node,
                    node_id,
                    &server_id,
                    &server.host,
                    &source_root,
                    &mount_root,
                    &marker_uuid,
                )?;
            }
        }
        let current = fs::read(&config_path).map_err(io_error)?;
        let current_digest = sha256_hex(&current).map_err(|error| (1, error.to_string()))?;
        if current_digest != old_digest {
            return Err((
                1,
                "cluster config changed during share preparation; no config was overwritten".into(),
            ));
        }
        backup_config(&config_path, &operation.id)?;
        operation.phase = "ADD_COMMITTING".into();
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        atomic_write(&config_path, candidate.as_bytes())?;
        for child_id in replaced_child_shares(&config, &share) {
            if let Some(child) = state.operations.get_mut(&format!("share:{child_id}")) {
                child.phase = "ABORTED".into();
                child.detail = Some(format!("superseded by parent share {share_id}"));
            }
        }
        operation.phase = "SYNC_PENDING".into();
        operation.detail = None;
        operation.candidate_config_sha256 =
            Some(sha256_hex(candidate.as_bytes()).map_err(|error| (1, error.to_string()))?);
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        if let Err(error) = sync_remote_configs(
            &candidate_config,
            &candidate,
            state_dir,
            &operation.id,
            None,
        ) {
            operation.detail = Some(error.clone());
            state.operations.insert(operation_key.clone(), operation);
            save_admin_state(&journal_path, &state)?;
            return Err((
                1,
                format!(
                    "share {share_id} is committed locally, but peer config sync is pending: {error}. Rerun the same mnode add command to resume."
                ),
            ));
        }
        operation.phase = "READY".into();
        operation.detail = None;
        state.operations.insert(operation_key, operation);
        save_admin_state(&journal_path, &state)?;
        println!(
            "NFS share {share_id} is available at {} on every configured node.",
            mount_root.display()
        );
        Ok(())
    })();
    finish_node_maintenance(maintenance, result)
}

fn repair_named_share(
    config_path: &Path,
    state_dir: &Path,
    config: &ClusterConfig,
    source_text: &str,
    share_id: &str,
    share: &ShareConfig,
    state: &mut AdminState,
    journal_path: &Path,
) -> AppResult<()> {
    let server_id = share.server.as_str();
    let server = &config.nodes[server_id];
    preflight_server_alias(server, &share.source_root, &share.mount_root)?;
    // The configured data source must still exist with its original identity.
    // Do not recreate a missing source as an empty replacement for user data.
    verify_named_share_mount(
        server,
        server_id,
        server_id,
        &server.host,
        &share.source_root,
        &share.source_root,
        &share.share_uuid,
    )?;
    preflight_share_clients(config, share)?;
    for (node_id, node) in &config.nodes {
        check_remote_idle(node, node_id, config_path)?;
    }

    let key = format!("share:{share_id}");
    let digest = sha256_hex(source_text.as_bytes()).map_err(|error| (1, error.to_string()))?;
    let pending = state
        .operations
        .get(&key)
        .filter(|op| !matches!(op.phase.as_str(), "READY" | "ABORTED"));
    if let Some(op) = pending
        && (op.action != "share"
            || !named_share_operation_matches(
                op,
                share_id,
                server_id,
                &share.source_root,
                &share.mount_root,
            )
            || op.machine_uuid.as_deref() != Some(share.share_uuid.as_str())
            || (op.old_config_sha256.as_deref() != Some(digest.as_str())
                && op.candidate_config_sha256.as_deref() != Some(digest.as_str())))
    {
        return Err((
            1,
            format!(
                "pending share operation {} does not match the active share/config; refusing to overwrite its recovery record",
                op.id
            ),
        ));
    }
    let mut operation = pending.cloned().unwrap_or_else(|| NodeOperation {
        id: Id128::random().to_string(),
        action: "share".into(),
        connection_endpoint: None,
        remote_config_path: None,
        node_id: server_id.into(),
        endpoint: named_share_operation_endpoint(
            share_id,
            server_id,
            &share.source_root,
            &share.mount_root,
        ),
        machine_uuid: Some(share.share_uuid.clone()),
        phase: "SETUP_PENDING".into(),
        old_config_sha256: None,
        candidate_config_sha256: None,
        managed_export: state
            .operations
            .get(&key)
            .is_some_and(|op| op.managed_export),
        managed_shares: BTreeSet::new(),
        client_setup_attempted: Some(false),
        detail: None,
    });
    operation.old_config_sha256 = Some(digest.clone());
    operation.candidate_config_sha256 = Some(digest);
    operation.phase = "SETUP_PENDING".into();
    operation.detail = Some("verifying and repairing configured NFS resources".into());
    state.operations.insert(key.clone(), operation.clone());
    save_admin_state(journal_path, state)?;

    let result = (|| -> AppResult<()> {
        prepare_server_alias(server, &share.source_root, &share.mount_root)?;
        let export_requests = config
            .nodes
            .iter()
            .filter(|(node_id, _)| node_id.as_str() != server_id)
            .map(|(node_id, node)| NfsExportRequest {
                root: share.source_root.to_string_lossy().into_owned(),
                client_ip: node.host.to_string(),
                share_uuid: share.share_uuid.clone(),
                node_id: node_id.clone(),
            })
            .collect::<Vec<_>>();
        let (managed, export_result) = ensure_nfs_exports(server, &export_requests, &operation.id);
        operation.managed_export |= managed.iter().any(|managed| *managed);
        export_result.map_err(|error| (1, error))?;
        for (node_id, node) in &config.nodes {
            if node_id == server_id {
                continue;
            }
            mount_share_candidate(node, server, &share.source_root, &share.mount_root).map_err(
                |error| {
                    (
                        1,
                        format!("cannot repair share {share_id} on {node_id}: {error}"),
                    )
                },
            )?;
        }
        for (node_id, node) in &config.nodes {
            verify_named_share_mount(
                node,
                node_id,
                server_id,
                &server.host,
                &share.source_root,
                &share.mount_root,
                &share.share_uuid,
            )?;
        }
        operation.phase = "SYNC_PENDING".into();
        state.operations.insert(key.clone(), operation.clone());
        save_admin_state(journal_path, state)?;
        sync_remote_configs(config, source_text, state_dir, &operation.id, None).map_err(
            |error| {
                (
                    1,
                    format!(
                        "share {share_id} is verified, but peer config sync is pending: {error}"
                    ),
                )
            },
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        operation.detail = Some(error.1.clone());
        state.operations.insert(key, operation);
        save_admin_state(journal_path, state)?;
        return Err(error);
    }
    operation.phase = "READY".into();
    operation.detail = None;
    state.operations.insert(key, operation);
    save_admin_state(journal_path, state)?;
    println!(
        "NFS share {share_id} is verified and available at {} on every configured node; missing exports, mounts and aliases were repaired.",
        share.mount_root.display()
    );
    Ok(())
}

fn named_share_request_matches(
    existing: &ShareConfig,
    server_id: &str,
    source_root: &Path,
    mount_root: &Path,
) -> bool {
    existing.server.as_str() == server_id
        && existing.source_root == source_root
        && existing.mount_root == mount_root
}

fn named_share_mount_root(share_id: &str, requested: Option<&str>) -> PathBuf {
    requested.map_or_else(
        || PathBuf::from(format!("/Users/Shared/macluster-shares/{share_id}")),
        PathBuf::from,
    )
}

fn named_share_operation_endpoint(
    share_id: &str,
    server_id: &str,
    source_root: &Path,
    mount_root: &Path,
) -> String {
    format!(
        "share:{share_id}:{server_id}:{}:{}",
        source_root.display(),
        mount_root.display()
    )
}

fn named_share_operation_matches(
    operation: &NodeOperation,
    share_id: &str,
    server_id: &str,
    source_root: &Path,
    mount_root: &Path,
) -> bool {
    if operation.node_id != server_id {
        return false;
    }
    if operation.endpoint
        == named_share_operation_endpoint(share_id, server_id, source_root, mount_root)
    {
        return true;
    }
    let default_mount_root = PathBuf::from(format!("/Users/Shared/macluster-shares/{share_id}"));
    mount_root == default_mount_root
        && operation.endpoint == format!("share:{share_id}:{}", source_root.display())
}

fn resolve_share_source(requested: &str, home: &str) -> AppResult<PathBuf> {
    let expanded = if let Some(relative) = requested.strip_prefix("~/") {
        format!("{home}/{relative}")
    } else if let Some(relative) = requested.strip_prefix("./") {
        format!("{home}/{relative}")
    } else if requested.starts_with('/') {
        requested.to_owned()
    } else {
        return Err((
            2,
            "share source must be absolute, ./relative, or ~/relative".into(),
        ));
    };
    let expanded = expanded.trim_end_matches('/');
    if !safe_absolute_remote_path(expanded) {
        return Err((
            2,
            "share source path is not normalized or contains unsupported characters".into(),
        ));
    }
    Ok(PathBuf::from(expanded))
}

// A parent can replace only children with exactly the same server and
// relative mapping. The pending share journal fences scheduling throughout
// this resumable transition; no user files or source markers are deleted.
fn migrate_child_shares(
    config: &ClusterConfig,
    parent: &ShareConfig,
    operation: &str,
) -> AppResult<()> {
    let ids = replaced_child_shares(config, parent);
    if ids.is_empty() {
        return Ok(());
    }
    let server = &config.nodes[parent.server.as_str()];
    let exports = read_nfs_exports(server)?;
    for id in &ids {
        let child = &config.shares[id];
        // Refuse hand-written or altered child exports before changing mounts.
        for (node_id, node) in &config.nodes {
            if node_id == parent.server.as_str() {
                continue;
            }
            let marker = format!("# macluster-managed {} {node_id}", child.share_uuid);
            let access = exports_authorize(
                &exports,
                &child.source_root.to_string_lossy(),
                &node.host,
                Some(&marker),
            );
            if !matches!(access, ExportAccess::Managed | ExportAccess::Absent) {
                return Err((
                    1,
                    format!(
                        "cannot replace share {id}: its export is not an exact managed entry; inspect /etc/exports before retrying"
                    ),
                ));
            }
        }
    }
    for (node_id, node) in &config.nodes {
        if node_id == parent.server.as_str() {
            continue;
        }
        let script = child_share_cleanup_script(config, parent, &ids, &server.host);
        run_interactive_admin_with_reason(
            node,
            &format!("retire managed child NFS mounts before changing shares on {node_id}"),
            &script,
        )
        .map_err(|error| (1, format!("cannot retire child share mounts on {node_id}: {error}. Rerun the same mnode add command to resume.")))?;
    }
    if parent.source_root != parent.mount_root {
        let script = child_share_alias_cleanup_script(config, parent, &ids);
        let result = ssh_output(server, &script, None)?;
        if !result.status.success() {
            return Err((
                1,
                command_error("cannot retire old share server aliases", &result),
            ));
        }
    }
    let export_groups = group_nfs_export_requests(ids.iter().flat_map(|id| {
        let child = &config.shares[id];
        config
            .nodes
            .iter()
            .filter(|(node_id, _)| node_id.as_str() != parent.server.as_str())
            .map(move |(node_id, node)| {
                (
                    parent.server.as_str().to_owned(),
                    NfsExportRequest {
                        root: child.source_root.to_string_lossy().into_owned(),
                        client_ip: node.host.to_string(),
                        share_uuid: child.share_uuid.clone(),
                        node_id: node_id.clone(),
                    },
                )
            })
    }));
    for (server_id, requests) in export_groups {
        let export_server = &config.nodes[&server_id];
        let statuses = remove_managed_nfs_exports(export_server, &requests, operation)
            .map_err(|error| (1, error))?;
        for (request, (_, still_authorized)) in requests.iter().zip(statuses) {
            if still_authorized {
                let share_id = ids
                    .iter()
                    .find(|id| config.shares[*id].share_uuid == request.share_uuid)
                    .map(String::as_str)
                    .unwrap_or("unknown");
                return Err((
                    1,
                    format!("share {share_id} still has an unmanaged export; inspect /etc/exports"),
                ));
            }
        }
    }
    eprintln!(
        "Parent share replaces managed child share(s): {}. Source files are preserved.",
        ids.into_iter().collect::<Vec<_>>().join(", ")
    );
    Ok(())
}

fn child_share_cleanup_script(
    config: &ClusterConfig,
    parent: &ShareConfig,
    ids: &BTreeSet<String>,
    host: &str,
) -> String {
    let parent_prefix = format!(
        "{host}:{} on {} (nfs",
        parent.source_root.display(),
        parent.mount_root.display()
    );
    let mut script = format!(
        "set -eu\nmounts=$(/sbin/mount)\nif printf '%s\\n' \"$mounts\" | /usr/bin/awk -v p={} 'index($0,p)==1 {{found=1}} END{{exit !found}}'; then exit 0; fi\n",
        shell_quote(&parent_prefix)
    );
    let mut directories = BTreeSet::new();
    for id in ids {
        let child = &config.shares[id];
        let prefix = format!(
            "{host}:{} on {} (nfs",
            child.source_root.display(),
            child.mount_root.display()
        );
        let destination = format!(" on {} (", child.mount_root.display());
        let target = shell_quote(&child.mount_root.to_string_lossy());
        let marker = shell_quote(
            &child
                .mount_root
                .join(".macluster-share-id")
                .to_string_lossy(),
        );
        script.push_str(&format!("if printf '%s\\n' \"$mounts\" | /usr/bin/awk -v p={} 'index($0,p)==1 {{found=1}} END{{exit !found}}'; then\n  [ \"$(/bin/cat {marker})\" = {} ] || {{ echo 'child share marker changed' >&2; exit 1; }}\n  /sbin/umount {target}\nelif printf '%s\\n' \"$mounts\" | /usr/bin/grep -F -- {} >/dev/null; then\n  echo 'child share mount changed' >&2; exit 1\nfi\n", shell_quote(&prefix), shell_quote(&child.share_uuid), shell_quote(&destination)));
        let mut dir = child.mount_root.as_path();
        while dir != parent.mount_root && dir.starts_with(&parent.mount_root) {
            directories.insert(dir.to_path_buf());
            dir = dir.parent().expect("contained directory");
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    for dir in directories {
        let target = shell_quote(&dir.to_string_lossy());
        script.push_str(&format!("if [ -L {target} ]; then echo 'child mount directory is a symlink' >&2; exit 1; fi\nif [ -d {target} ]; then /bin/rmdir {target}; fi\n"));
    }
    script
}

fn child_share_alias_cleanup_script(
    config: &ClusterConfig,
    parent: &ShareConfig,
    ids: &BTreeSet<String>,
) -> String {
    let target = shell_quote(&parent.mount_root.to_string_lossy());
    let source = shell_quote(&parent.source_root.to_string_lossy());
    let mut script = format!(
        "set -eu\nif [ -L {target} ]; then [ \"$(/usr/bin/readlink {target})\" = {source} ]; exit; fi\n"
    );
    let mut directories = BTreeSet::new();
    for id in ids {
        let child = &config.shares[id];
        let target = shell_quote(&child.mount_root.to_string_lossy());
        let source = shell_quote(&child.source_root.to_string_lossy());
        script.push_str(&format!("if [ -L {target} ]; then [ \"$(/usr/bin/readlink {target})\" = {source} ] || exit 1; /bin/rm {target}; elif [ -e {target} ]; then echo 'share alias changed' >&2; exit 1; fi\n"));
        let mut dir = child.mount_root.parent().expect("child parent");
        while dir.starts_with(&parent.mount_root) {
            directories.insert(dir.to_path_buf());
            if dir == parent.mount_root {
                break;
            }
            dir = dir.parent().expect("contained path");
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    for dir in directories {
        let dir = shell_quote(&dir.to_string_lossy());
        script.push_str(&format!(
            "if [ -e {dir} ]; then [ ! -L {dir} ] || exit 1; /bin/rmdir {dir}; fi\n"
        ));
    }
    script
}

fn replaced_child_shares(config: &ClusterConfig, parent: &ShareConfig) -> BTreeSet<String> {
    config
        .shares
        .iter()
        .filter(|(_, child)| {
            child.server == parent.server
                && child.mount_root != parent.mount_root
                && child
                    .mount_root
                    .strip_prefix(&parent.mount_root)
                    .ok()
                    .zip(child.source_root.strip_prefix(&parent.source_root).ok())
                    .is_some_and(|(mount, source)| mount == source)
        })
        .map(|(id, _)| id.clone())
        .collect()
}

fn remove_share_sections(source: &str, ids: &BTreeSet<String>) -> String {
    let mut skip = false;
    let mut result = String::new();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            skip = trimmed
                .strip_prefix("[shares.")
                .and_then(|s| s.strip_suffix(']'))
                .is_some_and(|id| ids.contains(id));
        }
        if !skip {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

fn append_share_config(
    source: &str,
    share_id: &str,
    share: &macluster_core::config::ShareConfig,
) -> AppResult<String> {
    let config = ClusterConfig::parse(source).map_err(|error| (2, error.to_string()))?;
    let replaced = replaced_child_shares(&config, share);
    let mut candidate = remove_share_sections(source, &replaced);
    if !candidate.ends_with('\n') {
        candidate.push('\n');
    }
    candidate.push_str(&format!(
        "\n[shares.{share_id}]\nserver = \"{}\"\nsource_root = \"{}\"\nmount_root = \"{}\"\nshare_uuid = \"{}\"\n",
        share.server,
        share.source_root.display(),
        share.mount_root.display(),
        share.share_uuid,
    ));
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

pub(crate) fn prepare_share_source(
    node: &NodeConfig,
    root: &Path,
    share_uuid: &str,
) -> AppResult<()> {
    let root = root.to_string_lossy();
    let check = format!(
        "root={}; current=''; old_ifs=$IFS; IFS='/'; set -- ${{root#/}}; IFS=$old_ifs; for part do current=\"$current/$part\"; if [ -L \"$current\" ]; then echo \"symlink path component: $current\" >&2; exit 1; fi; if [ -e \"$current\" ] && [ ! -d \"$current\" ]; then echo \"path component is not a directory: $current\" >&2; exit 1; fi; done; /bin/mkdir -p \"$root\" || exit; cd \"$root\" && /bin/pwd -P",
        shell_quote(&root)
    );
    let output = ssh_output(node, &check, None)?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != root {
        return Err((
            1,
            format!(
                "could not create or verify share source {root} as a real directory without symlink path components: {}",
                command_error("share source directory check failed", &output)
            ),
        ));
    }
    let filesystem_check = shell_join(&[
        &node.remote_binary,
        "internal",
        "local-share-source-check",
        "--path",
        &root,
    ]);
    let output = ssh_output(node, &filesystem_check, None)?;
    if !output.status.success() {
        return Err((
            1,
            format!(
                "share source {root} is not a usable NFS export: {}",
                command_error("NFS source check failed", &output)
            ),
        ));
    }
    let marker = format!("{root}/.macluster-share-id");
    let marker_is_symlink = ssh_output(node, &shell_join(&["test", "-L", &marker]), None)?;
    if marker_is_symlink.status.success() {
        return Err((
            1,
            format!("share marker at {marker} must be a regular file, not a symlink"),
        ));
    }
    let existing = ssh_output(node, &shell_join(&["test", "-f", &marker]), None)?;
    if existing.status.success() {
        let contents = ssh_output(node, &shell_join(&["/bin/cat", &marker]), None)?;
        if !contents.status.success()
            || String::from_utf8_lossy(&contents.stdout).trim() != share_uuid
        {
            return Err((
                1,
                format!("share source {root} already has a different macluster marker"),
            ));
        }
        return Ok(());
    }
    let command = format!(
        "set -C && /usr/bin/printf '%s\\n' {} > {}",
        shell_quote(share_uuid),
        shell_quote(&marker)
    );
    let output = ssh_output(node, &command, None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("could not write the managed share marker", &output),
        ));
    }
    Ok(())
}

fn validate_share_alias_paths(source: &Path, mount: &Path) -> AppResult<()> {
    if source != mount && (source.starts_with(mount) || mount.starts_with(source)) {
        return Err((
            2,
            format!(
                "share source {} and mount path {} overlap: one contains the other. Use the source directory itself as --mount-root, or a separate path outside it; check SOURCE_PATH for accidentally repeated path components",
                source.display(),
                mount.display()
            ),
        ));
    }
    Ok(())
}

fn preflight_server_alias(server: &NodeConfig, source: &Path, mount: &Path) -> AppResult<()> {
    validate_share_alias_paths(source, mount)?;
    if source == mount {
        return Ok(());
    }
    let source_text = source.to_string_lossy();
    let target = shell_quote(&mount.to_string_lossy());
    let script = format!(
        "set -eu\nif [ -L {target} ]; then [ \"$(/usr/bin/readlink {target})\" = {} ]; elif [ -e {target} ]; then exit 1; fi\n",
        shell_quote(&source_text)
    );
    let output = ssh_output(server, &script, None)?;
    if !output.status.success() {
        return Err((
            2,
            format!(
                "share mount alias {} already exists and does not point to source {}; refusing to replace the existing directory or link. Use the intended source directory as both SOURCE_PATH and --mount-root when sharing it at the same path",
                mount.display(),
                source.display()
            ),
        ));
    }
    Ok(())
}

fn prepare_server_alias(server: &NodeConfig, source: &Path, mount: &Path) -> AppResult<()> {
    preflight_server_alias(server, source, mount)?;
    if source == mount {
        return Ok(());
    }
    let source = source.to_string_lossy();
    let mount_path = mount;
    let parent = mount_path
        .parent()
        .ok_or_else(|| (2, "share mount path has no parent".into()))?;
    let mount = mount_path.to_string_lossy();
    let mkdir = shell_join(&["/bin/mkdir", "-p", &parent.to_string_lossy()]);
    let output = ssh_output(server, &mkdir, None)?;
    if !output.status.success() {
        return Err((
            1,
            command_error("could not create share alias parent", &output),
        ));
    }
    let exists = ssh_output(server, &shell_join(&["test", "-e", &mount]), None)?;
    if exists.status.success() {
        let readlink = ssh_output(server, &shell_join(&["/usr/bin/readlink", &mount]), None)?;
        if readlink.status.success() && String::from_utf8_lossy(&readlink.stdout).trim() == source {
            return Ok(());
        }
        return Err((
            1,
            format!(
                "share mount alias {} already exists and is not managed by this operation",
                mount
            ),
        ));
    }
    let output = ssh_output(
        server,
        &format!(
            "/bin/ln -s {} {}",
            shell_quote(&source),
            shell_quote(&mount)
        ),
        None,
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err((
            1,
            command_error("could not create share server alias", &output),
        ))
    }
}

fn preflight_share_clients(config: &ClusterConfig, share: &ShareConfig) -> AppResult<()> {
    let server = &config.nodes[share.server.as_str()];
    let children = replaced_child_shares(config, share)
        .iter()
        .map(|id| {
            let child = &config.shares[id];
            (
                child.mount_root.clone(),
                format!("{}:{}", server.host, child.source_root.display()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (node_id, node) in &config.nodes {
        if node_id == share.server.as_str() {
            continue;
        }
        preflight_share_mount(
            node,
            server,
            &share.source_root,
            &share.mount_root,
            &children,
        )
        .map_err(|error| {
            (
                2,
                format!("share client preflight failed on {node_id}: {error}"),
            )
        })?;
        preflight_client_share_alias(node, &share.source_root, &share.mount_root).map_err(
            |error| {
                (
                    2,
                    format!("share source path preflight failed on {node_id}: {error}"),
                )
            },
        )?;
    }
    Ok(())
}

// Read-only: accept the exact NFS mount, or directories that can be used
// without hiding files. Enrollment may explicitly opt into overlaying a
// same-path named software share; all ordinary share setup remains strict.
fn preflight_share_mount(
    node: &NodeConfig,
    server: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
    children: &BTreeMap<PathBuf, String>,
) -> Result<NamedShareMountStatus, String> {
    preflight_share_mount_with_overlay(node, server, source_root, mount_root, children, false)
}

fn preflight_share_mount_with_overlay(
    node: &NodeConfig,
    server: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
    children: &BTreeMap<PathBuf, String>,
    allow_existing_contents: bool,
) -> Result<NamedShareMountStatus, String> {
    let source = format!("{}:{}", server.host, source_root.display());
    let mount_text = mount_root.to_string_lossy();
    if allow_existing_contents && source_root != mount_root {
        return Err(
            "existing target contents may only be overlaid when source and mount paths match"
                .into(),
        );
    }
    let output = ssh_output(node, "/sbin/mount", None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(command_error("cannot inspect share client mounts", &output));
    }
    let table = String::from_utf8_lossy(&output.stdout);
    match named_share_mount_status(&table, &source, &mount_text) {
        NamedShareMountStatus::Expected => return Ok(NamedShareMountStatus::Expected),
        NamedShareMountStatus::MountedElsewhere(other) => {
            return Err(format!(
                "mount point {mount_text} is already mounted from {other}; refusing to mount {source}"
            ));
        }
        NamedShareMountStatus::NotMounted => {}
    }

    let mut allowed = BTreeSet::from([mount_root.to_path_buf()]);
    let mut pruned = Vec::new();
    for (child, expected_source) in children {
        if child == mount_root || !child.starts_with(mount_root) {
            return Err("managed child share is outside its prospective parent".into());
        }
        match named_share_mount_status(&table, expected_source, &child.to_string_lossy()) {
            NamedShareMountStatus::Expected => pruned.push(child.clone()),
            NamedShareMountStatus::MountedElsewhere(other) => {
                return Err(format!(
                    "child share {} is mounted from {other}",
                    child.display()
                ));
            }
            NamedShareMountStatus::NotMounted => {}
        }
        let mut dir = child.as_path();
        while dir != mount_root {
            allowed.insert(dir.to_path_buf());
            dir = dir.parent().ok_or("child share has no parent")?;
        }
    }
    let mut script = format!(
        "set -eu\nroot={}\ncurrent=''\nold_ifs=$IFS; IFS='/'; set -- ${{root#/}}; IFS=$old_ifs\nfor part do current=\"$current/$part\"; if [ -L \"$current\" ]; then echo \"symlink mount path component: $current\" >&2; exit 1; fi; if [ -e \"$current\" ] && [ ! -d \"$current\" ]; then echo \"mount path component is not a directory: $current\" >&2; exit 1; fi; done\n",
        shell_quote(&mount_text)
    );
    for path in &allowed {
        let p = shell_quote(&path.to_string_lossy());
        script.push_str(&format!("if [ -L {p} ]; then echo 'symlink in managed child mount path' >&2; exit 1; fi; if [ -e {p} ] && [ ! -d {p} ]; then echo 'managed child mount path is not a directory' >&2; exit 1; fi\n"));
    }
    if !allow_existing_contents {
        let mut find = vec!["/usr/bin/find".to_owned(), mount_text.to_string()];
        if !pruned.is_empty() {
            find.push("(".into());
            for (index, path) in pruned.iter().enumerate() {
                if index > 0 {
                    find.push("-o".into());
                }
                find.extend(["-path".into(), path.to_string_lossy().into_owned()]);
            }
            find.extend([")".into(), "-prune".into(), "-o".into()]);
        }
        find.extend(["!".into(), "(".into()]);
        for (index, path) in allowed.iter().enumerate() {
            if index > 0 {
                find.push("-o".into());
            }
            find.extend(["-path".into(), path.to_string_lossy().into_owned()]);
        }
        find.extend([
            ")".into(),
            "!".into(),
            "-type".into(),
            "d".into(),
            "-print".into(),
            "-prune".into(),
        ]);
        let refs = find.iter().map(String::as_str).collect::<Vec<_>>();
        script.push_str(&format!(
            "if [ -d \"$root\" ]; then {}; fi\n",
            shell_join(&refs)
        ));
    }
    let output = ssh_output(node, &script, None).map_err(|(_, error)| error)?;
    if !output.status.success() {
        return Err(command_error(
            &format!("cannot inspect mount point {mount_text}"),
            &output,
        ));
    }
    if !allow_existing_contents && !output.stdout.is_empty() {
        return Err(format!(
            "mount point {mount_text} is not empty; refusing to hide existing files or unrelated directories"
        ));
    }
    Ok(NamedShareMountStatus::NotMounted)
}

fn mount_share_candidate(
    node: &NodeConfig,
    server: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
) -> Result<(), String> {
    let request = prepare_share_mount_request(node, server, source_root, mount_root)?;
    if let Some(request) = request {
        run_client_mount_batch(
            node,
            std::slice::from_ref(&request),
            None,
            &format!(
                "mount named NFS share {} at {} and expose its original source path",
                server.host,
                mount_root.display()
            ),
        )?;
    }
    verify_named_share_mount_on_client(node, server, source_root, mount_root)
}

fn prepare_share_mount_request(
    node: &NodeConfig,
    server: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
) -> Result<Option<ClientMountRequest>, String> {
    prepare_share_mount_request_with_overlay(node, server, source_root, mount_root, false)
}

fn prepare_share_mount_request_with_overlay(
    node: &NodeConfig,
    server: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
    allow_existing_contents: bool,
) -> Result<Option<ClientMountRequest>, String> {
    let source = format!("{}:{}", server.host, source_root.display());
    let mount_text = mount_root.to_string_lossy();
    match preflight_share_mount_with_overlay(
        node,
        server,
        source_root,
        mount_root,
        &BTreeMap::new(),
        allow_existing_contents,
    )? {
        NamedShareMountStatus::Expected => {
            preflight_client_share_alias(node, source_root, mount_root)?;
            if source_root == mount_root {
                return Ok(Some(ClientMountRequest {
                    source,
                    mount_root: mount_root.to_path_buf(),
                    source_alias: None,
                    needs_privileged_mkdir: false,
                    needs_mount: false,
                    allow_existing_contents: false,
                }));
            }
            let alias_script = client_share_alias_script(source_root, mount_root);
            let output = ssh_output(node, &alias_script, None).map_err(|(_, error)| error)?;
            if output.status.success() {
                return Ok(Some(ClientMountRequest {
                    source,
                    mount_root: mount_root.to_path_buf(),
                    source_alias: Some(source_root.to_path_buf()),
                    needs_privileged_mkdir: false,
                    needs_mount: false,
                    allow_existing_contents: false,
                }));
            }
            if mount_point_permission_error(&String::from_utf8_lossy(&output.stderr)) {
                return Ok(Some(ClientMountRequest {
                    source,
                    mount_root: mount_root.to_path_buf(),
                    source_alias: Some(source_root.to_path_buf()),
                    needs_privileged_mkdir: false,
                    needs_mount: false,
                    allow_existing_contents: false,
                }));
            }
            return Err(command_error("could not create source path alias", &output));
        }
        NamedShareMountStatus::MountedElsewhere(other) => {
            return Err(format!(
                "mount point {mount_text} is already mounted from {other}; refusing to mount {source}"
            ));
        }
        NamedShareMountStatus::NotMounted => {}
    }
    preflight_client_share_alias(node, source_root, mount_root)?;
    let mkdir = shell_join(&["/bin/mkdir", "-p", &mount_text]);
    let output = ssh_output(node, &mkdir, None).map_err(|(_, error)| error)?;
    let mut privileged_mkdir = false;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        if mount_point_permission_error(&detail) {
            privileged_mkdir = true;
        } else {
            return Err(command_error(
                "could not prepare share mount point",
                &output,
            ));
        }
    }
    match preflight_share_mount_with_overlay(
        node,
        server,
        source_root,
        mount_root,
        &BTreeMap::new(),
        allow_existing_contents,
    )? {
        NamedShareMountStatus::NotMounted => {}
        NamedShareMountStatus::Expected => {
            return Ok(Some(ClientMountRequest {
                source,
                mount_root: mount_root.to_path_buf(),
                source_alias: (source_root != mount_root).then(|| source_root.to_path_buf()),
                needs_privileged_mkdir: false,
                needs_mount: false,
                allow_existing_contents: false,
            }));
        }
        NamedShareMountStatus::MountedElsewhere(other) => {
            return Err(format!(
                "mount point {mount_text} is already mounted from {other}; refusing to mount {source}"
            ));
        }
    }
    Ok(Some(ClientMountRequest {
        source,
        mount_root: mount_root.to_path_buf(),
        source_alias: (source_root != mount_root).then(|| source_root.to_path_buf()),
        needs_privileged_mkdir: privileged_mkdir,
        needs_mount: true,
        allow_existing_contents,
    }))
}

fn run_client_mount_batch(
    node: &NodeConfig,
    requests: &[ClientMountRequest],
    power_script: Option<&str>,
    purpose: &str,
) -> Result<(), String> {
    run_client_mount_batch_with_preparation(node, requests, "", power_script, purpose)
}

fn run_client_mount_batch_with_preparation(
    node: &NodeConfig,
    requests: &[ClientMountRequest],
    preparation: &str,
    power_script: Option<&str>,
    purpose: &str,
) -> Result<(), String> {
    let mount_script = persistent_mount_batch_script(node, requests);
    let mount_script = mount_script.map(|mounts| format!("{preparation}\n{mounts}"));
    let Some(script) = candidate_admin_script(power_script, mount_script.as_deref()) else {
        return Ok(());
    };
    run_interactive_admin_with_reason(node, purpose, &script)
}

fn verify_named_share_mount_on_client(
    node: &NodeConfig,
    server: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
) -> Result<(), String> {
    let source = format!("{}:{}", server.host, source_root.display());
    let mount_text = mount_root.to_string_lossy();
    let mounts = ssh_output(node, "/sbin/mount", None).map_err(|(_, error)| error)?;
    if mounts.status.success()
        && named_share_mount_status(
            &String::from_utf8_lossy(&mounts.stdout),
            &source,
            &mount_text,
        ) == NamedShareMountStatus::Expected
    {
        verify_client_share_alias(node, source_root, mount_root)
    } else {
        Err(format!("{mount_text} is not mounted from {source}"))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum NamedShareMountStatus {
    NotMounted,
    Expected,
    MountedElsewhere(String),
}

pub(crate) fn named_share_mount_status(
    mount_output: &str,
    expected_source: &str,
    mount_path: &str,
) -> NamedShareMountStatus {
    let mut found = None;
    for line in mount_output.lines() {
        let Some((source, destination_and_type)) = line.split_once(" on ") else {
            continue;
        };
        let Some((destination, filesystem)) = destination_and_type.split_once(" (") else {
            continue;
        };
        if destination != mount_path || !filesystem.ends_with(')') {
            continue;
        }
        if found.is_some() {
            return NamedShareMountStatus::MountedElsewhere(
                "multiple mounts at the requested path".into(),
            );
        }
        let filesystem_type = filesystem
            .strip_suffix(')')
            .and_then(|filesystem| filesystem.split(',').next())
            .map(str::trim);
        found = Some(
            if source == expected_source && filesystem_type == Some("nfs") {
                NamedShareMountStatus::Expected
            } else {
                NamedShareMountStatus::MountedElsewhere(source.to_owned())
            },
        );
    }
    found.unwrap_or(NamedShareMountStatus::NotMounted)
}

fn mount_point_permission_error(stderr: &str) -> bool {
    stderr.contains("Permission denied") || stderr.contains("Operation not permitted")
}

fn client_share_alias_script(alias: &Path, target: &Path) -> String {
    let alias = shell_quote(&alias.to_string_lossy());
    let target = shell_quote(&target.to_string_lossy());
    format!(
        "set -eu\nalias_path={alias}\ntarget_path={target}\nif [ -L \"$alias_path\" ]; then\n  actual=$(/usr/bin/readlink \"$alias_path\")\n  [ \"$actual\" = \"$target_path\" ] || {{ echo 'source path is an unrelated symlink' >&2; exit 1; }}\nelse\n  if [ -e \"$alias_path\" ]; then\n    [ -d \"$alias_path\" ] || {{ echo 'source path is not a directory' >&2; exit 1; }}\n    unexpected=$(/usr/bin/find \"$alias_path\" -mindepth 1 ! -type d -print -quit)\n    [ -z \"$unexpected\" ] || {{ echo 'source path contains files or other entries' >&2; exit 1; }}\n    /usr/bin/find \"$alias_path\" -depth -type d -exec /bin/rmdir {{}} +\n  fi\n  /bin/mkdir -p \"$(/usr/bin/dirname \"$alias_path\")\"\n  /bin/ln -s \"$target_path\" \"$alias_path\"\nfi\n"
    )
}

fn preflight_client_share_alias(
    node: &NodeConfig,
    alias: &Path,
    target: &Path,
) -> Result<(), String> {
    if alias == target {
        return Ok(());
    }
    let alias_text = shell_quote(&alias.to_string_lossy());
    let target_text = shell_quote(&target.to_string_lossy());
    let script = format!(
        "set -eu\nalias_path={alias_text}\ntarget_path={target_text}\nif [ -L \"$alias_path\" ]; then actual=$(/usr/bin/readlink \"$alias_path\"); [ \"$actual\" = \"$target_path\" ] || {{ echo 'source path is an unrelated symlink' >&2; exit 1; }}; elif [ -e \"$alias_path\" ]; then [ -d \"$alias_path\" ] || {{ echo 'source path is not a directory' >&2; exit 1; }}; unexpected=$(/usr/bin/find \"$alias_path\" -mindepth 1 ! -type d -print -quit); [ -z \"$unexpected\" ] || {{ echo 'source path contains files or other entries' >&2; exit 1; }}; fi\n"
    );
    let output = ssh_output(node, &script, None).map_err(|(_, error)| error)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(
            &format!("cannot safely expose source path {}", alias.display()),
            &output,
        ))
    }
}

fn verify_client_share_alias(node: &NodeConfig, alias: &Path, target: &Path) -> Result<(), String> {
    if alias == target {
        return Ok(());
    }
    let alias_text = shell_quote(&alias.to_string_lossy());
    let target_text = shell_quote(&target.to_string_lossy());
    let script =
        format!("[ -L {alias_text} ] && [ \"$(/usr/bin/readlink {alias_text})\" = {target_text} ]");
    let output = ssh_output(node, &script, None).map_err(|(_, error)| error)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(
            &format!(
                "source path alias {} does not point to {}",
                alias.display(),
                target.display()
            ),
            &output,
        ))
    }
}

fn configure_node_nfs_resources(
    config: &ClusterConfig,
    node_id: &str,
    node: &NodeConfig,
    operation_id: &str,
    managed_export: &mut bool,
    managed_shares: &mut BTreeSet<String>,
    power_setup: Option<PowerHelperSetup>,
    existing_power_setups: BTreeMap<String, PowerHelperSetup>,
) -> Result<(), String> {
    configure_node_nfs_resources_with_claim(
        config,
        node_id,
        node,
        operation_id,
        managed_export,
        managed_shares,
        power_setup,
        existing_power_setups,
        None,
    )
}

fn configure_node_nfs_resources_with_claim(
    config: &ClusterConfig,
    node_id: &str,
    node: &NodeConfig,
    operation_id: &str,
    managed_export: &mut bool,
    managed_shares: &mut BTreeSet<String>,
    power_setup: Option<PowerHelperSetup>,
    mut existing_power_setups: BTreeMap<String, PowerHelperSetup>,
    claim: Option<ControllerEpoch>,
) -> Result<(), String> {
    let result = (|| -> Result<(), String> {
        let mut export_entries = Vec::new();
        let mut mount_requests = Vec::new();
        let mut primary_preparation = String::new();
        let storage_id = config.storage_server.as_str();
        let storage = &config.nodes[storage_id];
        if node_id != storage_id {
            let request = match candidate_mount_command(
                node,
                storage,
                config.primary_source_root(),
                &config.shared_root,
            ) {
                Ok(request) => request,
                Err(error)
                    if claim.is_some()
                        && (error.contains("not empty and is not mounted")
                            || error.contains("already mounted from")) =>
                {
                    let plan = primary_reuse::plan(
                        node,
                        storage,
                        config.primary_source_root(),
                        &config.shared_root,
                        &config.share_uuid,
                        operation_id,
                    )?;
                    primary_preparation = plan.preparation;
                    eprintln!(
                        "Previous local shared data will be preserved at {}",
                        plan.backup_path.display()
                    );
                    Some(plan.request)
                }
                Err(error) => return Err(error),
            };
            if let Some(request) = request {
                mount_requests.push(request);
            }
            export_entries.push((
                storage_id.to_owned(),
                NfsExportRequest {
                    root: config.primary_source_root().to_string_lossy().into_owned(),
                    client_ip: node.host.to_string(),
                    share_uuid: config.share_uuid.clone(),
                    node_id: node_id.to_owned(),
                },
            ));
        }

        for (share_id, share) in &config.shares {
            let server_id = share.server.as_str();
            let server = if node_id == server_id {
                node
            } else {
                config.nodes.get(server_id).ok_or_else(|| {
                    format!("NFS server {server_id} for share {share_id} is missing")
                })?
            };
            if node_id == server_id {
                prepare_server_alias(server, &share.source_root, &share.mount_root)
                    .map_err(|(_, error)| error)?;
            } else {
                let has_nested_share = config.shares.iter().any(|(other_id, other_share)| {
                    other_id != share_id
                        && other_share.mount_root != share.mount_root
                        && other_share.mount_root.starts_with(&share.mount_root)
                });
                let allow_existing_contents =
                    claim.is_some() && !has_nested_share && share.source_root == share.mount_root;
                let request = prepare_share_mount_request_with_overlay(
                    node,
                    server,
                    &share.source_root,
                    &share.mount_root,
                    allow_existing_contents,
                )?;
                if allow_existing_contents
                    && request.as_ref().is_some_and(|request| request.needs_mount)
                {
                    eprintln!(
                        "Existing local files under {} are preserved and will be visible again when share '{}' is unmounted.",
                        share.mount_root.display(),
                        share_id
                    );
                }
                if let Some(request) = request {
                    mount_requests.push(request);
                }
                export_entries.push((
                    server_id.to_owned(),
                    NfsExportRequest {
                        root: share.source_root.to_string_lossy().into_owned(),
                        client_ip: node.host.to_string(),
                        share_uuid: share.share_uuid.clone(),
                        node_id: node_id.to_owned(),
                    },
                ));
            }
        }

        if let Some(controller) = claim {
            // All mount planning and consent above are read-only. Claim under
            // the Agent lock before exports, unmounts, or local data change.
            claim_enrollment_agent(
                node,
                node_id,
                Path::new("/dev/null"),
                &config.share_uuid,
                controller,
            )?;
        }
        for (server_id, requests) in group_nfs_export_requests(export_entries) {
            let server = config
                .nodes
                .get(&server_id)
                .ok_or_else(|| format!("NFS server {server_id} is missing"))?;
            let server_power_setup = existing_power_setups.remove(&server_id);
            let (managed, result) = ensure_nfs_exports_with_setup(
                server,
                &requests,
                operation_id,
                server_power_setup
                    .as_ref()
                    .map(|setup| setup.script.as_str()),
            );
            if let Some(setup) = &server_power_setup {
                cleanup_power_helper_stage(server, setup);
            }
            for (request, is_managed) in requests.iter().zip(managed) {
                if !is_managed {
                    continue;
                }
                if request.share_uuid == config.share_uuid {
                    *managed_export = true;
                } else if let Some((share_id, _)) = config
                    .shares
                    .iter()
                    .find(|(_, share)| share.share_uuid == request.share_uuid)
                {
                    managed_shares.insert(share_id.clone());
                }
            }
            result?;
        }

        for (existing_node_id, setup) in std::mem::take(&mut existing_power_setups) {
            if let Some(existing_node) = config.nodes.get(&existing_node_id) {
                let script = candidate_admin_script(Some(&setup.script), None)
                    .expect("power setup creates an administrative script");
                if let Err(error) = run_interactive_admin_with_reason(
                    existing_node,
                    "install or refresh the mtop power sampler",
                    &script,
                ) {
                    eprintln!("Power sampler setup for {existing_node_id} was skipped: {error}");
                }
                cleanup_power_helper_stage(existing_node, &setup);
            }
        }

        let power_script = power_setup.as_ref().map(|setup| setup.script.as_str());
        if !mount_requests.is_empty() || power_script.is_some() {
            run_client_mount_batch_with_preparation(
                node,
                &mount_requests,
                &primary_preparation,
                power_script,
                if power_script.is_some() {
                    "configure primary and named NFS mounts and the mtop power sampler"
                } else {
                    "configure primary and named NFS mounts"
                },
            )?;
        }

        if node_id != storage_id {
            verify_candidate_mount(
                node,
                storage,
                config.primary_source_root(),
                &config.shared_root,
            )?;
        }
        for (share_id, share) in &config.shares {
            let server_id = share.server.as_str();
            let server = if node_id == server_id {
                node
            } else {
                &config.nodes[server_id]
            };
            verify_named_share_mount(
                node,
                node_id,
                server_id,
                &server.host,
                &share.source_root,
                &share.mount_root,
                &share.share_uuid,
            )
            .map_err(|(_, error)| format!("share {share_id}: {error}"))?;
            if node_id != server_id {
                verify_client_share_alias(node, &share.source_root, &share.mount_root)?;
            }
        }
        Ok(())
    })();

    if let Some(setup) = &power_setup {
        cleanup_power_helper_stage(node, setup);
    }
    for (existing_node_id, setup) in existing_power_setups {
        if let Some(existing_node) = config.nodes.get(&existing_node_id) {
            cleanup_power_helper_stage(existing_node, &setup);
        }
    }
    result
}

fn verify_named_share_mount(
    node: &NodeConfig,
    node_id: &str,
    server_id: &str,
    server_host: &str,
    source: &Path,
    mount: &Path,
    uuid: &str,
) -> AppResult<()> {
    let is_server = node_id == server_id;
    let marker_root = if is_server { source } else { mount };
    let marker = marker_root.join(".macluster-share-id");
    let marker_is_symlink = ssh_output(
        node,
        &shell_join(&["test", "-L", &marker.to_string_lossy()]),
        None,
    )?;
    if marker_is_symlink.status.success() {
        return Err((
            1,
            format!("share marker at {} is a symlink", marker.display()),
        ));
    }
    let output = ssh_output(
        node,
        &shell_join(&["/bin/cat", &marker.to_string_lossy()]),
        None,
    )?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim() != uuid {
        return Err((
            1,
            format!("share marker at {} did not match", marker.display()),
        ));
    }
    if source != mount && is_server {
        let alias = ssh_output(
            node,
            &shell_join(&["/usr/bin/readlink", &mount.to_string_lossy()]),
            None,
        )?;
        if !alias.status.success()
            || String::from_utf8_lossy(&alias.stdout).trim() != source.to_string_lossy()
        {
            return Err((
                1,
                "share server alias does not point to the configured source".into(),
            ));
        }
    } else if !is_server {
        let mounts = ssh_output(node, "/sbin/mount", None)?;
        if !mounts.status.success() {
            return Err((
                1,
                command_error("cannot inspect named share mount", &mounts),
            ));
        }
        let expected_source = format!("{server_host}:{}", source.display());
        if named_share_mount_status(
            &String::from_utf8_lossy(&mounts.stdout),
            &expected_source,
            &mount.to_string_lossy(),
        ) != NamedShareMountStatus::Expected
        {
            return Err((
                1,
                format!(
                    "{} is not mounted from {}",
                    mount.display(),
                    source.display()
                ),
            ));
        }
    }
    Ok(())
}

fn should_resume_add_operation(phase: &str) -> bool {
    !matches!(phase, "READY" | "ABORTED")
}

fn pending_add_operation_for_endpoint(
    state: &AdminState,
    active_node_ids: &BTreeSet<String>,
    endpoint: &str,
) -> Option<(String, NodeOperation)> {
    state
        .operations
        .iter()
        .filter(|(_, operation)| {
            operation.action == "add"
                && operation.endpoint == endpoint
                && should_resume_add_operation(&operation.phase)
                && !active_node_ids.contains(&operation.node_id)
        })
        .min_by(|(_, left), (_, right)| {
            left.node_id
                .cmp(&right.node_id)
                .then_with(|| left.id.cmp(&right.id))
        })
        .map(|(key, operation)| (key.clone(), operation.clone()))
}

fn abort_duplicate_pristine_adds(
    state: &mut AdminState,
    endpoint: &str,
    keep_node_id: &str,
    machine_uuid: &str,
) -> usize {
    let mut aborted = 0;
    for operation in state.operations.values_mut() {
        if operation.action == "add"
            && operation.endpoint == endpoint
            && operation.node_id != keep_node_id
            && operation.phase == "SETUP_PENDING"
            && operation.machine_uuid.as_deref() == Some(machine_uuid)
            && operation.candidate_config_sha256.is_none()
            && !operation.managed_export
            && operation.managed_shares.is_empty()
        {
            operation.phase = "ABORTED".into();
            operation.detail = Some(format!(
                "duplicate pristine enrollment superseded by {keep_node_id}; this node ID remains reserved"
            ));
            aborted += 1;
        }
    }
    aborted
}

fn add_local_node(
    config_path: &Path,
    state_dir: &Path,
    selected_queue: Option<&str>,
    explicit_host: Option<Ipv4Addr>,
    defer_queue_for_share: bool,
) -> AppResult<()> {
    let maintenance = acquire_node_maintenance_scoped(
        config_path,
        state_dir,
        "local node enrollment",
        MaintenanceScope::Cluster,
    )?;
    if maintenance.recovered {
        return Ok(());
    }
    let result = (|| -> AppResult<()> {
        MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(|error| {
            (
                1,
                format!("cluster config/state directory binding failed: {error}"),
            )
        })?;
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let config_path = config_path.canonicalize().map_err(io_error)?;
        let source = fs::read_to_string(&config_path).map_err(io_error)?;
        let config = ClusterConfig::parse(&source).map_err(|error| (2, error.to_string()))?;
        let queue_name = selected_queue.unwrap_or(config.default_queue.as_str());
        if !config.queues.contains_key(queue_name) {
            return Err((2, format!("queue '{queue_name}' is not configured")));
        }
        let host = resolve_local_host(&config, explicit_host)?;
        let machine_uuid = local_platform_uuid()?;
        let execution_uid = unsafe { libc::geteuid() };
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, state_dir)?;
        let operation_key = format!("add-local:{machine_uuid}");
        if let Some(previous) = state
            .operations
            .get(&operation_key)
            .filter(|operation| operation.phase == "ABORTED")
        {
            state.reserved_node_ids.insert(previous.node_id.clone());
        }
        let pending_node_id = state
            .operations
            .get(&operation_key)
            .filter(|operation| !matches!(operation.phase.as_str(), "READY" | "ABORTED"))
            .map(|operation| operation.node_id.clone());
        let existing_id = find_local_machine_registration(&config, &host, &machine_uuid)?;
        let binary_path = std::env::current_exe().map_err(io_error)?;
        let binary = normalize_binary_path(&binary_path)?;
        let node_id = if let Some(id) = existing_id.as_deref() {
            if let Some(existing) = config.nodes.get(id) {
                if existing.transport != Transport::Local {
                    check_remote_idle(existing, id, &config_path)?;
                }
            }
            id.to_owned()
        } else if let Some(id) = pending_node_id {
            id
        } else {
            let mut reserved = state.reserved_node_ids.clone();
            reserved.extend(config.nodes.keys().cloned());
            if let Ok(storage) = Storage::open(state_dir) {
                for job in storage
                    .list_jobs(None)
                    .map_err(|error| (1, error.to_string()))?
                {
                    if let Some(node) = job.node {
                        reserved.insert(node.to_string());
                    }
                    if let Some(node) = job.spec.node {
                        reserved.insert(node.to_string());
                    }
                }
            }
            allocate_node_id(queue_name, &reserved)?
        };
        for (existing_id, node) in &config.nodes {
            check_remote_idle(node, existing_id, &config_path)?;
        }
        let storage_node = config
            .nodes
            .get(config.storage_server.as_str())
            .expect("storage server is configured");
        let storage_facts = read_remote_facts(storage_node)?;
        let local_gid = unsafe { libc::getegid() };
        if execution_uid != storage_facts.uid || local_gid != storage_facts.gid {
            return Err((
                2,
                format!(
                    "login node UID/GID is {execution_uid}/{local_gid}, but shared storage requires {}/{}",
                    storage_facts.uid, storage_facts.gid
                ),
            ));
        }
        let local_node = NodeConfig {
            host: host.to_string(),
            transport: Transport::Local,
            remote_binary: binary.clone(),
            ssh_user: None,
            ssh_port: None,
            ssh_identity_file: None,
            remote_config: Some(config_path.to_string_lossy().into_owned()),
            machine_uuid: Some(machine_uuid.clone()),
            execution_uid: Some(execution_uid),
        };
        let digest = sha256_hex(source.as_bytes()).map_err(|error| (1, error.to_string()))?;
        let mut operation = state
            .operations
            .get(&operation_key)
            .filter(|operation| should_resume_add_operation(&operation.phase))
            .cloned()
            .unwrap_or_else(|| NodeOperation {
                id: Id128::random().to_string(),
                action: "add".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: node_id.clone(),
                endpoint: format!("local@{host}:22"),
                machine_uuid: Some(machine_uuid.clone()),
                phase: "SETUP_PENDING".into(),
                old_config_sha256: Some(digest.clone()),
                candidate_config_sha256: None,
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: Some(false),
                detail: None,
            });
        operation.node_id = node_id.clone();
        if operation
            .old_config_sha256
            .as_deref()
            .is_some_and(|old| old != digest)
        {
            return Err((
            1,
            "cluster config changed during local enrollment; inspect the node admin journal before retrying".into(),
        ));
        }
        operation.phase = "SETUP_PENDING".into();
        operation.old_config_sha256 = Some(digest.clone());
        operation.candidate_config_sha256 = None;
        operation.detail = Some("agent binaries are being staged before config activation".into());
        state
            .machine_uuids
            .insert(node_id.clone(), machine_uuid.clone());
        state.reserved_node_ids.insert(node_id.clone());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        let (staged_source, staged_config) = stage_current_agents(
            &config,
            &source,
            &operation.id,
            // The target's power helper is installed later in the same privileged
            // client batch as its primary/named mounts. Existing nodes only need
            // binary staging here; installing their helper here could prompt twice
            // on the primary storage server during this enrollment.
            AgentStagePurpose::Share,
        )?;
        let local_node = NodeConfig {
            remote_binary: binary,
            ..local_node
        };
        let existing_power_setups = if defer_queue_for_share {
            BTreeMap::new()
        } else {
            prepare_power_helpers_for_nodes(&staged_config, &operation.id, Some(&machine_uuid))
        };
        let power_setup = if defer_queue_for_share {
            None
        } else {
            match prepare_power_helper(
                &local_node,
                execution_uid,
                std::env::consts::ARCH,
                &operation.id,
            ) {
                Ok(setup) => setup,
                Err(error) => {
                    eprintln!("Power sampler setup for local node {node_id} was skipped: {error}");
                    None
                }
            }
        };
        operation.client_setup_attempted = Some(true);
        operation.detail = Some("client NFS resources are being configured".into());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        if let Err(error) = configure_node_nfs_resources(
            &config,
            &node_id,
            &local_node,
            &operation.id,
            &mut operation.managed_export,
            &mut operation.managed_shares,
            power_setup,
            existing_power_setups,
        ) {
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            return Err((1, error));
        }
        if let Err((_, error)) = verify_login_share(&config_path) {
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&journal_path, &state)?;
            return Err((
                1,
                format!(
                    "login node must see the primary shared directory before enrollment can complete: {error}"
                ),
            ));
        }
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        let candidate = local_config_candidate(
            &staged_config,
            &staged_source,
            &node_id,
            queue_name,
            !defer_queue_for_share,
            &local_node,
        )?;
        let candidate_config =
            ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
        operation.phase = "ADD_COMMITTING".into();
        operation.candidate_config_sha256 =
            Some(sha256_hex(candidate.as_bytes()).map_err(|error| (1, error.to_string()))?);
        operation.detail = Some("local node config is being committed".into());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        backup_config(&config_path, &operation.id)?;
        atomic_write(&config_path, candidate.as_bytes())?;
        operation.phase = "SYNC_PENDING".into();
        operation.detail = None;
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&journal_path, &state)?;
        if let Err(error) = sync_remote_configs(
            &candidate_config,
            &candidate,
            state_dir,
            &operation.id,
            Some(&node_id),
        ) {
            operation.detail = Some(error.clone());
            state.operations.insert(operation_key.clone(), operation);
            save_admin_state(&journal_path, &state)?;
            return Err((
                1,
                format!(
                    "local node {node_id} is configured, but peer config sync is pending: {error}. Rerun `mnode -a local` to resume."
                ),
            ));
        }
        operation.phase = "READY".into();
        operation.detail = None;
        state.operations.insert(operation_key, operation);
        save_admin_state(&journal_path, &state)?;
        if defer_queue_for_share {
            println!(
                "Prepared local node {node_id}; it remains outside all queues until its requested NFS share commits."
            );
        } else {
            println!(
                "Local login node {node_id} is ready at {host} and stays outside compute queues."
            );
        }
        Ok(())
    })();
    finish_node_maintenance(maintenance, result)
}

fn local_config_candidate(
    config: &ClusterConfig,
    source: &str,
    node_id: &str,
    queue_name: &str,
    include_in_queue: bool,
    node: &NodeConfig,
) -> AppResult<String> {
    if !config.queues.contains_key(queue_name) {
        return Err((2, format!("queue '{queue_name}' is not configured")));
    }
    let is_login = config.login_node.is_none()
        || config
            .login_node
            .as_ref()
            .is_some_and(|login| login.as_str() == node_id);
    let mut candidate = source.to_owned();
    for (name, queue) in &config.queues {
        let mut members = queue.nodes.clone();
        if is_login {
            members.retain(|member| member != node_id);
        }
        if name == queue_name
            && include_in_queue
            && !is_login
            && !members.iter().any(|member| member == node_id)
        {
            members.push(node_id.to_owned());
        }
        candidate = replace_queue_members(&candidate, name, &members)?;
    }
    if config.login_node.is_none() {
        candidate = replace_section_key(
            &candidate,
            "[cluster]",
            "login_node",
            &format!("\"{node_id}\""),
        )?;
    }
    let entry = format!(
        "[nodes.{node_id}]\nhost = \"{}\"\ntransport = \"local\"\nremote_binary = \"{}\"\nremote_config = \"{}\"\nmachine_uuid = \"{}\"\nexecution_uid = {}\n",
        node.host,
        node.remote_binary,
        node.remote_config.as_deref().unwrap_or_default(),
        node.machine_uuid.as_deref().unwrap_or_default(),
        node.execution_uid.unwrap_or_default(),
    );
    let candidate = replace_or_append_table(&candidate, &format!("[nodes.{node_id}]"), &entry);
    ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    Ok(candidate)
}

fn replace_section_key(source: &str, section: &str, key: &str, value: &str) -> AppResult<String> {
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == section)
        .ok_or_else(|| (2, format!("config is missing {section}")))?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.trim_start().starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    if let Some(index) = (start + 1..end).find(|index| {
        lines[*index]
            .split_once('=')
            .is_some_and(|(existing, _)| existing.trim() == key)
    }) {
        lines[index] = format!("{key} = {value}");
    } else {
        lines.insert(end, format!("{key} = {value}"));
    }
    Ok(lines.join("\n") + if source.ends_with('\n') { "\n" } else { "" })
}

fn replace_or_append_table(source: &str, section: &str, replacement: &str) -> String {
    let mut lines: Vec<String> = source.lines().map(str::to_owned).collect();
    if let Some(start) = lines.iter().position(|line| line.trim() == section) {
        let end = lines[start + 1..]
            .iter()
            .position(|line| line.trim_start().starts_with('['))
            .map_or(lines.len(), |offset| start + 1 + offset);
        lines.splice(start..end, replacement.lines().map(str::to_owned));
        return lines.join("\n") + if source.ends_with('\n') { "\n" } else { "" };
    }
    let mut result = source.to_owned();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push('\n');
    result.push_str(replacement);
    result
}

fn find_local_machine_registration(
    config: &ClusterConfig,
    local_host: &Ipv4Addr,
    machine_uuid: &str,
) -> AppResult<Option<String>> {
    let mut match_id = None;
    for (id, node) in &config.nodes {
        let identity = if node.transport == Transport::Local {
            node.machine_uuid.clone()
        } else {
            Some(remote_machine_uuid(node).map_err(|(_, error)| {
                (
                    1,
                    format!("cannot verify registered node {id} identity: {error}"),
                )
            })?)
        };
        if node.host == local_host.to_string() || identity.as_deref() == Some(machine_uuid) {
            if identity
                .as_deref()
                .is_some_and(|value| value != machine_uuid)
            {
                return Err((
                    1,
                    format!(
                        "address {local_host} is already assigned to node {id} with a different machine UUID"
                    ),
                ));
            }
            if match_id.replace(id.clone()).is_some() {
                return Err((
                    1,
                    "this Mac appears under more than one configured node ID".into(),
                ));
            }
        }
    }
    Ok(match_id)
}

pub(crate) fn local_platform_uuid() -> AppResult<String> {
    let mut command = Command::new("/usr/sbin/ioreg");
    command.args(["-rd1", "-c", "IOPlatformExpertDevice"]);
    let output = run_child(command, None, Duration::from_secs(5))?;
    if !output.status.success() {
        return Err((1, command_error("ioreg failed", &output)));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| line.rsplit_once('=').map(|(_, value)| value.trim()))
        .map(|value| value.trim_matches('"').trim())
        .ok_or_else(|| (1, "IOPlatformUUID was not present in ioreg output".into()))?;
    Id128::parse(value).map_err(|error| (1, format!("invalid platform UUID: {error}")))?;
    Ok(value.to_ascii_lowercase())
}

fn resolve_local_host(config: &ClusterConfig, explicit: Option<Ipv4Addr>) -> AppResult<Ipv4Addr> {
    let addresses = local_ipv4_addresses()?;
    if let Some(host) = preferred_local_host(config, explicit, &addresses)? {
        return Ok(host);
    }
    for node in config
        .nodes
        .values()
        .filter(|node| node.transport == Transport::Ssh)
    {
        let mut route = Command::new("/sbin/route");
        route.args(["-n", "get", &node.host]);
        let output = run_child(route, None, Duration::from_secs(3))?;
        if output.status.success() {
            let route_text = String::from_utf8_lossy(&output.stdout);
            let interface = route_text
                .lines()
                .find_map(|line| line.trim().strip_prefix("interface: "))
                .map(str::to_owned);
            if let Some(interface) = interface {
                if let Ok(command_output) = Command::new("/sbin/ifconfig").arg(interface).output() {
                    let text = String::from_utf8_lossy(&command_output.stdout);
                    if let Some(address) = parse_ifconfig_ipv4(&text).into_iter().next() {
                        if addresses.contains(&address) {
                            return Ok(address);
                        }
                    }
                }
            }
        }
    }
    match addresses.as_slice() {
        [address] => Ok(*address),
        [] => Err((
            1,
            "no active non-loopback IPv4 interface was found; pass --host IPv4".into(),
        )),
        _ => Err((
            2,
            format!(
                "multiple active IPv4 addresses found ({}); pass --host IPv4 to select the cluster interface",
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

fn preferred_local_host(
    config: &ClusterConfig,
    explicit: Option<Ipv4Addr>,
    addresses: &[Ipv4Addr],
) -> AppResult<Option<Ipv4Addr>> {
    if let Some(host) = explicit {
        if addresses.contains(&host) {
            return Ok(Some(host));
        }
        return Err((
            2,
            format!("--host {host} is not assigned to an active local interface"),
        ));
    }
    if let Some((id, node)) = config
        .nodes
        .iter()
        .find(|(_, node)| node.transport == Transport::Local)
    {
        let host = node.host.parse::<Ipv4Addr>().map_err(|_| {
            (2, format!("registered local node {id} address '{}' is not IPv4; use --host IPv4 to select an active cluster interface", node.host))
        })?;
        if !addresses.contains(&host) {
            return Err((
                2,
                format!(
                    "registered local node {id} address {host} is not assigned to an active local interface; reconnect that interface or use --host IPv4 to explicitly change the cluster address"
                ),
            ));
        }
        return Ok(Some(host));
    }
    Ok(None)
}

pub(crate) fn local_ipv4_addresses() -> AppResult<Vec<Ipv4Addr>> {
    let output = Command::new("/sbin/ifconfig")
        .arg("-a")
        .output()
        .map_err(io_error)?;
    if !output.status.success() {
        return Err((1, command_error("ifconfig failed", &output)));
    }
    let mut addresses = parse_ifconfig_ipv4(&String::from_utf8_lossy(&output.stdout));
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

fn parse_ifconfig_ipv4(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let value = line.strip_prefix("inet ")?.split_whitespace().next()?;
            value.parse::<Ipv4Addr>().ok()
        })
        .filter(|address| {
            !address.is_loopback()
                && !address.is_link_local()
                && !address.is_unspecified()
                && !address.is_multicast()
                && *address != Ipv4Addr::BROADCAST
        })
        .collect()
}

fn add_ssh_node(
    config_path: &Path,
    state_dir: &Path,
    endpoint: NodeEndpoint,
    selected_queue: Option<&str>,
    defer_queue_for_share: bool,
) -> AppResult<()> {
    let maintenance = acquire_node_maintenance_scoped(
        config_path,
        state_dir,
        "node enrollment",
        MaintenanceScope::Cluster,
    )?;
    if maintenance.recovered {
        return Ok(());
    }
    let result = (|| -> AppResult<()> {
        MaintenanceLock::bind_state_dir(config_path, state_dir).map_err(|error| {
            (
                1,
                format!("cluster config/state directory binding failed: {error}"),
            )
        })?;
        fs::create_dir_all(state_dir).map_err(io_error)?;
        let config_path = config_path.canonicalize().map_err(io_error)?;
        let config_source = fs::read_to_string(&config_path).map_err(io_error)?;
        let config =
            ClusterConfig::parse(&config_source).map_err(|error| (2, error.to_string()))?;
        let queue_name = selected_queue.unwrap_or(config.default_queue.as_str());
        if !config.queues.contains_key(queue_name) {
            return Err((2, format!("queue '{queue_name}' is not configured")));
        }
        let endpoint_text = endpoint.canonical();
        let mut operation_key = format!("add:{endpoint_text}");
        let storage = Storage::open(state_dir).map_err(|error| (1, error.to_string()))?;
        let jobs = storage
            .list_jobs(None)
            .map_err(|error| (1, error.to_string()))?;
        let mut state =
            read_admin_state(&state_dir.join("node-admin.json"), &config_path, state_dir)?;
        if let Some((existing_id, existing_node)) = config
            .nodes
            .iter()
            .find(|(_, node)| node.host == endpoint.host.to_string())
        {
            if !existing_ssh_endpoint_matches(existing_node, &endpoint) {
                return Err((
                    2,
                    format!(
                        "host {} is already registered with a different transport, SSH user, or port; use its configured identity",
                        endpoint.host
                    ),
                ));
            }
            let configured_digest =
                sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
            let combined_pending_key = if defer_queue_for_share {
                let pending =
                    pending_combined_ssh_add(&state, existing_id, &endpoint, &configured_digest)?;
                if pending.is_none() {
                    // An ordinary share retry must not refresh setup or enroll a
                    // deliberately deferred node into the queue.
                    return Ok(());
                }
                pending
            } else {
                None
            };
            let machine_uuid = remote_machine_uuid(existing_node)?;
            if [
                existing_node.machine_uuid.as_deref(),
                state.machine_uuids.get(existing_id).map(String::as_str),
                combined_pending_key
                    .as_ref()
                    .and_then(|key| state.operations[key].machine_uuid.as_deref()),
            ]
            .into_iter()
            .flatten()
            .any(|known| !known.eq_ignore_ascii_case(&machine_uuid))
            {
                return Err((
                    1,
                    format!(
                        "host {} now reports a different machine UUID; refusing to reuse node {existing_id}",
                        endpoint.host
                    ),
                ));
            }
            if combined_pending_key.is_some() {
                let facts = read_remote_facts(existing_node)?;
                if existing_node
                    .execution_uid
                    .is_some_and(|expected| expected != facts.uid)
                {
                    return Err((
                        1,
                        format!(
                            "node {existing_id} execution UID changed; refusing enrollment sync"
                        ),
                    ));
                }
            }
            state
                .machine_uuids
                .insert(existing_id.clone(), machine_uuid.clone());
            state.reserved_node_ids.insert(existing_id.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            let queue_operation_key = format!("queue:{existing_id}:{queue_name}");
            let is_queue_member = config
                .queues
                .get(queue_name)
                .is_some_and(|queue| queue.nodes.iter().any(|member| member == existing_id));
            let pending_key = combined_pending_key.as_deref().or_else(|| {
                is_queue_member
                    .then(|| {
                        [operation_key.as_str(), queue_operation_key.as_str()]
                            .into_iter()
                            .find(|key| {
                                state.operations.get(*key).is_some_and(|operation| {
                                    operation.node_id == *existing_id
                                        && matches!(
                                            operation.phase.as_str(),
                                            "ADD_COMMITTING" | "SYNC_PENDING"
                                        )
                                })
                            })
                    })
                    .flatten()
            });
            if let Some(key) = pending_key {
                let operation = state
                    .operations
                    .get(key)
                    .cloned()
                    .expect("pending key was found in operation journal");
                if operation.candidate_config_sha256.as_deref() != Some(configured_digest.as_str())
                {
                    return Err((
                        1,
                        format!(
                            "node {existing_id} is present but its operation journal does not match the active config; inspect the node-admin journal"
                        ),
                    ));
                }
                let key = key.to_owned();
                resume_existing_ssh_add_sync(
                    &mut state,
                    &state_dir.join("node-admin.json"),
                    &key,
                    &endpoint,
                    |operation| {
                        sync_remote_configs(
                            &config,
                            &config_source,
                            state_dir,
                            &operation.id,
                            Some(existing_id),
                        )
                    },
                )?;
            }
            if defer_queue_for_share {
                return Ok(());
            }
            if is_queue_member {
                let facts = read_remote_facts(existing_node)?;
                if facts.os != "Darwin" {
                    return Err((2, format!("{} is not macOS", endpoint.host)));
                }
                if existing_node
                    .execution_uid
                    .is_some_and(|expected| expected != facts.uid)
                {
                    return Err((
                        1,
                        format!("node {existing_id} execution UID changed; refusing power setup"),
                    ));
                }
                ensure_agent_capabilities(existing_node).map_err(|(_, error)| {
                    (
                        1,
                        format!("cannot refresh node {existing_id} capabilities: {error}"),
                    )
                })?;
                let operation_id = state
                    .operations
                    .get(&operation_key)
                    .map(|operation| operation.id.clone())
                    .unwrap_or_else(|| Id128::random().to_string());
                check_remote_idle(existing_node, existing_id, &config_path)?;
                let handoff = enrollment_controller_epoch(state_dir).map_err(|error| (1, error))?;
                claim_enrollment_agent(
                    existing_node,
                    existing_id,
                    &config_path,
                    &config.share_uuid,
                    handoff,
                )
                .map_err(|error| (1, error))?;
                let power_setup =
                    prepare_power_helper(existing_node, facts.uid, &facts.arch, &operation_id)
                        .map_err(|error| {
                            (
                                1,
                                format!("cannot prepare power sampler on {existing_id}: {error}"),
                            )
                        })?;
                configure_node_nfs_resources(
                    &config,
                    existing_id,
                    existing_node,
                    &operation_id,
                    &mut false,
                    &mut BTreeSet::new(),
                    power_setup,
                    BTreeMap::new(),
                )
                .map_err(|error| {
                    (
                        1,
                        format!("cannot repair NFS resources on {existing_id}: {error}"),
                    )
                })?;
                println!("Node {existing_id} is already enrolled in queue {queue_name}.");
                println!(
                    "NFS mounts, automatic recovery and power sampler verified on {}.",
                    existing_node.host
                );
                return Ok(());
            }
            return add_existing_ssh_node_to_queue(
                &config_path,
                state_dir,
                &config_source,
                &config,
                existing_id,
                queue_name,
                &machine_uuid,
                &mut state,
            );
        }
        for job in jobs {
            if let Some(node) = job.node {
                state.reserved_node_ids.insert(node.to_string());
            }
            if let Some(node) = job.spec.node {
                state.reserved_node_ids.insert(node.to_string());
            }
        }
        for id in config.nodes.keys() {
            state.reserved_node_ids.insert(id.clone());
        }

        let active_node_ids = config.nodes.keys().cloned().collect();
        let pending = pending_add_operation_for_endpoint(&state, &active_node_ids, &endpoint_text);
        let mut operation = if let Some((pending_key, pending_operation)) = pending {
            operation_key = pending_key;
            Some(pending_operation)
        } else {
            let mut operation = state.operations.get(&operation_key).cloned();
            if operation.as_ref().is_some_and(|operation| {
                matches!(operation.phase.as_str(), "READY" | "ABORTED")
                    && !config.nodes.contains_key(&operation.node_id)
            }) {
                operation_key = format!("add:{endpoint_text}:{}", Id128::random());
                operation = None;
            }
            operation
        };
        if let Some(previous) = operation.as_ref() {
            if previous.phase == "READY" && config.nodes.contains_key(&previous.node_id) {
                println!("Node {} is already enrolled and ready.", previous.node_id);
                return Ok(());
            }
        }
        let node_id = if let Some(operation) = operation.as_ref() {
            operation.node_id.clone()
        } else {
            allocate_node_id(queue_name, &state.reserved_node_ids)?
        };
        state.reserved_node_ids.insert(node_id.clone());
        let id = operation
            .as_ref()
            .map(|operation| operation.id.clone())
            .unwrap_or_else(|| Id128::random().to_string());

        let mut remote = endpoint.node_config("/usr/local/bin/macluster".into(), None);
        crate::ssh_bootstrap::ensure_ssh_access(&mut remote, &endpoint.ssh_identity_endpoint())
            .map_err(|error| {
                (
                    1,
                    format!("SSH setup failed for {}: {error}", endpoint.host),
                )
            })?;
        let facts = read_remote_facts(&remote)?;
        if facts.os != "Darwin" {
            return Err((2, format!("{} is not macOS", endpoint.host)));
        }
        let machine_uuid = remote_machine_uuid(&remote)?;
        let storage_host = &config
            .nodes
            .get(config.storage_server.as_str())
            .expect("storage server is configured")
            .host;
        let client_ip = remote_route_ipv4(&remote, storage_host)?;
        if client_ip != endpoint.host {
            return Err((
                1,
                format!(
                    "SSH endpoint {} routes to the NFS server from {client_ip}; this version requires the endpoint and actual NFS client IP to match",
                    endpoint.host
                ),
            ));
        }
        if operation
            .as_ref()
            .and_then(|operation| operation.machine_uuid.as_deref())
            .is_some_and(|recorded| recorded != machine_uuid)
        {
            return Err((
                1,
                format!(
                    "endpoint {} now reports machine UUID {machine_uuid}, different from the pending enrollment identity; refusing to reuse its node ID",
                    endpoint.host
                ),
            ));
        }
        for (existing_id, existing_node) in &config.nodes {
            let identity = remote_machine_uuid(existing_node).map_err(|(_, error)| {
                (
                    1,
                    format!("cannot verify existing node {existing_id} identity: {error}"),
                )
            })?;
            if state
                .machine_uuids
                .get(existing_id)
                .is_some_and(|known| known != &identity)
            {
                return Err((
                    1,
                    format!(
                        "node {existing_id} reports machine UUID {identity}, different from its recorded identity; refusing enrollment"
                    ),
                ));
            }
            if identity == machine_uuid {
                return Err((
                    2,
                    format!("machine {machine_uuid} is already registered as {existing_id}"),
                ));
            }
            state.machine_uuids.insert(existing_id.clone(), identity);
        }
        let superseded_pending = if operation.is_some() {
            abort_duplicate_pristine_adds(&mut state, &endpoint_text, &node_id, &machine_uuid)
        } else {
            0
        };
        if superseded_pending > 0 {
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            eprintln!(
                "Consolidated {superseded_pending} duplicate pending enrollment record(s) for {}; resuming {node_id}. Superseded node IDs remain reserved.",
                endpoint.canonical()
            );
        }
        let storage_node = config
            .nodes
            .get(config.storage_server.as_str())
            .expect("storage server is configured");
        let storage_facts = read_remote_facts(storage_node)?;
        if facts.uid != storage_facts.uid || facts.gid != storage_facts.gid {
            return Err((
                2,
                format!(
                    "UID/GID mismatch: candidate is {}/{}, storage account must match",
                    facts.uid, facts.gid
                ),
            ));
        }
        verify_storage_root(
            storage_node,
            config.primary_source_root(),
            &config.share_uuid,
            storage_facts.uid,
            storage_facts.gid,
        )?;
        state
            .machine_uuids
            .insert(node_id.clone(), machine_uuid.clone());
        if operation.is_none() {
            operation = Some(NodeOperation {
                id,
                action: "add".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: node_id.clone(),
                endpoint: endpoint_text,
                machine_uuid: Some(machine_uuid.clone()),
                phase: "SETUP_PENDING".into(),
                old_config_sha256: Some(
                    sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?,
                ),
                candidate_config_sha256: None,
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: Some(false),
                detail: None,
            });
        }
        let operation = operation.as_mut().expect("operation was initialized");
        if is_uncommitted_enrollment(&config, operation) {
            operation.old_config_sha256 =
                Some(sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?);
        }
        operation.machine_uuid = Some(machine_uuid.clone());
        operation.phase = "SETUP_PENDING".into();
        operation.detail =
            Some("enrollment is incomplete; rerun the same mnode --add command to resume".into());
        if operation.old_config_sha256.is_none() {
            operation.old_config_sha256 =
                Some(sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?);
        }
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;

        for (existing_id, existing_node) in &config.nodes {
            check_remote_idle(existing_node, existing_id, &config_path)?;
        }
        let (staged_source, staged_config) = stage_current_agents(
            &config,
            &config_source,
            &operation.id,
            // The candidate node gets its helper together with its mount setup
            // below. Avoid a separate helper sudo on existing storage nodes.
            AgentStagePurpose::Share,
        )?;
        let config_source = staged_source;
        let config = staged_config;
        let binary = select_local_binary(&facts.arch)?;
        let binary_kb = fs::metadata(&binary)
            .map_err(io_error)?
            .len()
            .div_ceil(1024);
        let required_kb = binary_kb.saturating_mul(2).saturating_add(50_000);
        if facts.free_kb < required_kb {
            return Err((
                1,
                format!(
                    "node {} has {} KiB free, but enrollment needs about {} KiB",
                    endpoint.host, facts.free_kb, required_kb
                ),
            ));
        }
        let remote_home = checked_remote_path(&facts.home)?;
        let binary_digest = local_sha256(&binary)?;
        let remote_binary = format!(
            "{remote_home}/.local/share/macluster/clusters/{}/bin/{binary_digest}/macluster",
            config.share_uuid
        );
        // Keep this machine's own login configuration and older enrollment
        // snapshots separate from the compute Agent configuration we manage.
        let remote_config =
            remote_agent_config_path(&remote_home, &config.share_uuid, &machine_uuid);
        let mut node_config =
            endpoint.node_config(remote_binary.clone(), Some(remote_config.clone()));
        node_config.ssh_identity_file = remote.ssh_identity_file.clone();
        node_config.machine_uuid = Some(machine_uuid.clone());
        node_config.execution_uid = Some(facts.uid);
        ensure_remote_binary(&node_config, &binary, &facts.version, &operation.id)?;
        ensure_agent_capabilities(&node_config)?;
        let candidate_source = config_path_candidate(
            &config,
            &config_source,
            &node_id,
            queue_name,
            !defer_queue_for_share,
            &endpoint,
            &remote_binary,
            &remote_config,
            node_config.ssh_identity_file.as_deref(),
            &machine_uuid,
            facts.uid,
        )?;
        operation.remote_config_path = Some(remote_config.clone());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;
        ensure_remote_config(
            &node_config,
            &remote_config,
            &candidate_source,
            &operation.id,
            state_dir,
        )?;
        let candidate_config =
            ClusterConfig::parse(&candidate_source).map_err(|error| (2, error.to_string()))?;
        let candidate_node_id =
            NodeId::new(node_id.clone()).map_err(|error| (2, error.to_string()))?;
        let mut candidate_transport = ClusterTransport::new_with_namespace(
            PathBuf::from("/dev/null"),
            config.share_uuid.clone(),
        );
        candidate_transport.timeout = Duration::from_secs(12);
        let bridge = candidate_transport
            .call(&candidate_node_id, &node_config, Operation::Ping)
            .map_err(|error| (1, format!("candidate agent bridge check failed: {error}")))?;
        if bridge != ResponseBody::Pong {
            return Err((
                1,
                "candidate agent bridge returned an unexpected response".into(),
            ));
        }
        check_remote_idle(&node_config, &node_id, &config_path)?;
        if let Err((_, error)) = verify_login_share(&config_path) {
            operation.detail = Some(
                "login node does not currently see the configured NFS export and share marker"
                    .into(),
            );
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            return Err((
                1,
                format!(
                    "login node must have the configured NFS share mounted and verified before enrolling another node: {error}"
                ),
            ));
        }
        let candidate_digest =
            sha256_hex(candidate_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
        operation.phase = "CANDIDATE_INSTALLED".into();
        operation.candidate_config_sha256 = Some(candidate_digest);
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;

        let existing_power_setups =
            prepare_power_helpers_for_nodes(&config, &operation.id, Some(&machine_uuid));
        let power_setup =
            match prepare_power_helper(&node_config, facts.uid, &facts.arch, &operation.id) {
                Ok(setup) => setup,
                Err(error) => {
                    eprintln!("Power sampler setup for {node_id} was skipped: {error}");
                    None
                }
            };
        operation.client_setup_attempted = Some(true);
        operation.detail = Some("client NFS resources are being configured".into());
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;
        let handoff = enrollment_controller_epoch(state_dir).map_err(|error| (1, error))?;
        if let Err(detail) = configure_node_nfs_resources_with_claim(
            &config,
            &node_id,
            &node_config,
            &operation.id,
            &mut operation.managed_export,
            &mut operation.managed_shares,
            power_setup,
            existing_power_setups,
            Some(handoff),
        ) {
            operation.phase = "SETUP_PENDING".into();
            operation.detail = Some(detail.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            return Err((1, detail));
        }
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;
        let check = match remote_node_check(&node_config, &node_id) {
            Ok(check) => check,
            Err((_, error)) => {
                operation.phase = "SETUP_PENDING".into();
                operation.detail = Some(error.clone());
                state
                    .operations
                    .insert(operation_key.clone(), operation.clone());
                save_admin_state(&state_dir.join("node-admin.json"), &state)?;
                return Err((1, error));
            }
        };
        if check.machine_uuid.as_deref() != Some(machine_uuid.as_str()) {
            operation.phase = "SETUP_PENDING".into();
            operation.detail = Some("remote machine identity changed during enrollment".into());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            return Err((
                1,
                "remote machine identity changed during enrollment".into(),
            ));
        }
        if !check.shared_storage_ready {
            operation.phase = "SETUP_PENDING".into();
            operation.detail = Some("remote NFS marker or mount source did not match".into());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            return Err((
                1,
                "candidate mounted NFS but share marker/source verification failed".into(),
            ));
        }
        if let Err((_, error)) =
            verify_cross_node_write(&config.shared_root, &node_config, &operation.id)
        {
            operation.phase = "SETUP_PENDING".into();
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            return Err((1, error));
        }

        let current_bytes = fs::read(&config_path).map_err(io_error)?;
        let current_digest = sha256_hex(&current_bytes).map_err(|error| (1, error.to_string()))?;
        if operation.old_config_sha256.as_deref() != Some(current_digest.as_str()) {
            return Err((
                1,
                "cluster config changed during node enrollment; no local config was overwritten"
                    .into(),
            ));
        }
        backup_config(&config_path, &operation.id)?;
        operation.phase = "ADD_COMMITTING".into();
        operation.candidate_config_sha256 =
            Some(sha256_hex(candidate_source.as_bytes()).map_err(|error| (1, error.to_string()))?);
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;
        atomic_write(&config_path, candidate_source.as_bytes())?;
        operation.phase = "SYNC_PENDING".into();
        operation.detail = None;
        state
            .operations
            .insert(operation_key.clone(), operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;
        if let Err(error) = sync_remote_configs(
            &candidate_config,
            &candidate_source,
            state_dir,
            &operation.id,
            Some(&node_id),
        ) {
            operation.detail = Some(error.clone());
            state
                .operations
                .insert(operation_key.clone(), operation.clone());
            save_admin_state(&state_dir.join("node-admin.json"), &state)?;
            return Err((
                1,
                format!(
                    "node {node_id} was added locally, but peer config sync is pending: {error}. Rerun the same `mnode -a {}` command to resume.",
                    endpoint.canonical()
                ),
            ));
        }
        operation.phase = "READY".into();
        operation.detail = None;
        state.operations.insert(operation_key, operation.clone());
        save_admin_state(&state_dir.join("node-admin.json"), &state)?;
        if defer_queue_for_share {
            println!(
                "Prepared node {node_id}; it remains outside all queues until its requested NFS share commits."
            );
        } else {
            println!("Added node {node_id} to queue {queue_name}.");
        }
        println!("Machine UUID: {machine_uuid}");
        println!("Remote config: {remote_config}");
        println!(
            "NFS recovery is configured: missing managed mounts will be restored automatically after boot or network recovery."
        );
        Ok(())
    })();
    finish_node_maintenance(maintenance, result)
}

fn add_existing_ssh_node_to_queue(
    config_path: &Path,
    state_dir: &Path,
    config_source: &str,
    config: &ClusterConfig,
    node_id: &str,
    queue_name: &str,
    machine_uuid: &str,
    state: &mut AdminState,
) -> AppResult<()> {
    for (id, node) in &config.nodes {
        check_remote_idle(node, id, config_path)?;
    }
    let handoff = enrollment_controller_epoch(state_dir).map_err(|error| (1, error))?;
    let node = config
        .nodes
        .get(node_id)
        .ok_or_else(|| (2, "node is not configured".into()))?;
    claim_enrollment_agent(node, node_id, config_path, &config.share_uuid, handoff)
        .map_err(|error| (1, error))?;
    let operation_key = format!("queue:{node_id}:{queue_name}");
    let old_digest =
        sha256_hex(config_source.as_bytes()).map_err(|error| (1, error.to_string()))?;
    let candidate = queue_candidate_with_node(config, config_source, queue_name, node_id)?;
    let candidate_config =
        ClusterConfig::parse(&candidate).map_err(|error| (2, error.to_string()))?;
    let candidate_digest =
        sha256_hex(candidate.as_bytes()).map_err(|error| (1, error.to_string()))?;
    let operation = match state.operations.get(&operation_key).cloned() {
        Some(existing)
            if existing.phase != "READY"
                && existing.node_id == node_id
                && existing.old_config_sha256.as_deref() == Some(old_digest.as_str())
                && existing.candidate_config_sha256.as_deref()
                    == Some(candidate_digest.as_str()) =>
        {
            existing
        }
        Some(existing) if existing.phase != "READY" => {
            return Err((
                1,
                format!(
                    "queue update for {node_id} has an incomplete operation {}; resume or inspect it before changing the config",
                    existing.id
                ),
            ));
        }
        _ => NodeOperation {
            id: Id128::random().to_string(),
            action: "add".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: node_id.to_owned(),
            endpoint: format!("queue:{queue_name}"),
            machine_uuid: Some(machine_uuid.to_owned()),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some(old_digest.clone()),
            candidate_config_sha256: Some(candidate_digest.clone()),
            managed_export: false,
            managed_shares: BTreeSet::new(),
            client_setup_attempted: Some(false),
            detail: None,
        },
    };
    state
        .machine_uuids
        .insert(node_id.to_owned(), machine_uuid.to_owned());
    state.reserved_node_ids.insert(node_id.to_owned());
    let mut operation = operation;
    operation.phase = "SETUP_PENDING".into();
    operation.detail = Some(format!("adding {node_id} to queue {queue_name}"));
    state
        .operations
        .insert(operation_key.clone(), operation.clone());
    let journal_path = state_dir.join("node-admin.json");
    save_admin_state(&journal_path, state)?;

    operation.client_setup_attempted = Some(true);
    state
        .operations
        .insert(operation_key.clone(), operation.clone());
    save_admin_state(&journal_path, state)?;
    if let Err(error) = configure_node_nfs_resources(
        config,
        node_id,
        node,
        &operation.id,
        &mut operation.managed_export,
        &mut operation.managed_shares,
        None,
        BTreeMap::new(),
    ) {
        operation.detail = Some(error.clone());
        state.operations.insert(operation_key.clone(), operation);
        save_admin_state(&journal_path, state)?;
        return Err((1, error));
    }

    let active = fs::read(config_path).map_err(io_error)?;
    if sha256_hex(&active).map_err(|error| (1, error.to_string()))? != old_digest {
        return Err((
            1,
            "cluster config changed during queue update; refusing to overwrite it".into(),
        ));
    }
    backup_config(config_path, &operation.id)?;
    operation.phase = "ADD_COMMITTING".into();
    operation.detail = Some("queue membership is being committed".into());
    state
        .operations
        .insert(operation_key.clone(), operation.clone());
    save_admin_state(&journal_path, state)?;
    atomic_write(config_path, candidate.as_bytes())?;
    operation.phase = "SYNC_PENDING".into();
    operation.detail = None;
    state
        .operations
        .insert(operation_key.clone(), operation.clone());
    save_admin_state(&journal_path, state)?;
    if let Err(error) = sync_remote_configs(
        &candidate_config,
        &candidate,
        state_dir,
        &operation.id,
        None,
    ) {
        operation.detail = Some(error.clone());
        state.operations.insert(operation_key.clone(), operation);
        save_admin_state(&journal_path, state)?;
        return Err((
            1,
            format!(
                "node {node_id} joined queue {queue_name} locally, but peer config sync is pending: {error}. Rerun `mnode -a` with the same endpoint and queue."
            ),
        ));
    }
    operation.phase = "READY".into();
    operation.detail = None;
    state.operations.insert(operation_key, operation);
    save_admin_state(&journal_path, state)?;
    println!("Node {node_id} joined queue {queue_name}.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Action, AdminState, AgentBuildCompatibility, AgentBuildState, AgentStagePurpose, AppResult,
        ClientMountRequest, ClientUnmountRequest, ClusterConfig, NFS_DAEMON_PATH,
        NamedShareMountStatus, NodeEndpoint, NodeListRow, NodeNfsMapping, NodeOperation,
        ShareConfig, UpdateRecovery, abort_duplicate_pristine_adds,
        acquire_maintenance_client_lock, acquire_node_maintenance, acquire_node_maintenance_with,
        acquire_node_maintenance_with_confirmation_using, admin_shell_command,
        agent_update_recovery_pending, append_client_mount_marker_check, candidate_admin_script,
        classify_configured_agents, cleanup_node_from_endpoint, client_mount_batch_script,
        client_mount_status_awk_script, client_nfs_cleanup_batch_script, client_nfs_cleanup_plan,
        client_share_alias_script, config_path_candidate, controller_command_matches,
        dispatch_sync_pending, ensure_controller_recovery_clean,
        ensure_no_node_maintenance_in_progress, existing_ssh_endpoint_matches, format_node_list,
        inspect_configured_agent_build, list_nodes, local_config_candidate,
        maintenance_inputs_unchanged, managed_binary_digest, migration_controller_epoch,
        mount_point_permission_error, named_share_mount_root, named_share_mount_status,
        named_share_operation_endpoint, named_share_operation_matches, named_share_request_matches,
        nfs_exports_read_command, nfs_exports_update_baseline_read_command,
        nfs_exports_update_script, nfs_exports_update_script_for_expected, nfs_mount_source,
        node_admin_recovery_pending, node_nfs_mappings, normalize_binary_path, parse_action,
        parse_agent_build_probe, parse_nfs_exports_update_baseline,
        pending_add_may_have_client_state, pending_add_operation_for_endpoint,
        pending_combined_ssh_add, pending_local_share_retry_node,
        pending_managed_export_cleanup_plan, plan_ensure_nfs_exports, plan_remove_nfs_exports,
        power_helper_install_script, power_launch_daemon_plist, preferred_local_host,
        queue_candidate_with_node, read_admin_state, remote_execution_status,
        reset_admin_operations, reset_node_from_endpoint, resume_existing_ssh_add_sync,
        save_admin_state, should_resume_add_operation, shutdown_confirmation_accepted,
        update_recovery, validate_pending_node_identity, validate_storage_root_access,
    };
    use macluster_core::config::{NodeConfig, Transport};
    use macluster_core::maintenance::MaintenanceLock;
    use macluster_core::storage::{ReadOnlyJobStore, Storage};
    use macluster_protocol::framing::sha256_hex;
    use macluster_protocol::identifiers::{Id128, NodeId, QueueName};
    use macluster_protocol::types::{ControllerEpoch, JobMode, JobSpec, NodeHealth};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

    fn test_exports_path() -> PathBuf {
        std::env::temp_dir().join(format!("macluster-exports-{}.test", Id128::random()))
    }

    #[test]
    fn administrator_command_timeout_is_bounded_and_preserves_foreground_group() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec /bin/sleep 30"]);
        let started = std::time::Instant::now();
        let error = super::wait_admin_child(command, Duration::from_millis(60)).unwrap_err();
        assert!(error.contains(super::ADMIN_TIMEOUT), "{error}");
        assert!(started.elapsed() < Duration::from_secs(2));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 17"]);
        assert_eq!(
            super::wait_admin_child(command, Duration::from_secs(2))
                .unwrap()
                .code(),
            Some(17)
        );
    }

    #[test]
    fn noninteractive_admin_executes_passwordless_command_without_tty() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let sudo = root.join("sudo");
        fs::write(
            &sudo,
            r#"#!/bin/sh
[ "$1" = -n ] || exit 90
shift
exec "$@"
"#,
        )
        .unwrap();
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
        let script =
            super::noninteractive_admin_script(sudo.to_str().unwrap(), "printf authorized");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        let output = super::run_child(command, None, Duration::from_secs(2)).unwrap();
        assert!(output.status.success(), "{:?}", output);
        assert_eq!(output.stdout, b"authorized");
        assert!(super::admin_authorization_required(
            "sudo: a password is required"
        ));
        assert!(!super::admin_authorization_required("nfsd: invalid export"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn agent_update_skips_root_helpers_when_versions_are_current() {
        let config = parse_build_test_config();
        let mut calls = 0;
        let result = super::refresh_agent_helpers_with_admin(
            &config,
            "test",
            |_, _| Ok(None),
            |_, _| Ok(None),
            |_, _, _| {
                calls += 1;
                Err("unexpected administrator operation during Agent update".into())
            },
        )
        .unwrap();
        assert!(!result);
        assert_eq!(calls, 0);
    }

    #[test]
    fn interrupted_maintenance_can_abort_only_when_original_config_and_journal_are_unchanged() {
        let config_before = "config-before";
        let journal_before = "journal-before";
        assert!(maintenance_inputs_unchanged(
            Some(config_before),
            Some(journal_before),
            Some(config_before),
            Some(journal_before)
        ));
        assert!(!maintenance_inputs_unchanged(
            Some(config_before),
            Some(journal_before),
            Some("config-candidate"),
            Some("journal-before")
        ));
        assert!(!maintenance_inputs_unchanged(
            Some(config_before),
            Some(journal_before),
            Some(config_before),
            Some("journal-changed")
        ));
        assert!(!maintenance_inputs_unchanged(
            None,
            None,
            Some(config_before),
            Some(journal_before)
        ));
    }

    #[test]
    fn maintenance_client_lock_serializes_frontend_operations() {
        let state_dir = std::env::temp_dir().join(format!(
            "macluster-maintenance-client-lock-{}",
            Id128::random()
        ));
        fs::create_dir_all(&state_dir).unwrap();
        let first = acquire_maintenance_client_lock(&state_dir).unwrap();
        assert!(acquire_maintenance_client_lock(&state_dir).is_err());
        drop(first);
        assert!(acquire_maintenance_client_lock(&state_dir).is_ok());
        fs::remove_dir_all(state_dir).unwrap();
    }

    #[test]
    fn maintenance_completion_retries_transient_controller_blockers() {
        let mut attempts = 0;
        super::retry_maintenance_completion("Agent update", || {
            attempts += 1;
            Ok(attempts == 3)
        })
        .expect("completion should retry until the controller accepts it");

        assert_eq!(attempts, 3);
    }

    #[test]
    fn export_requests_are_grouped_by_the_mac_that_serves_them() {
        let request = |root: &str, client_ip: &str, share_uuid: &str, node_id: &str| {
            super::NfsExportRequest {
                root: root.into(),
                client_ip: client_ip.into(),
                share_uuid: share_uuid.into(),
                node_id: node_id.into(),
            }
        };
        let groups = super::group_nfs_export_requests([
            (
                "storage-a".into(),
                request("/share/one", "192.0.2.10", "one", "worker-a"),
            ),
            (
                "storage-a".into(),
                request("/share/two", "192.0.2.10", "two", "worker-a"),
            ),
            (
                "storage-b".into(),
                request("/share/three", "192.0.2.11", "three", "worker-b"),
            ),
        ]);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups["storage-a"].len(), 2);
        assert_eq!(groups["storage-b"].len(), 1);
    }

    #[test]
    fn migration_reuses_the_running_controller_epoch_instead_of_fencing_it() {
        let state =
            std::env::temp_dir().join(format!("macluster-migration-epoch-{}", Id128::random()));
        let storage = Storage::open(&state).unwrap();
        let first = storage.begin_controller_epoch().unwrap();
        assert_eq!(migration_controller_epoch(&state).unwrap(), first);
        assert_eq!(storage.current_controller_epoch().unwrap(), Some(first));
        assert_eq!(super::enrollment_controller_epoch(&state).unwrap(), first);
        assert_eq!(storage.current_controller_epoch().unwrap(), Some(first));
        drop(storage);
        assert_eq!(
            ReadOnlyJobStore::open(&state)
                .unwrap()
                .current_controller_epoch()
                .unwrap(),
            Some(first)
        );
        fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn stale_maintenance_epoch_restarts_only_an_idle_matching_controller() {
        let running = ControllerEpoch {
            controller_uuid: macluster_protocol::identifiers::ControllerUuid::random(),
            epoch: 5,
        };
        let newer = ControllerEpoch {
            epoch: 6,
            ..running
        };
        let mut restarted = false;
        assert!(
            super::recover_stale_controller_epoch_with(running, Some(newer), false, || {
                restarted = true;
                Ok(())
            })
            .unwrap()
        );
        assert!(restarted);
        assert!(
            super::recover_stale_controller_epoch_with(running, Some(newer), true, || panic!(
                "must not interrupt active work"
            ))
            .is_err()
        );
        assert!(
            !super::recover_stale_controller_epoch_with(running, Some(running), false, || panic!(
                "current controller needs no restart"
            ))
            .unwrap()
        );
        assert!(
            super::recover_stale_controller_epoch_with(
                running,
                Some(ControllerEpoch {
                    controller_uuid: macluster_protocol::identifiers::ControllerUuid::random(),
                    epoch: 6
                }),
                false,
                || panic!("must not restart a different identity")
            )
            .is_err()
        );
    }

    #[test]
    fn ensure_nfs_exports_batches_managed_entries_and_preserves_operator_exports() {
        let requests = vec![
            super::NfsExportRequest {
                root: "/Users/Shared/one".into(),
                client_ip: "192.0.2.10".into(),
                share_uuid: "share-one".into(),
                node_id: "worker-a".into(),
            },
            super::NfsExportRequest {
                root: "/Users/Shared/two".into(),
                client_ip: "192.0.2.11".into(),
                share_uuid: "share-two".into(),
                node_id: "worker-b".into(),
            },
        ];
        let original = "# operator note\n/Users/Shared/operator 192.0.2.0 -mask 255.255.255.0\n";

        let (candidate, statuses, changed) =
            plan_ensure_nfs_exports(original, &requests).expect("plan export additions");

        assert!(changed);
        assert!(statuses.iter().all(|managed| *managed));
        assert!(
            candidate.contains(
                "# operator note\n/Users/Shared/operator 192.0.2.0 -mask 255.255.255.0\n"
            )
        );
        assert!(
            candidate
                .contains("# macluster-managed share-one worker-a\n/Users/Shared/one 192.0.2.10\n")
        );
        assert!(
            candidate
                .contains("# macluster-managed share-two worker-b\n/Users/Shared/two 192.0.2.11\n")
        );
    }

    #[test]
    fn ensure_nfs_exports_adds_multiple_clients_for_the_same_root() {
        let requests = vec![
            super::NfsExportRequest {
                root: "/Users/Shared/data".into(),
                client_ip: "192.0.2.10".into(),
                share_uuid: "share-a".into(),
                node_id: "worker-a".into(),
            },
            super::NfsExportRequest {
                root: "/Users/Shared/data".into(),
                client_ip: "192.0.2.11".into(),
                share_uuid: "share-b".into(),
                node_id: "worker-b".into(),
            },
        ];

        let (candidate, managed, changed) =
            plan_ensure_nfs_exports("", &requests).expect("plan both client exports");

        assert!(changed);
        assert_eq!(managed, [true, true]);
        assert!(
            candidate
                .contains("# macluster-managed share-a worker-a\n/Users/Shared/data 192.0.2.10\n")
        );
        assert!(
            candidate
                .contains("# macluster-managed share-b worker-b\n/Users/Shared/data 192.0.2.11\n")
        );
    }

    #[test]
    fn ensure_nfs_exports_adds_client_alongside_existing_macos_per_host_entry() {
        let request = super::NfsExportRequest {
            root: "/Users/Shared/data".into(),
            client_ip: "192.0.2.11".into(),
            share_uuid: "share-b".into(),
            node_id: "worker-b".into(),
        };
        let original = "/Users/Shared/data 192.0.2.10\n";

        let (candidate, managed, changed) =
            plan_ensure_nfs_exports(original, &[request]).expect("plan additional client");

        assert!(changed);
        assert_eq!(managed, [true]);
        assert!(candidate.starts_with(original));
        assert!(
            candidate
                .contains("# macluster-managed share-b worker-b\n/Users/Shared/data 192.0.2.11\n")
        );
    }

    #[test]
    fn ensure_nfs_exports_does_not_treat_maproot_argument_as_host_restriction() {
        let request = super::NfsExportRequest {
            root: "/Users/Shared/data".into(),
            client_ip: "192.0.2.11".into(),
            share_uuid: "share-b".into(),
            node_id: "worker-b".into(),
        };

        let (candidate, managed, changed) =
            plan_ensure_nfs_exports("/Users/Shared/data -maproot 501:20\n", &[request])
                .expect("maproot-only export is unrestricted");

        assert!(!changed);
        assert_eq!(managed, [false]);
        assert_eq!(candidate, "/Users/Shared/data -maproot 501:20\n");
    }

    #[test]
    fn ensure_nfs_exports_refuses_unrecognized_hostname_restrictions() {
        let request = super::NfsExportRequest {
            root: "/Users/Shared/data".into(),
            client_ip: "192.0.2.11".into(),
            share_uuid: "share-b".into(),
            node_id: "worker-b".into(),
        };

        let result =
            plan_ensure_nfs_exports("/Users/Shared/data worker-a.example.com\n", &[request]);

        assert!(result.is_err(), "unknown host syntax must fail closed");
    }

    #[test]
    fn ensure_nfs_exports_parses_equals_network_and_mask_options() {
        let request = super::NfsExportRequest {
            root: "/Users/Shared/data".into(),
            client_ip: "198.51.100.11".into(),
            share_uuid: "share-b".into(),
            node_id: "worker-b".into(),
        };

        let (candidate, managed, changed) = plan_ensure_nfs_exports(
            "/Users/Shared/data -network=192.0.2.0 -mask=255.255.255.0\n",
            &[request],
        )
        .expect("add a client outside the restricted network");

        assert!(changed);
        assert_eq!(managed, [true]);
        assert!(
            candidate.contains(
                "# macluster-managed share-b worker-b\n/Users/Shared/data 198.51.100.11\n"
            )
        );

        let inside_network = super::NfsExportRequest {
            root: "/Users/Shared/data".into(),
            client_ip: "192.0.2.11".into(),
            share_uuid: "share-c".into(),
            node_id: "worker-c".into(),
        };
        let (candidate, managed, changed) = plan_ensure_nfs_exports(
            "/Users/Shared/data -network=192.0.2.0 -mask=255.255.255.0\n",
            &[inside_network],
        )
        .expect("existing network authorization should be recognized");
        assert!(!changed);
        assert_eq!(managed, [false]);
        assert_eq!(
            candidate,
            "/Users/Shared/data -network=192.0.2.0 -mask=255.255.255.0\n"
        );

        let named_network = plan_ensure_nfs_exports(
            "/Users/Shared/data -network=workers\n",
            &[super::NfsExportRequest {
                root: "/Users/Shared/data".into(),
                client_ip: "192.0.2.11".into(),
                share_uuid: "share-d".into(),
                node_id: "worker-d".into(),
            }],
        );
        assert!(
            named_network.is_err(),
            "unresolved network names must fail closed"
        );
    }

    #[test]
    fn remove_nfs_exports_batches_exact_entries_and_preserves_unmanaged_lines() {
        let requests = vec![
            super::NfsExportRequest {
                root: "/Users/Shared/one".into(),
                client_ip: "192.0.2.10".into(),
                share_uuid: "share-one".into(),
                node_id: "worker-a".into(),
            },
            super::NfsExportRequest {
                root: "/Users/Shared/two".into(),
                client_ip: "192.0.2.11".into(),
                share_uuid: "share-two".into(),
                node_id: "worker-b".into(),
            },
        ];
        let original = concat!(
            "# operator note\n/Users/Shared/operator 192.0.2.0 -mask 255.255.255.0\n",
            "# macluster-managed share-one worker-a\n/Users/Shared/one 192.0.2.10\n",
            "# macluster-managed share-two worker-b\n/Users/Shared/two 192.0.2.11\n",
        );

        let (candidate, statuses, changed) =
            plan_remove_nfs_exports(original, &requests).expect("plan export removals");

        assert!(changed);
        assert!(statuses.iter().all(|(removed, _)| *removed));
        assert!(
            statuses
                .iter()
                .all(|(_, still_authorized)| !still_authorized)
        );
        assert_eq!(
            candidate,
            "# operator note\n/Users/Shared/operator 192.0.2.0 -mask 255.255.255.0\n"
        );
    }

    #[test]
    fn power_install_and_export_reload_share_one_admin_wrapper() {
        let update = super::nfs_exports_update_commands(
            "# macluster-managed share worker\n/Users/Shared/data 192.0.2.10\n",
            "",
            "operation-1",
        )
        .unwrap();
        let script = candidate_admin_script(Some("install helper"), Some(&update)).unwrap();
        let command = admin_shell_command("/usr/bin/sudo", &script);

        assert_eq!(command.matches("/usr/bin/sudo").count(), 1);
        let helper = script.find("install helper").unwrap();
        let export_reload = script.find("/etc/exports").unwrap();
        assert!(helper < export_reload);
        assert!(script.contains("if ! /bin/sh -c"));
    }

    #[test]
    fn client_mount_batch_creates_checks_mounts_and_aliases_under_one_sudo_wrapper() {
        let requests = vec![
            ClientMountRequest {
                source: "192.0.2.1:/Users/Shared/primary".into(),
                mount_root: PathBuf::from("/Volumes/macluster"),
                source_alias: None,
                needs_privileged_mkdir: true,
                needs_mount: true,
                allow_existing_contents: false,
            },
            ClientMountRequest {
                source: "192.0.2.1:/Users/operator/mamba".into(),
                mount_root: PathBuf::from("/Volumes/mamba"),
                source_alias: Some(PathBuf::from("/Users/operator/mamba")),
                needs_privileged_mkdir: false,
                needs_mount: true,
                allow_existing_contents: false,
            },
        ];

        let mounts = client_mount_batch_script(&requests).expect("build client mount batch");
        let script =
            candidate_admin_script(Some("install power"), Some(&mounts)).expect("wrap admin batch");
        let command = admin_shell_command("/usr/bin/sudo", &script);

        assert_eq!(command.matches("/usr/bin/sudo").count(), 1);
        assert!(script.contains("install power"));
        let mkdir = mounts.find("/bin/mkdir -p /Volumes/macluster").unwrap();
        let empty_check = mounts.find("mount point is not empty").unwrap();
        let primary_mount = mounts
            .find("/sbin/mount_nfs -o resvport 192.0.2.1:/Users/Shared/primary")
            .unwrap();
        let second_mount = mounts
            .find("/sbin/mount_nfs -o resvport 192.0.2.1:/Users/operator/mamba")
            .unwrap();
        let alias = mounts
            .find("/bin/ln -s \"$target_path\" \"$alias_path\"")
            .unwrap();
        assert!(mkdir < empty_check);
        assert!(empty_check < primary_mount);
        assert!(primary_mount < second_mount);
        assert!(second_mount < alias);
        assert!(mounts.contains("/bin/ls -A /Volumes/macluster"));
    }

    #[test]
    fn client_mount_batch_continues_after_an_alias_already_points_to_its_target() {
        let root = std::env::temp_dir().join(format!("macluster-alias-batch-{}", Id128::random()));
        let first_target = root.join("first-target");
        let second_target = root.join("second-target");
        let first_alias = root.join("first-alias");
        let second_alias = root.join("second-alias");
        fs::create_dir_all(&first_target).unwrap();
        fs::create_dir_all(&second_target).unwrap();
        std::os::unix::fs::symlink(&first_target, &first_alias).unwrap();
        let requests = vec![
            ClientMountRequest {
                source: "192.0.2.1:/first".into(),
                mount_root: first_target.clone(),
                source_alias: Some(first_alias),
                needs_privileged_mkdir: false,
                needs_mount: false,
                allow_existing_contents: false,
            },
            ClientMountRequest {
                source: "192.0.2.1:/second".into(),
                mount_root: second_target.clone(),
                source_alias: Some(second_alias.clone()),
                needs_privileged_mkdir: false,
                needs_mount: false,
                allow_existing_contents: false,
            },
        ];

        let script = client_mount_batch_script(&requests).unwrap();
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(fs::read_link(&second_alias).unwrap(), second_target);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nfs_recovery_is_disabled_before_unmount_even_if_mount_has_disappeared() {
        let request = ClientUnmountRequest {
            source: "192.0.2.1:/data".into(),
            mount_root: PathBuf::from("/Volumes/example"),
            share_uuid: "00000000-0000-4000-8000-000000000001".into(),
            label: "example".into(),
        };
        let script = client_nfs_cleanup_batch_script(&[request], &[]);
        assert!(
            script.find("internal nfs-recovery remove").unwrap()
                < script.find("mounts=$(/sbin/mount)").unwrap()
        );
    }

    #[test]
    fn client_nfs_cleanup_batch_unmounts_only_exact_mounts_and_removes_exact_aliases() {
        let requests = vec![
            ClientUnmountRequest {
                source: "192.0.2.1:/Users/Shared/primary".into(),
                mount_root: PathBuf::from("/Users/Shared/macluster"),
                share_uuid: "primary-uuid".into(),
                label: "primary".into(),
            },
            ClientUnmountRequest {
                source: "192.0.2.3:/Users/operator/mamba".into(),
                mount_root: PathBuf::from("/Volumes/mamba"),
                share_uuid: "mamba-uuid".into(),
                label: "mamba".into(),
            },
        ];
        let aliases = vec![(
            PathBuf::from("/Users/operator/mamba"),
            PathBuf::from("/Volumes/mamba"),
        )];

        let script = client_nfs_cleanup_batch_script(&requests, &aliases);

        assert_eq!(script.matches("/sbin/umount").count(), 2);
        assert!(script.contains("192.0.2.1:/Users/Shared/primary"));
        assert!(script.contains("/Users/Shared/macluster/.macluster-share-id"));
        assert!(script.contains("primary-uuid"));
        assert!(script.contains("mamba-uuid"));
        assert!(script.contains("filesystem == \"nfs\""));
        assert!(script.contains("/usr/bin/readlink"));
        assert!(script.contains("/bin/rm"));
        assert!(!script.contains("rm -rf"));
        let first_unmount = script.find("/sbin/umount").unwrap();
        assert!(script.find("mamba-uuid").unwrap() < first_unmount);
        let syntax = Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .output()
            .expect("run POSIX shell syntax check");
        assert!(
            syntax.status.success(),
            "generated cleanup script must parse: {}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[test]
    fn cleanup_alias_permission_failure_is_reported_for_admin_retry() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = test_exports_path();
        let protected = root.join("protected");
        let alias = protected.join("source");
        let target = root.join("mounted");
        fs::create_dir_all(&protected).unwrap();
        fs::create_dir_all(&target).unwrap();
        symlink(&target, &alias).unwrap();
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o000)).unwrap();
        let script = client_nfs_cleanup_batch_script(&[], &[(alias, target)]);
        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .expect("run alias cleanup");
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(mount_point_permission_error(&error), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_marker_permission_failure_is_reported_for_admin_retry() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_exports_path();
        let mount_root = root.join("protected-mount");
        fs::create_dir_all(&mount_root).unwrap();
        fs::write(mount_root.join(".macluster-share-id"), "share-uuid").unwrap();
        fs::set_permissions(&mount_root, fs::Permissions::from_mode(0o000)).unwrap();
        let request = ClientUnmountRequest {
            source: "192.0.2.1:/shared".into(),
            mount_root: mount_root.clone(),
            share_uuid: "share-uuid".into(),
            label: "test share".into(),
        };
        let mut script = String::from("set -eu\nmount_status=expected\n");
        append_client_mount_marker_check(&mut script, &request);
        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .expect("run marker verification");
        fs::set_permissions(&mount_root, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(mount_point_permission_error(&error), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn client_nfs_cleanup_plan_contains_only_mounts_owned_by_the_removed_client() {
        let config = ClusterConfig::parse(
            r#"
[cluster]
name = "test"
default_queue = "arm"
shared_root = "/Users/Shared/macluster"
share_uuid = "11111111-1111-4111-8111-111111111111"
storage_server = "storage"
protocol_version = 1

[queues.arm]
nodes = ["worker"]
scheduler = "fifo"

[nodes.storage]
host = "192.0.2.1"
transport = "ssh"
ssh_user = "operator"

[nodes.worker]
host = "192.0.2.2"
transport = "ssh"
ssh_user = "operator"

[shares.tools]
server = "storage"
source_root = "/Users/Shared/tools"
mount_root = "/Volumes/tools"
share_uuid = "22222222-2222-4222-8222-222222222222"

[shares.worker-local]
server = "worker"
source_root = "/Users/Shared/worker-tools"
mount_root = "/Volumes/worker-tools"
share_uuid = "33333333-3333-4333-8333-333333333333"
"#,
        )
        .expect("parse cleanup fixture");

        let (requests, aliases) = client_nfs_cleanup_plan(&config, "worker");

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].source, "192.0.2.1:/Users/Shared/macluster");
        assert_eq!(requests[1].source, "192.0.2.1:/Users/Shared/tools");
        assert_eq!(
            aliases,
            vec![(
                PathBuf::from("/Users/Shared/tools"),
                PathBuf::from("/Volumes/tools"),
            )]
        );

        let (server_requests, server_aliases) = client_nfs_cleanup_plan(&config, "storage");
        assert_eq!(server_requests.len(), 1);
        assert_eq!(
            server_requests[0].source,
            "192.0.2.2:/Users/Shared/worker-tools"
        );
        assert_eq!(server_aliases.len(), 1);
    }

    #[test]
    fn pending_add_cleanup_detects_attempted_and_legacy_client_setup() {
        let mut operation = NodeOperation {
            id: "pending".into(),
            action: "add".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "worker".into(),
            endpoint: "operator@192.0.2.2:22".into(),
            machine_uuid: None,
            phase: "SETUP_PENDING".into(),
            old_config_sha256: None,
            candidate_config_sha256: None,
            managed_export: false,
            managed_shares: BTreeSet::new(),
            client_setup_attempted: Some(false),
            detail: None,
        };

        assert!(!pending_add_may_have_client_state(&operation));
        operation.client_setup_attempted = Some(true);
        assert!(pending_add_may_have_client_state(&operation));
        operation.client_setup_attempted = Some(false);
        operation.phase = "CANDIDATE_INSTALLED".into();
        assert!(pending_add_may_have_client_state(&operation));

        operation.endpoint = "queue:arm".into();
        operation.phase = "SETUP_PENDING".into();
        operation.client_setup_attempted = None;
        assert!(!pending_add_may_have_client_state(&operation));
    }

    #[test]
    fn reset_admin_projection_preserves_pending_client_setup_uncertainty() {
        let root = std::env::temp_dir().join(format!("macluster-reset-admin-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config_path = root.join("config.toml");
        fs::write(&config_path, "cluster fixture").unwrap();
        let config_path = config_path.canonicalize().unwrap();
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let state_dir = state_dir.canonicalize().unwrap();
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, &state_dir).unwrap();
        let operation = |id: &str, endpoint: &str, attempted| NodeOperation {
            id: id.into(),
            action: "add".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: id.into(),
            endpoint: endpoint.into(),
            machine_uuid: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: None,
            candidate_config_sha256: None,
            managed_export: false,
            managed_shares: BTreeSet::new(),
            client_setup_attempted: attempted,
            detail: None,
        };
        state.operations.insert(
            "attempted".into(),
            operation("attempted", "operator@192.0.2.2:22", Some(true)),
        );
        state.operations.insert(
            "not-attempted".into(),
            operation("not-attempted", "operator@192.0.2.3:22", Some(false)),
        );
        state.operations.insert(
            "legacy".into(),
            operation("legacy", "operator@192.0.2.4:22", None),
        );
        state
            .operations
            .get_mut("attempted")
            .unwrap()
            .remote_config_path = Some(
            "/Users/operator/.config/macluster/clusters/cluster/agents/machine/config.toml".into(),
        );
        save_admin_state(&journal_path, &state).unwrap();

        let operations = reset_admin_operations(&config_path, &state_dir).unwrap();

        let by_id = operations
            .into_iter()
            .map(|operation| (operation.node_id.clone(), operation))
            .collect::<BTreeMap<_, _>>();
        assert!(by_id["attempted"].client_setup_may_have_run);
        assert!(!by_id["not-attempted"].client_setup_may_have_run);
        assert!(by_id["legacy"].client_setup_may_have_run);
        assert_eq!(
            by_id["attempted"].remote_config_path.as_deref(),
            Some("/Users/operator/.config/macluster/clusters/cluster/agents/machine/config.toml")
        );
        assert!(by_id["legacy"].remote_config_path.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_export_cleanup_plan_reconciles_every_exact_export_for_the_candidate() {
        let config = ClusterConfig::parse(
            r#"
[cluster]
name = "test"
default_queue = "arm"
shared_root = "/Users/Shared/macluster"
share_uuid = "11111111-1111-4111-8111-111111111111"
storage_server = "storage"
protocol_version = 1

[queues.arm]
nodes = ["worker"]
scheduler = "fifo"

[nodes.storage]
host = "192.0.2.1"
transport = "ssh"
ssh_user = "operator"

[nodes.worker]
host = "192.0.2.2"
transport = "ssh"
ssh_user = "operator"

[shares.tools]
server = "storage"
source_root = "/Users/Shared/tools"
mount_root = "/Volumes/tools"
share_uuid = "22222222-2222-4222-8222-222222222222"

[shares.worker-local]
server = "worker"
source_root = "/Users/Shared/worker-tools"
mount_root = "/Volumes/worker-tools"
share_uuid = "33333333-3333-4333-8333-333333333333"
"#,
        )
        .expect("parse export cleanup fixture");

        let groups = pending_managed_export_cleanup_plan(&config, "worker", "192.0.2.2");
        let requests = &groups["storage"];
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].0, None);
        assert_eq!(requests[0].1.root, "/Users/Shared/macluster");
        assert_eq!(requests[1].0.as_deref(), Some("tools"));
        assert_eq!(requests[1].1.root, "/Users/Shared/tools");

        let storage_groups = pending_managed_export_cleanup_plan(&config, "storage", "192.0.2.1");
        assert_eq!(storage_groups.len(), 1);
        let worker_export = &storage_groups["worker"][0].1;
        assert_eq!(worker_export.root, "/Users/Shared/worker-tools");
    }

    #[test]
    fn pending_cleanup_requires_a_matching_recorded_machine_identity() {
        assert!(
            validate_pending_node_identity(
                "worker",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
                "01234567-89AB-CDEF-0123-456789ABCDEF"
            )
            .is_ok()
        );
        assert!(
            validate_pending_node_identity(
                "worker",
                Some("01234567-89ab-cdef-0123-456789abcdef"),
                "fedcba98-7654-3210-fedc-ba9876543210"
            )
            .unwrap_err()
            .contains("different from its recorded identity")
        );
        assert!(
            validate_pending_node_identity("worker", None, "01234567-89ab-cdef-0123-456789abcdef")
                .unwrap_err()
                .contains("no recorded machine UUID")
        );
    }

    #[test]
    fn old_node_admin_journals_treat_unknown_client_setup_as_cleanup_candidate() {
        let operation: NodeOperation = serde_json::from_str(
            r#"{"id":"old","action":"add","node_id":"worker","endpoint":"operator@192.0.2.2:22","machine_uuid":null,"phase":"SETUP_PENDING","old_config_sha256":null,"candidate_config_sha256":null,"managed_export":false,"managed_shares":[],"detail":null}"#,
        )
        .expect("deserialize legacy operation");

        assert_eq!(operation.client_setup_attempted, None);
        assert!(pending_add_may_have_client_state(&operation));
    }

    #[test]
    fn pending_cleanup_endpoint_ignores_an_optional_share_source_path() {
        let node = cleanup_node_from_endpoint("local@192.0.2.2:22:/Users/Shared/tools", None)
            .expect("reconstruct pending local node identity");

        assert_eq!(node.transport, Transport::Local);
        assert_eq!(node.host, "192.0.2.2");
    }

    #[test]
    fn primary_mount_status_rejects_an_unrelated_mount_at_the_requested_path() {
        let output = "192.0.2.8:/unrelated on /Volumes/macluster (nfs, nodev, nosuid)\n";

        assert_eq!(
            super::named_share_mount_status(
                output,
                "192.0.2.1:/Users/Shared/primary",
                "/Volumes/macluster"
            ),
            NamedShareMountStatus::MountedElsewhere("192.0.2.8:/unrelated".into())
        );
    }

    #[test]
    fn nfs_cleanup_status_rejects_stacked_mounts_at_the_same_path() {
        let output = concat!(
            "192.0.2.1:/expected on /Volumes/macluster (nfs, nodev)\n",
            "192.0.2.2:/other on /Volumes/macluster (nfs, nodev)\n"
        );

        assert_eq!(
            super::named_share_mount_status(output, "192.0.2.1:/expected", "/Volumes/macluster"),
            NamedShareMountStatus::MountedElsewhere("multiple mounts at the requested path".into())
        );
    }

    #[test]
    fn cleanup_awk_requires_one_exact_nfs_mount() {
        let awk = super::shell_quote(client_mount_status_awk_script());
        let run = |mounts: &str| {
            let script = format!(
                "printf '%s\\n' {} | /usr/bin/awk -v source={} -v mount={} {}",
                super::shell_quote(mounts),
                super::shell_quote("192.0.2.1:/expected"),
                super::shell_quote("/Volumes/macluster"),
                awk
            );
            let output = Command::new("/bin/sh")
                .args(["-c", &script])
                .output()
                .expect("execute mount classification");
            assert!(output.status.success());
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };

        assert_eq!(
            run("192.0.2.1:/expected on /Volumes/macluster (nfs, nodev)"),
            "expected"
        );
        assert_eq!(
            run("192.0.2.1:/expected on /Volumes/macluster (apfs, local)"),
            "other"
        );
        assert_eq!(
            run(concat!(
                "192.0.2.1:/expected on /Volumes/macluster (nfs, nodev)\n",
                "192.0.2.2:/other on /Volumes/macluster (nfs, nodev)"
            )),
            "other"
        );
        assert_eq!(run(""), "none");
    }

    #[test]
    fn client_share_alias_script_replaces_only_empty_directory_trees() {
        use std::os::unix::fs::symlink;

        let root = test_exports_path();
        let alias = root.join("source-prefix");
        let target = root.join("mounted-share");
        fs::create_dir_all(alias.join("envs/analysis")).unwrap();
        fs::create_dir_all(&target).unwrap();

        let script = client_share_alias_script(&alias, &target);
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_link(&alias).unwrap(), target);

        // Running setup twice is idempotent.
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        fs::remove_file(&alias).unwrap();
        fs::create_dir(&alias).unwrap();
        fs::write(alias.join("keep.txt"), "user data").unwrap();
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(alias.join("keep.txt")).unwrap(),
            "user data"
        );

        fs::remove_dir_all(&alias).unwrap();
        let unrelated = root.join("unrelated-target");
        fs::create_dir(&unrelated).unwrap();
        symlink(&unrelated, &alias).unwrap();
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(fs::read_link(&alias).unwrap(), unrelated);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn controller_shutdown_confirmation_accepts_only_yes_responses() {
        assert!(shutdown_confirmation_accepted("y"));
        assert!(shutdown_confirmation_accepted(" Y\n"));
        assert!(shutdown_confirmation_accepted("yes\n"));
        assert!(!shutdown_confirmation_accepted("n\n"));
        assert!(!shutdown_confirmation_accepted(""));
        assert!(!shutdown_confirmation_accepted("maybe\n"));
    }

    #[test]
    fn interactive_ssh_hides_normal_disconnect_messages_but_keeps_errors() {
        assert!(super::SSH_OPTIONS.contains(&"-oLogLevel=ERROR"));
        assert!(super::INTERACTIVE_SSH_OPTIONS.contains(&"-oLogLevel=ERROR"));
    }

    #[test]
    fn managed_agent_path_digest_requires_a_full_hex_parent_directory() {
        let digest = "0123456789abcdef".repeat(4);
        assert_eq!(
            managed_binary_digest(&format!(
                "/home/user/.local/share/macluster/bin/{digest}/macluster"
            )),
            Some(digest.clone())
        );
        assert_eq!(managed_binary_digest("/usr/local/bin/macluster"), None);
        assert_eq!(
            managed_binary_digest(&format!("/home/user/bin/not-a-digest/macluster")),
            None
        );
        assert_eq!(
            managed_binary_digest(&format!("/home/user/bin/{}/other", "a".repeat(64))),
            None
        );
        assert!(super::is_expected_managed_agent_path(
            &format!("/home/user/bin/{digest}/macluster"),
            &digest
        ));
        assert!(!super::is_expected_managed_agent_path(
            &format!("/usr/local/bin/macluster"),
            &digest
        ));
    }

    #[test]
    fn legacy_agent_probe_requires_a_valid_hash_and_reports_version() {
        let digest = "a".repeat(64);
        let parsed = parse_agent_build_probe(&format!(
            "VERSION=macluster 0.1.0 (protocol 1)\nSHA256={digest}\n"
        ))
        .unwrap();
        assert_eq!(parsed.version, "macluster 0.1.0 (protocol 1)");
        assert_eq!(parsed.sha256, Some(digest));
        let version_only =
            parse_agent_build_probe("VERSION=macluster 0.1.0\nSHA256=bad\n").unwrap();
        assert_eq!(version_only.version, "macluster 0.1.0");
        assert_eq!(version_only.sha256, None);
    }

    #[test]
    fn local_agent_build_is_classified_by_file_digest() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("macluster");
        fs::write(&binary, b"current local agent").unwrap();
        let node = NodeConfig {
            host: "127.0.0.1".into(),
            transport: Transport::Local,
            remote_binary: binary.display().to_string(),
            ssh_user: None,
            ssh_port: None,
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: None,
            execution_uid: None,
        };
        let digest = sha256_hex(b"current local agent").unwrap();
        assert_eq!(
            inspect_configured_agent_build(&node, &digest),
            AgentBuildState::Current
        );
        assert_eq!(
            inspect_configured_agent_build(&node, &sha256_hex(b"different agent").unwrap()),
            AgentBuildState::Stale
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn global_agent_classification_includes_login_and_all_queues() {
        let config = parse_build_test_config();
        let compatibility = classify_configured_agents(&config, |node_id, _| match node_id {
            "login" => AgentBuildState::Current,
            "arm-a" => AgentBuildState::Current,
            "arm-b" => AgentBuildState::Stale,
            _ => AgentBuildState::Unknown,
        });
        assert_eq!(compatibility.current, ["arm-a", "login"]);
        assert_eq!(compatibility.stale, ["arm-b"]);
        assert!(compatibility.requires_update());

        let unknown = classify_configured_agents(&config, |_, _| AgentBuildState::Unknown);
        assert_eq!(unknown.unknown, ["arm-a", "arm-b", "login"]);
        assert!(!unknown.requires_update());
    }

    #[test]
    fn agent_validation_cache_key_changes_when_ssh_identity_changes() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let identity = root.join("id_ed25519");
        fs::write(&identity, b"first-key-material").unwrap();
        let mut config = parse_build_test_config();
        config.nodes.get_mut("arm-a").unwrap().ssh_identity_file =
            Some(identity.display().to_string());
        let first = super::agent_validation_cache_key(&config).unwrap();
        fs::write(&identity, b"rotated-key-material-with-new-size").unwrap();
        let second = super::agent_validation_cache_key(&config).unwrap();
        assert_ne!(first, second);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn agent_validation_cache_keeps_unknown_for_at_most_sixty_seconds() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let config = parse_build_test_config();
        let key = super::agent_validation_cache_key(&config).unwrap();
        let path = root.join("cache.json");
        let now = super::validation_now_ms();
        let unknown = AgentBuildCompatibility {
            current: vec!["login".into()],
            stale: Vec::new(),
            unknown: vec!["arm-a".into()],
            missing_required_features: Vec::new(),
        };
        super::write_agent_validation_cache(
            &path,
            super::AgentValidationCache {
                schema: super::AGENT_VALIDATION_CACHE_SCHEMA,
                key: key.clone(),
                checked_unix_ms: now.saturating_sub(45_000),
                compatibility: unknown.clone(),
            },
        );
        let (cached, age_ms) = super::read_agent_validation_cache(&path, &key).unwrap();
        assert_eq!(cached, unknown);
        assert!((45_000..=46_000).contains(&age_ms));

        super::write_agent_validation_cache(
            &path,
            super::AgentValidationCache {
                schema: super::AGENT_VALIDATION_CACHE_SCHEMA,
                key: key.clone(),
                checked_unix_ms: now.saturating_sub(60_001),
                compatibility: unknown,
            },
        );
        assert!(super::read_agent_validation_cache(&path, &key).is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn required_agent_features_include_namespaced_job_storage() {
        assert!(
            super::REQUIRED_AGENT_FEATURES
                .contains(&macluster_protocol::types::NAMESPACED_JOBS_FEATURE)
        );
    }

    #[test]
    fn agent_update_batches_changed_privileged_helpers_in_one_admin_script() {
        let script = super::agent_update_admin_script(
            Some("install-power-helper"),
            Some("refresh-nfs-helper"),
        )
        .unwrap();
        assert_eq!(script, "set -e\ninstall-power-helper\nrefresh-nfs-helper\n");
        assert_eq!(script.matches("set -e").count(), 1);
        assert!(super::agent_update_admin_script(None, None).is_none());
    }

    #[test]
    fn nfs_helper_probe_checks_version_files_and_service_registration() {
        let mounts = vec![
            super::ClientUnmountRequest {
                source: "192.0.2.1:/shared".into(),
                mount_root: PathBuf::from("/Users/Shared/macluster"),
                share_uuid: "00000000-0000-4000-8000-000000000001".into(),
                label: "primary".into(),
            },
            super::ClientUnmountRequest {
                source: "192.0.2.1:/tools".into(),
                mount_root: PathBuf::from("/Users/Shared/tools"),
                share_uuid: "00000000-0000-4000-8000-000000000002".into(),
                label: "tools".into(),
            },
        ];
        let script = super::client_nfs_recovery_version_probe_script(&mounts).unwrap();
        assert!(script.contains("/bin/cat"));
        let first_marker = crate::nfs_recovery::version_marker_path(&mounts[0].mount_root);
        let second_marker = crate::nfs_recovery::version_marker_path(&mounts[1].mount_root);
        assert!(script.contains(first_marker.to_str().unwrap()));
        assert!(script.contains(second_marker.to_str().unwrap()));
        assert_eq!(script.matches("printf '%s\\n'").count(), 2);
        assert!(!script.contains("internal nfs-recovery refresh"));
        let syntax = Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "{}",
            String::from_utf8_lossy(&syntax.stderr)
        );
    }

    #[test]
    fn nfs_update_script_refreshes_only_outdated_mount_helpers() {
        let mut config = parse_build_test_config();
        config.shares.insert(
            "tools".into(),
            ShareConfig {
                server: NodeId::new("login").unwrap(),
                source_root: "/Users/shared/tools".into(),
                mount_root: "/Users/shared/tools".into(),
                share_uuid: "00000000-0000-4000-8000-000000000002".into(),
            },
        );
        let digest = "ab".repeat(32);
        let node = config.nodes.get_mut("arm-a").unwrap();
        node.remote_binary = format!("/Users/test/.local/share/macluster/bin/{digest}/macluster");
        node.execution_uid = Some(501);

        let script =
            super::client_nfs_recovery_refresh_script(&config, "arm-a", &BTreeSet::from([1]))
                .unwrap()
                .unwrap();
        assert_eq!(script.matches("internal nfs-recovery refresh").count(), 1);
        assert!(script.contains("/Users/shared/tools"));
        assert!(script.contains(&digest));
        assert!(!script.contains("/tmp/macluster-shared"));
    }

    #[test]
    fn missing_required_capability_forces_agent_update() {
        let missing = super::missing_required_agent_features(&[
            "agent.node-health.v1".into(),
            "agent.interactive-pty.v1".into(),
        ]);
        assert!(missing.contains(&macluster_protocol::types::NAMESPACED_JOBS_FEATURE));

        let compatibility = AgentBuildCompatibility {
            current: vec!["arm-a".into()],
            missing_required_features: vec!["arm-a".into()],
            ..AgentBuildCompatibility::default()
        };
        assert!(compatibility.requires_update());
    }

    #[test]
    fn deferred_privileged_helper_refresh_is_detected_from_private_marker() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        assert!(!super::agent_helper_refresh_pending(&root).unwrap());
        super::atomic_write(&root.join(super::HELPER_REFRESH_PENDING_FILE), b"pending\n").unwrap();
        assert!(super::agent_helper_refresh_pending(&root).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn power_preparation_failure_stays_pending_until_a_successful_retry() {
        let mut config = parse_build_test_config();
        config.nodes.retain(|id, _| id == "login");
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let deferred = super::refresh_agent_helpers_for_update_with(
            &config,
            "retry-test",
            |_, _| Err("temporary upload failure".into()),
            |_, _| Ok(None),
        )
        .unwrap();
        assert!(deferred);
        super::set_agent_helper_refresh_pending(&root, deferred);
        assert!(super::agent_helper_refresh_pending(&root).unwrap());
        let deferred = super::refresh_agent_helpers_for_update_with(
            &config,
            "retry-test",
            |_, _| Ok(None),
            |_, _| Ok(None),
        )
        .unwrap();
        assert!(!deferred);
        super::set_agent_helper_refresh_pending(&root, deferred);
        assert!(!super::agent_helper_refresh_pending(&root).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_agent_repair_replaces_stale_file_and_preserves_unmanaged_file() {
        use std::os::unix::fs::PermissionsExt;
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("current");
        let payload = format!(
            "#!/bin/sh\nprintf 'macluster {}\\n'\n",
            env!("CARGO_PKG_VERSION")
        );
        fs::write(&binary, &payload).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let digest = super::local_sha256(&binary).unwrap();
        let destination = root.join(&digest).join("macluster");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(&destination, b"damaged agent").unwrap();
        let mut node = parse_build_test_config().nodes["login"].clone();
        node.remote_binary = destination.to_string_lossy().into_owned();
        super::ensure_remote_binary(&node, &binary, "14.0", "repair-test").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), payload.as_bytes());
        let unmanaged = root.join("macluster");
        fs::write(&unmanaged, b"keep this file").unwrap();
        node.remote_binary = unmanaged.to_string_lossy().into_owned();
        assert!(super::ensure_remote_binary(&node, &binary, "14.0", "repair-test").is_err());
        assert_eq!(fs::read(unmanaged).unwrap(), b"keep this file");
        fs::remove_dir_all(root).unwrap();
    }

    fn parse_build_test_config() -> ClusterConfig {
        ClusterConfig::parse(
            "[cluster]\nname=\"test\"\ndefault_queue=\"compute\"\nlogin_node=\"login\"\nshared_root=\"/tmp/macluster-shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"login\"\nprotocol_version=1\n\n[queues.compute]\nnodes=[\"login\",\"arm-a\",\"arm-b\"]\nscheduler=\"fifo\"\n\n[queues.login-pool]\nnodes=[\"login\"]\nscheduler=\"fifo\"\n\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/usr/local/bin/macluster\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\n\n[nodes.arm-a]\nhost=\"192.0.2.10\"\ntransport=\"ssh\"\nremote_binary=\"/usr/local/bin/macluster\"\nssh_user=\"test\"\nssh_port=22\n\n[nodes.arm-b]\nhost=\"192.0.2.11\"\ntransport=\"ssh\"\nremote_binary=\"/usr/local/bin/macluster\"\nssh_user=\"test\"\nssh_port=22\n",
        )
        .unwrap()
    }

    #[test]
    fn local_address_policy_reuses_registered_interface_with_multiple_addresses() {
        let mut config = parse_build_test_config();
        config.nodes.get_mut("login").unwrap().host = "192.168.2.2".into();
        let addresses =
            ["198.18.0.1", "192.168.3.5", "192.168.2.2"].map(|address| address.parse().unwrap());
        assert_eq!(
            preferred_local_host(&config, None, &addresses).unwrap(),
            Some("192.168.2.2".parse().unwrap())
        );
    }

    #[test]
    fn local_address_policy_requires_explicit_change_for_inactive_registration() {
        let mut config = parse_build_test_config();
        config.nodes.get_mut("login").unwrap().host = "192.168.2.2".into();
        let replacement = "192.168.3.5".parse().unwrap();
        let addresses = [replacement];
        let error = preferred_local_host(&config, None, &addresses).unwrap_err();
        assert!(error.1.contains("192.168.2.2"), "{error:?}");
        assert!(error.1.contains("--host"), "{error:?}");
        assert_eq!(
            preferred_local_host(&config, Some(replacement), &addresses).unwrap(),
            Some(replacement)
        );
        assert!(
            preferred_local_host(&config, Some("192.168.9.9".parse().unwrap()), &addresses)
                .is_err()
        );
        config.nodes.remove("login");
        assert_eq!(
            preferred_local_host(&config, None, &addresses).unwrap(),
            None
        );
    }

    #[test]
    fn nfs_mapping_details_distinguish_local_alias_and_mount_with_per_share_health() {
        let mut config = parse_build_test_config();
        config.shares.insert(
            "JanusX".into(),
            ShareConfig {
                server: NodeId::new("login").unwrap(),
                source_root: "/Users/example/script/JanusX".into(),
                mount_root: "/Users/Shared/JanusX".into(),
                share_uuid: "00000000-0000-4000-8000-000000000002".into(),
            },
        );
        let mut health = NodeHealth {
            machine_uuid: config.nodes["login"].machine_uuid.clone().unwrap(),
            execution_uid: 501,
            execution_digest: config.execution_digest().unwrap(),
            primary_share_ready: true,
            shares: BTreeMap::from([("JanusX".into(), false)]),
            features: Vec::new(),
        };
        let server = node_nfs_mappings(&config, "login", Some(&health));
        assert_eq!(server[0].name, "primary");
        assert_eq!(server[0].kind, "LOCAL");
        assert_eq!(server[0].state, "READY");
        assert_eq!(server[0].source_node, "login");
        assert_eq!(server[0].target, "/tmp/macluster-shared");
        assert_eq!(server[1].name, "JanusX");
        assert_eq!(server[1].kind, "ALIAS");
        assert_eq!(server[1].state, "PENDING");
        assert_eq!(server[1].source_node, "login");
        assert_eq!(server[1].target, "/Users/Shared/JanusX");

        let client = node_nfs_mappings(&config, "arm-a", Some(&health));
        assert!(client.iter().all(|mapping| mapping.kind == "MOUNT"));
        let offline = node_nfs_mappings(&config, "arm-a", None);
        assert!(offline.iter().all(|mapping| mapping.state == "UNKNOWN"));
        assert_eq!(offline[1].source_node, server[1].source_node);
        assert_eq!(offline[1].target, server[1].target);

        config.storage_source_root = Some("/Users/Shared/storage".into());
        let outdated = node_nfs_mappings(&config, "login", Some(&health));
        assert!(outdated.iter().all(|mapping| mapping.state == "UNKNOWN"));
        health.execution_digest = config.execution_digest().unwrap();
        health.shares.clear();
        let refreshed = node_nfs_mappings(&config, "login", Some(&health));
        assert_eq!(refreshed[0].kind, "ALIAS");
        assert_eq!(refreshed[0].state, "READY");
        assert_eq!(refreshed[1].state, "UNKNOWN");
        health.execution_uid = 0;
        assert!(
            node_nfs_mappings(&config, "login", Some(&health))
                .iter()
                .all(|mapping| mapping.state == "UNKNOWN")
        );
    }

    #[test]
    fn controller_process_verification_checks_uid_executable_and_command() {
        assert!(controller_command_matches(
            PathBuf::from("/Users/example/mac cluster/macluster").as_path(),
            501,
            501,
            "/Users/example/mac cluster/macluster controller run"
        ));
        assert!(controller_command_matches(
            PathBuf::from("/usr/local/bin/macluster").as_path(),
            501,
            501,
            "/usr/local/bin/macluster --config /tmp/cluster.toml controller run"
        ));
        assert!(!controller_command_matches(
            PathBuf::from("/usr/local/bin/macluster").as_path(),
            502,
            501,
            "/usr/local/bin/macluster controller run"
        ));
        assert!(!controller_command_matches(
            PathBuf::from("/usr/local/bin/other").as_path(),
            501,
            501,
            "/usr/local/bin/other controller run"
        ));
        assert!(!controller_command_matches(
            PathBuf::from("/usr/local/bin/macluster").as_path(),
            501,
            501,
            "/usr/local/bin/macluster msub"
        ));
    }

    #[test]
    fn node_maintenance_gate_blocks_submissions_and_cleans_up() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);

        let guard = acquire_node_maintenance(&config, &state, "test maintenance").unwrap();
        assert!(barrier.is_file());
        assert!(ensure_no_node_maintenance_in_progress(&config, &state).is_err());
        drop(guard);

        assert!(!barrier.exists());
        assert!(ensure_no_node_maintenance_in_progress(&config, &state).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn node_maintenance_waits_for_controller_lock_release() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        fs::create_dir_all(&state).unwrap();
        let controller_lock = MaintenanceLock::shared(&config).unwrap();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);
        let worker_config = config.clone();
        let worker_state = state.clone();
        let worker = std::thread::spawn(move || {
            acquire_node_maintenance_with(
                &worker_config,
                &worker_state,
                "test drain",
                |_| {},
                |_| Ok(()),
                |_, _| Ok(None),
                |_, _, _, _| panic!("no controller process should be stopped"),
            )
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !barrier.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "maintenance did not publish its submission barrier"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(ensure_no_node_maintenance_in_progress(&config, &state).is_err());
        drop(controller_lock);

        let guard = worker.join().unwrap().unwrap();
        drop(guard);
        assert!(!barrier.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn declining_controller_shutdown_leaves_no_maintenance_barrier() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        fs::create_dir_all(&state).unwrap();
        let controller_lock = MaintenanceLock::shared(&config).unwrap();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);

        let result = acquire_node_maintenance_with(
            &config,
            &state,
            "Agent update",
            |_| {},
            |_| {
                Err((
                    1,
                    "Agent update cancelled; controller remains running".into(),
                ))
            },
            |_, _| Ok(Some(12345)),
            |_, _, _, _| panic!("a declined shutdown must not stop the controller"),
        );

        assert!(result.is_err());
        assert!(!barrier.exists());
        drop(controller_lock);
        assert!(MaintenanceLock::exclusive(&config).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_job_preflight_keeps_controller_running_and_clears_barrier() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        let controller_lock = MaintenanceLock::shared(&config).unwrap();
        let storage = Storage::open(&state).unwrap();
        let snapshot = storage.stage_snapshot(b"sleep 10\n").unwrap();
        let job = storage
            .submit_once(
                macluster_protocol::identifiers::RequestId::random(),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("q").unwrap(),
                    node: None,
                    name: "active".into(),
                    cwd: "/tmp".into(),
                    stdout_path: "/tmp/stdout".into(),
                    stderr_path: "/tmp/stderr".into(),
                    walltime_secs: None,
                    env: Default::default(),
                    mode: JobMode::Batch,
                    snapshot: Some(snapshot),
                },
            )
            .unwrap();
        storage
            .reserve_job(job.id, NodeId::new("worker").unwrap())
            .unwrap();
        storage.mark_running(job.id).unwrap();
        drop(storage);

        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);
        let mut stopped = false;
        let mut asked_to_stop = false;
        let result = acquire_node_maintenance_with(
            &config,
            &state,
            "Agent update",
            |_| {},
            |_| {
                asked_to_stop = true;
                Ok(())
            },
            |_, _| Ok(Some(12345)),
            |_, _, _, _| {
                stopped = true;
                panic!("active work must block before stopping the controller")
            },
        );

        let error = result.err().unwrap().1;
        assert!(error.contains("active jobs or output sync"), "{error}");
        assert!(
            !asked_to_stop,
            "must not ask when active work blocks maintenance"
        );
        assert!(!stopped);
        assert!(!barrier.exists());
        drop(controller_lock);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn preconfirmed_agent_update_does_not_ask_to_stop_controller_twice() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        fs::create_dir_all(&state).unwrap();
        let controller_lock = std::sync::Arc::new(std::sync::Mutex::new(Some(
            MaintenanceLock::shared(&config).unwrap(),
        )));
        let stop_lock = controller_lock.clone();
        let guard = acquire_node_maintenance_with_confirmation_using(
            &config,
            &state,
            "Agent update",
            true,
            |_| {},
            |_| panic!("a preconfirmed update must not prompt a second time"),
            |_, _| Ok(Some(12345)),
            |config, _, _, _| {
                stop_lock.lock().unwrap().take();
                MaintenanceLock::exclusive(config).map_err(|error| (1, error.to_string()))
            },
        )
        .unwrap();

        drop(guard);
        assert!(controller_lock.lock().unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn confirmed_controller_shutdown_stops_owner_before_maintenance() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        fs::create_dir_all(&state).unwrap();
        let controller_lock = std::sync::Arc::new(std::sync::Mutex::new(Some(
            MaintenanceLock::shared(&config).unwrap(),
        )));
        let stop_lock = controller_lock.clone();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);
        let mut confirmation_called = false;
        let mut controller_notified = false;

        let guard = acquire_node_maintenance_with(
            &config,
            &state,
            "Agent update",
            |_| controller_notified = true,
            |_| {
                confirmation_called = true;
                Ok(())
            },
            |_, _| Ok(Some(12345)),
            |config, _, pid, operation| {
                assert_eq!(pid, 12345);
                assert_eq!(operation, "Agent update");
                stop_lock.lock().unwrap().take();
                MaintenanceLock::exclusive(config).map_err(|error| (1, error.to_string()))
            },
        )
        .unwrap();

        assert!(confirmation_called);
        assert!(
            !controller_notified,
            "a confirmed immediate stop must not wake the controller into a concurrent shutdown"
        );
        assert!(barrier.is_file());
        drop(guard);
        assert!(!barrier.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn node_maintenance_recovers_a_stale_barrier_record() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        fs::create_dir_all(&state).unwrap();
        let barrier = macluster_core::maintenance::maintenance_barrier_path(&config);
        fs::write(
            &barrier,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "config_path": config,
                "state_dir": state,
                "owner_pid": 999999
            }))
            .unwrap(),
        )
        .unwrap();

        let guard = acquire_node_maintenance(&config, &state, "test recovery").unwrap();
        assert!(barrier.is_file());
        drop(guard);
        assert!(!barrier.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn local_share_test_node() -> NodeConfig {
        let mut node = NodeEndpoint::parse("operator@192.0.2.1")
            .unwrap()
            .node_config("unused".into(), None);
        node.transport = Transport::Local;
        node
    }

    fn enrollment_config_fixture() -> (PathBuf, PathBuf, NodeConfig, String) {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        let source = "[cluster]\nname=\"test\"\ndefault_queue=\"compute\"\nshared_root=\"/tmp/shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.compute]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"192.0.2.2\"\ntransport=\"ssh\"\nremote_binary=\"/old/macluster\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\n";
        fs::write(&path, source).unwrap();
        let mut node = local_share_test_node();
        node.machine_uuid = Some("01234567-89ab-cdef-0123-456789abcdef".into());
        node.execution_uid = Some(501);
        (root, path, node, source.into())
    }

    #[test]
    fn enrollment_accepts_equivalent_existing_remote_configuration() {
        let (root, path, node, source) = enrollment_config_fixture();
        let result = super::ensure_remote_config(
            &node,
            path.to_str().unwrap(),
            &format!("{source}\n# enrollment retry\n"),
            "test-retry",
            &root,
        );
        let retained = fs::read_to_string(&path).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(retained, source);
    }

    #[test]
    fn enrollment_refreshes_stale_config_and_preserves_each_retry_backup() {
        let (root, path, node, source) = enrollment_config_fixture();
        let unrelated = root.join("old-login-config.toml");
        fs::write(&unrelated, "original standalone cluster").unwrap();
        let mut before = source.clone();
        for binary in ["/new/macluster", "/newer/macluster"] {
            let candidate = source.replace("/old/macluster", binary);
            let mut checked = false;
            super::ensure_remote_config_with_idle_check(
                &node,
                path.to_str().unwrap(),
                &candidate,
                "same-operation",
                &root,
                |connection, id, config_path| {
                    assert_eq!(id, "worker");
                    assert_eq!(connection.remote_config.as_deref(), path.to_str());
                    assert_eq!(config_path, path);
                    assert_eq!(fs::read_to_string(&path).unwrap(), before);
                    checked = true;
                    Ok(())
                },
            )
            .unwrap();
            assert!(checked);
            let digest = sha256_hex(before.as_bytes()).unwrap();
            let backup = format!(
                "{}.macluster-same-operation-enroll-{}.bak",
                path.display(),
                &digest[..16]
            );
            assert_eq!(fs::read_to_string(backup).unwrap(), before);
            before = super::compatible_agent_config(&candidate).unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), before);
        }
        assert_eq!(
            fs::read_to_string(unrelated).unwrap(),
            "original standalone cluster"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_preserves_busy_nodes_and_pending_output() {
        for blocker in ["running task", "pending output synchronization"] {
            let (root, path, node, source) = enrollment_config_fixture();
            let candidate = source.replace("/old/macluster", "/new/macluster");
            let result = super::ensure_remote_config_with_idle_check(
                &node,
                path.to_str().unwrap(),
                &candidate,
                "blocked",
                &root,
                |_, _, _| Err((1, blocker.into())),
            );
            assert!(result.unwrap_err().1.contains(blocker));
            assert_eq!(fs::read_to_string(&path).unwrap(), source);
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn enrollment_accepts_old_storage_address_only_for_the_same_storage_machine() {
        let (root, path, node, source) = enrollment_config_fixture();
        let moved = source.replace("192.0.2.2", "192.0.2.20");
        super::ensure_remote_config_with_idle_check(
            &node,
            path.to_str().unwrap(),
            &moved,
            "moved",
            &root,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            super::compatible_agent_config(&moved).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_detects_config_changes_during_idle_verification() {
        let (root, path, node, source) = enrollment_config_fixture();
        let changed = format!("{source}\n# another administrator changed this file\n");
        let candidate = source.replace("/old/macluster", "/new/macluster");
        let result = super::ensure_remote_config_with_idle_check(
            &node,
            path.to_str().unwrap(),
            &candidate,
            "concurrent",
            &root,
            |_, _, _| {
                fs::write(&path, &changed).unwrap();
                Ok(())
            },
        );
        assert!(
            result
                .unwrap_err()
                .1
                .contains("changed while checking enrollment")
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), changed);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_uses_a_machine_scoped_config_and_preserves_old_login_configuration() {
        let (root, _path, node, source) = enrollment_config_fixture();
        let uuid = "00000000-0000-4000-8000-000000000001";
        let legacy = root.join(format!(".config/macluster/clusters/{uuid}/config.toml"));
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        let old_login = source.replace(uuid, "00000000-0000-4000-8000-000000000099");
        fs::write(&legacy, &old_login).unwrap();
        let destination = super::remote_agent_config_path(
            root.to_str().unwrap(),
            uuid,
            node.machine_uuid.as_deref().unwrap(),
        );
        assert_ne!(std::path::Path::new(&destination), legacy);
        super::ensure_remote_config_with_idle_check(
            &node,
            &destination,
            &source,
            "fresh-agent",
            &root,
            |_, _, _| panic!("the new Agent config does not replace an existing config"),
        )
        .unwrap();
        assert_eq!(fs::read_to_string(&legacy).unwrap(), old_login);
        assert_eq!(
            fs::read_to_string(&destination).unwrap(),
            super::compatible_agent_config(&source).unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_preserves_foreign_cluster_machine_and_account_configs() {
        for (old, new) in [
            (
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000099",
            ),
            (
                "01234567-89ab-cdef-0123-456789abcdef",
                "01234567-89ab-cdef-0123-456789abcdee",
            ),
            ("execution_uid=501", "execution_uid=502"),
            ("shared_root=\"/tmp/shared\"", "shared_root=\"/tmp/other\""),
        ] {
            let (root, path, node, source) = enrollment_config_fixture();
            let previous = source.replace(old, new);
            fs::write(&path, &previous).unwrap();
            let result = super::ensure_remote_config_with_idle_check(
                &node,
                path.to_str().unwrap(),
                &source,
                "foreign",
                &root,
                |_, _, _| panic!("foreign config must not be used for execution checks"),
            );
            assert!(result.is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), previous);
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn matching_local_marker_does_not_substitute_for_a_client_nfs_mount() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let uuid = "00000000-0000-4000-8000-000000000001";
        fs::write(root.join(".macluster-share-id"), uuid).unwrap();
        let result = super::verify_named_share_mount(
            &local_share_test_node(),
            "worker",
            "storage",
            "192.0.2.2",
            &root,
            &root,
            uuid,
        );
        assert!(
            result.is_err(),
            "a local directory with a matching marker is not NFS"
        );
        super::verify_named_share_mount(
            &local_share_test_node(),
            "storage",
            "storage",
            "192.0.2.2",
            &root,
            &root,
            uuid,
        )
        .expect("the storage server uses the local source directory");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    fn share_registration_fixture(
        root: &std::path::Path,
        source: &std::path::Path,
        mount: &std::path::Path,
        existing: bool,
    ) -> PathBuf {
        let binary = root.join("idle-agent.py");
        fs::write(&binary, "#!/usr/bin/python3\nimport json,struct,sys\nif 'agent-stdio' not in sys.argv: sys.exit(77)\nn=struct.unpack('>I',sys.stdin.buffer.read(4))[0]\nr=json.loads(sys.stdin.buffer.read(n))\np=json.dumps({'protocol_version':r['protocol_version'],'request_id':r['request_id'],'result':{'Err':'NOT_FOUND'}}).encode()\nsys.stdout.buffer.write(struct.pack('>I',len(p))+p)\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let config_path = root.join("config.toml");
        let mut text = format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"arm\"\nshared_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"storage\"\nprotocol_version = 1\n[queues.arm]\nnodes = [\"{}\"]\nscheduler = \"fifo\"\n[nodes.storage]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nremote_binary = \"{}\"\n",
            root.join("shared").display(),
            "storage",
            binary.display()
        );
        if existing {
            text.push_str(&format!("[shares.tools]\nserver = \"storage\"\nsource_root = \"{}\"\nmount_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000002\"\n", source.display(), mount.display()));
        }
        text = text.replace(
            "transport = \"local\"\n",
            &format!("transport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = {}\n", unsafe { libc::geteuid() }),
        );
        fs::write(&config_path, text).unwrap();
        config_path
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn client_path_preflight_rejects_conflicts_without_mutating_filesystem() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("project");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), "existing client files").unwrap();
        let config_path = share_registration_fixture(&root, &source, &source, false);
        let before = fs::read(&config_path).unwrap();
        let mut config = ClusterConfig::parse(std::str::from_utf8(&before).unwrap()).unwrap();
        // Use the local filesystem as the client transport boundary in this
        // test; no real NFS mounts or administrator privileges are involved.
        let mut client = config.nodes["storage"].clone();
        client.host = "192.0.2.2".into();
        config.nodes.insert("worker".into(), client.clone());
        let share = ShareConfig {
            server: NodeId::new("storage").unwrap(),
            source_root: source.clone(),
            mount_root: source.clone(),
            share_uuid: "00000000-0000-4000-8000-000000000002".into(),
        };
        let error = super::preflight_share_clients(&config, &share).unwrap_err();
        assert!(error.1.contains("not empty"), "{error:?}");
        assert!(!source.join(".macluster-share-id").exists());
        assert_eq!(fs::read(&config_path).unwrap(), before);
        assert_eq!(
            fs::read_to_string(source.join("keep.txt")).unwrap(),
            "existing client files"
        );
        let missing = root.join("missing-parent/mount");
        super::preflight_share_mount(
            &client,
            &config.nodes["storage"],
            &source,
            &missing,
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(!missing.parent().unwrap().exists());
        let symlink = root.join("symlink");
        std::os::unix::fs::symlink(&source, &symlink).unwrap();
        let error = super::preflight_share_mount(
            &client,
            &config.nodes["storage"],
            &source,
            &symlink,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert!(error.contains("symlink"), "{error}");

        let parent = root.join("parent");
        let child = parent.join("sub/child");
        fs::create_dir_all(&child).unwrap();
        let children = BTreeMap::from([(child.clone(), "192.0.2.1:/source/sub/child".into())]);
        super::preflight_share_mount(
            &client,
            &config.nodes["storage"],
            &source,
            &parent,
            &children,
        )
        .unwrap();
        fs::write(parent.join("unrelated.txt"), "keep").unwrap();
        assert!(
            super::preflight_share_mount(
                &client,
                &config.nodes["storage"],
                &source,
                &parent,
                &children
            )
            .unwrap_err()
            .contains("not empty")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn registering_an_existing_share_repairs_its_missing_server_alias() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("source");
        let mount = root.join("alias");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join(".macluster-share-id"),
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap();
        fs::write(source.join("keep.txt"), "shared files").unwrap();
        let config = share_registration_fixture(&root, &source, &mount, true);
        let before = fs::read(&config).unwrap();
        let state = root.join("state");
        super::register_named_share(
            &config,
            &state,
            "storage",
            None,
            "tools",
            source.to_str().unwrap(),
            mount.to_str(),
        )
        .unwrap();
        assert_eq!(
            fs::read_link(&mount).expect("repeat add must restore the missing alias"),
            source
        );
        assert_eq!(
            fs::read_to_string(mount.join("keep.txt")).unwrap(),
            "shared files"
        );
        assert_eq!(fs::read(&config).unwrap(), before);
        let journal: serde_json::Value =
            serde_json::from_slice(&fs::read(state.join("node-admin.json")).unwrap()).unwrap();
        assert_eq!(journal["operations"]["share:tools"]["phase"], "READY");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn named_share_rejects_nested_source_and_mount_before_enrollment() {
        for (source, mount) in [
            (
                "/Users/operator/project/Users/operator/project",
                "/Users/operator/project",
            ),
            ("/Users/operator/project", "/Users/operator/project/alias"),
        ] {
            let args = [
                "-a".to_owned(),
                format!("local:{source}"),
                "--share-id".into(),
                "project".into(),
                "--mount-root".into(),
                mount.into(),
            ];
            let error = match parse_action(&args) {
                Err(error) => error,
                Ok(_) => panic!("nested source and alias must be rejected before enrollment"),
            };
            assert_eq!(error.0, 2);
            assert!(error.1.contains(source), "{error:?}");
            assert!(error.1.contains(mount), "{error:?}");
        }
    }

    #[test]
    fn named_share_accepts_same_source_mount_and_separate_prefix_siblings() {
        for mount in ["/Users/operator/project", "/Users/operator/project-copy"] {
            let args = [
                "-a",
                "local:/Users/operator/project",
                "--share-id",
                "project",
                "--mount-root",
                mount,
            ]
            .map(str::to_owned);
            assert!(parse_action(&args).is_ok());
        }
    }

    #[test]
    fn remove_accepts_a_pending_share_identifier() {
        let args = ["-rm", "share:volumes_data"].map(str::to_owned);
        assert!(matches!(
            parse_action(&args),
            Ok(Action::Remove { target, connect: None }) if target == "share:volumes_data"
        ));
    }

    #[test]
    fn removal_accepts_an_explicit_connection_for_a_moved_node() {
        let args = ["-rm", "default-a", "--connect", "operator@192.0.2.10"].map(str::to_owned);
        assert!(
            parse_action(&args).is_ok(),
            "removal must allow the registered Mac to be reached at its current address"
        );
    }

    #[test]
    fn removal_rejects_connection_paths_and_share_overrides() {
        for args in [
            [
                "-rm",
                "default-a",
                "--connect",
                "operator@192.0.2.10:/tmp/share",
            ],
            ["-rm", "share:tools", "--connect", "operator@192.0.2.10"],
        ] {
            assert!(parse_action(&args.map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn removal_connection_preserves_agent_identity_and_resumes_saved_address() {
        let mut node = NodeEndpoint::parse("operator@192.0.2.10")
            .unwrap()
            .node_config(
                "/Users/operator/agent".into(),
                Some("/Users/operator/config.toml".into()),
            );
        node.machine_uuid = Some("00000000-0000-4000-8000-000000000001".into());
        node.ssh_identity_file = Some("/Users/operator/.ssh/original-key".into());
        let endpoint = NodeEndpoint::parse("operator@192.0.2.20:2222").unwrap();
        let moved =
            super::removal_connection_node("worker", &node, Some(&endpoint), None, None).unwrap();
        assert_eq!(moved.host, "192.0.2.20");
        assert_eq!(moved.ssh_port, Some(2222));
        assert_eq!(moved.remote_binary, "/Users/operator/agent");
        assert_eq!(
            moved.remote_config.as_deref(),
            Some("/Users/operator/config.toml")
        );
        assert_eq!(
            moved.ssh_identity_file.as_deref(),
            Some("/Users/operator/.ssh/original-key")
        );
        assert_eq!(node.host, "192.0.2.10");
        let resumed = super::removal_connection_node(
            "worker",
            &node,
            None,
            Some("operator@192.0.2.20:2222"),
            None,
        )
        .unwrap();
        assert_eq!(resumed.host, "192.0.2.20");
        assert_eq!(resumed.ssh_port, Some(2222));
    }

    #[test]
    fn removal_redirect_requires_a_registered_identity_and_same_account() {
        let node = NodeEndpoint::parse("operator@192.0.2.10")
            .unwrap()
            .node_config("/agent".into(), None);
        let moved = NodeEndpoint::parse("operator@192.0.2.20").unwrap();
        assert!(super::removal_connection_node("worker", &node, Some(&moved), None, None).is_err());
        let uuid = "00000000-0000-4000-8000-000000000001";
        assert!(
            super::removal_connection_node("worker", &node, Some(&moved), None, Some(uuid)).is_ok()
        );
        let other_user = NodeEndpoint::parse("other@192.0.2.20").unwrap();
        assert!(
            super::removal_connection_node("worker", &node, Some(&other_user), None, Some(uuid))
                .is_err()
        );
        let mut local = node;
        local.transport = Transport::Local;
        assert!(
            super::removal_connection_node("worker", &local, Some(&moved), None, Some(uuid))
                .is_err()
        );
    }

    #[test]
    fn removal_identity_must_match_both_config_and_journal() {
        let mut node = NodeEndpoint::parse("operator@192.0.2.20")
            .unwrap()
            .node_config("/agent".into(), None);
        let expected = "01234567-89ab-cdef-0123-456789abcdef";
        let different = "00000000-0000-4000-8000-000000000001";
        node.machine_uuid = Some(expected.into());
        assert!(
            super::validate_removal_identity(
                "worker",
                &node,
                Some(expected),
                &expected.to_uppercase()
            )
            .is_ok()
        );
        assert!(
            super::validate_removal_identity("worker", &node, Some(expected), different).is_err()
        );
        assert!(
            super::validate_removal_identity("worker", &node, Some(different), expected).is_err()
        );
    }

    #[test]
    fn removal_connection_survives_journal_reload_without_changing_export_endpoint() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "# test identity").unwrap();
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let journal = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal, &config, &state_dir).unwrap();
        let uuid = "01234567-89ab-cdef-0123-456789abcdef";
        let mut node = NodeEndpoint::parse("operator@192.0.2.10")
            .unwrap()
            .node_config("/agent".into(), None);
        node.machine_uuid = Some(uuid.into());
        state.operations.insert(
            "remove:worker".into(),
            NodeOperation {
                id: Id128::random().to_string(),
                action: "remove".into(),
                node_id: "worker".into(),
                endpoint: "operator@192.0.2.10:22".into(),
                connection_endpoint: Some("operator@192.0.2.20:2222".into()),
                remote_config_path: None,
                machine_uuid: Some(uuid.into()),
                phase: "REMOVAL_PENDING".into(),
                old_config_sha256: None,
                candidate_config_sha256: None,
                managed_export: true,
                managed_shares: Default::default(),
                client_setup_attempted: None,
                detail: None,
            },
        );
        save_admin_state(&journal, &state).unwrap();
        let resumed = read_admin_state(&journal, &config, &state_dir).unwrap();
        let connection =
            super::removal_connection_from_state("worker", &node, None, &resumed).unwrap();
        assert_eq!(connection.host, "192.0.2.20");
        assert_eq!(connection.ssh_port, Some(2222));
        let reset_ops = reset_admin_operations(&config, &state_dir).unwrap();
        assert_eq!(reset_ops[0].endpoint, "operator@192.0.2.10:22");
        assert_eq!(
            reset_ops[0].connection_endpoint.as_deref(),
            Some("operator@192.0.2.20:2222")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removal_stale_local_address_is_rejected_before_any_state_is_created() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("state");
        let source = "[cluster]\nname=\"test\"\ndefault_queue=\"compute\"\nlogin_node=\"login\"\nshared_root=\"/tmp/macluster-shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.compute]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"192.0.2.1\"\ntransport=\"local\"\nremote_binary=\"/unused\"\n[nodes.worker]\nhost=\"127.0.0.1\"\ntransport=\"ssh\"\nssh_user=\"operator\"\nremote_binary=\"/must-not-execute\"\n";
        let source = source.replace("[nodes.worker]", "machine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\n[nodes.worker]");
        fs::write(&config, &source).unwrap();
        let error = super::remove_node(&config, &state, "worker", None).unwrap_err();
        assert!(error.1.contains("belongs to this login Mac"), "{error:?}");
        assert!(error.1.contains("--connect"), "{error:?}");
        assert_eq!(fs::read_to_string(&config).unwrap(), source);
        assert!(
            !state.exists(),
            "a rejected destination must not create maintenance or job state"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_share_mount_cleanup_matches_only_one_exact_nfs_mount() {
        let expected = "192.0.2.1:/Volumes/Data on /Volumes/Data (nfs, nodev)\n";
        assert_eq!(
            super::pending_share_mount_present(
                expected,
                "192.0.2.1:/Volumes/Data",
                "/Volumes/Data"
            ),
            Ok(true)
        );
        assert_eq!(
            super::pending_share_mount_present(
                "/dev/disk5s1 on /Volumes/Data (apfs, local)\n",
                "192.0.2.1:/Volumes/Data",
                "/Volumes/Data"
            ),
            Ok(false),
            "a local volume at the destination is not a pending NFS mount"
        );
        let stacked = concat!(
            "192.0.2.1:/Volumes/Data on /Volumes/Data (nfs, nodev)\n",
            "/dev/disk5s1 on /Volumes/Data (apfs, local)\n",
        );
        assert!(
            super::pending_share_mount_present(stacked, "192.0.2.1:/Volumes/Data", "/Volumes/Data")
                .is_err()
        );
    }

    #[test]
    fn pending_share_endpoint_parser_checks_share_server_and_paths() {
        let parsed = super::parse_pending_named_share_endpoint(
            "share:volumes_data:default-a:/Volumes/Data:/Volumes/Data",
        )
        .unwrap();
        assert_eq!(parsed.0, "volumes_data");
        assert_eq!(parsed.1, "default-a");
        assert_eq!(parsed.2, PathBuf::from("/Volumes/Data"));
        assert_eq!(parsed.3, PathBuf::from("/Volumes/Data"));
        assert!(
            super::parse_pending_named_share_endpoint(
                "share:bad/id:default-a:/Volumes/Data:/Volumes/Data"
            )
            .is_err()
        );
        assert!(
            super::parse_pending_named_share_endpoint(
                "share:volumes_data:default-a:relative:/Volumes/Data"
            )
            .is_err()
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn pending_share_cancellation_rejects_nodes_without_recorded_machine_identity() {
        let mut node = NodeEndpoint::parse("operator@127.0.0.1")
            .unwrap()
            .node_config("unused".into(), None);
        node.transport = Transport::Local;
        node.machine_uuid = None;
        let state = AdminState {
            version: 1,
            config_path: "/tmp/config.toml".into(),
            state_dir: "/tmp/state".into(),
            reserved_node_ids: BTreeSet::new(),
            machine_uuids: BTreeMap::new(),
            operations: BTreeMap::new(),
        };

        let error = super::verify_registered_node_identity("login-01", &node, &state)
            .expect_err("cleanup must fail closed without a recorded machine UUID");
        assert!(error.1.contains("no recorded machine UUID"), "{error:?}");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn pending_share_cancellation_accepts_identity_recorded_in_admin_journal() {
        let mut node = NodeEndpoint::parse("operator@127.0.0.1")
            .unwrap()
            .node_config("unused".into(), None);
        node.transport = Transport::Local;
        node.machine_uuid = None;
        let state = AdminState {
            version: 1,
            config_path: "/tmp/config.toml".into(),
            state_dir: "/tmp/state".into(),
            reserved_node_ids: BTreeSet::new(),
            machine_uuids: BTreeMap::from([(
                "login-01".into(),
                super::local_platform_uuid().unwrap(),
            )]),
            operations: BTreeMap::new(),
        };

        super::verify_registered_node_identity("login-01", &node, &state)
            .expect("the admin journal can supply the recorded machine UUID");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn pending_share_cancellation_removes_only_its_marker_and_records_abort() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("external-share");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), "shared data").unwrap();
        let config_path = share_registration_fixture(&root, &source, &source, false);
        let machine_uuid = super::local_platform_uuid().unwrap();
        let config_text = fs::read_to_string(&config_path)
            .unwrap()
            .replace("01234567-89ab-cdef-0123-456789abcdef", &machine_uuid);
        fs::write(&config_path, &config_text).unwrap();
        let config_path = config_path.canonicalize().unwrap();
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        let state_dir = state_dir.canonicalize().unwrap();
        let share_uuid = "00000000-0000-4000-8000-000000000002";
        fs::write(source.join(".macluster-share-id"), share_uuid).unwrap();

        let mut state =
            super::read_admin_state(&state_dir.join("node-admin.json"), &config_path, &state_dir)
                .unwrap();
        state.machine_uuids.insert("storage".into(), machine_uuid);
        state.operations.insert(
            "share:tools".into(),
            super::NodeOperation {
                id: "pending-share-cancel-test".into(),
                action: "share".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: "storage".into(),
                endpoint: format!(
                    "share:tools:storage:{}:{}",
                    source.display(),
                    source.display()
                ),
                machine_uuid: Some(share_uuid.into()),
                phase: "SETUP_PENDING".into(),
                old_config_sha256: Some(sha256_hex(config_text.as_bytes()).unwrap()),
                candidate_config_sha256: None,
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: Some(false),
                detail: None,
            },
        );
        super::save_admin_state(&state_dir.join("node-admin.json"), &state).unwrap();

        super::remove_pending_share(&config_path, &state_dir, "tools").unwrap();

        let state =
            super::read_admin_state(&state_dir.join("node-admin.json"), &config_path, &state_dir)
                .unwrap();
        assert_eq!(state.operations["share:tools"].phase, "ABORTED");
        assert!(!source.join(".macluster-share-id").exists());
        assert_eq!(
            fs::read_to_string(source.join("keep.txt")).unwrap(),
            "shared data"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn share_alias_preflight_preserves_existing_files_and_creates_no_paths() {
        let root = test_exports_path();
        let existing = root.join("existing-project");
        let source = root.join("source");
        fs::create_dir_all(&existing).unwrap();
        fs::write(existing.join("project.txt"), "keep this content").unwrap();
        let mut node = NodeEndpoint::parse("operator@192.0.2.1")
            .unwrap()
            .node_config("unused".into(), None);
        node.transport = Transport::Local;

        let error = super::preflight_server_alias(&node, &source, &existing).unwrap_err();
        assert!(error.1.contains(&source.to_string_lossy().to_string()));
        assert!(error.1.contains(&existing.to_string_lossy().to_string()));
        assert_eq!(
            fs::read_to_string(existing.join("project.txt")).unwrap(),
            "keep this content"
        );
        assert!(!source.exists());
        assert!(super::preflight_server_alias(&node, &existing, &existing).is_ok());

        let missing_alias = root.join("missing-parent/alias");
        assert!(super::preflight_server_alias(&node, &source, &missing_alias).is_ok());
        assert!(!missing_alias.parent().unwrap().exists());

        let alias = root.join("alias");
        std::os::unix::fs::symlink(&source, &alias).unwrap();
        assert!(super::preflight_server_alias(&node, &source, &alias).is_ok());
        assert!(super::preflight_server_alias(&node, &existing, &alias).is_err());
        assert_eq!(fs::read_link(&alias).unwrap(), source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn storage_root_accepts_different_group_when_account_access_is_verified() {
        assert!(validate_storage_root_access(501, 0, 501, 20, true).is_ok());
        let error = validate_storage_root_access(501, 0, 501, 20, false).unwrap_err();
        assert!(error.contains("cannot read, write, and traverse"));
    }

    #[test]
    fn ssh_identity_path_is_quoted_in_enrollment_config() {
        let source = r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "/Users/Shared/macluster"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "storage"
protocol_version = 1

[queues.mini01]
nodes = ["storage"]
scheduler = "fifo"

[nodes.storage]
host = "192.0.2.1"
transport = "ssh"
remote_binary = "/usr/local/bin/macluster"
"#;
        let config = ClusterConfig::parse(source).expect("parse source config");
        let endpoint = NodeEndpoint::parse("worker@192.0.2.2").unwrap();
        let identity_file = "/Users/operator/.ssh/keys/worker \"quoted\"\\id";

        let candidate = config_path_candidate(
            &config,
            source,
            "worker",
            "mini01",
            true,
            &endpoint,
            "/Users/operator/.local/bin/macluster",
            "/Users/operator/.config/macluster/config.toml",
            Some(identity_file),
            "01234567-89ab-cdef-0123-456789abcdef",
            501,
        )
        .expect("build candidate config");
        let updated = ClusterConfig::parse(&candidate).expect("parse candidate config");

        assert_eq!(
            updated.nodes["worker"].ssh_identity_file.as_deref(),
            Some(identity_file)
        );
        assert!(candidate.contains(
            "ssh_identity_file = \"/Users/operator/.ssh/keys/worker \\\"quoted\\\"\\\\id\""
        ));
    }

    #[test]
    fn storage_root_still_requires_the_account_to_own_the_directory() {
        let error = validate_storage_root_access(502, 0, 501, 20, true).unwrap_err();
        assert!(error.contains("owner UID must match"));
    }

    #[test]
    fn pending_add_retry_reuses_one_id_and_aborts_only_pristine_duplicates() {
        fn add_operation(node_id: &str, machine_uuid: &str) -> NodeOperation {
            NodeOperation {
                id: format!("operation-{node_id}"),
                action: "add".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: node_id.into(),
                endpoint: "operator@192.0.2.1:22".into(),
                machine_uuid: Some(machine_uuid.into()),
                phase: "SETUP_PENDING".into(),
                old_config_sha256: Some("config-digest".into()),
                candidate_config_sha256: None,
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: Some(false),
                detail: None,
            }
        }

        let mut state = AdminState {
            version: 1,
            config_path: "/tmp/config.toml".into(),
            state_dir: "/tmp/state".into(),
            reserved_node_ids: BTreeSet::from(["arm-b".into(), "arm-c".into()]),
            machine_uuids: BTreeMap::new(),
            operations: BTreeMap::from([
                (
                    "add:operator@192.0.2.1:22:older".into(),
                    add_operation("arm-c", "same-machine"),
                ),
                (
                    "add:operator@192.0.2.1:22:newer".into(),
                    add_operation("arm-b", "same-machine"),
                ),
            ]),
        };
        let active_node_ids = BTreeSet::from(["login-01".to_owned()]);

        let (key, operation) =
            pending_add_operation_for_endpoint(&state, &active_node_ids, "operator@192.0.2.1:22")
                .expect("retry should find a prior operation even when its key is suffixed");
        assert_eq!(operation.node_id, "arm-b");
        assert_eq!(key, "add:operator@192.0.2.1:22:newer");

        let aborted = abort_duplicate_pristine_adds(
            &mut state,
            "operator@192.0.2.1:22",
            "arm-b",
            "same-machine",
        );

        assert_eq!(aborted, 1);
        assert_eq!(
            state.operations["add:operator@192.0.2.1:22:older"].phase,
            "ABORTED"
        );
        assert_eq!(
            state.operations["add:operator@192.0.2.1:22:newer"].phase,
            "SETUP_PENDING"
        );
        assert!(state.reserved_node_ids.contains("arm-c"));
    }

    #[test]
    fn local_execution_status_uses_the_active_cluster_config() {
        let root = test_exports_path();
        fs::create_dir_all(&root).expect("create test root");
        let config = root.join("config.toml");
        fs::write(&config, "[cluster]\nname = \"test\"\n").expect("write active cluster config");
        let binary = root.join("macluster");
        fs::write(
            &binary,
            "#!/bin/sh\nif [ \"$1\" != \"--config\" ]; then exit 90; fi\nprintf 'received config: %s\\n' \"$2\" >&2\nexit 1\n",
        )
        .expect("write fake local agent");
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("make fake agent executable");
        let node = NodeConfig {
            host: "192.0.2.1".into(),
            transport: Transport::Local,
            remote_binary: binary.to_string_lossy().into_owned(),
            ssh_user: None,
            ssh_port: None,
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            execution_uid: Some(501),
        };

        let error = remote_execution_status(&node, "login-01", &config)
            .expect_err("fake agent intentionally exits before returning a frame");

        assert!(
            error.1.contains(&config.to_string_lossy().to_string()),
            "{error:?}"
        );
        assert!(!error.1.contains("/dev/null"), "{error:?}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn node_listing_uses_one_successful_health_request() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("macluster");
        let log = root.join("calls");
        let health = NodeHealth {
            machine_uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
            execution_uid: 501,
            execution_digest: "test-digest".into(),
            primary_share_ready: true,
            shares: BTreeMap::new(),
            features: Vec::new(),
        };
        let encoded_health =
            serde_json::to_string(&serde_json::to_string(&health).unwrap()).unwrap();
        let log_path = serde_json::to_string(log.to_str().unwrap()).unwrap();
        fs::write(&binary, format!(
            "#!/usr/bin/python3\nimport json,struct,sys\nwith open({log_path},'a') as f: f.write('call\\n')\nif 'agent-stdio' not in sys.argv: sys.exit(77)\nn=struct.unpack('>I',sys.stdin.buffer.read(4))[0]\nr=json.loads(sys.stdin.buffer.read(n))\nh=json.loads({encoded_health})\np=json.dumps({{'protocol_version':r['protocol_version'],'request_id':r['request_id'],'result':{{'Ok':{{'type':'health','payload':h}}}}}}).encode()\nsys.stdout.buffer.write(struct.pack('>I',len(p))+p)\n"
        )).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        let mut node = parse_build_test_config().nodes["login"].clone();
        node.transport = Transport::Local;
        node.remote_binary = binary.to_string_lossy().into_owned();
        let (observed, online) =
            super::probe_node_list(&root.join("config.toml"), "test", "login", &node);
        assert_eq!(observed, Some(health));
        assert!(online);
        assert_eq!(fs::read_to_string(&log).unwrap(), "call\n");
        fs::write(
            &binary,
            format!(
                "#!/bin/sh\nprintf 'call\\n' >> {}\nexit 1\n",
                super::shell_quote(log.to_str().unwrap())
            ),
        )
        .unwrap();
        let (observed, online) =
            super::probe_node_list(&root.join("config.toml"), "test", "login", &node);
        assert!(observed.is_none());
        assert!(!online);
        assert_eq!(fs::read_to_string(&log).unwrap(), "call\ncall\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn listing_nodes_without_active_config_tells_user_to_initialize() {
        let root =
            std::env::temp_dir().join(format!("macluster-uninitialized-{}", Id128::random()));
        fs::create_dir_all(&root).expect("create test root");
        let result = list_nodes(&root.join("config.toml"), &root.join("controller"));
        let error = result.expect_err("listing requires an active cluster config");
        let _ = fs::remove_dir_all(&root);

        assert!(error.1.contains("macluster init"), "{error:?}");
    }

    #[test]
    fn node_list_shows_common_nfs_mappings_once_after_all_node_rows() {
        let row = |id: &str, host: &str, state: &'static str, target: &str| -> NodeListRow {
            NodeListRow {
                columns: [
                    id.into(),
                    host.into(),
                    "local".into(),
                    "22".into(),
                    "-".into(),
                    "READY".into(),
                ],
                mappings: vec![NodeNfsMapping {
                    name: "primary".into(),
                    state,
                    kind: "MOUNT",
                    source_node: "login-01".into(),
                    target: target.into(),
                }],
            }
        };
        let output = format_node_list(&[
            row("login-01", "192.0.2.1", "READY", "/Users/Shared/macluster"),
            row("arm-a", "192.0.2.2", "READY", "/Users/Shared/macluster"),
        ]);

        let login_row = output.find("login-01").unwrap();
        let worker_row = output.find("arm-a").unwrap();
        let mappings_heading = output.find("NFS MAPPINGS").unwrap();
        let first_mapping = output.find("    primary").unwrap();
        assert!(login_row < worker_row, "{output}");
        assert!(!output.contains("READY\n\narm-a"), "{output}");
        assert!(worker_row < mappings_heading, "{output}");
        assert!(mappings_heading < first_mapping, "{output}");
        assert_eq!(
            output
                .matches("primary  READY    MOUNT    login-01 → /Users/Shared/macluster")
                .count(),
            1,
            "{output}"
        );
        assert!(!output.contains("\n  login-01\n"), "{output}");
        assert!(!output.contains("\n  arm-a\n"), "{output}");
        assert!(!output.contains("PHASE"));
        assert!(!output.contains("SOURCE"));
        assert!(!output.contains("TARGET"));
    }

    #[test]
    fn admin_authorization_guidance_is_printed_once_for_multiple_macs() {
        const CHILD_MARKER: &str = "MACLUSTER_ADMIN_AUTH_NOTICE_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let node = |host: &str, user: &str| NodeConfig {
                host: host.into(),
                transport: Transport::Ssh,
                remote_binary: "/usr/local/bin/macluster".into(),
                ssh_user: Some(user.into()),
                ssh_port: Some(22),
                ssh_identity_file: None,
                remote_config: None,
                machine_uuid: None,
                execution_uid: None,
            };
            super::announce_admin_authorization(
                &node("192.0.2.2", "login-user"),
                "install the power sampler and authorize the NFS export",
            );
            super::announce_admin_authorization(
                &node("192.0.2.1", "storage-user"),
                "mount the primary NFS share",
            );
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "node_admin::tests::admin_authorization_guidance_is_printed_once_for_multiple_macs",
                "--nocapture",
            ])
            .env(CHILD_MARKER, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr
                .matches("Administrator authorization may be requested")
                .count(),
            1,
            "{stderr}"
        );
        assert!(stderr.contains("192.0.2.2 (login-user):"), "{stderr}");
        assert!(stderr.contains("192.0.2.1 (storage-user):"), "{stderr}");
        assert!(stderr.contains("separate from the SSH login password"));
    }

    #[test]
    fn local_enrollment_candidate_sets_login_identity_without_queueing_it() {
        let source = r#"
[cluster]
name = "test"
default_queue = "mini01"
shared_root = "/Users/Shared/macluster"
share_uuid = "00000000-0000-4000-8000-000000000001"
storage_server = "storage"
protocol_version = 1

[queues.mini01]
nodes = ["storage"]
scheduler = "fifo"

[nodes.storage]
host = "192.168.2.1"
transport = "ssh"
remote_binary = "/usr/local/bin/macluster"
ssh_user = "operator"
ssh_port = 22
"#;
        let config = ClusterConfig::parse(source).expect("parse cluster config");
        let local_node = NodeConfig {
            host: "192.168.2.2".into(),
            transport: Transport::Local,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: None,
            ssh_port: None,
            ssh_identity_file: None,
            remote_config: Some("/Users/Shared/macluster/config.toml".into()),
            machine_uuid: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            execution_uid: Some(501),
        };

        let candidate =
            local_config_candidate(&config, source, "login", "mini01", true, &local_node)
                .expect("build local enrollment config");
        let updated = ClusterConfig::parse(&candidate).expect("parse candidate config");

        assert_eq!(
            updated.login_node.as_ref().map(NodeId::as_str),
            Some("login")
        );
        assert_eq!(updated.queues["mini01"].nodes, vec!["storage"]);
    }

    #[test]
    fn local_named_share_registration_does_not_queue_login_node() {
        let source = "[cluster]\nname = \"test\"\nlogin_node = \"login\"\ndefault_queue = \"mini01\"\nshared_root = \"/Users/Shared/macluster\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"login\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"login\", \"worker\"]\nscheduler = \"fifo\"\n\n[queues.analysis]\nnodes = [\"login\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nremote_binary = \"/usr/local/bin/macluster\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.worker]\nhost = \"192.0.2.2\"\ntransport = \"ssh\"\nremote_binary = \"/usr/local/bin/macluster\"\n";
        let config = ClusterConfig::parse(source).expect("parse legacy queue membership");

        let candidate = queue_candidate_with_node(&config, source, "mini01", "login")
            .expect("build local share candidate");
        let updated = ClusterConfig::parse(&candidate).expect("parse updated share candidate");

        assert_eq!(updated.queues["mini01"].nodes, vec!["worker"]);
        assert!(updated.queues["analysis"].nodes.is_empty());
    }

    #[test]
    fn primary_mount_source_uses_server_path_not_client_mount_path() {
        let storage = NodeConfig {
            host: "192.168.2.1".into(),
            transport: Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("operator".into()),
            ssh_port: Some(22),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: None,
            execution_uid: None,
        };

        assert_eq!(
            nfs_mount_source(&storage, std::path::Path::new("/Volumes/Storage/macluster")),
            "192.168.2.1:/Volumes/Storage/macluster"
        );
    }

    #[test]
    fn normalizes_duplicate_separators_in_binary_path_before_storing_it() {
        let executable = std::env::current_exe().unwrap();
        let parent = executable.parent().unwrap();
        let file_name = executable.file_name().unwrap();
        let invoked_path = PathBuf::from(format!(
            "{}//{}",
            parent.display(),
            file_name.to_string_lossy()
        ));

        let normalized = normalize_binary_path(&invoked_path).unwrap();

        assert_eq!(
            normalized,
            executable.canonicalize().unwrap().to_string_lossy()
        );
    }

    fn read_exports(path: &PathBuf) -> std::process::Output {
        Command::new("/bin/sh")
            .arg("-c")
            .arg(nfs_exports_read_command(&path.to_string_lossy()))
            .output()
            .expect("run exports reader shell command")
    }

    #[test]
    fn parse_action_accepts_custom_mount_root_for_local_share() {
        let args = [
            "-a",
            "local:/Users/operator/mamba/envs/analysis",
            "--share-id",
            "analysis",
            "--mount-root",
            "/Users/operator/mamba/envs/analysis",
        ]
        .map(str::to_owned);

        let Action::Add(options) = parse_action(&args).expect("parse custom mount root") else {
            panic!("expected node add action");
        };
        assert_eq!(
            options.mount_root.as_deref(),
            Some("/Users/operator/mamba/envs/analysis")
        );
    }

    #[test]
    fn parse_action_rejects_non_absolute_mount_root() {
        for path in [
            "relative/path",
            "/",
            "/Users//Shared/tools",
            "/Users/Shared/../tools",
            "/Users/Shared/./tools",
            "/Users/user name/tools",
        ] {
            let args = [
                "-a",
                "local:/Users/Shared/tools",
                "--share-id",
                "tools",
                "--mount-root",
                path,
            ]
            .map(str::to_owned);

            let error = match parse_action(&args) {
                Err(error) => error,
                Ok(_) => panic!("invalid mount root {path} must be rejected"),
            };

            assert_eq!(error.0, 2);
            assert!(
                error.1.contains("normalized absolute path"),
                "path {path}: {}",
                error.1
            );
        }
    }

    #[test]
    fn share_directory_inputs_accept_trailing_slashes() {
        for endpoint in [
            "local:/Users/operator/mamba/",
            "operator@192.0.2.20:/Users/operator/mamba/",
        ] {
            for mount in ["/Users/operator/mamba/", "/Users/operator/mamba///"] {
                let args = ["-a", endpoint, "--share-id", "mamba", "--mount-root", mount]
                    .map(str::to_owned);
                let Action::Add(options) = parse_action(&args).unwrap() else {
                    panic!("expected add action");
                };
                assert_eq!(options.mount_root.as_deref(), Some("/Users/operator/mamba"));
                let source = match options.target {
                    super::AddTarget::Local { source_path, .. } => source_path.unwrap(),
                    super::AddTarget::Ssh(endpoint) => endpoint.source_path.unwrap(),
                };
                assert_eq!(
                    super::resolve_share_source(&source, "/Users/operator").unwrap(),
                    PathBuf::from("/Users/operator/mamba")
                );
            }
        }
        for source in ["~/mamba/", "./mamba///"] {
            assert_eq!(
                super::resolve_share_source(source, "/Users/operator").unwrap(),
                PathBuf::from("/Users/operator/mamba")
            );
        }
        for source in ["/", "///", "/Users/../mamba/", "/Users//operator/mamba/"] {
            assert!(super::resolve_share_source(source, "/Users/operator").is_err());
        }
    }

    #[test]
    fn parse_action_rejects_mount_root_without_named_share() {
        let args = ["-a", "local", "--mount-root", "/Users/Shared/tools"].map(str::to_owned);

        let error = match parse_action(&args) {
            Err(error) => error,
            Ok(_) => panic!("mount root requires a named source share"),
        };

        assert_eq!(error.0, 2);
        assert!(
            error.1.contains("SOURCE_PATH and --share-id"),
            "{}",
            error.1
        );
    }

    #[test]
    fn parse_action_without_mount_root_keeps_existing_named_share_syntax() {
        let args = ["-a", "local:/Users/Shared/tools", "--share-id", "tools"].map(str::to_owned);

        let Action::Add(options) = parse_action(&args).expect("parse existing share syntax") else {
            panic!("expected node add action");
        };
        assert!(options.mount_root.is_none());
    }

    #[test]
    fn named_share_request_matches_requires_same_mount_root() {
        let server = NodeId::new("login").unwrap();
        let existing = ShareConfig {
            server: server.clone(),
            source_root: PathBuf::from("/Users/Shared/tools"),
            mount_root: PathBuf::from("/Users/Shared/macluster-shares/tools"),
            share_uuid: String::new(),
        };

        assert!(!named_share_request_matches(
            &existing,
            "login",
            PathBuf::from("/Users/Shared/tools").as_path(),
            PathBuf::from("/Users/operator/mamba/envs/analysis").as_path(),
        ));
    }

    #[test]
    fn named_share_request_matches_same_server_source_and_mount() {
        let server = NodeId::new("login").unwrap();
        let existing = ShareConfig {
            server,
            source_root: PathBuf::from("/Users/Shared/tools"),
            mount_root: PathBuf::from("/Users/Shared/macluster-shares/tools"),
            share_uuid: String::new(),
        };

        assert!(named_share_request_matches(
            &existing,
            "login",
            PathBuf::from("/Users/Shared/tools").as_path(),
            PathBuf::from("/Users/Shared/macluster-shares/tools").as_path(),
        ));
    }

    #[test]
    fn named_share_mount_root_uses_explicit_path_when_provided() {
        assert_eq!(
            named_share_mount_root("analysis", Some("/Users/operator/mamba/envs/analysis")),
            PathBuf::from("/Users/operator/mamba/envs/analysis")
        );
    }

    #[test]
    fn named_share_mount_root_keeps_legacy_default_when_omitted() {
        assert_eq!(
            named_share_mount_root("tools", None),
            PathBuf::from("/Users/Shared/macluster-shares/tools")
        );
    }

    #[test]
    fn named_share_operation_identity_includes_mount_root() {
        let source = PathBuf::from("/Users/operator/mamba/envs/analysis");
        let default_mount = PathBuf::from("/Users/Shared/macluster-shares/analysis");
        let original_mount = PathBuf::from("/Users/operator/mamba/envs/analysis");

        assert_ne!(
            named_share_operation_endpoint("analysis", "login", &source, &default_mount),
            named_share_operation_endpoint("analysis", "login", &source, &original_mount)
        );
    }

    #[test]
    fn named_share_operation_resumes_legacy_default_path_journal() {
        let source = PathBuf::from("/Users/Shared/tools");
        let default_mount = PathBuf::from("/Users/Shared/macluster-shares/tools");
        let legacy = NodeOperation {
            id: "old-share-op".into(),
            action: "share".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "login".into(),
            endpoint: "share:tools:/Users/Shared/tools".into(),
            machine_uuid: None,
            phase: "SETUP_PENDING".into(),
            old_config_sha256: None,
            candidate_config_sha256: None,
            managed_export: false,
            managed_shares: Default::default(),
            client_setup_attempted: Some(false),
            detail: None,
        };

        assert!(named_share_operation_matches(
            &legacy,
            "tools",
            "login",
            &source,
            &default_mount,
        ));
        assert!(!named_share_operation_matches(
            &legacy,
            "tools",
            "login",
            &source,
            &PathBuf::from("/Users/Shared/tools"),
        ));
    }

    #[test]
    fn mount_point_permission_errors_are_distinguished_from_other_failures() {
        assert!(mount_point_permission_error("mkdir: Permission denied"));
        assert!(mount_point_permission_error(
            "mkdir: Operation not permitted"
        ));
        assert!(!mount_point_permission_error(
            "Host key verification failed"
        ));
        assert!(!mount_point_permission_error("Connection timed out"));
    }

    #[test]
    fn named_share_mount_status_rejects_another_source_at_the_requested_path() {
        let output =
            "192.168.2.9:/other on /Users/operator/mamba/envs/analysis (nfs, nodev, nosuid)\n";

        assert_eq!(
            named_share_mount_status(
                output,
                "192.168.2.2:/Users/operator/mamba/envs/analysis",
                "/Users/operator/mamba/envs/analysis",
            ),
            NamedShareMountStatus::MountedElsewhere("192.168.2.9:/other".into())
        );

        let local_volume =
            "/dev/disk3s5 on /Users/operator/mamba/envs/analysis (apfs, local, journaled)\n";
        assert_eq!(
            named_share_mount_status(
                local_volume,
                "192.168.2.2:/Users/operator/mamba/envs/analysis",
                "/Users/operator/mamba/envs/analysis",
            ),
            NamedShareMountStatus::MountedElsewhere("/dev/disk3s5".into())
        );
    }

    #[test]
    fn named_share_mount_status_accepts_only_the_exact_expected_source_and_path() {
        let expected_source = "192.168.2.2:/Users/operator/mamba/envs/analysis";
        let expected_path = "/Users/operator/mamba/envs/analysis";
        let expected = format!("{expected_source} on {expected_path} (nfs, nodev, nosuid)\n");
        let other_path = format!("{expected_source} on {expected_path}-other (nfs, nodev)\n");

        assert_eq!(
            named_share_mount_status(&expected, expected_source, expected_path),
            NamedShareMountStatus::Expected
        );
        assert_eq!(
            named_share_mount_status(
                &format!("{expected_source} on {expected_path} (nfs)\n"),
                expected_source,
                expected_path,
            ),
            NamedShareMountStatus::Expected
        );
        assert_eq!(
            named_share_mount_status(&other_path, expected_source, expected_path),
            NamedShareMountStatus::NotMounted
        );
    }

    #[test]
    fn power_launch_daemon_uses_fixed_root_helper_and_cluster_uid() {
        let plist = power_launch_daemon_plist(501);
        assert!(
            plist.contains("<string>/Library/PrivilegedHelperTools/org.macluster.power</string>")
        );
        assert!(plist.contains("<string>--serve</string>"));
        assert!(plist.contains("<string>501</string>"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <true/>"));
        assert!(!plist.contains("/bin/sh"));
    }

    #[test]
    fn power_helper_install_script_creates_system_directories_before_installing() {
        let script =
            power_helper_install_script("/tmp/power.bin", "/tmp/power.plist", "fixture-digest");
        let create_directory = script
            .find("/bin/mkdir -p /Library/PrivilegedHelperTools /Library/LaunchDaemons")
            .expect("prepare the privileged helper directory");
        let install_helper = script
            .find("/usr/bin/install -o root -g wheel -m 755")
            .expect("install the privileged helper");
        assert!(create_directory < install_helper);
        assert!(!script.contains("sudo"));
    }

    #[test]
    fn power_helper_bootstrap_retries_transient_failure_and_stops_after_limit() {
        use std::os::unix::fs::PermissionsExt;
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let fake = root.join("launchctl");
        let count = root.join("attempts");
        let install = power_helper_install_script("/tmp/power", "/tmp/plist", "digest");
        let retry = install[install.find("attempt=0\n").unwrap()..]
            .split("/bin/launchctl kickstart")
            .next()
            .unwrap()
            .replace(
                "/bin/launchctl",
                &super::shell_quote(&fake.to_string_lossy()),
            )
            .replace("/bin/sleep 0.25", "/usr/bin/true");
        for (threshold, expected_attempts, success) in [(3, 3, true), (100, 20, false)] {
            let _ = fs::remove_file(&count);
            fs::write(&fake, format!(
                "#!/bin/sh\nn=$(cat {} 2>/dev/null || echo 0)\nn=$((n + 1))\necho $n > {}\n[ $n -ge {threshold} ]\n",
                super::shell_quote(&count.to_string_lossy()),
                super::shell_quote(&count.to_string_lossy()),
            )).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
            let output = Command::new("/bin/sh")
                .args(["-c", &retry])
                .output()
                .unwrap();
            assert_eq!(output.status.success(), success);
            assert_eq!(
                fs::read_to_string(&count).unwrap().trim(),
                expected_attempts.to_string()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn power_helper_install_rejects_corrupt_staging_before_privileged_changes() {
        let helper = crate::embedded_power::ExtractedHelper::new().unwrap();
        fs::write(helper.path(), b"damaged helper").unwrap();
        let script = power_helper_install_script(
            &helper.path().to_string_lossy(),
            "/unused/plist",
            &crate::embedded_power::digest().unwrap(),
        );
        // Execute only the validation prefix, never a system installation.
        let validation = script.split("/bin/mkdir").next().unwrap();
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(validation)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("checksum mismatch"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn power_helper_setup_stages_embedded_payload_without_a_companion_binary() {
        use super::{cleanup_power_helper_stage, local_sha256, prepare_power_helper};
        use std::path::Path;
        let node = local_share_test_node();
        let operation = Id128::random().to_string();
        // Different peer UID guarantees a new staged plist; never install it.
        let setup = prepare_power_helper(&node, 606060, std::env::consts::ARCH, &operation)
            .unwrap()
            .expect("stage a helper for the test peer UID");
        let staged_digest = local_sha256(Path::new(&setup.staged_binary)).unwrap();
        let plist = fs::read_to_string(&setup.staged_plist).unwrap();
        cleanup_power_helper_stage(&node, &setup);
        assert_eq!(staged_digest, crate::embedded_power::digest().unwrap());
        assert!(plist.contains("<string>606060</string>"));
        assert!(!Path::new(&setup.staged_binary).exists());
        assert!(!Path::new(&setup.staged_plist).exists());
    }

    fn execute_candidate_admin_batch(
        root: &std::path::Path,
        power: Option<&str>,
        mount: Option<&str>,
    ) -> (std::process::Output, String, String) {
        fs::create_dir(root).expect("create test directory");
        let fake_sudo = root.join("sudo");
        let calls = root.join("sudo-calls");
        let steps = root.join("steps");
        fs::write(
            &fake_sudo,
            "#!/bin/sh\nprintf 'sudo\\n' >> \"$MACLUSTER_SUDO_CALLS\"\n[ \"$1\" = /bin/sh ] || exit 97\nshift\nexec /bin/sh \"$@\"\n",
        )
        .expect("write fake sudo");
        fs::set_permissions(&fake_sudo, fs::Permissions::from_mode(0o700))
            .expect("make fake sudo executable");

        let body =
            candidate_admin_script(power, mount).expect("at least one admin action is required");
        let command_line = admin_shell_command(&fake_sudo.to_string_lossy(), &body);
        let output = Command::new("/bin/sh")
            .args(["-c", &command_line])
            .env("MACLUSTER_SUDO_CALLS", &calls)
            .env("MACLUSTER_ADMIN_STEPS", &steps)
            .output()
            .expect("run generated admin command");
        let call_log = fs::read_to_string(&calls).expect("read sudo calls");
        let step_log = fs::read_to_string(&steps).unwrap_or_default();
        (output, call_log, step_log)
    }

    #[test]
    fn candidate_power_and_mount_actions_run_in_one_admin_session() {
        let root = std::env::temp_dir().join(format!("macluster-admin-batch-{}", Id128::random()));
        let power = "printf 'power\\n' >> \"$MACLUSTER_ADMIN_STEPS\"";
        let mount = "printf 'mount\\n' >> \"$MACLUSTER_ADMIN_STEPS\"";
        let (output, calls, steps) = execute_candidate_admin_batch(&root, Some(power), Some(mount));

        assert!(
            output.status.success(),
            "generated admin command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(calls, "sudo\n");
        assert_eq!(steps, "power\nmount\n");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn candidate_mount_continues_when_optional_power_setup_fails() {
        let root = std::env::temp_dir().join(format!("macluster-admin-batch-{}", Id128::random()));
        let mount = "printf 'mount\\n' >> \"$MACLUSTER_ADMIN_STEPS\"";
        let (output, calls, steps) =
            execute_candidate_admin_batch(&root, Some("false"), Some(mount));

        assert!(output.status.success());
        assert_eq!(calls, "sudo\n");
        assert_eq!(steps, "mount\n");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn completed_local_enrollment_starts_a_fresh_refresh_operation() {
        assert!(should_resume_add_operation("SETUP_PENDING"));
        assert!(should_resume_add_operation("SYNC_PENDING"));
        assert!(!should_resume_add_operation("READY"));
        assert!(!should_resume_add_operation("ABORTED"));
    }

    #[test]
    fn local_share_retry_skips_enrollment_refresh_for_legacy_journal_after_binary_path_changes() {
        let config_source = r#"
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
host = "192.168.2.2"
transport = "local"
remote_binary = "/Users/operator/script/macluster/target/release/macluster"
machine_uuid = "01234567-89ab-cdef-0123-456789abcdef"
execution_uid = 501
"#;
        let config = ClusterConfig::parse(config_source).expect("parse local node config");
        let operation = NodeOperation {
            id: "legacy-share-op".into(),
            action: "share".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "login".into(),
            endpoint: "share:analysis:/Users/operator/mamba/envs/analysis".into(),
            machine_uuid: Some("00000000-0000-4000-8000-000000000002".into()),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some(sha256_hex(config_source.as_bytes()).unwrap()),
            candidate_config_sha256: None,
            managed_export: false,
            managed_shares: Default::default(),
            client_setup_attempted: Some(false),
            detail: None,
        };
        let host = "192.168.2.2".parse().unwrap();

        assert_ne!(
            std::env::current_exe().unwrap().to_string_lossy().as_ref(),
            config.nodes["login"].remote_binary
        );
        assert!(named_share_operation_matches(
            &operation,
            "analysis",
            "login",
            PathBuf::from("/Users/operator/mamba/envs/analysis").as_path(),
            PathBuf::from("/Users/Shared/macluster-shares/analysis").as_path(),
        ));
        assert_eq!(
            pending_local_share_retry_node(
                &config,
                Some(&operation),
                &host,
                "01234567-89ab-cdef-0123-456789abcdef",
                501,
            )
            .unwrap(),
            Some("login".into())
        );
    }

    #[test]
    fn local_share_retry_refuses_to_refresh_when_registered_local_identity_changed() {
        let config = ClusterConfig::parse(
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
host = "192.168.2.2"
transport = "local"
machine_uuid = "01234567-89ab-cdef-0123-456789abcdef"
execution_uid = 501
"#,
        )
        .expect("parse local node config");
        let operation = NodeOperation {
            id: "pending-share-op".into(),
            action: "share".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "login".into(),
            endpoint: "legacy-share-endpoint".into(),
            machine_uuid: None,
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some("old-config-digest".into()),
            candidate_config_sha256: None,
            managed_export: false,
            managed_shares: Default::default(),
            client_setup_attempted: Some(false),
            detail: None,
        };

        let error = pending_local_share_retry_node(
            &config,
            Some(&operation),
            &"192.168.2.2".parse().unwrap(),
            "fedcba98-7654-3210-fedc-ba9876543210",
            501,
        )
        .unwrap_err();

        assert!(error.1.contains("cannot refresh local node configuration"));
        assert!(error.1.contains("pending-share-op"));
    }

    fn update_operation(phase: &str, old_digest: &str, candidate_digest: &str) -> NodeOperation {
        NodeOperation {
            id: "test-update".into(),
            action: "update".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "all".into(),
            endpoint: "cluster".into(),
            machine_uuid: None,
            phase: phase.into(),
            old_config_sha256: Some(old_digest.into()),
            candidate_config_sha256: Some(candidate_digest.into()),
            managed_export: false,
            managed_shares: Default::default(),
            client_setup_attempted: Some(false),
            detail: None,
        }
    }

    #[test]
    fn update_recovery_resumes_staging_only_when_old_config_is_active() {
        let operation = update_operation("UPDATE_FAILED", "old", "candidate");

        assert_eq!(
            update_recovery(Some(&operation), "old").unwrap(),
            UpdateRecovery::Stage
        );
        assert!(update_recovery(Some(&operation), "other").is_err());
    }

    #[test]
    fn superseded_failed_update_without_candidate_is_abandoned_safely() {
        let mut operation = update_operation("UPDATE_FAILED", "old", "candidate");
        operation.candidate_config_sha256 = None;
        assert_eq!(
            update_recovery(Some(&operation), "new-config").unwrap(),
            UpdateRecovery::AbandonUncommittedFailure
        );
        operation.candidate_config_sha256 = Some("candidate".into());
        assert!(update_recovery(Some(&operation), "new-config").is_err());
        operation.phase = "UPDATE_STAGING".into();
        operation.candidate_config_sha256 = None;
        assert!(update_recovery(Some(&operation), "new-config").is_err());
    }

    #[test]
    fn update_recovery_resumes_sync_only_when_candidate_config_is_active() {
        let committing = update_operation("UPDATE_COMMITTING", "old", "candidate");
        let sync_pending = update_operation("SYNC_PENDING", "old", "candidate");

        assert_eq!(
            update_recovery(Some(&committing), "candidate").unwrap(),
            UpdateRecovery::Sync
        );
        assert_eq!(
            update_recovery(Some(&committing), "old").unwrap(),
            UpdateRecovery::Stage
        );
        assert_eq!(
            update_recovery(Some(&sync_pending), "candidate").unwrap(),
            UpdateRecovery::Sync
        );
        assert!(update_recovery(Some(&sync_pending), "old").is_err());
    }

    #[test]
    fn incomplete_agent_update_journal_is_a_submission_recovery_blocker() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config_path = root.join("config.toml");
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(&config_path, "[cluster]\n").unwrap();

        assert!(!agent_update_recovery_pending(&config_path, &state_dir).unwrap());
        let config_path = config_path.canonicalize().unwrap();
        let state_dir = state_dir.canonicalize().unwrap();
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, &state_dir).unwrap();
        state.operations.insert(
            "update:all".into(),
            update_operation("SYNC_PENDING", "old", "candidate"),
        );
        save_admin_state(&journal_path, &state).unwrap();
        assert!(agent_update_recovery_pending(&config_path, &state_dir).unwrap());

        state.operations.get_mut("update:all").unwrap().phase = "READY".into();
        save_admin_state(&journal_path, &state).unwrap();
        assert!(!agent_update_recovery_pending(&config_path, &state_dir).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn agent_update_keeps_enrollment_draft_cleanup_provenance() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let source = "[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nshared_root=\"/tmp/shared\"\nshare_uuid=\"00000000-0000-4000-8000-000000000001\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/usr/bin/true\"\nmachine_uuid=\"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid=501\n";
        let config = ClusterConfig::parse(source).unwrap();
        let digest = macluster_protocol::framing::sha256_hex(source.as_bytes()).unwrap();
        let mut update = update_operation("SYNC_PENDING", "old", &digest);
        update.action = "update".into();
        let mut draft = update_operation("SETUP_PENDING", "old", "draft-candidate");
        draft.action = "add".into();
        draft.node_id = "new-worker".into();
        let mut foreign = draft.clone();
        foreign.old_config_sha256 = Some("another-config".into());
        let mut state = AdminState {
            version: 1,
            config_path: root.join("config.toml").to_string_lossy().into_owned(),
            state_dir: root.to_string_lossy().into_owned(),
            reserved_node_ids: BTreeSet::new(),
            machine_uuids: BTreeMap::new(),
            operations: BTreeMap::from([
                ("update:all".into(), update.clone()),
                ("add:draft".into(), draft),
                ("add:foreign".into(), foreign),
            ]),
        };
        super::finish_update_sync(
            &mut state,
            &root.join("node-admin.json"),
            "update:all",
            update,
            &config,
            source,
            &root,
        )
        .unwrap();
        assert_eq!(
            state.operations["add:draft"].old_config_sha256.as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(state.operations["add:draft"].phase, "SETUP_PENDING");
        assert_eq!(
            state.operations["add:draft"]
                .candidate_config_sha256
                .as_deref(),
            Some("draft-candidate")
        );
        assert_eq!(
            state.operations["add:foreign"].old_config_sha256.as_deref(),
            Some("another-config")
        );
        assert_eq!(state.operations["update:all"].phase, "READY");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn enrollment_drafts_are_not_active_cluster_maintenance() {
        let config = parse_build_test_config();
        let mut operation = update_operation("SETUP_PENDING", "old", "candidate");
        operation.action = "add".into();
        operation.node_id = "new-worker".into();
        assert!(super::is_uncommitted_enrollment(&config, &operation));
        let mut state = AdminState {
            version: 1,
            config_path: String::new(),
            state_dir: String::new(),
            reserved_node_ids: BTreeSet::new(),
            machine_uuids: BTreeMap::new(),
            operations: BTreeMap::from([("add:draft".into(), operation.clone())]),
        };
        super::ensure_no_pending_admin_operation_for_config(&state, &config).unwrap();
        state.operations.get_mut("add:draft").unwrap().phase = "ADD_COMMITTING".into();
        assert!(super::ensure_no_pending_admin_operation_for_config(&state, &config).is_err());
        operation.phase = "CANDIDATE_INSTALLED".into();
        assert!(super::is_uncommitted_enrollment(&config, &operation));
        operation.phase = "ADD_COMMITTING".into();
        assert!(!super::is_uncommitted_enrollment(&config, &operation));
        operation.phase = "SYNC_PENDING".into();
        assert!(!super::is_uncommitted_enrollment(&config, &operation));
        operation.phase = "SETUP_PENDING".into();
        operation.node_id = "arm-a".into();
        assert!(!super::is_uncommitted_enrollment(&config, &operation));
        operation.node_id = "new-worker".into();
        operation.action = "remove".into();
        assert!(!super::is_uncommitted_enrollment(&config, &operation));
    }

    #[test]
    fn pending_node_operation_is_reported_separately_from_update_recovery() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config_path = root.join("config.toml");
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(&config_path, "[cluster]\n").unwrap();
        let config_path = config_path.canonicalize().unwrap();
        let state_dir = state_dir.canonicalize().unwrap();
        let journal_path = state_dir.join("node-admin.json");
        let mut state = read_admin_state(&journal_path, &config_path, &state_dir).unwrap();
        state.operations.insert(
            "add:worker".into(),
            NodeOperation {
                id: "pending-add".into(),
                action: "add".into(),
                connection_endpoint: None,
                remote_config_path: None,
                node_id: "worker".into(),
                endpoint: "operator@192.0.2.2:22".into(),
                machine_uuid: None,
                phase: "SETUP_PENDING".into(),
                old_config_sha256: None,
                candidate_config_sha256: None,
                managed_export: false,
                managed_shares: BTreeSet::new(),
                client_setup_attempted: None,
                detail: None,
            },
        );
        state.operations.insert(
            "update:all".into(),
            update_operation("SYNC_PENDING", "old", "candidate"),
        );
        save_admin_state(&journal_path, &state).unwrap();

        assert!(node_admin_recovery_pending(&config_path, &state_dir).unwrap());
        assert!(agent_update_recovery_pending(&config_path, &state_dir).unwrap());

        state.operations.get_mut("add:worker").unwrap().phase = "READY".into();
        save_admin_state(&journal_path, &state).unwrap();
        assert!(!node_admin_recovery_pending(&config_path, &state_dir).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn child_share_cleanup_checks_identity_preserves_files_and_resumes() {
        use std::os::unix::fs::PermissionsExt;
        let root =
            std::env::temp_dir().join(format!("macluster-share-cleanup-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let mount = root.join("mount");
        let child = mount.join("python");
        fs::create_dir_all(source.join("python")).unwrap();
        fs::write(source.join("python/user.py"), "keep").unwrap();
        let parent = ShareConfig {
            server: NodeId::new("server").unwrap(),
            source_root: source.clone(),
            mount_root: mount.clone(),
            share_uuid: Id128::random().to_string(),
        };
        let child_uuid = Id128::random().to_string();
        let text = format!(
            "[cluster]\nname=\"test\"\ndefault_queue=\"q\"\nshared_root=\"/Users/Shared/macluster\"\nshare_uuid=\"{}\"\nstorage_server=\"server\"\nprotocol_version=1\n[queues.q]\nnodes=[\"server\"]\nscheduler=\"fifo\"\n[nodes.server]\nhost=\"192.0.2.1\"\ntransport=\"ssh\"\n[shares.child]\nserver=\"server\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"{child_uuid}\"\n",
            Id128::random(),
            source.join("python").display(),
            child.display()
        );
        let config = ClusterConfig::parse(&text).unwrap();
        let ids = BTreeSet::from(["child".to_owned()]);
        let mounts = root.join("mounts");
        let unmount = root.join("umount");
        fs::write(&unmount, "#!/bin/sh\n/bin/rm \"$1/.macluster-share-id\"\n").unwrap();
        fs::set_permissions(&unmount, fs::Permissions::from_mode(0o700)).unwrap();
        let script = super::child_share_cleanup_script(&config, &parent, &ids, "192.0.2.1")
            .replace(
                "/sbin/mount",
                &format!("/bin/cat {}", super::shell_quote(&mounts.to_string_lossy())),
            )
            .replace("/usr/bin/sudo ", "")
            .replace(
                "/sbin/umount",
                &super::shell_quote(&unmount.to_string_lossy()),
            );
        let run = || {
            Command::new("/bin/sh")
                .args(["-c", &script])
                .output()
                .unwrap()
        };
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join(".macluster-share-id"), "wrong").unwrap();
        let expected_mount = format!(
            "192.0.2.1:{} on {} (nfs)\n",
            source.join("python").display(),
            child.display()
        );
        fs::write(&mounts, &expected_mount).unwrap();
        assert!(!run().status.success());
        assert!(child.join(".macluster-share-id").exists());
        fs::write(child.join(".macluster-share-id"), &child_uuid).unwrap();
        fs::write(
            &mounts,
            expected_mount.replace("192.0.2.1:", "unrelated192.0.2.1:"),
        )
        .unwrap();
        assert!(!run().status.success());
        assert!(child.join(".macluster-share-id").exists());
        fs::write(&mounts, &expected_mount).unwrap();
        assert!(run().status.success());
        assert!(!child.exists());
        fs::write(&mounts, "").unwrap();
        assert!(run().status.success());
        // A resumed operation must not remove directories inside a mounted parent.
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("keep"), "keep").unwrap();
        fs::write(
            &mounts,
            format!(
                "192.0.2.1:{} on {} (nfs)\n",
                source.display(),
                mount.display()
            ),
        )
        .unwrap();
        assert!(run().status.success());
        assert!(child.join("keep").exists());
        // Unmounted directories with local contents are never deleted recursively.
        fs::write(&mounts, "").unwrap();
        assert!(!run().status.success());
        assert!(child.join("keep").exists());
        assert_eq!(
            fs::read_to_string(source.join("python/user.py")).unwrap(),
            "keep"
        );
        fs::remove_dir_all(&child).unwrap();
        std::os::unix::fs::symlink(source.join("python"), &child).unwrap();
        let alias_script = super::child_share_alias_cleanup_script(&config, &parent, &ids);
        let result = Command::new("/bin/sh")
            .args(["-c", &alias_script])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!mount.exists());
        assert!(source.join("python/user.py").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parent_share_replaces_only_equivalent_child_shares() {
        let source = r#"[cluster]
name="test"
default_queue="q"
shared_root="/Users/Shared/macluster"
share_uuid="00000000-0000-4000-8000-000000000001"
storage_server="login"
protocol_version=1
[queues.q]
nodes=["login"]
scheduler="fifo"
[nodes.login]
host="192.0.2.1"
transport="ssh"
[shares.child]
server="login"
source_root="/source/JanusX/python"
mount_root="/mount/JanusX/python"
share_uuid="00000000-0000-4000-8000-000000000002"
"#;
        let parent = ShareConfig {
            server: NodeId::new("login").unwrap(),
            source_root: "/source/JanusX".into(),
            mount_root: "/mount/JanusX".into(),
            share_uuid: "00000000-0000-4000-8000-000000000003".into(),
        };
        let candidate = super::append_share_config(source, "parent", &parent).unwrap();
        let config = ClusterConfig::parse(&candidate).unwrap();
        assert!(!config.shares.contains_key("child"));
        assert_eq!(config.shares["parent"].source_root, parent.source_root);
        let incompatible = source.replace("/mount/JanusX/python", "/mount/JanusX/other");
        assert!(super::append_share_config(&incompatible, "parent", &parent).is_err());
    }

    #[test]
    fn all_node_update_does_not_install_the_power_helper() {
        assert!(AgentStagePurpose::Enrollment.installs_power_helper());
        assert!(!AgentStagePurpose::Update.installs_power_helper());
        assert!(!AgentStagePurpose::Share.installs_power_helper());
    }

    #[test]
    fn controller_waits_for_uncertain_all_node_update_commit_to_be_resumed() {
        let root =
            std::env::temp_dir().join(format!("macluster-update-recovery-{}", Id128::random()));
        let config_path = root.join("config.toml");
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).expect("create update recovery fixture");
        fs::write(&config_path, "[cluster]\nname = \"test\"\n").expect("write config");
        let journal = serde_json::json!({
            "version": 1,
            "config_path": config_path.canonicalize().unwrap().to_string_lossy(),
            "state_dir": state_dir.canonicalize().unwrap().to_string_lossy(),
            "reserved_node_ids": [],
            "machine_uuids": {},
            "operations": {
                "update:all": {
                    "id": Id128::random().to_string(),
                    "action": "update",
                    "node_id": "all",
                    "endpoint": "cluster",
                    "machine_uuid": null,
                    "phase": "UPDATE_COMMITTING",
                    "old_config_sha256": "old",
                    "candidate_config_sha256": "candidate",
                    "managed_export": false,
                    "managed_shares": [],
                    "detail": null
                }
            }
        });
        fs::write(
            state_dir.join("node-admin.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .expect("write update journal");

        let result = ensure_controller_recovery_clean(&config_path, &state_dir);

        assert!(
            result
                .unwrap_err()
                .contains("rerun the command that triggered the Agent update")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn controller_dispatch_barrier_covers_update_peer_sync() {
        let root = std::env::temp_dir().join(format!("macluster-update-sync-{}", Id128::random()));
        let config_path = root.join("config.toml");
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).expect("create update sync fixture");
        let config = "[cluster]\nname = \"test\"\n";
        fs::write(&config_path, config).expect("write config");
        let config_path = config_path.canonicalize().unwrap();
        let state_dir = state_dir.canonicalize().unwrap();
        let digest = sha256_hex(config.as_bytes()).unwrap();
        let operation = update_operation("SYNC_PENDING", "old", &digest);
        let mut state = AdminState {
            version: 1,
            config_path: config_path.to_string_lossy().into_owned(),
            state_dir: state_dir.to_string_lossy().into_owned(),
            reserved_node_ids: Default::default(),
            machine_uuids: Default::default(),
            operations: Default::default(),
        };
        state.operations.insert("update:all".into(), operation);
        save_admin_state(&state_dir.join("node-admin.json"), &state).unwrap();

        assert!(dispatch_sync_pending(&config_path, &state_dir).unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn omitted_ssh_port_matches_default_port_22() {
        let endpoint = NodeEndpoint::parse("operator@192.168.2.1").unwrap();
        let mut configured = endpoint.node_config("/usr/local/bin/macluster".into(), None);
        configured.ssh_port = None;

        assert!(existing_ssh_endpoint_matches(&configured, &endpoint));
        let different_port = NodeEndpoint::parse("operator@192.168.2.1:2222").unwrap();
        assert!(!existing_ssh_endpoint_matches(&configured, &different_port));
        let different_user = NodeEndpoint::parse("other@192.168.2.1").unwrap();
        assert!(!existing_ssh_endpoint_matches(&configured, &different_user));
    }

    fn combined_ssh_add_fixture(phase: &str) -> (NodeEndpoint, String, AdminState) {
        let endpoint = NodeEndpoint::parse("operator@192.0.2.10:/Users/Shared/tools").unwrap();
        let key = format!("add:{}", endpoint.canonical());
        let mut operation = update_operation(phase, "old", "enrolled-config");
        operation.id = "original-enrollment".into();
        operation.action = "add".into();
        operation.node_id = "arm-b".into();
        operation.endpoint = endpoint.canonical();
        operation.machine_uuid = Some("original-machine".into());
        let state = AdminState {
            version: 1,
            config_path: "/tmp/config.toml".into(),
            state_dir: "/tmp/state".into(),
            reserved_node_ids: BTreeSet::from(["arm-b".into()]),
            machine_uuids: BTreeMap::from([("arm-b".into(), "original-machine".into())]),
            operations: BTreeMap::from([(key.clone(), operation)]),
        };
        (endpoint, key, state)
    }

    #[test]
    fn combined_ssh_retry_syncs_deferred_enrollment_before_changing_shares() {
        let root =
            std::env::temp_dir().join(format!("macluster-combined-retry-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let journal_path = root.join("node-admin.json");
        let (endpoint, key, mut state) = combined_ssh_add_fixture("ADD_COMMITTING");
        let mut events = Vec::new();
        let mut run_combined_retry = |state: &mut AdminState, fail_sync: bool| -> AppResult<()> {
            let pending = pending_combined_ssh_add(state, "arm-b", &endpoint, "enrolled-config")?;
            if let Some(key) = pending {
                resume_existing_ssh_add_sync(state, &journal_path, &key, &endpoint, |operation| {
                    assert_eq!(operation.id, "original-enrollment");
                    assert_eq!(operation.phase, "SYNC_PENDING");
                    events.push("enrollment-sync");
                    if fail_sync {
                        Err("second peer unavailable after first peer synced".into())
                    } else {
                        Ok(())
                    }
                })?;
            }
            events.push("share");
            Ok(())
        };

        assert!(run_combined_retry(&mut state, true).is_err());
        assert_eq!(state.operations[&key].phase, "SYNC_PENDING");
        assert!(
            state.operations[&key]
                .detail
                .as_deref()
                .unwrap()
                .contains("second peer")
        );
        let persisted: AdminState =
            serde_json::from_slice(&fs::read(&journal_path).unwrap()).unwrap();
        assert_eq!(persisted.operations[&key].phase, "SYNC_PENDING");
        run_combined_retry(&mut state, false).unwrap();
        // A share failure after enrollment can retry with a changed share config
        // without reopening or refreshing the completed enrollment.
        assert!(
            pending_combined_ssh_add(&state, "arm-b", &endpoint, "share-config")
                .unwrap()
                .is_none()
        );
        run_combined_retry(&mut state, false).unwrap();
        drop(run_combined_retry);
        assert_eq!(
            events,
            ["enrollment-sync", "enrollment-sync", "share", "share"]
        );
        assert_eq!(state.operations[&key].phase, "READY");
        assert_eq!(state.operations.len(), 1);
        assert_eq!(state.reserved_node_ids, BTreeSet::from(["arm-b".into()]));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn combined_ssh_retry_rejects_changed_pending_endpoint_or_config() {
        let (endpoint, key, mut state) = combined_ssh_add_fixture("SYNC_PENDING");
        for changed in [
            "other@192.0.2.10:/Users/Shared/tools",
            "operator@192.0.2.10:2222:/Users/Shared/tools",
            "operator@192.0.2.10:/Users/Shared/other",
        ] {
            assert!(
                pending_combined_ssh_add(
                    &state,
                    "arm-b",
                    &NodeEndpoint::parse(changed).unwrap(),
                    "enrolled-config",
                )
                .is_err()
            );
        }
        assert!(pending_combined_ssh_add(&state, "arm-b", &endpoint, "changed-config").is_err());
        let mut duplicate = state.operations[&key].clone();
        duplicate.id = "duplicate-enrollment".into();
        state
            .operations
            .insert(format!("{key}:duplicate"), duplicate);
        assert!(pending_combined_ssh_add(&state, "arm-b", &endpoint, "enrolled-config").is_err());
    }

    #[test]
    fn combined_ssh_share_retry_does_not_resume_ready_enrollment_or_queue_update() {
        let (endpoint, key, mut state) = combined_ssh_add_fixture("READY");
        assert!(
            pending_combined_ssh_add(&state, "arm-b", &endpoint, "share-config")
                .unwrap()
                .is_none()
        );
        let mut queue_update = state.operations[&key].clone();
        queue_update.phase = "SYNC_PENDING".into();
        queue_update.endpoint = "queue:arm".into();
        state
            .operations
            .insert("queue:arm-b:arm".into(), queue_update);
        assert!(
            pending_combined_ssh_add(&state, "arm-b", &endpoint, "share-config")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ssh_identity_endpoint_ignores_optional_share_source_path() {
        let base = NodeEndpoint::parse("operator@192.0.2.10").unwrap();
        let first_share = NodeEndpoint::parse("operator@192.0.2.10:/Users/Shared/tools").unwrap();
        let second_share =
            NodeEndpoint::parse("operator@192.0.2.10:/Users/Shared/environment").unwrap();
        let other_user = NodeEndpoint::parse("other@192.0.2.10").unwrap();

        assert_eq!(
            base.ssh_identity_endpoint(),
            first_share.ssh_identity_endpoint()
        );
        assert_eq!(
            first_share.ssh_identity_endpoint(),
            second_share.ssh_identity_endpoint()
        );
        assert_ne!(
            base.ssh_identity_endpoint(),
            other_user.ssh_identity_endpoint()
        );
    }

    #[test]
    fn reset_endpoint_reconstruction_keeps_the_recorded_transport_identity() {
        let uuid = "01234567-89ab-cdef-0123-456789abcdef".to_owned();
        let ssh = reset_node_from_endpoint("operator@192.168.2.3:2222", Some(uuid.clone()))
            .expect("reconstruct pending SSH node");
        assert_eq!(ssh.transport, Transport::Ssh);
        assert_eq!(ssh.host, "192.168.2.3");
        assert_eq!(ssh.ssh_user.as_deref(), Some("operator"));
        assert_eq!(ssh.ssh_port, Some(2222));
        assert_eq!(ssh.machine_uuid.as_deref(), Some(uuid.as_str()));

        let local = reset_node_from_endpoint("local@192.168.2.2:22", Some(uuid))
            .expect("reconstruct pending local node");
        assert_eq!(local.transport, Transport::Local);
        assert_eq!(local.ssh_user, None);
    }

    #[test]
    fn missing_exports_file_is_successfully_read_as_empty() {
        let path = test_exports_path();
        assert!(!path.exists());

        let output = read_exports(&path);

        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn existing_exports_file_contents_are_preserved() {
        let path = test_exports_path();
        let contents = b"/Users/Shared/macluster 192.168.2.2\n";
        fs::write(&path, contents).expect("create exports test file");

        let output = read_exports(&path);

        let _ = fs::remove_file(&path);
        assert!(output.status.success());
        assert_eq!(output.stdout, contents);
    }

    #[test]
    fn pending_nfs_transaction_reads_the_saved_original_as_planning_baseline() {
        let root = test_exports_path();
        fs::create_dir_all(&root).expect("create transaction test directory");
        let exports = root.join("exports");
        let backup = root.join("exports.bak");
        let state = backup.with_extension("bak.txn");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate = "/Users/Shared/original 192.0.2.10\n/Users/Shared/new 192.0.2.11\n";
        fs::write(&exports, candidate).expect("write already-installed candidate");
        fs::write(&backup, original).expect("save transaction original");
        fs::write(
            &state,
            "MACLUSTER_NFS_TXN_V1|yes|yes|yes|baseline|before|candidate\n",
        )
        .expect("write transaction state");

        let command = nfs_exports_update_baseline_read_command(
            &exports.to_string_lossy(),
            &backup.to_string_lossy(),
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .output()
            .expect("run transaction baseline reader");
        assert!(output.status.success());
        let response = String::from_utf8(output.stdout).expect("decode baseline response");

        assert_eq!(
            parse_nfs_exports_update_baseline(&response).unwrap(),
            (original.to_owned(), true)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nfs_exports_baseline_reader_handles_missing_legacy_backups_under_zsh() {
        let root = std::env::temp_dir().join(format!("macluster-zsh-nfs-glob-{}", Id128::random()));
        fs::create_dir_all(&root).expect("create empty exports directory");
        let exports = root.join("exports");
        let backup = root.join("exports.bak");
        let command = nfs_exports_update_baseline_read_command(
            &exports.to_string_lossy(),
            &backup.to_string_lossy(),
        );

        let output = Command::new("/bin/zsh")
            .arg("-c")
            .arg(command)
            .output()
            .expect("run baseline reader under the default macOS SSH shell");

        assert!(
            output.status.success(),
            "zsh rejected the no-backup glob: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            parse_nfs_exports_update_baseline(&String::from_utf8(output.stdout).unwrap()).unwrap(),
            (String::new(), false)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_per_operation_transaction_is_migrated_and_reloaded() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let legacy_backup = etc.join("exports.macluster-old-operation.bak");
        let legacy_temporary = etc.join("exports.macluster-old-operation.tmp");
        let log = root.join("nfsd.log");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate = format!("{original}/Users/Shared/worker 192.0.2.11\n");
        fs::write(&exports, &candidate).expect("write interrupted legacy candidate");
        fs::write(&legacy_backup, original).expect("write legacy backup");
        fs::write(&legacy_temporary, &candidate).expect("write legacy candidate copy");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; fi\nexit 0\n",
                log = super::shell_quote(&log.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let baseline_command = nfs_exports_update_baseline_read_command(
            &exports.to_string_lossy(),
            &backup.to_string_lossy(),
        );
        let baseline_output = Command::new("/bin/sh")
            .arg("-c")
            .arg(baseline_command)
            .output()
            .expect("inspect legacy transaction");
        assert!(baseline_output.status.success());
        assert_eq!(
            parse_nfs_exports_update_baseline(&String::from_utf8(baseline_output.stdout).unwrap())
                .unwrap(),
            (original.to_owned(), true)
        );

        let script = nfs_exports_update_script_for_expected(
            &candidate,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("resume legacy transaction");

        assert!(
            output.status.success(),
            "legacy recovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate);
        assert!(!legacy_backup.exists());
        assert!(!legacy_temporary.exists());
        assert!(!backup.with_extension("bak.txn").exists());
        assert!(fs::read_to_string(&log).unwrap().contains("update\n"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nfs_daemon_uses_macos_system_path() {
        assert_eq!(NFS_DAEMON_PATH, "/sbin/nfsd");
    }

    #[test]
    fn nfs_exports_update_preserves_the_existing_file_inode() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/existing 192.0.2.9\n";
        let candidate = format!(
            "{original}# macluster-managed test arm-a\n/Users/Shared/macluster 192.0.2.2\n"
        );
        fs::write(&exports, original).expect("write existing exports");
        let original_inode = fs::metadata(&exports).expect("stat existing exports").ino();
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            "#!/bin/sh\nif [ \"$1\" = status ]; then\n  echo 'nfsd service is enabled'\n  echo 'nfsd is running'\nfi\nexit 0\n",
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script(
            &candidate,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run generated NFS update script");

        assert!(
            output.status.success(),
            "update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&exports).expect("read updated exports"),
            candidate
        );
        assert_eq!(
            fs::metadata(&exports).expect("stat updated exports").ino(),
            original_inode,
            "updating exports must write the existing file instead of renaming over it"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_nfs_update_is_reloaded_on_retry() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let log = root.join("nfsd.log");
        let interrupted = root.join("interrupted");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/existing 192.0.2.9\n";
        let candidate = format!(
            "{original}# macluster-managed test arm-a\n/Users/Shared/macluster 192.0.2.2\n"
        );
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; exit 0; fi\nif [ \"$1\" = update ] && [ ! -e {interrupted} ]; then : > {interrupted}; kill -9 \"$PPID\"; exit 137; fi\nexit 0\n",
                log = super::shell_quote(&log.to_string_lossy()),
                interrupted = super::shell_quote(&interrupted.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script_for_expected(
            &candidate,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let first = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run first NFS update attempt");
        assert!(
            !first.status.success(),
            "fake daemon should interrupt first update"
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate);
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);

        let retry = Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("retry NFS update");

        assert!(
            retry.status.success(),
            "retry failed: {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate);
        assert!(!backup.exists(), "completed retry should clear its backup");
        assert!(
            fs::read_to_string(&log)
                .expect("read daemon invocation log")
                .lines()
                .filter(|line| *line == "update")
                .count()
                >= 2,
            "retry must call nfsd update after resuming the written candidate"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn changed_retry_candidate_keeps_the_first_original_backup() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let interrupted = root.join("interrupted");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/existing 192.0.2.9\n";
        let first_candidate = format!(
            "{original}# macluster-managed test arm-a\n/Users/Shared/macluster 192.0.2.2\n"
        );
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; exit 0; fi\nif [ \"$1\" = update ]; then if [ ! -e {interrupted} ]; then : > {interrupted}; kill -9 \"$PPID\"; else exit 1; fi; fi\nexit 0\n",
                interrupted = super::shell_quote(&interrupted.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let first_script = nfs_exports_update_script_for_expected(
            &first_candidate,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let first = Command::new("/bin/sh")
            .arg("-c")
            .arg(first_script)
            .output()
            .expect("run interrupted add");
        assert!(!first.status.success());
        assert_eq!(fs::read_to_string(&exports).unwrap(), first_candidate);

        // A reset/cancel retry can have a different candidate: the interrupted
        // add must be removed, while the original backup remains authoritative.
        let retry_script = nfs_exports_update_script_for_expected(
            original,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let retry = Command::new("/bin/sh")
            .arg("-c")
            .arg(retry_script)
            .output()
            .expect("run changed-candidate retry");

        assert!(!retry.status.success(), "fake daemon rejects the reload");
        assert_eq!(fs::read_to_string(&exports).unwrap(), original);
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        assert!(backup.with_extension("bak.txn").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_changed_candidate_retry_accepts_the_previous_live_file() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let interrupted = root.join("interrupted");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate_a = format!("{original}/Users/Shared/a 192.0.2.11\n");
        let candidate_b = format!("{original}/Users/Shared/b 192.0.2.12\n");
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; exit 0; fi\nif [ \"$1\" = update ] && [ ! -e {interrupted} ]; then : > {interrupted}; kill -9 \"$PPID\"; exit 137; fi\nexit 0\n",
                interrupted = super::shell_quote(&interrupted.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script_a = nfs_exports_update_script_for_expected(
            &candidate_a,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let first = Command::new("/bin/sh")
            .arg("-c")
            .arg(script_a)
            .output()
            .expect("interrupt candidate A after writing");
        assert!(!first.status.success());
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate_a);

        let mut candidate_b_body = super::nfs_exports_update_body(
            &candidate_b,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &nfsd.to_string_lossy(),
        )
        .unwrap();
        let state = backup.with_extension("bak.txn");
        let state_new = state.with_extension("txn.new");
        let state_publish = format!(
            "/bin/mv -f {} {}\ntransaction_active=yes\n",
            super::shell_quote(&state_new.to_string_lossy()),
            super::shell_quote(&state.to_string_lossy()),
        );
        assert!(candidate_b_body.contains(&state_publish));
        candidate_b_body = candidate_b_body.replacen(
            &state_publish,
            &format!("{state_publish}kill -9 \"$$\"\n"),
            1,
        );
        let interrupted_before_write = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "/bin/sh -c {}",
                super::shell_quote(&candidate_b_body)
            ))
            .output()
            .expect("interrupt after publishing candidate B");
        assert!(!interrupted_before_write.status.success());
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate_a);

        let script_b = nfs_exports_update_script_for_expected(
            &candidate_b,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let retry = Command::new("/bin/sh")
            .arg("-c")
            .arg(script_b)
            .output()
            .expect("retry candidate B");

        assert!(
            retry.status.success(),
            "retry failed: {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate_b);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_partial_exports_write_is_recovered_from_the_backup() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate = format!(
            "{original}{}",
            "/Users/Shared/worker 192.0.2.11\n".repeat(40)
        );
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; fi\nexit 0\n",
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script_for_expected(
            &candidate,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let write_command = format!(
            "/bin/cat {} > {}\n",
            super::shell_quote(&temporary.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let partial_write = format!(
            "/usr/bin/head -c 16 {} > {}\nkill -9 \"$$\"\n",
            super::shell_quote(&temporary.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let interrupted_script = script.replacen(&write_command, &partial_write, 1);
        assert_ne!(
            interrupted_script, script,
            "test must interrupt the live write"
        );
        let first = Command::new("/bin/sh")
            .arg("-c")
            .arg(interrupted_script)
            .output()
            .expect("kill process during exports write");
        assert!(!first.status.success());
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate[..16]);
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);

        let retry = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("recover partial exports write");

        assert!(
            retry.status.success(),
            "recovery failed: {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_backup_restore_is_recovered_on_the_next_retry() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate = "# retained operator export\n";
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; fi\nexit 0\n",
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script_for_expected(
            candidate,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let write_command = format!(
            "/bin/cat {} > {}\n",
            super::shell_quote(&temporary.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let partial_candidate_write = format!(
            "/usr/bin/head -c 5 {} > {}\nkill -9 \"$$\"\n",
            super::shell_quote(&temporary.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let interrupted_candidate = script.replacen(&write_command, &partial_candidate_write, 1);
        assert_ne!(interrupted_candidate, script);
        let first = Command::new("/bin/sh")
            .arg("-c")
            .arg(interrupted_candidate)
            .output()
            .expect("interrupt candidate write");
        assert!(!first.status.success());

        let restore_command = format!(
            "if [ \"$had_original\" = yes ]; then /bin/cat {} > {}; else /bin/rm -f {}; fi\n",
            super::shell_quote(&backup.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let partial_restore = format!(
            "if [ \"$had_original\" = yes ]; then /usr/bin/head -c 10 {} > {}; kill -9 \"$$\"; else /bin/rm -f {}; fi\n",
            super::shell_quote(&backup.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let interrupted_restore = script.replacen(&restore_command, &partial_restore, 1);
        assert_ne!(
            interrupted_restore, script,
            "test must interrupt backup restoration"
        );
        let second = Command::new("/bin/sh")
            .arg("-c")
            .arg(interrupted_restore)
            .output()
            .expect("interrupt backup restoration");
        assert!(!second.status.success());
        assert_eq!(fs::read_to_string(&exports).unwrap(), &original[..10]);

        let retry = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("recover interrupted backup restoration");

        assert!(
            retry.status.success(),
            "recovery failed: {}",
            String::from_utf8_lossy(&retry.stderr)
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn partial_exports_write_failure_restores_original_file() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate = format!("{original}{}", "# padding\n".repeat(600));
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            "#!/bin/sh\nif [ \"$1\" = status ]; then echo 'nfsd service is enabled'; echo 'nfsd is running'; fi\nexit 0\n",
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let body = super::nfs_exports_update_body(
            &candidate,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &nfsd.to_string_lossy(),
        )
        .expect("build update body");
        let write_command = format!(
            "/bin/cat {} > {}\n",
            super::shell_quote(&temporary.to_string_lossy()),
            super::shell_quote(&exports.to_string_lossy())
        );
        let limited_write = format!("ulimit -f 1\n{write_command}");
        let limited_body = body.replacen(&write_command, &limited_write, 1);
        assert_ne!(limited_body, body, "test must inject the write limit");
        let script = format!("/bin/sh -c {}", super::shell_quote(&limited_body));
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run size-limited update");

        assert!(!output.status.success(), "candidate exceeds the file limit");
        assert_eq!(fs::read_to_string(&exports).unwrap(), original);
        assert!(!backup.with_extension("bak.txn").exists());
        assert!(!backup.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_nfs_export_transactions_are_serialized() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let entered = root.join("first-entered-status");
        let release = root.join("release-first-status");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/original 192.0.2.10\n";
        let candidate_a = format!("{original}/Users/Shared/a 192.0.2.11\n");
        let candidate_b = format!("{original}/Users/Shared/b 192.0.2.12\n");
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nif [ \"$1\" = status ]; then\n  if [ ! -e {entered} ]; then : > {entered}; while [ ! -e {release} ]; do sleep 0.01; done; fi\n  echo 'nfsd service is enabled'; echo 'nfsd is running'; exit 0\nfi\nexit 0\n",
                entered = super::shell_quote(&entered.to_string_lossy()),
                release = super::shell_quote(&release.to_string_lossy()),
            ),
        )
        .expect("write blocking fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let first_script = nfs_exports_update_script_for_expected(
            &candidate_a,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let second_script = nfs_exports_update_script_for_expected(
            &candidate_b,
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let first = Command::new("/bin/sh")
            .arg("-c")
            .arg(first_script)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start first NFS transaction");
        for _ in 0..500 {
            if entered.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            entered.exists(),
            "first transaction did not reach status check"
        );

        let second = Command::new("/bin/sh")
            .arg("-c")
            .arg(second_script)
            .output()
            .expect("start competing NFS transaction");
        fs::write(&release, "release").expect("release first transaction");
        let first = first.wait_with_output().expect("finish first transaction");

        assert!(
            !second.status.success(),
            "a concurrent server-side transaction must fail before mutating exports"
        );
        assert!(
            first.status.success(),
            "first transaction failed: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(fs::read_to_string(&exports).unwrap(), candidate_a);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nfs_privacy_denial_preserves_exports_and_explains_server_authorization() {
        let root = test_exports_path();
        fs::create_dir_all(&root).unwrap();
        let exports = root.join("exports");
        let temporary = root.join("exports.tmp");
        let backup = root.join("exports.bak");
        let nfsd = root.join("nfsd");
        let original = "/Users/Shared/old 192.0.2.7\n";
        fs::write(&exports, original).unwrap();
        fs::write(
            &nfsd,
            "#!/bin/sh\nif [ \"$1\" = status ]; then\n  echo 'nfsd service is enabled'; echo 'nfsd is running'; exit 0\nfi\necho 'exports:2: sandbox_check failed. nfsd has no read access to /Volumes/private' >&2\nexit 1\n",
        ).unwrap();
        fs::set_permissions(&nfsd, fs::Permissions::from_mode(0o755)).unwrap();
        let script = super::nfs_exports_update_body(
            "/Volumes/private 192.0.2.8\n",
            original,
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &nfsd.to_string_lossy(),
        )
        .unwrap();
        let output = Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert_eq!(fs::read_to_string(&exports).unwrap(), original);
        assert!(!backup.exists());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("sandbox_check failed"), "{error}");
        assert!(error.contains("Full Disk Access"), "{error}");
        assert!(error.contains("/sbin/nfsd restart"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn first_nfs_enrollment_creates_exports_and_starts_service() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let log = root.join("nfsd.log");
        let sudo_log = root.join("sudo.log");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        fs::write(
            &sudo,
            format!(
                "#!/bin/sh\nprintf 'sudo\\n' >> {}\nexec \"$@\"\n",
                super::shell_quote(&sudo_log.to_string_lossy())
            ),
        )
        .expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nprintf 'CMD:' >> {log}\nfor arg in \"$@\"; do printf ' %s' \"$arg\" >> {log}; done\nprintf '\\n' >> {log}\nif [ \"$1\" = status ]; then\n  echo 'nfsd service is enabled'\n  echo 'nfsd is not running'\n  exit 1\nfi\nexit 0\n",
                log = super::shell_quote(&log.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script(
            "/Users/Shared/macluster 192.168.2.2\n",
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run generated NFS setup script");

        assert!(
            output.status.success(),
            "setup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&exports).expect("read generated exports"),
            "/Users/Shared/macluster 192.168.2.2\n"
        );
        assert_eq!(
            fs::read_to_string(&log).expect("read nfsd invocation log"),
            format!(
                "CMD: status\nCMD: -F {} checkexports\nCMD: start\nCMD: checkexports\nCMD: update\n",
                temporary.display()
            )
        );
        assert_eq!(
            fs::read_to_string(&sudo_log).expect("read sudo invocation log"),
            "sudo\n",
            "NFS administration should authenticate once for this terminal session"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn nfs_update_refuses_to_replace_exports_changed_after_preflight() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let nfsd_log = root.join("nfsd.log");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let preflight_contents = "/Users/Shared/old 192.0.2.7\n";
        let operator_update = "/Users/Shared/operator 192.0.2.8\n";
        fs::write(&exports, preflight_contents).expect("write preflight exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nprintf 'called\\n' >> {}\nexit 0\n",
                super::shell_quote(&nfsd_log.to_string_lossy())
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script(
            "/Users/Shared/macluster 192.0.2.9\n",
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        fs::write(&exports, operator_update).expect("concurrent operator edit");
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run generated NFS update script");

        assert!(
            !output.status.success(),
            "concurrent edits must stop the update"
        );
        assert_eq!(
            fs::read_to_string(&exports).expect("read preserved operator exports"),
            operator_update
        );
        assert!(
            !nfsd_log.exists(),
            "NFS service update must not start after a conflict"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_nfs_update_restores_existing_exports_and_service_state() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let log = root.join("nfsd.log");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        let original = "/Users/Shared/existing 192.168.2.9\n";
        fs::write(&exports, original).expect("write existing exports");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nprintf 'CMD:' >> {log}\nfor arg in \"$@\"; do printf ' %s' \"$arg\" >> {log}; done\nprintf '\\n' >> {log}\nif [ \"$1\" = status ]; then\n  echo 'nfsd service is disabled'\n  echo 'nfsd is not running'\n  exit 1\nfi\nif [ \"$1\" = update ]; then exit 1; fi\nexit 0\n",
                log = super::shell_quote(&log.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script(
            "/Users/Shared/macluster 192.168.2.2\n",
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run generated NFS setup script");

        assert!(!output.status.success());
        assert_eq!(
            fs::read_to_string(&exports).expect("read restored exports"),
            original
        );
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        assert!(backup.with_extension("bak.txn").exists());
        let invocations = fs::read_to_string(&log).expect("read nfsd invocation log");
        assert!(invocations.contains("CMD: enable\n"));
        assert!(invocations.contains("CMD: start\n"));
        assert!(invocations.ends_with("CMD: stop\nCMD: disable\n"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_first_nfs_setup_removes_new_exports_file() {
        let root = test_exports_path();
        let etc = root.join("etc");
        let bin = root.join("bin");
        fs::create_dir_all(&etc).expect("create fake etc directory");
        fs::create_dir_all(&bin).expect("create fake bin directory");
        let exports = etc.join("exports");
        let temporary = etc.join("exports.tmp");
        let backup = etc.join("exports.bak");
        let log = root.join("nfsd.log");
        let sudo = bin.join("sudo");
        let nfsd = bin.join("nfsd");
        fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("write fake sudo");
        fs::write(
            &nfsd,
            format!(
                "#!/bin/sh\nprintf 'CMD:' >> {log}\nfor arg in \"$@\"; do printf ' %s' \"$arg\" >> {log}; done\nprintf '\\n' >> {log}\nif [ \"$1\" = status ]; then\n  echo 'nfsd service is enabled'\n  echo 'nfsd is not running'\n  exit 1\nfi\nif [ \"$1\" = update ]; then exit 1; fi\nexit 0\n",
                log = super::shell_quote(&log.to_string_lossy()),
            ),
        )
        .expect("write fake nfsd");
        for executable in [&sudo, &nfsd] {
            fs::set_permissions(executable, fs::Permissions::from_mode(0o755))
                .expect("make test executable");
        }

        let script = nfs_exports_update_script(
            "/Users/Shared/macluster 192.168.2.2\n",
            &exports.to_string_lossy(),
            &temporary.to_string_lossy(),
            &backup.to_string_lossy(),
            &sudo.to_string_lossy(),
            &nfsd.to_string_lossy(),
        );
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .expect("run generated NFS setup script");

        assert!(!output.status.success());
        assert!(
            !exports.exists(),
            "first-use exports file should be removed"
        );
        assert!(!backup.exists());
        assert!(backup.with_extension("bak.txn").exists());
        let _ = fs::remove_dir_all(root);
    }
}
