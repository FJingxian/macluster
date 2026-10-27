use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use macluster_core::{
    config::{ClusterConfig, NodeConfig, Transport},
    maintenance::MaintenanceLock,
    storage::Storage,
};
use macluster_protocol::{
    framing::sha256_hex,
    identifiers::Id128,
    types::{ExecutionStatus, JobState, RuntimePhase},
};
use serde::{Deserialize, Serialize};

use super::{AppResult, InitOptions, atomic_create_config, prompt_value};
use crate::node_admin;

const RESET_JOURNAL_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResetMode {
    #[default]
    RebuildAfterCleanup,
    ClearToUninitialized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArchiveTransition {
    CompletedUninitialized,
    InstallTarget,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ResetJournal {
    version: u32,
    id: String,
    phase: String,
    config_path: String,
    state_dir: String,
    old_config: String,
    old_config_sha256: String,
    #[serde(default)]
    local_agent_state: Option<String>,
    #[serde(default)]
    mode: ResetMode,
    #[serde(default)]
    discard_terminal_sync: bool,
    #[serde(default)]
    abandonment_recorded: bool,
    #[serde(default)]
    abandoned_sync_manifest_written: bool,
    #[serde(default)]
    abandoned_sync_jobs: Vec<AbandonedSyncJob>,
    target_config: String,
    target_options: InitOptions,
    #[serde(default)]
    target_context: Option<super::InitContext>,
    archive_dir: String,
    completed_steps: std::collections::BTreeSet<String>,
    detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AbandonedSyncJob {
    job_id: u64,
    state: JobState,
    node: Option<macluster_protocol::identifiers::NodeId>,
    start_token: Option<macluster_protocol::identifiers::StartToken>,
    snapshot_sync_pending: bool,
    log_sync_pending: bool,
}

impl ResetJournal {
    fn mark_completed(&mut self, step: impl Into<String>) {
        self.completed_steps.insert(step.into());
    }

    fn is_completed(&self, step: &str) -> bool {
        self.completed_steps.contains(step)
    }
}

pub(crate) fn journal_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".macluster-reset.json");
    config_path.with_file_name(name)
}

pub(crate) fn ensure_no_reset_in_progress(config_path: &Path, state_dir: &Path) -> AppResult<()> {
    let canonical = config_path
        .canonicalize()
        .unwrap_or_else(|_| config_path.to_path_buf());
    let path = journal_path(&canonical);
    if !path.exists() {
        return Ok(());
    }
    let bytes = fs::read(&path).map_err(|error| {
        (
            1,
            format!(
                "cannot read reset recovery journal {}: {error}",
                path.display()
            ),
        )
    })?;
    let journal: ResetJournal = serde_json::from_slice(&bytes).map_err(|error| {
        (
            1,
            format!(
                "reset recovery journal {} is invalid: {error}; keep the controller stopped and inspect the journal",
                path.display()
            ),
        )
    })?;
    validate_reset_journal(&journal)?;
    validate_journal_binding(&journal, &canonical, state_dir)?;
    if journal.phase == "COMPLETE" {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err((
                    1,
                    format!(
                        "reset is complete, but its recovery journal {} cannot be removed: {error}; rerun `macluster init` to finish cleanup",
                        path.display()
                    ),
                ));
            }
        }
        return Ok(());
    }
    Err((
        1,
        format!(
            "cluster reset {} is in phase {}; resume it with `macluster init` before submitting or starting the controller",
            journal.id, journal.phase
        ),
    ))
}

pub(crate) fn run(
    config_path: PathBuf,
    state_dir: PathBuf,
    options: InitOptions,
) -> AppResult<Option<InitOptions>> {
    if unsafe { libc::geteuid() } == 0 {
        return Err((
            1,
            "run `macluster init` as the normal login account, not root; cluster config is per-user".into(),
        ));
    }
    let config_path = if config_path.exists() {
        config_path
            .canonicalize()
            .map_err(|error| (1, error.to_string()))?
    } else {
        super::absolute_path(&config_path).map_err(|error| (1, error.to_string()))?
    };
    let state_dir = super::absolute_path(&state_dir).map_err(|error| (1, error.to_string()))?;
    let state_dir = if state_dir.exists() {
        state_dir.canonicalize().map_err(|error| {
            (
                1,
                format!(
                    "cannot resolve state directory {}: {error}",
                    state_dir.display()
                ),
            )
        })?
    } else {
        state_dir
    };
    let path = journal_path(&config_path);
    let requested_force = options.force;
    let mut journal = if path.exists() {
        let journal = load_journal(&path)?;
        validate_resume_options(&journal.target_options, &options)?;
        validate_journal_binding(&journal, &config_path, &state_dir)?;
        if journal.phase == "COMPLETE" {
            fs::remove_file(&path).map_err(|error| (1, error.to_string()))?;
            if journal.mode == ResetMode::ClearToUninitialized {
                println!("The previous reset is complete.");
                println!("Continuing with new cluster setup.");
                return Ok(Some(journal.target_options));
            } else {
                println!("The previous reset is complete.");
                println!("Start the controller with `macluster controller run`.");
            }
            return Ok(None);
        }
        journal
    } else {
        create_reset_journal(&config_path, &state_dir, options, &path)?
    };

    if requested_force && !journal.discard_terminal_sync {
        let old = ClusterConfig::parse(&journal.old_config)
            .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
        confirm_force_escalation(&old.name, Path::new(&journal.archive_dir))?;
        enable_force_reset(&mut journal);
        save_journal(&path, &journal, false)?;
    }
    if journal.discard_terminal_sync && !requested_force {
        eprintln!(
            "Resuming reset with its saved force policy: terminal-job snapshot/log sync may be abandoned, and unsynchronized output may be unavailable. Active jobs still block reset."
        );
    }

    let _maintenance = wait_for_exclusive_lock(&config_path, &state_dir)?;
    let local_agent_state = local_agent_state_path(&journal);
    let blockers = match job_blockers(&state_dir, journal.discard_terminal_sync) {
        Ok(blockers) => blockers,
        Err((code, error)) if journal.phase == "DRAINING" => {
            cancel_temporary_drain(&path);
            return Err((
                code,
                format!(
                    "reset was cancelled before cleanup: {error}. Restart the controller with `macluster controller run` after checking the state directory."
                ),
            ));
        }
        Err(error) => return Err(error),
    };
    if !blockers.is_empty() {
        let temporary_barrier_removed = journal.phase == "DRAINING";
        if temporary_barrier_removed {
            cancel_temporary_drain(&path);
        }
        let retry = if journal.discard_terminal_sync {
            "`macluster init --force`"
        } else {
            "`macluster init`"
        };
        let recovery_hint = match (temporary_barrier_removed, journal.discard_terminal_sync) {
            (true, true) => format!("The old config is unchanged and the temporary reset barrier was removed. Cancel the listed nonterminal jobs with `mkill`, restart the updated controller, then retry {retry}."),
            (true, false) => "The old config is unchanged and the temporary reset barrier was removed. Use `mkill` for jobs you do not want to run, restart the controller to finish reconciliation/log sync, then retry `macluster init`.".into(),
            (false, _) => format!("The reset barrier remains active; resolve the listed nonterminal blockers and rerun {retry}."),
        };
        return Err((
            1,
            format!(
                "reset is paused because jobs or log synchronization are still active:\n  {}\n{recovery_hint}",
                blockers.join("\n  "),
            ),
        ));
    }
    if journal.discard_terminal_sync && !journal.abandonment_recorded {
        journal.abandoned_sync_jobs = terminal_sync_abandonments(&state_dir)?;
        journal.abandonment_recorded = true;
        save_journal(&path, &journal, false)?;
    }
    if journal.phase == "DRAINING" {
        let current = match fs::read_to_string(&config_path) {
            Ok(current) => current,
            Err(error) => {
                cancel_temporary_drain(&path);
                return Err((
                    1,
                    format!(
                        "reset was cancelled before cleanup because the config could not be re-read: {error}. Restart the controller with `macluster controller run`."
                    ),
                ));
            }
        };
        let current_digest =
            sha256_hex(current.as_bytes()).map_err(|error| (1, error.to_string()))?;
        if current_digest != journal.old_config_sha256 {
            cancel_temporary_drain(&path);
            return Err((
                1,
                "cluster config changed while reset was draining; reset was cancelled before cleanup. Review the current config, restart the controller, and retry.".into(),
            ));
        }
        let old = ClusterConfig::parse(&journal.old_config)
            .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
        if let Err((code, error)) =
            ensure_old_paths_are_outside_shared_root(&config_path, &state_dir, &old.shared_root)
        {
            cancel_temporary_drain(&path);
            return Err((
                code,
                format!(
                    "reset was cancelled before cleanup: {error}. Restart the controller with `macluster controller run`."
                ),
            ));
        }
        let plan = match ResetPlan::preflight(
            &old,
            &config_path,
            &state_dir,
            &journal.id,
            Path::new(&journal.archive_dir),
            &local_agent_state,
            journal.discard_terminal_sync,
            &journal.abandoned_sync_jobs,
        ) {
            Ok(plan) => plan,
            Err((code, error)) => {
                cancel_temporary_drain(&path);
                return Err((
                    code,
                    format!(
                        "reset was cancelled before cleanup because old-cluster preflight failed: {error}. Restart the controller with `macluster controller run` after resolving the preflight issue."
                    ),
                ));
            }
        };
        begin_controller_reset(&config_path, &state_dir)?;
        journal.phase = "CLEANING".into();
        save_journal(&path, &journal, false)?;
        cleanup_resources(&mut journal, &plan, &path)?;
        journal.phase = "REMOTE_CONFIGS".into();
        save_journal(&path, &journal, false)?;
    }
    if journal.phase == "CLEANING" {
        begin_controller_reset(&config_path, &state_dir)?;
        let old = ClusterConfig::parse(&journal.old_config)
            .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
        let plan = ResetPlan::preflight_cleanup_resume(
            &old,
            &config_path,
            &state_dir,
            &journal.id,
            Path::new(&journal.archive_dir),
            &local_agent_state,
            journal.discard_terminal_sync,
            &journal.abandoned_sync_jobs,
        )?;
        cleanup_resources(&mut journal, &plan, &path)?;
        journal.phase = "REMOTE_CONFIGS".into();
        save_journal(&path, &journal, false)?;
    }
    if journal.phase == "REMOTE_CONFIGS" {
        let old = ClusterConfig::parse(&journal.old_config)
            .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
        let plan = ResetPlan::preflight_remote_config_resume(
            &old,
            &config_path,
            &state_dir,
            &journal.id,
            Path::new(&journal.archive_dir),
            &local_agent_state,
        )?;
        archive_remote_configs(&mut journal, &plan, &path)?;
        quiesce_publishers(&mut journal, &plan, &path)?;
        archive_remote_agent_states(&mut journal, &plan, &path)?;
        journal.phase = "ARCHIVING".into();
        save_journal(&path, &journal, false)?;
    }
    if journal.phase == "ARCHIVING" {
        if advance_archive_phase(&mut journal, &path)? == ArchiveTransition::CompletedUninitialized
        {
            println!(
                "Cluster reset complete. Active config removed: {}",
                journal.config_path
            );
            println!("Continuing with new cluster setup.");
            return Ok(Some(journal.target_options));
        }
    }
    if journal.phase == "INSTALLING" {
        install_target(&mut journal, &path)?;
        journal.phase = "COMPLETE".into();
        save_journal(&path, &journal, false)?;
        fs::remove_file(&path).map_err(|error| {
            (
                1,
                format!("reset completed but journal removal failed: {error}"),
            )
        })?;
        println!("Cluster reset complete.");
        println!("Start the controller with `macluster controller run`.");
    }
    Ok(None)
}

fn begin_controller_reset(config_path: &Path, state_dir: &Path) -> AppResult<()> {
    let binding = macluster_core::service::ServiceBinding::load(config_path, state_dir)
        .map_err(|error| (1, format!("cannot bind controller service reset: {error}")))?;
    let manager = crate::service::ServiceManager::current(binding).map_err(|error| {
        (
            1,
            format!("cannot prepare controller service reset: {error}"),
        )
    })?;
    if !manager.service_dir().join("intent.json").exists() && !manager.plist_path().exists() {
        return Ok(());
    }
    manager.begin_reset().map_err(|error| {
        (
            1,
            format!("cannot stop the controller service for reset: {error}"),
        )
    })
}

fn cancel_temporary_drain(path: &Path) {
    if let Err(error) = fs::remove_file(path) {
        if error.kind() != io::ErrorKind::NotFound {
            eprintln!(
                "macluster: could not remove temporary reset barrier {}: {error}; rerun `macluster init` to recover",
                path.display()
            );
        }
    }
}

fn ensure_old_paths_are_outside_shared_root(
    config_path: &Path,
    state_dir: &Path,
    shared_root: &Path,
) -> AppResult<()> {
    if state_dir.starts_with(shared_root) || shared_root.starts_with(state_dir) {
        return Err((
            2,
            format!(
                "old controller state {} overlaps the old shared root {}; refusing to archive files from shared storage",
                state_dir.display(),
                shared_root.display()
            ),
        ));
    }
    if config_path.starts_with(shared_root) {
        return Err((
            2,
            format!(
                "old config {} is inside the old shared root {}; refusing to remove cluster control files from shared storage",
                config_path.display(),
                shared_root.display()
            ),
        ));
    }
    if config_path.starts_with(state_dir) || state_dir.starts_with(config_path) {
        return Err((
            2,
            format!(
                "old config {} and controller state {} overlap; refusing an archive that could move the active config with the state directory",
                config_path.display(),
                state_dir.display()
            ),
        ));
    }
    Ok(())
}

fn load_journal(path: &Path) -> AppResult<ResetJournal> {
    let bytes = fs::read(path).map_err(|error| (1, error.to_string()))?;
    let journal: ResetJournal = serde_json::from_slice(&bytes).map_err(|error| {
        (
            1,
            format!("reset journal {} is invalid: {error}", path.display()),
        )
    })?;
    validate_reset_journal(&journal)?;
    Ok(journal)
}

fn validate_reset_journal(journal: &ResetJournal) -> AppResult<()> {
    if journal.version != RESET_JOURNAL_VERSION {
        return Err((
            1,
            format!("unsupported reset journal version {}", journal.version),
        ));
    }
    if !matches!(
        journal.phase.as_str(),
        "DRAINING" | "CLEANING" | "REMOTE_CONFIGS" | "ARCHIVING" | "INSTALLING" | "COMPLETE"
    ) {
        return Err((
            1,
            format!(
                "reset journal has unknown phase '{}'; keep the controller stopped and inspect the journal",
                journal.phase
            ),
        ));
    }
    if journal.abandoned_sync_manifest_written && !journal.abandonment_recorded {
        return Err((
            1,
            "reset journal records a force manifest without an abandonment record".into(),
        ));
    }
    Ok(())
}

fn validate_journal_binding(
    journal: &ResetJournal,
    config_path: &Path,
    state_dir: &Path,
) -> AppResult<()> {
    let recorded_config = normalized_path(Path::new(&journal.config_path));
    let expected_config = normalized_path(config_path);
    let recorded_state = normalized_path(Path::new(&journal.state_dir));
    let expected_state = normalized_path(state_dir);
    if recorded_config != expected_config || recorded_state != expected_state {
        return Err((
            1,
            "reset journal belongs to a different config or state path".into(),
        ));
    }
    Ok(())
}

fn normalized_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn validate_resume_options(saved: &InitOptions, supplied: &InitOptions) -> AppResult<()> {
    let conflicts = supplied
        .name
        .as_ref()
        .is_some_and(|value| saved.name.as_ref() != Some(value))
        || supplied
            .queue
            .as_ref()
            .is_some_and(|value| saved.queue.as_ref() != Some(value))
        || supplied
            .shared_root
            .as_ref()
            .is_some_and(|value| saved.shared_root.as_ref() != Some(value))
        || supplied.host.is_some_and(|value| saved.host != Some(value))
        || supplied.primary_nfs.as_ref().is_some_and(|value| {
            saved.primary_nfs.as_ref().is_none_or(|saved| {
                saved.user != value.user
                    || saved.host != value.host
                    || saved.port != value.port
                    || saved.source_root != value.source_root
            })
        });
    if conflicts {
        return Err((
            2,
            "a reset is already in progress with different target options; rerun `macluster init` without changing them".into(),
        ));
    }
    Ok(())
}

fn create_reset_journal(
    config_path: &Path,
    state_dir: &Path,
    options: InitOptions,
    path: &Path,
) -> AppResult<ResetJournal> {
    if !config_path.is_file() {
        return Err((
            1,
            format!(
                "cannot reset: config {} does not exist",
                config_path.display()
            ),
        ));
    }
    let old_config = fs::read_to_string(config_path).map_err(|error| (1, error.to_string()))?;
    let old = ClusterConfig::parse(&old_config).map_err(|error| (2, error.to_string()))?;

    let id = Id128::random().to_string();
    let archive_parent = state_dir
        .parent()
        .ok_or_else(|| (2, "state directory has no parent for its archive".into()))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let archive_dir = archive_parent
        .join("macluster-archive")
        .join(format!("{timestamp}-{id}"));
    if archive_dir.starts_with(&old.shared_root) {
        return Err((2, "archive path overlaps a shared root".into()));
    }
    for (server_id, source_root) in
        std::iter::once((old.storage_server.as_str(), old.primary_source_root())).chain(
            old.shares
                .values()
                .map(|share| (share.server.as_str(), share.source_root.as_path())),
        )
    {
        if old
            .nodes
            .get(server_id)
            .is_some_and(|node| node.transport == Transport::Local)
            && (archive_dir.starts_with(source_root) || source_root.starts_with(&archive_dir))
        {
            return Err((
                2,
                format!(
                    "archive path {} overlaps local NFS source {}; choose a different controller state location before resetting",
                    archive_dir.display(),
                    source_root.display()
                ),
            ));
        }
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err((
            2,
            "`init` requires terminal confirmation before resetting an existing cluster".into(),
        ));
    }
    println!(
        "Reset will detach all nodes, clear primary and named NFS shares (including incomplete setup), remove exact managed mounts, exports, aliases and share markers, and archive the old config and controller state. The controller will stop when reset begins; active jobs will not be killed, and reset will pause if they or output synchronization remain. Shared directories and their data files will be preserved. After cleanup, init continues directly to new cluster setup."
    );
    if options.force {
        println!(
            "FORCE: pending snapshot/log synchronization for terminal jobs will be abandoned. Their unsynchronized output may be unavailable through macluster. Active jobs still block reset."
        );
    }
    println!("Old cluster: {} (share {})", old.name, old.share_uuid);
    println!("Archive: {}", archive_dir.display());
    let response = prompt_value(
        &format!(
            "Reset existing cluster '{}', stop its controller now, and configure a new one? (Y/N)",
            old.name
        ),
        None,
        "N",
    )?;
    if !response.eq_ignore_ascii_case("y") && !response.eq_ignore_ascii_case("yes") {
        return Err((1, "cluster reset cancelled".into()));
    }
    let old_config_sha256 =
        sha256_hex(old_config.as_bytes()).map_err(|error| (1, error.to_string()))?;
    let journal = ResetJournal {
        version: RESET_JOURNAL_VERSION,
        id,
        phase: "DRAINING".into(),
        config_path: config_path.to_string_lossy().into_owned(),
        state_dir: state_dir.to_string_lossy().into_owned(),
        old_config,
        old_config_sha256,
        local_agent_state: Some(
            macluster_agent::default_state_dir()
                .to_string_lossy()
                .into_owned(),
        ),
        mode: ResetMode::ClearToUninitialized,
        discard_terminal_sync: options.force,
        abandonment_recorded: false,
        abandoned_sync_manifest_written: false,
        abandoned_sync_jobs: Vec::new(),
        target_config: String::new(),
        target_options: options,
        target_context: None,
        archive_dir: archive_dir.to_string_lossy().into_owned(),
        completed_steps: BTreeSet::new(),
        detail: None,
    };
    save_journal(path, &journal, true)?;
    Ok(journal)
}

fn confirm_force_escalation(cluster_name: &str, archive_dir: &Path) -> AppResult<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err((
            2,
            "upgrading an existing reset with `--force` requires an interactive terminal for typed confirmation".into(),
        ));
    }
    println!(
        "FORCE: pending snapshot/log synchronization for terminal jobs will be abandoned. Their unsynchronized output may be unavailable through macluster. Active jobs still block reset."
    );
    println!("Old cluster: {cluster_name}");
    println!("Archive: {}", archive_dir.display());
    let response = prompt_value(
        "Discard terminal-job sync and continue reset? (Y/N)",
        None,
        "N",
    )?;
    if !response.eq_ignore_ascii_case("y") && !response.eq_ignore_ascii_case("yes") {
        return Err((1, "cluster reset cancelled".into()));
    }
    Ok(())
}

fn enable_force_reset(journal: &mut ResetJournal) {
    journal.discard_terminal_sync = true;
}

#[derive(Clone)]
struct MountSpec {
    node_id: String,
    node: NodeConfig,
    server_host: String,
    source_root: PathBuf,
    mount_root: PathBuf,
    label: String,
}

#[derive(Clone)]
struct MarkerSpec {
    server_id: String,
    server: NodeConfig,
    source_root: PathBuf,
    share_uuid: String,
    label: String,
}

#[derive(Clone)]
struct AliasSpec {
    server_id: String,
    server: NodeConfig,
    source_root: PathBuf,
    mount_root: PathBuf,
    committed: bool,
}

#[derive(Clone)]
struct RemoteConfigSpec {
    node_id: String,
    node: NodeConfig,
    path: String,
    backup: String,
}

#[derive(Clone)]
struct RemoteAgentStateSpec {
    node_id: String,
    node: NodeConfig,
    path: String,
    archive: String,
    stop_publisher: bool,
}

struct ExportGroup {
    server: NodeConfig,
    specs: Vec<ManagedExportSpec>,
}

fn check_reset_remote_status(
    node_id: &str,
    remote_status: AppResult<Option<ExecutionStatus>>,
    discard_terminal_sync: bool,
    abandoned_sync_jobs: &[AbandonedSyncJob],
) -> AppResult<()> {
    let Some(status) = remote_status? else {
        // An agent that has never run a job has no execution record.
        return Ok(());
    };
    if status.phase != RuntimePhase::Idle {
        return Err((
            1,
            format!("remote execution state for {node_id} is {:?}", status.phase),
        ));
    }
    if !status.log_sync_pending {
        return Ok(());
    }

    let terminal_status_matches_abandoned_job = discard_terminal_sync
        && status.terminal_state.is_some_and(JobState::is_terminal)
        && abandoned_sync_jobs.iter().any(|job| {
            job.state.is_terminal()
                && job.log_sync_pending
                && job
                    .node
                    .as_ref()
                    .is_some_and(|node| node.as_str() == node_id)
                && job.job_id == status.job_id
                && job.start_token == Some(status.start_token)
                && Some(job.state) == status.terminal_state
        });
    if terminal_status_matches_abandoned_job {
        Ok(())
    } else {
        Err((
            1,
            format!(
                "remote job log synchronization on {node_id} does not match a recorded terminal job eligible for force reset"
            ),
        ))
    }
}

struct ResetPlan {
    nodes: BTreeMap<String, NodeConfig>,
    active_nodes: BTreeSet<String>,
    known_uuids: BTreeMap<String, String>,
    mounts: Vec<MountSpec>,
    exports: BTreeMap<String, ExportGroup>,
    markers: BTreeMap<(String, PathBuf, String), MarkerSpec>,
    aliases: Vec<AliasSpec>,
    remote_configs: Vec<RemoteConfigSpec>,
    remote_agent_states: Vec<RemoteAgentStateSpec>,
}

impl ResetPlan {
    fn preflight(
        config: &ClusterConfig,
        config_path: &Path,
        state_dir: &Path,
        reset_id: &str,
        archive_dir: &Path,
        local_agent_state: &Path,
        discard_terminal_sync: bool,
        abandoned_sync_jobs: &[AbandonedSyncJob],
    ) -> AppResult<Self> {
        let known_uuids = known_machine_uuids(state_dir)?;
        let config_bytes = fs::read(config_path).map_err(|error| {
            (
                1,
                format!("cannot verify active config while planning reset: {error}"),
            )
        })?;
        let config_digest = sha256_hex(&config_bytes).map_err(|error| (1, error.to_string()))?;
        let mut plan = Self {
            nodes: config.nodes.clone(),
            active_nodes: config.nodes.keys().cloned().collect(),
            known_uuids: known_uuids.clone(),
            mounts: Vec::new(),
            exports: BTreeMap::new(),
            markers: BTreeMap::new(),
            aliases: Vec::new(),
            remote_configs: Vec::new(),
            remote_agent_states: Vec::new(),
        };
        let storage_id = config.storage_server.as_str();
        let primary_server = config.nodes.get(storage_id).ok_or_else(|| {
            (
                1,
                "primary storage node is missing from the old config".into(),
            )
        })?;
        plan.add_share(
            storage_id,
            primary_server,
            config.primary_source_root(),
            &config.shared_root,
            &config.share_uuid,
            "primary",
        );
        for (share_id, share) in &config.shares {
            let server = config.nodes.get(share.server.as_str()).ok_or_else(|| {
                (
                    1,
                    format!("NFS server for named share {share_id} is missing"),
                )
            })?;
            plan.add_share(
                share.server.as_str(),
                server,
                &share.source_root,
                &share.mount_root,
                &share.share_uuid,
                share_id,
            );
            if share.source_root != share.mount_root {
                plan.aliases.push(AliasSpec {
                    server_id: share.server.to_string(),
                    server: server.clone(),
                    source_root: share.source_root.clone(),
                    mount_root: share.mount_root.clone(),
                    committed: true,
                });
                // Named-share clients also get a source-prefix symlink so
                // scripts with absolute shebangs from the login environment
                // keep working when the NFS mount lives at a separate path.
                for (node_id, node) in &config.nodes {
                    if node_id == share.server.as_str() {
                        continue;
                    }
                    plan.aliases.push(AliasSpec {
                        server_id: node_id.clone(),
                        server: node.clone(),
                        source_root: share.mount_root.clone(),
                        mount_root: share.source_root.clone(),
                        // Older configs may predate source-prefix aliases.
                        // Remove only an exact link; preserve everything else.
                        committed: false,
                    });
                }
            }
        }

        let operations = node_admin::reset_admin_operations(config_path, state_dir)?;
        plan.add_pending_admin_resources(config, operations, &known_uuids, &config_digest)?;

        for (node_id, node) in &plan.nodes {
            verify_node_identity(node_id, node, known_uuids.get(node_id))?;
            if plan.active_nodes.contains(node_id) {
                check_reset_remote_status(
                    node_id,
                    node_admin::remote_execution_status(node, node_id, config_path),
                    discard_terminal_sync,
                    abandoned_sync_jobs,
                )
                .map_err(|(_, error)| {
                    (
                        1,
                        format!(
                            "cannot reset while node {node_id} is occupied or unreachable: {error}"
                        ),
                    )
                })?;
            }
        }
        plan.collect_remote_configs(reset_id, &config.share_uuid)?;
        plan.preflight_mounts()?;
        plan.preflight_exports()?;
        plan.preflight_markers()?;
        plan.preflight_aliases()?;
        plan.preflight_remote_configs(config)?;
        plan.preflight_remote_agent_states()?;
        preflight_local_agent_state(local_agent_state, archive_dir)?;
        Ok(plan)
    }

    fn preflight_cleanup_resume(
        config: &ClusterConfig,
        config_path: &Path,
        state_dir: &Path,
        reset_id: &str,
        archive_dir: &Path,
        local_agent_state: &Path,
        discard_terminal_sync: bool,
        abandoned_sync_jobs: &[AbandonedSyncJob],
    ) -> AppResult<Self> {
        Self::preflight(
            config,
            config_path,
            state_dir,
            reset_id,
            archive_dir,
            local_agent_state,
            discard_terminal_sync,
            abandoned_sync_jobs,
        )
    }

    fn preflight_remote_config_resume(
        config: &ClusterConfig,
        config_path: &Path,
        state_dir: &Path,
        reset_id: &str,
        archive_dir: &Path,
        local_agent_state: &Path,
    ) -> AppResult<Self> {
        let known_uuids = known_machine_uuids(state_dir)?;
        let config_bytes = fs::read(config_path).map_err(|error| {
            (
                1,
                format!(
                    "cannot verify active config while recovering remote config cleanup: {error}"
                ),
            )
        })?;
        let config_digest = sha256_hex(&config_bytes).map_err(|error| (1, error.to_string()))?;
        let mut plan = Self {
            nodes: config.nodes.clone(),
            active_nodes: config.nodes.keys().cloned().collect(),
            known_uuids: known_uuids.clone(),
            mounts: Vec::new(),
            exports: BTreeMap::new(),
            markers: BTreeMap::new(),
            aliases: Vec::new(),
            remote_configs: Vec::new(),
            remote_agent_states: Vec::new(),
        };
        let operations = node_admin::reset_admin_operations(config_path, state_dir)?;
        plan.add_pending_admin_resources(config, operations, &known_uuids, &config_digest)?;
        for (node_id, node) in &plan.nodes {
            verify_node_identity(node_id, node, known_uuids.get(node_id))?;
        }
        plan.collect_remote_configs(reset_id, &config.share_uuid)?;
        plan.preflight_remote_configs(config)?;
        plan.preflight_remote_agent_states()?;
        preflight_local_agent_state(local_agent_state, archive_dir)?;
        Ok(plan)
    }

    fn add_pending_admin_resources(
        &mut self,
        config: &ClusterConfig,
        operations: Vec<node_admin::ResetAdminOperation>,
        known_uuids: &BTreeMap<String, String>,
        config_digest: &str,
    ) -> AppResult<()> {
        for operation in operations {
            if matches!(operation.phase.as_str(), "READY" | "REMOVED" | "ABORTED") {
                continue;
            }
            if !admin_operation_matches_digest(&operation, config_digest) {
                return Err((
                    1,
                    format!(
                        "node admin operation {} for {} does not match the active config; resolve it with mnode or retry msub to finish the Agent update before resetting",
                        operation.id, operation.node_id
                    ),
                ));
            }
            macluster_protocol::identifiers::NodeId::new(operation.node_id.clone()).map_err(
                |error| {
                    (
                        1,
                        format!(
                            "node admin operation {} has an invalid node ID: {error}",
                            operation.id
                        ),
                    )
                },
            )?;
            match operation.action.as_str() {
                "update" => continue,
                "add" | "remove" => {
                    if self.nodes.contains_key(&operation.node_id) {
                        if let (Some(recorded), Some(configured)) = (
                            operation.machine_uuid.as_ref(),
                            self.nodes[&operation.node_id].machine_uuid.as_ref(),
                        ) && !recorded.eq_ignore_ascii_case(configured)
                        {
                            return Err((
                                1,
                                format!(
                                    "pending node operation {} for {} has a different machine UUID from the active config",
                                    operation.id, operation.node_id
                                ),
                            ));
                        }
                        if operation.action == "remove" {
                            let connection = node_admin::pending_removal_connection(
                                &operation.node_id,
                                &self.nodes[&operation.node_id],
                                operation.connection_endpoint.as_deref(),
                                known_uuids.get(&operation.node_id).map(String::as_str),
                            )?;
                            self.nodes
                                .insert(operation.node_id.clone(), connection.clone());
                            for mount in &mut self.mounts {
                                if mount.node_id == operation.node_id {
                                    mount.node = connection.clone();
                                }
                            }
                            for alias in &mut self.aliases {
                                if alias.server_id == operation.node_id {
                                    alias.server = connection.clone();
                                }
                            }
                        }
                        continue;
                    }
                    let expected_uuid = operation
                        .machine_uuid
                        .clone()
                        .or_else(|| known_uuids.get(&operation.node_id).cloned())
                        .ok_or_else(|| (1, format!("cannot safely reset pending node operation {} for {}: no machine UUID is recorded", operation.id, operation.node_id)))?;
                    if known_uuids
                        .get(&operation.node_id)
                        .is_some_and(|known| !known.eq_ignore_ascii_case(&expected_uuid))
                    {
                        return Err((
                            1,
                            format!(
                                "pending node operation {} for {} conflicts with its recorded machine UUID",
                                operation.id, operation.node_id
                            ),
                        ));
                    }
                    let export_client = node_admin::reset_node_from_endpoint(
                        &operation.endpoint,
                        Some(expected_uuid),
                    )?;
                    let mut node = if operation.action == "remove" {
                        node_admin::pending_removal_connection(
                            &operation.node_id,
                            &export_client,
                            operation.connection_endpoint.as_deref(),
                            known_uuids.get(&operation.node_id).map(String::as_str),
                        )?
                    } else {
                        export_client.clone()
                    };
                    node.remote_config = operation.remote_config_path.clone();
                    if node.transport == Transport::Local {
                        let actual = node_admin::local_platform_uuid()?;
                        if !node
                            .machine_uuid
                            .as_deref()
                            .is_some_and(|expected| expected.eq_ignore_ascii_case(&actual))
                        {
                            return Err((
                                1,
                                format!(
                                    "pending local node {} no longer matches its recorded machine identity",
                                    operation.node_id
                                ),
                            ));
                        }
                    }
                    self.nodes.insert(operation.node_id.clone(), node.clone());
                    let may_have_client_resources =
                        operation.action == "remove" || operation.client_setup_may_have_run;
                    if may_have_client_resources {
                        self.add_client_mounts(config, &operation.node_id, &node)?;
                        let exports = node_admin::pending_managed_export_cleanup_plan(
                            config,
                            &operation.node_id,
                            &export_client.host,
                        );
                        for (server_id, requests) in exports {
                            let server = config.nodes.get(&server_id).ok_or_else(|| {
                                (
                                    1,
                                    format!(
                                        "NFS server {server_id} for pending node {} is missing",
                                        operation.node_id
                                    ),
                                )
                            })?;
                            for (_, request) in requests {
                                self.add_client_export(
                                    &server_id,
                                    server,
                                    &request.share_uuid,
                                    Path::new(&request.root),
                                    &request.node_id,
                                    &export_client,
                                );
                            }
                        }
                    }
                }
                "share" => {
                    let (share_id, server_id, source_root, mount_root) =
                        parse_pending_share_endpoint(&operation.endpoint, &operation.node_id)?;
                    if server_id != operation.node_id {
                        return Err((
                            1,
                            format!(
                                "pending share operation {} records a different node and NFS server ID",
                                operation.id
                            ),
                        ));
                    }
                    if let Some(active) = config.shares.get(&share_id) {
                        if active.share_uuid != operation.machine_uuid.clone().unwrap_or_default()
                            || active.source_root != source_root
                            || active.mount_root != mount_root
                            || active.server.as_str() != server_id
                        {
                            return Err((
                                1,
                                format!(
                                    "pending share operation {} conflicts with active share {share_id}",
                                    operation.id
                                ),
                            ));
                        }
                        continue;
                    }
                    let share_uuid = operation.machine_uuid.as_deref().ok_or_else(|| {
                        (
                            1,
                            format!(
                                "pending share operation {} has no recorded share UUID",
                                operation.id
                            ),
                        )
                    })?;
                    Id128::parse(share_uuid).map_err(|error| {
                        (
                            1,
                            format!(
                                "pending share operation {} has an invalid UUID: {error}",
                                operation.id
                            ),
                        )
                    })?;
                    let server = config.nodes.get(&server_id).ok_or_else(|| (1, format!("pending share operation {} refers to unregistered NFS server {server_id}; refusing unsafe cleanup", operation.id)))?;
                    self.add_share(
                        &server_id,
                        server,
                        &source_root,
                        &mount_root,
                        share_uuid,
                        &share_id,
                    );
                    if source_root != mount_root {
                        self.aliases.push(AliasSpec {
                            server_id: server_id.clone(),
                            server: server.clone(),
                            source_root: source_root.clone(),
                            mount_root: mount_root.clone(),
                            committed: false,
                        });
                        for (node_id, node) in &config.nodes {
                            if node_id == &server_id {
                                continue;
                            }
                            self.aliases.push(AliasSpec {
                                server_id: node_id.clone(),
                                server: node.clone(),
                                source_root: mount_root.clone(),
                                mount_root: source_root.clone(),
                                committed: false,
                            });
                        }
                    }
                }
                other => {
                    return Err((
                        1,
                        format!(
                            "node admin operation {} has unsupported action '{other}' and is not safe to ignore during reset",
                            operation.id
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn add_share(
        &mut self,
        server_id: &str,
        server: &NodeConfig,
        source_root: &Path,
        mount_root: &Path,
        share_uuid: &str,
        label: &str,
    ) {
        let key = (
            server_id.to_owned(),
            source_root.to_path_buf(),
            share_uuid.to_owned(),
        );
        self.markers.entry(key).or_insert_with(|| MarkerSpec {
            server_id: server_id.to_owned(),
            server: server.clone(),
            source_root: source_root.to_path_buf(),
            share_uuid: share_uuid.to_owned(),
            label: label.to_owned(),
        });
        for (node_id, node) in &self.nodes {
            if node_id == server_id {
                continue;
            }
            self.mounts.push(MountSpec {
                node_id: node_id.clone(),
                node: node.clone(),
                server_host: server.host.clone(),
                source_root: source_root.to_path_buf(),
                mount_root: mount_root.to_path_buf(),
                label: label.to_owned(),
            });
            self.exports
                .entry(server_id.to_owned())
                .or_insert_with(|| ExportGroup {
                    server: server.clone(),
                    specs: Vec::new(),
                })
                .specs
                .push(ManagedExportSpec {
                    share_uuid: share_uuid.to_owned(),
                    node_id: node_id.clone(),
                    source_root: source_root.to_string_lossy().into_owned(),
                    client_ip: node.host.clone(),
                });
        }
    }

    fn add_client_mounts(
        &mut self,
        config: &ClusterConfig,
        node_id: &str,
        node: &NodeConfig,
    ) -> AppResult<()> {
        let primary = config
            .nodes
            .get(config.storage_server.as_str())
            .expect("validated storage server");
        self.mounts.push(MountSpec {
            node_id: node_id.to_owned(),
            node: node.clone(),
            server_host: primary.host.clone(),
            source_root: config.primary_source_root().to_path_buf(),
            mount_root: config.shared_root.clone(),
            label: "primary".into(),
        });
        for (share_id, share) in &config.shares {
            let server = config
                .nodes
                .get(share.server.as_str())
                .expect("validated share server");
            if node_id != share.server.as_str() {
                self.mounts.push(MountSpec {
                    node_id: node_id.to_owned(),
                    node: node.clone(),
                    server_host: server.host.clone(),
                    source_root: share.source_root.clone(),
                    mount_root: share.mount_root.clone(),
                    label: share_id.clone(),
                });
                if share.source_root != share.mount_root {
                    self.aliases.push(AliasSpec {
                        server_id: node_id.to_owned(),
                        server: node.clone(),
                        source_root: share.mount_root.clone(),
                        mount_root: share.source_root.clone(),
                        // The setup may have been interrupted before the node
                        // was committed to the active config. Remove only an
                        // exact source-prefix link if it exists.
                        committed: false,
                    });
                }
            }
        }
        Ok(())
    }

    fn add_client_export(
        &mut self,
        server_id: &str,
        server: &NodeConfig,
        share_uuid: &str,
        source_root: &Path,
        node_id: &str,
        node: &NodeConfig,
    ) {
        self.exports
            .entry(server_id.to_owned())
            .or_insert_with(|| ExportGroup {
                server: server.clone(),
                specs: Vec::new(),
            })
            .specs
            .push(ManagedExportSpec {
                share_uuid: share_uuid.to_owned(),
                node_id: node_id.to_owned(),
                source_root: source_root.to_string_lossy().into_owned(),
                client_ip: node.host.clone(),
            });
    }

    fn collect_remote_configs(&mut self, reset_id: &str, share_uuid: &str) -> AppResult<()> {
        for (node_id, node) in &self.nodes {
            if node.transport != Transport::Ssh {
                continue;
            }
            let facts = node_admin::read_remote_facts(node).map_err(|(_, error)| {
                (
                    1,
                    format!("cannot inspect remote config location on {node_id}: {error}"),
                )
            })?;
            let home = node_admin::checked_remote_path(&facts.home)?;
            let active = self.active_nodes.contains(node_id);
            let path = if active {
                node.remote_config
                    .clone()
                    .unwrap_or_else(|| format!("{home}/.config/macluster/config.toml"))
            } else {
                pending_agent_config_path(&home, share_uuid, node)?
            };
            let path = node_admin::checked_remote_path(&path)?;
            let backup = format!("{path}.macluster-reset-{reset_id}.bak");
            self.remote_configs.push(RemoteConfigSpec {
                node_id: node_id.clone(),
                node: node.clone(),
                path,
                backup,
            });
            if let Some(state) =
                Self::remote_agent_state_spec(active, node_id, node, &home, reset_id)?
            {
                self.remote_agent_states.push(state);
            }
        }
        Ok(())
    }

    fn remote_agent_state_spec(
        active: bool,
        node_id: &str,
        node: &NodeConfig,
        home: &str,
        reset_id: &str,
    ) -> AppResult<Option<RemoteAgentStateSpec>> {
        // Pending enrollments never ran this cluster's jobs. The account-global
        // Agent store may belong to another live cluster and is not our resource.
        if !active {
            return Ok(None);
        }
        let (path, archive) = remote_agent_state_paths(home, reset_id)?;
        Ok(Some(RemoteAgentStateSpec {
            node_id: node_id.to_owned(),
            node: node.clone(),
            path,
            archive,
            stop_publisher: true,
        }))
    }

    fn preflight_remote_agent_states(&self) -> AppResult<()> {
        for state in &self.remote_agent_states {
            let script = remote_agent_state_preflight_script(&state.path, &state.archive);
            let output = node_admin::ssh_output(&state.node, &script, None)?;
            if !output.status.success() {
                return Err((
                    1,
                    format!(
                        "cannot safely archive agent state on {}: {}",
                        state.node_id,
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn preflight_remote_configs(&self, config: &ClusterConfig) -> AppResult<()> {
        for remote in &self.remote_configs {
            let source = read_remote_regular_file(&remote.node, &remote.path)?;
            let backup = read_remote_regular_file(&remote.node, &remote.backup)?;
            if let Some(bytes) = backup {
                let archived = ClusterConfig::parse(&String::from_utf8_lossy(&bytes)).map_err(|error| {
                    (1, format!("reset archive {} on {} is not a recognized cluster config: {error}", remote.backup, remote.node_id))
                })?;
                if !belongs_to_cluster(&archived, config) {
                    return Err((
                        1,
                        format!(
                            "reset archive {} on {} belongs to another cluster; refusing to overwrite it",
                            remote.backup, remote.node_id
                        ),
                    ));
                }
                if let Some(source_bytes) = source.as_deref()
                    && ClusterConfig::parse(&String::from_utf8_lossy(source_bytes))
                        .is_ok_and(|existing| belongs_to_cluster(&existing, config))
                    && bytes.as_slice() != source_bytes
                {
                    return Err((
                        1,
                        format!(
                            "both active and archived cluster configs exist at different versions on {}; refusing to choose one",
                            remote.node_id
                        ),
                    ));
                }
            }
        }
        Ok(())
    }

    fn preflight_mounts(&self) -> AppResult<()> {
        let mut outputs = BTreeMap::<String, String>::new();
        for mount in &self.mounts {
            if !outputs.contains_key(&mount.node_id) {
                let output = node_admin::ssh_output(&mount.node, "/sbin/mount", None)?;
                if !output.status.success() {
                    return Err((
                        1,
                        format!(
                            "cannot inspect mounts on {}: {}",
                            mount.node_id,
                            String::from_utf8_lossy(&output.stderr).trim()
                        ),
                    ));
                }
                outputs.insert(
                    mount.node_id.clone(),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                );
            }
            let output = outputs
                .get(&mount.node_id)
                .expect("mount output was collected");
            if mount_conflict(
                output,
                &mount.server_host,
                &mount.source_root,
                &mount.mount_root,
            ) {
                return Err((
                    1,
                    format!(
                        "cannot reset {} on {}: its expected NFS mount at {} is stacked or ambiguous",
                        mount.label,
                        mount.node_id,
                        mount.mount_root.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    fn verify_node(&self, node_id: &str, node: &NodeConfig) -> AppResult<()> {
        verify_node_identity(node_id, node, self.known_uuids.get(node_id))
    }

    fn preflight_exports(&self) -> AppResult<()> {
        for (server_id, group) in &self.exports {
            let exports = node_admin::read_nfs_exports(&group.server).map_err(|(_, error)| {
                (
                    1,
                    format!("cannot inspect NFS exports on {server_id}: {error}"),
                )
            })?;
            remove_managed_exports(&exports, &group.specs).map_err(|error| {
                (
                    1,
                    format!("cannot safely reset NFS exports on {server_id}: {error}"),
                )
            })?;
        }
        Ok(())
    }

    fn preflight_markers(&self) -> AppResult<()> {
        for marker in self.markers.values() {
            if let Err(error) = inspect_marker(marker) {
                if permission_error(&error) {
                    announce_reset_admin(
                        &marker.server_id,
                        &marker.server,
                        "verify a protected managed NFS marker",
                    );
                    node_admin::run_interactive_admin(
                        &marker.server,
                        &marker_check_script(marker, false),
                    )
                    .map_err(|admin_error| {
                        (
                            1,
                            format!(
                                "cannot verify share marker on {} with administrator access: {admin_error}",
                                marker.server_id
                            ),
                        )
                    })?;
                } else {
                    return Err((1, error));
                }
            }
        }
        Ok(())
    }

    fn preflight_aliases(&self) -> AppResult<()> {
        for alias in &self.aliases {
            match alias_is_exact(alias) {
                Ok(true) => {}
                Ok(false) if alias.committed => {}
                Ok(false) => eprintln!(
                    "Preserving existing path {} on {}: the pending share did not create its expected alias. Its managed NFS rules and markers will still be cleared.",
                    alias.mount_root.display(),
                    alias.server_id
                ),
                Err((_, error)) if permission_error(&error) => {
                    announce_reset_admin(
                        &alias.server_id,
                        &alias.server,
                        "verify a protected NFS path alias",
                    );
                    node_admin::run_interactive_admin(
                        &alias.server,
                        &alias_preflight_script(alias),
                    )
                    .map_err(|admin_error| {
                        (
                            1,
                            format!(
                                "cannot verify NFS alias {} on {} with administrator access: {admin_error}",
                                alias.mount_root.display(),
                                alias.server_id
                            ),
                        )
                    })?;
                }
                Err((_, error)) => return Err((1, error)),
            }
        }
        Ok(())
    }
}

fn parse_pending_share_endpoint(
    endpoint: &str,
    operation_node_id: &str,
) -> AppResult<(String, String, PathBuf, PathBuf)> {
    let mut fields = endpoint.splitn(5, ':');
    if fields.next() != Some("share") {
        return Err((
            1,
            format!("pending share endpoint '{endpoint}' has an unknown format"),
        ));
    }
    let share_id = fields.next().unwrap_or_default();
    macluster_protocol::identifiers::NodeId::new(share_id.to_owned()).map_err(|error| {
        (
            1,
            format!("pending share endpoint '{endpoint}' has an invalid share ID: {error}"),
        )
    })?;
    let remaining: Vec<_> = fields.collect();
    let (server_id, source, mount) = match remaining.as_slice() {
        [source] => (
            operation_node_id.to_owned(),
            *source,
            format!("/Users/Shared/macluster-shares/{share_id}"),
        ),
        [server, source, mount] => ((*server).to_owned(), *source, (*mount).to_owned()),
        _ => {
            return Err((
                1,
                format!(
                    "pending share endpoint '{endpoint}' does not record its source and mount paths"
                ),
            ));
        }
    };
    if share_id.is_empty() || server_id.is_empty() {
        return Err((
            1,
            format!("pending share endpoint '{endpoint}' is missing its share or server ID"),
        ));
    }
    macluster_protocol::identifiers::NodeId::new(server_id.clone()).map_err(|error| {
        (
            1,
            format!("pending share endpoint '{endpoint}' has an invalid server ID: {error}"),
        )
    })?;
    let source_root = PathBuf::from(source);
    let mount_root = PathBuf::from(mount);
    super::validate_absolute_path(&source_root, "pending share source")?;
    super::validate_absolute_path(&mount_root, "pending share mount")?;
    Ok((share_id.to_owned(), server_id, source_root, mount_root))
}

fn admin_operation_matches_digest(
    operation: &node_admin::ResetAdminOperation,
    config_digest: &str,
) -> bool {
    operation.old_config_sha256.as_deref() == Some(config_digest)
        || operation.candidate_config_sha256.as_deref() == Some(config_digest)
}

fn mount_conflict(output: &str, host: &str, source_root: &Path, mount_root: &Path) -> bool {
    let expected_source = format!("{host}:{}", source_root.display());
    let root = mount_root.to_string_lossy();
    let mut mounts_at_path = 0;
    let mut expected_mounts = 0;
    for line in output.lines() {
        let Some((source, destination)) = line.split_once(" on ") else {
            continue;
        };
        let Some((target, filesystem)) = destination.split_once(" (") else {
            continue;
        };
        if target != root {
            continue;
        }
        mounts_at_path += 1;
        if source == expected_source && filesystem.split(',').next() == Some("nfs") {
            expected_mounts += 1;
        }
    }
    expected_mounts > 0 && (expected_mounts != 1 || mounts_at_path != 1)
}

fn reset_mount_unmount_step(source: &str, mount_root: &Path) -> String {
    let awk = node_admin::shell_quote(node_admin::client_mount_status_awk_script());
    let source = node_admin::shell_quote(source);
    let mount = node_admin::shell_quote(&mount_root.to_string_lossy());
    let target = node_admin::shell_quote(&mount_root.to_string_lossy());
    format!(
        "mounts=$(/sbin/mount)\nmount_status=$(printf '%s\\n' \"$mounts\" | /usr/bin/awk -v source={source} -v mount={mount} {awk})\ncase \"$mount_status\" in expected) /sbin/umount {target} ;; none) : ;; *) echo 'mount changed or is stacked after reset preflight; refusing to unmount it' >&2; exit 1 ;; esac\n"
    )
}

fn verify_node_identity(node_id: &str, node: &NodeConfig, known: Option<&String>) -> AppResult<()> {
    if let (Some(configured), Some(recorded)) = (node.machine_uuid.as_ref(), known)
        && !configured.eq_ignore_ascii_case(recorded)
    {
        return Err((
            1,
            format!(
                "node {node_id} machine UUID in the config conflicts with its admin journal record"
            ),
        ));
    }
    if node.transport == Transport::Local {
        let actual = node_admin::local_platform_uuid()?;
        let expected = node.machine_uuid.as_ref().or(known);
        if expected.is_some_and(|expected| !expected.eq_ignore_ascii_case(&actual)) {
            return Err((1, format!("local node {node_id} machine identity changed")));
        }
        if node
            .execution_uid
            .is_some_and(|uid| uid != unsafe { libc::geteuid() })
        {
            return Err((1, format!("local node {node_id} execution UID changed")));
        }
        return Ok(());
    }
    let expected = node.machine_uuid.as_ref().or(known).ok_or_else(|| {
        (
            1,
            format!(
                "cannot reset remote node {node_id}: its machine UUID is not recorded; enroll/update it first so reset can verify identity"
            ),
        )
    })?;
    let actual = node_admin::remote_machine_uuid(node)
        .map_err(|(_, error)| (1, format!("cannot verify node {node_id} identity: {error}")))?;
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err((1, format!("node {node_id} machine identity changed")));
    }
    let facts = node_admin::read_remote_facts(node)
        .map_err(|(_, error)| (1, format!("cannot inspect node {node_id}: {error}")))?;
    if node.execution_uid.is_some_and(|uid| uid != facts.uid) {
        return Err((1, format!("node {node_id} execution UID changed")));
    }
    Ok(())
}

fn known_machine_uuids(state_dir: &Path) -> AppResult<BTreeMap<String, String>> {
    let path = state_dir.join("node-admin.json");
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err((1, error.to_string())),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| (1, format!("node admin journal is invalid: {error}")))?;
    let Some(map) = value
        .get("machine_uuids")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(BTreeMap::new());
    };
    Ok(map
        .iter()
        .filter_map(|(node, uuid)| Some((node.clone(), uuid.as_str()?.to_owned())))
        .collect())
}

fn save_journal(path: &Path, journal: &ResetJournal, create_only: bool) -> AppResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| (1, "reset journal has no parent directory".into()))?;
    fs::create_dir_all(parent).map_err(|error| (1, error.to_string()))?;
    let temporary = parent.join(format!(".reset-{}.tmp", Id128::random()));
    let bytes = serde_json::to_vec_pretty(journal).map_err(|error| (1, error.to_string()))?;
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if create_only {
            fs::hard_link(&temporary, path)?;
            fs::remove_file(&temporary)?;
        } else {
            fs::rename(&temporary, path)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists && create_only {
            (1, "another reset journal was created concurrently".into())
        } else {
            (
                1,
                format!("cannot write reset journal {}: {error}", path.display()),
            )
        }
    })
}

fn wait_for_exclusive_lock(config_path: &Path, state_dir: &Path) -> AppResult<MaintenanceLock> {
    let _ = macluster_controller::wake::notify_controller(state_dir);
    let started = Instant::now();
    let mut last_message = Instant::now();
    let mut checked_controller_owner = false;
    loop {
        let result = if config_path.exists() {
            MaintenanceLock::exclusive(config_path)
        } else {
            MaintenanceLock::exclusive_for_creation(config_path)
        };
        match result {
            Ok(lock) => return Ok(lock),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if !checked_controller_owner {
                    checked_controller_owner = true;
                    if let Some(pid) = node_admin::find_controller_process(config_path, state_dir)?
                    {
                        return node_admin::stop_controller_process(
                            config_path,
                            state_dir,
                            pid,
                            "init reset",
                        );
                    }
                }
                if last_message.elapsed() >= Duration::from_secs(5) {
                    eprintln!(
                        "Waiting for the controller to drain active jobs and release its config lock…"
                    );
                    last_message = Instant::now();
                }
                if started.elapsed() >= Duration::from_secs(300) {
                    return Err((
                        1,
                        "the config lock stayed busy for five minutes and no verified controller process was found to stop. The reset barrier remains active; finish the other cluster command, then rerun `macluster init`.".into(),
                    ));
                }
                thread::sleep(Duration::from_millis(250));
            }
            Err(error) => {
                return Err((1, format!("cannot acquire reset maintenance lock: {error}")));
            }
        }
    }
}

fn job_blockers(state_dir: &Path, discard_terminal_sync: bool) -> AppResult<Vec<String>> {
    if !state_dir.join("controller.sqlite3").exists() {
        return Ok(Vec::new());
    }
    let storage = Storage::open(state_dir).map_err(|error| (1, error.to_string()))?;
    let jobs = storage
        .list_jobs(None)
        .map_err(|error| (1, error.to_string()))?;
    let mut blockers = Vec::new();
    for job in jobs {
        let abandon_sync = discard_terminal_sync && job.state.is_terminal();
        if matches!(
            job.state,
            JobState::Pending | JobState::Starting | JobState::Running | JobState::Cancelling
        ) {
            blockers.push(format!("job {} is {:?}", job.id, job.state));
        }
        if job.snapshot_sync_pending && !abandon_sync {
            blockers.push(format!("job {} snapshot sync is pending", job.id));
        }
        if job.log_sync_pending && !abandon_sync {
            blockers.push(format!("job {} output log sync is pending", job.id));
        }
    }
    Ok(blockers)
}

fn terminal_sync_abandonments(state_dir: &Path) -> AppResult<Vec<AbandonedSyncJob>> {
    if !state_dir.join("controller.sqlite3").exists() {
        return Ok(Vec::new());
    }
    let storage = Storage::open(state_dir).map_err(|error| (1, error.to_string()))?;
    let jobs = storage
        .list_jobs(None)
        .map_err(|error| (1, error.to_string()))?;
    Ok(jobs
        .into_iter()
        .filter(|job| {
            job.state.is_terminal() && (job.snapshot_sync_pending || job.log_sync_pending)
        })
        .map(|job| AbandonedSyncJob {
            job_id: job.id,
            state: job.state,
            node: job.node,
            start_token: job.start_token,
            snapshot_sync_pending: job.snapshot_sync_pending,
            log_sync_pending: job.log_sync_pending,
        })
        .collect())
}

struct CleanupBatch<'a> {
    node: &'a NodeConfig,
    nodes: Vec<(String, &'a NodeConfig)>,
    mounts: Vec<&'a MountSpec>,
    exports: Vec<(&'a str, &'a ExportGroup)>,
    aliases: Vec<(usize, &'a AliasSpec)>,
}

impl<'a> CleanupBatch<'a> {
    fn add_node(&mut self, node_id: &str, node: &'a NodeConfig) {
        if !self.nodes.iter().any(|(id, _)| id == node_id) {
            self.nodes.push((node_id.to_owned(), node));
        }
        // If this physical Mac is also the local login host, use the local
        // transport for this cleanup phase's privileged session.
        if node.transport == Transport::Local {
            self.node = node;
        }
    }
}

fn cleanup_batch_key(node: &NodeConfig) -> String {
    if let Some(machine_uuid) = node.machine_uuid.as_deref() {
        return format!("machine:{machine_uuid}");
    }
    match node.transport {
        Transport::Local => format!("local:{}", node.host),
        Transport::Ssh => format!(
            "ssh:{}@{}:{}",
            node.ssh_user.as_deref().unwrap_or_default(),
            node.host,
            node.ssh_port.unwrap_or(22)
        ),
    }
}

fn cleanup_batches<'a>(
    journal: &ResetJournal,
    plan: &'a ResetPlan,
) -> BTreeMap<String, CleanupBatch<'a>> {
    let mut batches = BTreeMap::<String, CleanupBatch<'a>>::new();
    for mount in &plan.mounts {
        let step = format!("mounts:{}", mount.node_id);
        if journal.is_completed(&step) {
            continue;
        }
        let batch = batches
            .entry(cleanup_batch_key(&mount.node))
            .or_insert_with(|| CleanupBatch {
                node: &mount.node,
                nodes: Vec::new(),
                mounts: Vec::new(),
                exports: Vec::new(),
                aliases: Vec::new(),
            });
        batch.add_node(&mount.node_id, &mount.node);
        batch.mounts.push(mount);
    }
    for (server_id, group) in &plan.exports {
        let step = format!("exports:{server_id}");
        if journal.is_completed(&step) {
            continue;
        }
        let batch = batches
            .entry(cleanup_batch_key(&group.server))
            .or_insert_with(|| CleanupBatch {
                node: &group.server,
                nodes: Vec::new(),
                mounts: Vec::new(),
                exports: Vec::new(),
                aliases: Vec::new(),
            });
        batch.add_node(server_id, &group.server);
        batch.exports.push((server_id.as_str(), group));
    }
    for (index, alias) in plan.aliases.iter().enumerate() {
        let step = format!("alias:{}:{index}", alias.server_id);
        if journal.is_completed(&step) {
            continue;
        }
        let batch = batches
            .entry(cleanup_batch_key(&alias.server))
            .or_insert_with(|| CleanupBatch {
                node: &alias.server,
                nodes: Vec::new(),
                mounts: Vec::new(),
                exports: Vec::new(),
                aliases: Vec::new(),
            });
        batch.add_node(&alias.server_id, &alias.server);
        batch.aliases.push((index, alias));
    }
    batches
}

fn cleanup_resources(journal: &mut ResetJournal, plan: &ResetPlan, path: &Path) -> AppResult<()> {
    quiesce_publishers(journal, plan, path)?;
    let original_config = ClusterConfig::parse(&journal.old_config)
        .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
    for (_, batch) in cleanup_batches(journal, plan) {
        let node = batch.node;
        let node_id = batch
            .nodes
            .first()
            .map(|(id, _)| id.as_str())
            .unwrap_or("unknown node");
        for (id, identity) in &batch.nodes {
            plan.verify_node(id, identity)?;
        }
        let mut privileged_script = String::from("set -e\n");
        let mut has_privileged_changes = false;
        let mut admin_actions = Vec::new();
        if !batch.mounts.is_empty() {
            let output = node_admin::ssh_output(node, "/sbin/mount", None)?;
            if !output.status.success() {
                return Err((
                    1,
                    format!("cannot recheck mounts on {node_id} before unmount"),
                ));
            }
            let mount_table = String::from_utf8_lossy(&output.stdout);
            let mut targets = Vec::new();
            for mount in &batch.mounts {
                let expected = mount_matches(
                    &mount_table,
                    &mount.server_host,
                    &mount.source_root,
                    &mount.mount_root,
                );
                if mount_conflict(
                    &mount_table,
                    &mount.server_host,
                    &mount.source_root,
                    &mount.mount_root,
                ) {
                    return Err((
                        1,
                        format!(
                            "managed mount {} on {node_id} became stacked or ambiguous after reset preflight; refusing to unmount it",
                            mount.mount_root.display()
                        ),
                    ));
                }
                if expected && !targets.contains(&mount.mount_root) {
                    targets.push(mount.mount_root.clone());
                }
            }
            if !targets.is_empty() {
                has_privileged_changes = true;
                admin_actions.push("unmount managed NFS shares");
                for mount in batch
                    .mounts
                    .iter()
                    .filter(|mount| targets.contains(&mount.mount_root))
                {
                    privileged_script.push_str(&reset_mount_unmount_step(
                        &format!("{}:{}", mount.server_host, mount.source_root.display()),
                        &mount.mount_root,
                    ));
                }
            }
            for mount in &batch.mounts {
                if mount.mount_root != original_config.shared_root {
                    continue;
                }
                let probe = node_admin::primary_restore_probe(
                    &mount.mount_root,
                    &original_config.share_uuid,
                );
                let present = node_admin::ssh_output(node, &probe, None)?;
                if present.status.success() {
                    has_privileged_changes = true;
                    admin_actions.push("restore preserved local primary data");
                    privileged_script.push_str(&node_admin::primary_restore_script(
                        &mount.mount_root,
                        &original_config.share_uuid,
                    ));
                } else if present.status.code() != Some(1) {
                    return Err((
                        1,
                        format!("cannot inspect preserved primary directory on {node_id}"),
                    ));
                }
            }
        }

        let mut removed_any_export = false;
        if !batch.exports.is_empty() {
            let (original, transaction_pending) =
                node_admin::read_nfs_exports_update_baseline(node).map_err(|(_, error)| {
                    (1, format!("cannot inspect exports on {node_id}: {error}"))
                })?;
            let mut candidate = original.clone();
            removed_any_export |= transaction_pending;
            for (server_id, group) in &batch.exports {
                let (updated, removed) =
                    remove_managed_exports(&candidate, &group.specs).map_err(|error| {
                        (
                            1,
                            format!("cannot safely edit exports on {server_id}: {error}"),
                        )
                    })?;
                candidate = updated;
                removed_any_export |= removed;
                if !removed {
                    eprintln!(
                        "No exact managed NFS export markers were present on {server_id}; operator-managed exports were left untouched."
                    );
                }
            }
            if removed_any_export {
                admin_actions.push("remove managed NFS exports and reload NFS");
                let update_commands =
                    node_admin::nfs_exports_update_commands(&candidate, &original, &journal.id)
                        .map_err(|error| {
                            (
                                1,
                                format!("cannot prepare NFS export update on {node_id}: {error}"),
                            )
                        })?;
                privileged_script.push_str(&update_commands);
                has_privileged_changes = true;
            }
        }

        let mut completed_aliases = Vec::new();
        for (index, alias) in &batch.aliases {
            plan.verify_node(&alias.server_id, &alias.server)?;
            let cleanup_alias = match alias_is_exact(alias) {
                Ok(exact) => exact,
                Err((_, error)) if permission_error(&error) => true,
                Err((_, error)) => return Err((1, error)),
            };
            if cleanup_alias {
                admin_actions.push("remove managed NFS aliases");
                privileged_script.push_str(&alias_cleanup_script(alias));
                has_privileged_changes = true;
            }
            completed_aliases.push((*index, alias.server_id.clone()));
        }

        if has_privileged_changes {
            for (id, identity) in &batch.nodes {
                plan.verify_node(id, identity)?;
            }
            let account = if node.transport == Transport::Local {
                std::env::var("USER").unwrap_or_else(|_| "current local user".into())
            } else {
                node.ssh_user
                    .clone()
                    .unwrap_or_else(|| "default SSH user".into())
            };
            let connection = if node.transport == Transport::Local {
                "local"
            } else {
                "SSH"
            };
            eprintln!(
                "Reset administrator access: node {node_id}, {account}@{} ({connection}).\n  Operation: {}.\n  If prompted, enter this Mac's administrator password. Authorization is separate for each Mac; valid sudo credentials may skip the prompt.",
                node.host,
                admin_actions.join("; ")
            );
            node_admin::run_interactive_admin(node, &privileged_script).map_err(|error| {
                (
                    1,
                    format!("cannot clean managed NFS resources on {node_id}: {error}"),
                )
            })?;
        }
        let mut completed_mounts = BTreeSet::new();
        for mount in &batch.mounts {
            if completed_mounts.insert(mount.node_id.as_str()) {
                journal.mark_completed(format!("mounts:{}", mount.node_id));
            }
        }
        for (server_id, _) in &batch.exports {
            journal.mark_completed(format!("exports:{server_id}"));
        }
        for (index, server_id) in completed_aliases {
            journal.mark_completed(format!("alias:{server_id}:{index}"));
        }
        if !batch.mounts.is_empty() || !batch.exports.is_empty() || !batch.aliases.is_empty() {
            save_journal(path, journal, false)?;
        }
    }

    for (index, marker) in plan.markers.values().enumerate() {
        let step = format!("marker:{}:{}:{index}", marker.server_id, marker.label);
        if journal.is_completed(&step) {
            continue;
        }
        plan.verify_node(&marker.server_id, &marker.server)?;
        remove_marker(marker)?;
        journal.mark_completed(step);
        save_journal(path, journal, false)?;
    }
    Ok(())
}

fn quiesce_publishers(
    journal: &mut ResetJournal,
    plan: &ResetPlan,
    journal_path: &Path,
) -> AppResult<()> {
    let old = ClusterConfig::parse(&journal.old_config).map_err(|error| (1, error.to_string()))?;
    // Ask the namespace-aware Agent to archive before issuing any shutdown
    // command. Unsupported old binaries must preserve their state untouched.
    archive_remote_agent_states(journal, plan, journal_path)?;
    for state in &plan.remote_agent_states {
        journal.mark_completed(format!("log-sync-stopped:{}", state.node_id));
    }
    quiesce_local_publisher(journal, &old.share_uuid)?;
    journal.mark_completed("log-sync-stopped:local");
    save_journal(journal_path, journal, false)
}

fn remote_publisher_stop_command(
    state: &RemoteAgentStateSpec,
    share_uuid: &str,
    reset_id: &str,
) -> Option<String> {
    state.stop_publisher.then(|| {
        format!(
            "{} --state-dir {} internal stop-log-sync --share-id {} --reset-id {}",
            node_admin::shell_quote(&state.node.remote_binary),
            node_admin::shell_quote(&state.path),
            node_admin::shell_quote(share_uuid),
            node_admin::shell_quote(reset_id)
        )
    })
}

fn pending_remote_config_path(home: &str, share_uuid: &str) -> AppResult<String> {
    let home = node_admin::checked_remote_path(home)?;
    let share_uuid = Id128::parse(share_uuid)
        .map_err(|error| (1, format!("invalid cluster share UUID: {error}")))?;
    let path = PathBuf::from(home)
        .join(".config/macluster/clusters")
        .join(share_uuid.to_string())
        .join("config.toml")
        .to_string_lossy()
        .into_owned();
    node_admin::checked_remote_path(&path)
}

fn pending_agent_config_path(home: &str, share_uuid: &str, node: &NodeConfig) -> AppResult<String> {
    let Some(recorded) = node.remote_config.as_deref() else {
        return pending_remote_config_path(home, share_uuid);
    };
    let uuid = node
        .machine_uuid
        .as_deref()
        .ok_or_else(|| (1, "pending Agent config has no machine UUID".into()))?;
    Id128::parse(uuid).map_err(|error| {
        (
            1,
            format!("pending Agent has an invalid machine UUID: {error}"),
        )
    })?;
    let expected = node_admin::remote_agent_config_path(home, share_uuid, uuid);
    let legacy = pending_remote_config_path(home, share_uuid)?;
    let legacy_default = format!("{home}/.config/macluster/config.toml");
    if recorded != expected && recorded != legacy && recorded != legacy_default {
        return Err((1, "pending Agent config path does not match its cluster and machine identity; preserving it".into()));
    }
    node_admin::checked_remote_path(recorded)
}

fn quiesce_local_publisher(journal: &ResetJournal, share_uuid: &str) -> AppResult<()> {
    let share = Id128::parse(share_uuid).map_err(|error| (1, error.to_string()))?;
    let reset = Id128::parse(&journal.id).map_err(|error| (1, error.to_string()))?;
    macluster_agent::log_sync::quiesce(
        &local_agent_state_path(journal),
        share,
        reset,
        Duration::from_secs(5),
    )
    .map_err(|error| {
        (
            1,
            format!("cannot stop local log publication before reset: {error}"),
        )
    })
}

fn archive_remote_configs(
    journal: &mut ResetJournal,
    plan: &ResetPlan,
    journal_path: &Path,
) -> AppResult<()> {
    let old = ClusterConfig::parse(&journal.old_config)
        .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
    for remote in &plan.remote_configs {
        let step = format!("remote-config:{}", remote.node_id);
        if journal.is_completed(&step) {
            continue;
        }
        plan.verify_node(&remote.node_id, &remote.node)?;
        let source = read_remote_regular_file(&remote.node, &remote.path)?;
        let backup = read_remote_regular_file(&remote.node, &remote.backup)?;
        if let Some(backup_bytes) = backup.as_deref() {
            let archived =
                ClusterConfig::parse(&String::from_utf8_lossy(backup_bytes)).map_err(|error| {
                    (
                        1,
                        format!(
                            "reset archive {} on {} is invalid: {error}",
                            remote.backup, remote.node_id
                        ),
                    )
                })?;
            if !belongs_to_cluster(&archived, &old) {
                return Err((
                    1,
                    format!(
                        "reset archive {} on {} belongs to another cluster; refusing to overwrite it",
                        remote.backup, remote.node_id
                    ),
                ));
            }
        }
        match source {
            Some(bytes) => {
                let belongs = ClusterConfig::parse(&String::from_utf8_lossy(&bytes))
                    .is_ok_and(|existing| belongs_to_cluster(&existing, &old));
                if !belongs {
                    eprintln!(
                        "Preserving remote config {} on {} because it no longer matches the old cluster identity.",
                        remote.path, remote.node_id
                    );
                } else {
                    match backup.as_deref() {
                        Some(backup_bytes) if backup_bytes == bytes.as_slice() => {
                            plan.verify_node(&remote.node_id, &remote.node)?;
                            remote_remove_exact_config_copy(remote, &bytes)?;
                        }
                        Some(_) => {
                            return Err((
                                1,
                                format!(
                                    "remote config {} and its reset archive differ on {}; refusing to discard either copy",
                                    remote.path, remote.node_id
                                ),
                            ));
                        }
                        None => {
                            plan.verify_node(&remote.node_id, &remote.node)?;
                            remote_move_exact_config(remote, &bytes)?;
                        }
                    }
                }
            }
            None => {}
        }
        journal.mark_completed(step);
        save_journal(journal_path, journal, false)?;
    }
    Ok(())
}

fn archive_remote_agent_states(
    journal: &mut ResetJournal,
    plan: &ResetPlan,
    journal_path: &Path,
) -> AppResult<()> {
    for state in &plan.remote_agent_states {
        let step = format!("remote-agent-state:{}", state.node_id);
        if journal.is_completed(&step) {
            continue;
        }
        plan.verify_node(&state.node_id, &state.node)?;
        let old = ClusterConfig::parse(&journal.old_config)
            .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
        let command = remote_agent_state_archive_command(
            state,
            &old.share_uuid,
            journal.discard_terminal_sync,
        );
        let mut output = node_admin::ssh_output(&state.node, &command, None)?;
        if archive_command_is_owned_busy(&output) {
            // Busy is returned only after complete namespace provenance was
            // established. The current Agent rechecks that proof under its
            // state lock before it writes a publisher shutdown barrier.
            if let Some(stop) = remote_publisher_stop_command(state, &old.share_uuid, &journal.id) {
                let stopped = node_admin::ssh_output(&state.node, &stop, None)?;
                if !stopped.status.success() {
                    return Err((
                        1,
                        format!(
                            "cannot stop log publication on {} before reset: {}",
                            state.node_id,
                            String::from_utf8_lossy(&stopped.stderr).trim()
                        ),
                    ));
                }
                output = node_admin::ssh_output(&state.node, &command, None)?;
            }
        }
        if archive_command_is_unsupported(&output) {
            eprintln!(
                "Preserving Agent state on {}: its installed binary does not support namespace-aware archival; update it before archiving this state.",
                state.node_id
            );
        } else if !output.status.success() {
            return Err((
                1,
                format!(
                    "could not archive the prior macluster agent state on {}: {}",
                    state.node_id,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        } else {
            let outcome = serde_json::from_slice(&output.stdout).map_err(|error| {
                (
                    1,
                    format!(
                        "invalid Agent archive response from {}: {error}",
                        state.node_id
                    ),
                )
            })?;
            report_agent_archive_outcome(outcome, &state.node_id);
        }
        journal.mark_completed(step);
        save_journal(journal_path, journal, false)?;
    }
    Ok(())
}

fn remote_agent_state_paths(home: &str, reset_id: &str) -> AppResult<(String, String)> {
    let home = node_admin::checked_remote_path(home)?;
    let reset_id =
        Id128::parse(reset_id).map_err(|error| (2, format!("invalid reset ID: {error}")))?;
    let state = PathBuf::from(&home)
        .join("Library/Application Support/macluster/agent")
        .to_string_lossy()
        .into_owned();
    let archive = PathBuf::from(&home)
        .join("Library/Application Support/macluster/macluster-archive")
        .join(format!("agent-state-{reset_id}"))
        .to_string_lossy()
        .into_owned();
    // HOME and reset ID are validated above. The remaining components are
    // fixed macOS paths; Application Support intentionally contains a space.
    // Every remote command quotes the complete resulting path.
    Ok((state, archive))
}

fn remote_agent_state_preflight_script(source: &str, archive: &str) -> String {
    let source = node_admin::shell_quote(source);
    let archive = node_admin::shell_quote(archive);
    format!(
        "set -eu\nsource={source}\narchive={archive}\n\
         if [ -L \"$source\" ] || [ -L \"$archive\" ]; then echo 'agent state or archive path is a symlink' >&2; exit 1; fi\n\
         if [ -e \"$source\" ] && [ ! -d \"$source\" ]; then echo 'agent state path is not a directory' >&2; exit 1; fi\n\
         if [ -e \"$archive\" ] && [ ! -d \"$archive\" ]; then echo 'agent state archive path is not a directory' >&2; exit 1; fi\n\
"
    )
}

fn preflight_local_agent_state(source: &Path, archive_dir: &Path) -> AppResult<()> {
    let archive = archive_dir.join("agent-local-state");
    let script =
        remote_agent_state_preflight_script(&source.to_string_lossy(), &archive.to_string_lossy());
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .map_err(|error| (1, format!("cannot inspect local agent state: {error}")))?;
    if !output.status.success() {
        return Err((
            1,
            format!(
                "cannot safely archive local agent state: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(())
}

fn remote_agent_state_archive_command(
    state: &RemoteAgentStateSpec,
    share_uuid: &str,
    discard_terminal_sync: bool,
) -> String {
    format!(
        "{} --state-dir {} internal archive-agent-state --share-id {} --archive {}{}",
        node_admin::shell_quote(&state.node.remote_binary),
        node_admin::shell_quote(&state.path),
        node_admin::shell_quote(share_uuid),
        node_admin::shell_quote(&state.archive),
        if discard_terminal_sync {
            " --discard-terminal-sync"
        } else {
            ""
        },
    )
}

fn archive_command_is_owned_busy(output: &std::process::Output) -> bool {
    output.status.code() == Some(1)
        && output.stdout.is_empty()
        && String::from_utf8_lossy(&output.stderr).trim()
            == format!("macluster: {}", macluster_agent::AgentError::Busy)
}

fn archive_command_is_unsupported(output: &std::process::Output) -> bool {
    output.status.code() == Some(2)
        && output.stdout.is_empty()
        && String::from_utf8_lossy(&output.stderr).trim() == "macluster: unknown internal command"
}

fn report_agent_archive_outcome(outcome: macluster_agent::admin::ArchiveOutcome, location: &str) {
    if outcome == macluster_agent::admin::ArchiveOutcome::PreservedForeign {
        eprintln!(
            "Preserving Agent state on {location}: its namespace is foreign, mixed, or unproven."
        );
    }
}

fn remote_move_exact_config(remote: &RemoteConfigSpec, bytes: &[u8]) -> AppResult<()> {
    remote_change_exact_config(remote, bytes, "/bin/mv")
}

fn remote_remove_exact_config_copy(remote: &RemoteConfigSpec, bytes: &[u8]) -> AppResult<()> {
    remote_change_exact_config(remote, bytes, "/bin/rm")
}

fn remote_change_exact_config(
    remote: &RemoteConfigSpec,
    bytes: &[u8],
    command: &str,
) -> AppResult<()> {
    let digest = sha256_hex(bytes).map_err(|error| (1, error.to_string()))?;
    let source = node_admin::shell_quote(&remote.path);
    let backup = node_admin::shell_quote(&remote.backup);
    let mut script = format!(
        "set -e; test -f {source}; test ! -L {source}; actual=$(/usr/bin/shasum -a 256 {source}); actual=${{actual%% *}}; test \"$actual\" = {}; ",
        node_admin::shell_quote(&digest)
    );
    match command {
        "/bin/mv" => {
            script.push_str(&format!(
                "test ! -e {backup}; test ! -L {backup}; /bin/mv {source} {backup}"
            ));
        }
        "/bin/rm" => script.push_str(&format!("/bin/rm {source}")),
        _ => return Err((1, "unsupported remote config cleanup operation".into())),
    }
    let output = node_admin::ssh_output(&remote.node, &script, None)?;
    if !output.status.success() {
        return Err((
            1,
            format!(
                "could not archive verified remote cluster config on {}: {}",
                remote.node_id,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        ));
    }
    Ok(())
}

fn read_remote_regular_file(node: &NodeConfig, path: &str) -> AppResult<Option<Vec<u8>>> {
    let quoted = node_admin::shell_quote(path);
    let present =
        node_admin::ssh_output(node, &format!("test -e {quoted} || test -L {quoted}"), None)?;
    if !present.status.success() {
        if present.status.code() == Some(1) {
            return Ok(None);
        }
        return Err((
            1,
            format!(
                "cannot inspect remote path {path}: {}",
                String::from_utf8_lossy(&present.stderr).trim()
            ),
        ));
    }
    let symlink = node_admin::ssh_output(node, &format!("test -L {quoted}"), None)?;
    if symlink.status.success() {
        return Err((
            1,
            format!("remote config path {path} is a symlink; refusing reset cleanup"),
        ));
    }
    if symlink.status.code() != Some(1) {
        return Err((
            1,
            format!("cannot verify remote config path {path} is not a symlink"),
        ));
    }
    let regular = node_admin::ssh_output(node, &format!("test -f {quoted}"), None)?;
    if !regular.status.success() {
        return Err((
            1,
            format!("remote config path {path} exists but is not a regular file"),
        ));
    }
    let contents = node_admin::ssh_output(node, &format!("/bin/cat {quoted}"), None)?;
    if !contents.status.success() {
        return Err((
            1,
            format!(
                "cannot read remote config {path}: {}",
                String::from_utf8_lossy(&contents.stderr).trim()
            ),
        ));
    }
    Ok(Some(contents.stdout))
}

fn belongs_to_cluster(existing: &ClusterConfig, expected: &ClusterConfig) -> bool {
    let existing_storage_host = existing
        .nodes
        .get(existing.storage_server.as_str())
        .map(|node| &node.host);
    let expected_storage_host = expected
        .nodes
        .get(expected.storage_server.as_str())
        .map(|node| &node.host);
    existing.share_uuid == expected.share_uuid
        && existing.shared_root == expected.shared_root
        && existing.primary_source_root() == expected.primary_source_root()
        && existing_storage_host == expected_storage_host
}

fn permission_error(error: &str) -> bool {
    error.contains("Permission denied") || error.contains("Operation not permitted")
}

fn announce_reset_admin(node_id: &str, node: &NodeConfig, purpose: &str) {
    let account = if node.transport == Transport::Local {
        std::env::var("USER").unwrap_or_else(|_| "current account".into())
    } else {
        node.ssh_user
            .clone()
            .unwrap_or_else(|| "default SSH account".into())
    };
    eprintln!(
        "Reset administrator authorization may be requested on node {node_id}, {account}@{} to {purpose}. If prompted, enter this Mac's administrator password.",
        node.host
    );
}

fn remote_path_type(node: &NodeConfig, path: &Path) -> Result<Option<String>, String> {
    let quoted = node_admin::shell_quote(&path.to_string_lossy());
    let output =
        node_admin::ssh_output(node, &format!("/usr/bin/stat -f '%HT' {quoted} 2>&1"), None)
            .map_err(|(_, error)| error)?;
    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ));
    }
    let detail = format!("{}", String::from_utf8_lossy(&output.stdout).trim());
    if detail.contains("No such file or directory") {
        Ok(None)
    } else {
        Err(format!("cannot inspect {}: {detail}", path.display()))
    }
}

fn inspect_marker(marker: &MarkerSpec) -> Result<(), String> {
    let path = marker.source_root.join(".macluster-share-id");
    match remote_path_type(&marker.server, &path)? {
        None => Ok(()),
        Some(kind) if kind == "Regular File" => {
            let quoted = node_admin::shell_quote(&path.to_string_lossy());
            let contents =
                node_admin::ssh_output(&marker.server, &format!("/bin/cat {quoted} 2>&1"), None)
                    .map_err(|(_, error)| error)?;
            if !contents.status.success() {
                return Err(format!(
                    "cannot read share marker {}: {}",
                    path.display(),
                    String::from_utf8_lossy(&contents.stdout).trim()
                ));
            }
            if !managed_marker_matches(
                &String::from_utf8_lossy(&contents.stdout),
                &marker.share_uuid,
            ) {
                return Err(format!(
                    "share marker {} does not match the old cluster UUID; refusing to remove it",
                    path.display()
                ));
            }
            Ok(())
        }
        Some(kind) => Err(format!(
            "share marker {} is {kind}; refusing to remove it",
            path.display()
        )),
    }
}

fn marker_check_script(marker: &MarkerSpec, remove: bool) -> String {
    let path = node_admin::shell_quote(
        &marker
            .source_root
            .join(".macluster-share-id")
            .to_string_lossy(),
    );
    let uuid = node_admin::shell_quote(&marker.share_uuid);
    let action = if remove {
        "/bin/rm \"$marker_path\""
    } else {
        ":"
    };
    format!(
        "set -eu\nmarker_path={path}\nexpected_uuid={uuid}\nif marker_type=$(/usr/bin/stat -f '%HT' \"$marker_path\" 2>&1); then\n  [ \"$marker_type\" = 'Regular File' ] || {{ echo 'share marker is not a regular file; refusing reset' >&2; exit 1; }}\n  if marker_contents=$(/bin/cat \"$marker_path\" 2>&1); then [ \"$marker_contents\" = \"$expected_uuid\" ] || {{ echo 'share marker UUID changed; refusing reset' >&2; exit 1; }}; else echo \"$marker_contents\" >&2; exit 1; fi\n  {action}\nelse\n  case \"$marker_type\" in *'No such file or directory'*) : ;; *) echo \"$marker_type\" >&2; exit 1 ;; esac\nfi\n"
    )
}

fn alias_preflight_script(alias: &AliasSpec) -> String {
    let path = node_admin::shell_quote(&alias.mount_root.to_string_lossy());
    let target = node_admin::shell_quote(&alias.source_root.to_string_lossy());
    let expected_alias = if alias.committed {
        "echo 'managed alias changed; refusing reset' >&2; exit 1"
    } else {
        ":"
    };
    format!(
        "set -eu\nalias_path={path}\ntarget_path={target}\nif alias_type=$(/usr/bin/stat -f '%HT' \"$alias_path\" 2>&1); then\n  if [ \"$alias_type\" = 'Symbolic Link' ]; then if alias_target=$(/usr/bin/readlink \"$alias_path\" 2>&1); then [ \"$alias_target\" = \"$target_path\" ] || {{ {expected_alias}; }}; else echo \"$alias_target\" >&2; exit 1; fi\n  elif [ \"$alias_type\" != 'No such file or directory' ]; then {expected_alias}; fi\nelse\n  case \"$alias_type\" in *'No such file or directory'*) : ;; *) echo \"$alias_type\" >&2; exit 1 ;; esac\nfi\n"
    )
}

fn alias_is_exact(alias: &AliasSpec) -> AppResult<bool> {
    let Some(kind) =
        remote_path_type(&alias.server, &alias.mount_root).map_err(|error| (1, error))?
    else {
        return Ok(false);
    };
    if kind != "Symbolic Link" {
        if alias.committed {
            return Err((
                1,
                format!(
                    "named-share alias {} is {kind}, not the configured symlink",
                    alias.mount_root.display()
                ),
            ));
        }
        return Ok(false);
    }
    let path = node_admin::shell_quote(&alias.mount_root.to_string_lossy());
    let link = node_admin::ssh_output(
        &alias.server,
        &format!("/usr/bin/readlink {path} 2>&1"),
        None,
    )
    .map_err(|(_, error)| (1, error))?;
    if !link.status.success() {
        return Err((
            1,
            format!(
                "cannot read alias {}: {}",
                alias.mount_root.display(),
                String::from_utf8_lossy(&link.stdout).trim()
            ),
        ));
    }
    if String::from_utf8_lossy(&link.stdout).trim() == alias.source_root.to_string_lossy() {
        return Ok(true);
    }
    if alias.committed {
        Err((
            1,
            format!(
                "named-share alias {} no longer points to its configured target",
                alias.mount_root.display()
            ),
        ))
    } else {
        Ok(false)
    }
}

fn alias_cleanup_script(alias: &AliasSpec) -> String {
    let path = node_admin::shell_quote(&alias.mount_root.to_string_lossy());
    let target = node_admin::shell_quote(&alias.source_root.to_string_lossy());
    let changed = if alias.committed {
        "echo 'managed alias changed after reset preflight' >&2; exit 1"
    } else {
        ":"
    };
    format!(
        "if [ -L {path} ]; then actual=$(/usr/bin/readlink {path}); if [ \"$actual\" = {target} ]; then /bin/rm {path}; else {changed}; fi; elif [ -e {path} ]; then {changed}; fi\n"
    )
}

#[cfg(test)]
fn remove_alias(alias: &AliasSpec) -> AppResult<()> {
    let script = format!("set -e\n{}", alias_cleanup_script(alias));
    let output = node_admin::ssh_output(&alias.server, &script, None)?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if detail.contains("Permission denied") || detail.contains("Operation not permitted") {
        eprintln!(
            "Reset administrator access: node {}, {}@{}.\n  Operation: remove the exact macluster-managed NFS alias {}.\n  If prompted, enter this Mac's administrator password.",
            alias.server_id,
            alias.server.ssh_user.as_deref().unwrap_or("local account"),
            alias.server.host,
            alias.mount_root.display()
        );
        node_admin::run_interactive_admin(&alias.server, &script).map_err(|error| {
            (
                1,
                format!(
                    "alias {} changed after reset preflight or could not be removed: {error}",
                    alias.mount_root.display()
                ),
            )
        })?;
        return Ok(());
    }
    if !output.status.success() {
        return Err((
            1,
            format!(
                "alias {} changed after reset preflight or could not be removed: {}",
                alias.mount_root.display(),
                detail
            ),
        ));
    }
    Ok(())
}

fn remove_marker(marker: &MarkerSpec) -> AppResult<()> {
    let path = marker.source_root.join(".macluster-share-id");
    let script = marker_check_script(marker, true);
    let output = node_admin::ssh_output(&marker.server, &script, None)?;
    if !output.status.success() {
        let detail = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        if permission_error(&detail) {
            announce_reset_admin(
                &marker.server_id,
                &marker.server,
                "remove a protected managed NFS marker",
            );
            node_admin::run_interactive_admin(&marker.server, &script).map_err(|error| {
                (
                    1,
                    format!(
                        "marker {} could not be removed with administrator access: {error}",
                        path.display()
                    ),
                )
            })?;
        } else {
            return Err((
                1,
                format!(
                    "marker {} no longer matches the reset UUID or could not be removed: {detail}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn archive_old_cluster(journal: &mut ResetJournal, path: &Path) -> AppResult<()> {
    if !journal.is_completed("log-sync-stopped:local") {
        let old =
            ClusterConfig::parse(&journal.old_config).map_err(|error| (1, error.to_string()))?;
        quiesce_local_publisher(journal, &old.share_uuid)?;
        journal.mark_completed("log-sync-stopped:local");
        save_journal(path, journal, false)?;
    }
    let archive_dir = PathBuf::from(&journal.archive_dir);
    fs::create_dir_all(&archive_dir).map_err(|error| (1, error.to_string()))?;
    ensure_abandoned_sync_manifest(journal, path)?;
    let state_dir = PathBuf::from(&journal.state_dir);
    let archived_state = archive_dir.join("controller");
    if !journal.is_completed("archive:state") {
        match (state_dir.exists(), archived_state.exists()) {
            (true, false) => fs::rename(&state_dir, &archived_state).map_err(|error| {
                (
                    1,
                    format!(
                        "cannot archive controller state {}: {error}",
                        state_dir.display()
                    ),
                )
            })?,
            (false, true) => {}
            (false, false) => {}
            (true, true) => {
                return Err((
                    1,
                    "both live and archived controller state exist; refusing to merge them".into(),
                ));
            }
        }
        journal.mark_completed("archive:state");
        save_journal(path, journal, false)?;
    }

    if !journal.is_completed("archive:local-agent-state") {
        let local_agent_state = local_agent_state_path(journal);
        let archived_agent_state = archive_dir.join("agent-local-state");
        let old = ClusterConfig::parse(&journal.old_config)
            .map_err(|error| (1, format!("saved old config is invalid: {error}")))?;
        let outcome = macluster_agent::admin::archive_idle_namespace(
            &local_agent_state,
            &archived_agent_state,
            &old.share_uuid,
            journal.discard_terminal_sync,
        )
        .map_err(|error| (1, format!("cannot archive local agent state: {error}")))?;
        report_agent_archive_outcome(outcome, "this account");
        journal.mark_completed("archive:local-agent-state");
        save_journal(path, journal, false)?;
    }

    let config_path = PathBuf::from(&journal.config_path);
    let archived_config = archive_dir.join("config.toml");
    if !journal.is_completed("archive:config") {
        archive_file_exact(
            &config_path,
            &archived_config,
            &journal.old_config_sha256,
            "cluster config",
        )?;
        journal.mark_completed("archive:config");
        save_journal(path, journal, false)?;
    }

    let binding = binding_path(&config_path);
    let archived_binding = archive_dir.join("config.state-dir-binding");
    if !journal.is_completed("archive:binding") {
        if binding.exists() {
            if archived_binding.exists() {
                let active = fs::read(&binding).map_err(|error| (1, error.to_string()))?;
                let archived =
                    fs::read(&archived_binding).map_err(|error| (1, error.to_string()))?;
                if active != archived {
                    return Err((
                        1,
                        "state-directory binding changed during reset archive".into(),
                    ));
                }
                fs::remove_file(&binding).map_err(|error| (1, error.to_string()))?;
            } else {
                archive_file_copy(&binding, &archived_binding)?;
            }
        }
        journal.mark_completed("archive:binding");
        save_journal(path, journal, false)?;
    }
    Ok(())
}

fn archive_abandoned_sync_manifest(journal: &ResetJournal) -> AppResult<()> {
    if !journal.abandonment_recorded {
        return Ok(());
    }
    let destination = PathBuf::from(&journal.archive_dir).join("abandoned-sync.json");
    let bytes = serde_json::to_vec_pretty(&journal.abandoned_sync_jobs)
        .map_err(|error| (1, error.to_string()))?;
    if destination.exists() {
        let current = fs::read(&destination).map_err(|error| (1, error.to_string()))?;
        if current != bytes {
            return Err((
                1,
                format!(
                    "archive manifest {} already contains different data",
                    destination.display()
                ),
            ));
        }
        return Ok(());
    }
    let parent = destination
        .parent()
        .expect("abandoned-sync manifest has a parent");
    let temporary = parent.join(format!(".abandoned-sync-{}.tmp", Id128::random()));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if fs::read(&destination)? != bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "archive manifest changed concurrently",
                    ));
                }
            }
            Err(error) => return Err(error),
        }
        fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| {
        (
            1,
            format!(
                "cannot archive abandoned sync manifest {}: {error}",
                destination.display()
            ),
        )
    })
}

fn ensure_abandoned_sync_manifest(journal: &mut ResetJournal, path: &Path) -> AppResult<()> {
    const STEP: &str = "archive:abandoned-sync";

    if !journal.abandonment_recorded {
        if !journal.is_completed(STEP) {
            journal.mark_completed(STEP);
            save_journal(path, journal, false)?;
        }
        return Ok(());
    }

    if journal.abandoned_sync_manifest_written {
        verify_archived_abandoned_sync_manifest(journal)?;
        if !journal.is_completed(STEP) {
            journal.mark_completed(STEP);
            save_journal(path, journal, false)?;
        }
        return Ok(());
    }

    // A normal reset may already have completed this step without writing a
    // force manifest. If it is later upgraded, create the manifest once from
    // the captured journal record before treating the completed step as final.
    archive_abandoned_sync_manifest(journal)?;
    journal.abandoned_sync_manifest_written = true;
    journal.mark_completed(STEP);
    save_journal(path, journal, false)
}

fn verify_archived_abandoned_sync_manifest(journal: &ResetJournal) -> AppResult<()> {
    if !journal.abandonment_recorded {
        return Ok(());
    }
    let destination = PathBuf::from(&journal.archive_dir).join("abandoned-sync.json");
    let expected = serde_json::to_vec_pretty(&journal.abandoned_sync_jobs)
        .map_err(|error| (1, error.to_string()))?;
    let current = fs::read(&destination).map_err(|error| {
        (
            1,
            format!(
                "cannot verify completed archive manifest {}: {error}",
                destination.display()
            ),
        )
    })?;
    if current != expected {
        return Err((
            1,
            format!(
                "completed archive manifest {} is missing matching journal data",
                destination.display()
            ),
        ));
    }
    Ok(())
}

fn advance_archive_phase(journal: &mut ResetJournal, path: &Path) -> AppResult<ArchiveTransition> {
    archive_old_cluster(journal, path)?;
    if journal.mode == ResetMode::RebuildAfterCleanup {
        journal.phase = "INSTALLING".into();
        save_journal(path, journal, false)?;
        return Ok(ArchiveTransition::InstallTarget);
    }

    let config_path = PathBuf::from(&journal.config_path);
    let state_dir = PathBuf::from(&journal.state_dir);
    if config_path.exists() || state_dir.exists() || binding_path(&config_path).exists() {
        return Err((
            1,
            "reset archived the old cluster but an active config, state directory, or state binding reappeared; leaving the reset journal for recovery".into(),
        ));
    }

    journal.phase = "COMPLETE".into();
    save_journal(path, journal, false)?;
    fs::remove_file(path).map_err(|error| {
        (
            1,
            format!("reset completed but journal removal failed: {error}"),
        )
    })?;
    Ok(ArchiveTransition::CompletedUninitialized)
}

fn archive_file_exact(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
    label: &str,
) -> AppResult<()> {
    if source.exists() {
        let bytes = fs::read(source).map_err(|error| (1, error.to_string()))?;
        let digest = sha256_hex(&bytes).map_err(|error| (1, error.to_string()))?;
        if digest != expected_sha256 {
            return Err((
                1,
                format!("{label} changed during reset; refusing to archive unexpected contents"),
            ));
        }
        if destination.exists() {
            let archived = fs::read(destination).map_err(|error| (1, error.to_string()))?;
            if archived != bytes {
                return Err((
                    1,
                    format!(
                        "archive destination {} already contains different contents",
                        destination.display()
                    ),
                ));
            }
            fs::remove_file(source)
                .map_err(|error| (1, format!("cannot move {label} to archive: {error}")))?;
        } else {
            archive_file_copy(source, destination)?;
        }
    } else if destination.exists() {
        let bytes = fs::read(destination).map_err(|error| (1, error.to_string()))?;
        let digest = sha256_hex(&bytes).map_err(|error| (1, error.to_string()))?;
        if digest != expected_sha256 {
            return Err((
                1,
                format!("archived {label} does not match its saved digest"),
            ));
        }
    } else {
        return Err((1, format!("neither live nor archived {label} exists")));
    }
    Ok(())
}

fn archive_file_copy(source: &Path, destination: &Path) -> AppResult<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| (1, error.to_string()))?;
    }
    let temp = destination.with_file_name(format!(".archive-{}.tmp", Id128::random()));
    let result = (|| -> io::Result<()> {
        fs::copy(source, &temp)?;
        File::open(&temp)?.sync_all()?;
        fs::rename(&temp, destination)?;
        File::open(
            destination
                .parent()
                .expect("archive destination has parent"),
        )?
        .sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(|error| (1, format!("cannot archive {}: {error}", source.display())))?;
    fs::remove_file(source).map_err(|error| {
        (
            1,
            format!(
                "cannot remove archived source {}: {error}",
                source.display()
            ),
        )
    })
}

fn binding_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".macluster.state-dir");
    config_path.with_file_name(name)
}

fn local_agent_state_path(journal: &ResetJournal) -> PathBuf {
    journal
        .local_agent_state
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(macluster_agent::default_state_dir)
}

fn install_target(journal: &mut ResetJournal, path: &Path) -> AppResult<()> {
    let config_path = PathBuf::from(&journal.config_path);
    let state_dir = PathBuf::from(&journal.state_dir);
    let target_context = journal.target_context.as_ref().ok_or_else(|| {
        (
            1,
            "saved reset target identity is missing; keep the controller stopped and inspect the reset journal".into(),
        )
    })?;
    let current_uuid = node_admin::local_platform_uuid()?;
    if !current_uuid.eq_ignore_ascii_case(&target_context.login_uuid) {
        return Err((
            1,
            "login Mac identity changed during reset; refusing to install the saved topology"
                .into(),
        ));
    }
    let mut config_source = journal.target_config.clone();
    let mut config =
        ClusterConfig::parse(&config_source).map_err(|error| (1, error.to_string()))?;
    let already_committed = if config_path.exists() {
        let current = fs::read_to_string(&config_path).map_err(|error| (1, error.to_string()))?;
        if current != config_source {
            return Err((
                1,
                "a different config appeared during reset; refusing to overwrite it".into(),
            ));
        }
        true
    } else {
        false
    };

    if !already_committed {
        if let Some(primary) = journal.target_options.primary_nfs.as_ref() {
            super::prepare_remote_primary_for_reset(
                &mut config_source,
                &mut config,
                primary,
                &journal.id,
            )?;
        } else {
            super::prepare_local_primary_for_reset(&config.shared_root, &config.share_uuid)?;
        }
        journal.target_config = config_source.clone();
        save_journal(path, journal, false)?;
        atomic_create_config(&config_path, config_source.as_bytes())?;
    }
    MaintenanceLock::bind_state_dir(&config_path, &state_dir).map_err(|error| {
        (
            1,
            format!("new config was committed but state binding failed: {error}"),
        )
    })?;
    if journal.target_options.primary_nfs.is_some() {
        fs::create_dir_all(&state_dir).map_err(|error| (1, error.to_string()))?;
        node_admin::sync_remote_configs(&config, &config_source, &state_dir, &journal.id, None)
            .map_err(|error| {
                (
                    1,
                    format!("new config is committed but remote config sync is pending: {error}"),
                )
            })?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedExportSpec {
    share_uuid: String,
    node_id: String,
    source_root: String,
    client_ip: String,
}

fn mount_matches(output: &str, host: &str, source_root: &Path, mount_root: &Path) -> bool {
    let source = format!("{host}:{}", source_root.display());
    matches!(
        node_admin::named_share_mount_status(output, &source, &mount_root.to_string_lossy(),),
        node_admin::NamedShareMountStatus::Expected
    )
}

fn managed_marker_matches(contents: &str, share_uuid: &str) -> bool {
    contents.trim() == share_uuid
}

fn remove_managed_exports(
    exports: &str,
    specs: &[ManagedExportSpec],
) -> Result<(String, bool), String> {
    let mut expected = BTreeMap::new();
    for spec in specs {
        let marker = format!("# macluster-managed {} {}", spec.share_uuid, spec.node_id);
        let rule = format!("{} {}", spec.source_root, spec.client_ip);
        if expected
            .insert(marker.clone(), rule.clone())
            .is_some_and(|existing| existing != rule)
        {
            return Err(format!(
                "conflicting reset records refer to managed export marker {marker}"
            ));
        }
    }

    let lines: Vec<_> = exports.lines().collect();
    let mut updated = Vec::with_capacity(lines.len());
    let mut removed = false;
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if let Some(expected_rule) = expected.get(line) {
            let actual_rule = lines.get(index + 1).copied().unwrap_or_default();
            if actual_rule.trim() != expected_rule {
                return Err(format!(
                    "managed NFS marker {line} is not followed by its expected export rule; refusing to edit exports"
                ));
            }
            removed = true;
            index += 2;
        } else {
            updated.push(line);
            index += 1;
        }
    }
    let updated = if updated.is_empty() {
        String::new()
    } else {
        updated.join("\n") + if exports.ends_with('\n') { "\n" } else { "" }
    };
    Ok((updated, removed))
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires MACLUSTER_TEST_CONFIG, MACLUSTER_TEST_STATE, MACLUSTER_TEST_AGENT_STATE and reachable idle nodes"]
    fn live_reset_preflight_is_read_only() {
        use std::path::PathBuf;
        let config_path = PathBuf::from(std::env::var("MACLUSTER_TEST_CONFIG").unwrap());
        let state = PathBuf::from(std::env::var("MACLUSTER_TEST_STATE").unwrap());
        let agent = PathBuf::from(std::env::var("MACLUSTER_TEST_AGENT_STATE").unwrap());
        let before = fs::read(&config_path).unwrap();
        let config =
            macluster_core::config::ClusterConfig::parse(std::str::from_utf8(&before).unwrap())
                .unwrap();
        let id = Id128::random().to_string();
        let archive = state
            .parent()
            .unwrap()
            .join(format!("reset-preflight-probe-{id}"));
        let plan = super::ResetPlan::preflight(
            &config,
            &config_path,
            &state,
            &id,
            &archive,
            &agent,
            false,
            &[],
        )
        .unwrap();
        assert_eq!(fs::read(&config_path).unwrap(), before);
        assert!(!archive.exists());
        assert!(
            plan.remote_agent_states
                .iter()
                .all(|item| item.path.contains("Library/Application Support/"))
        );

        println!(
            "Read-only reset preflight passed: {} nodes, {} mounts, {} remote agent archives planned; active config unchanged.",
            plan.nodes.len(),
            plan.mounts.len(),
            plan.remote_agent_states.len()
        );
    }

    #[test]
    fn reset_accepts_standard_macos_agent_paths_without_relaxing_home_validation() {
        let id = "00000000-0000-4000-8000-000000000001";
        let (state, archive) = super::remote_agent_state_paths("/Users/operator", id).unwrap();
        assert_eq!(
            state,
            "/Users/operator/Library/Application Support/macluster/agent"
        );
        assert_eq!(
            archive,
            format!(
                "/Users/operator/Library/Application Support/macluster/macluster-archive/agent-state-{id}"
            )
        );
        for home in [
            "/",
            "/Users/../tmp",
            "/Users/a\nb",
            "/Users/a;touch",
            "/Users/a//b",
        ] {
            assert!(super::remote_agent_state_paths(home, id).is_err());
        }
        assert!(super::remote_agent_state_paths("/Users/operator", "../../elsewhere").is_err());
    }

    use super::{
        AbandonedSyncJob, AliasSpec, ArchiveTransition, ExportGroup, ManagedExportSpec, MountSpec,
        RemoteAgentStateSpec, ResetJournal, ResetMode, ResetPlan, admin_operation_matches_digest,
        advance_archive_phase, archive_abandoned_sync_manifest, belongs_to_cluster,
        check_reset_remote_status, cleanup_batch_key, cleanup_batches, enable_force_reset,
        ensure_abandoned_sync_manifest, ensure_no_reset_in_progress,
        ensure_old_paths_are_outside_shared_root, job_blockers, journal_path,
        managed_marker_matches, mount_conflict, mount_matches, parse_pending_share_endpoint,
        pending_remote_config_path, remote_publisher_stop_command, remove_managed_exports,
        terminal_sync_abandonments, verify_archived_abandoned_sync_manifest,
    };
    use std::{collections::BTreeMap, fs, net::Ipv4Addr, os::unix::fs::PermissionsExt, path::Path};

    use macluster_core::storage::Storage;
    use macluster_protocol::{
        identifiers::{Id128, NodeId, QueueName, RequestId},
        types::{ExecutionStatus, JobMode, JobSpec, JobState, RuntimePhase},
    };

    fn journal() -> ResetJournal {
        ResetJournal {
            version: super::RESET_JOURNAL_VERSION,
            id: "reset-test".into(),
            phase: "CLEANING".into(),
            config_path: "/tmp/macluster/config.toml".into(),
            state_dir: "/tmp/macluster/state".into(),
            old_config: String::new(),
            old_config_sha256: String::new(),
            local_agent_state: Some(
                std::env::temp_dir()
                    .join(format!(
                        "macluster-reset-test-agent-{}-{}",
                        std::process::id(),
                        Id128::random()
                    ))
                    .to_string_lossy()
                    .into_owned(),
            ),
            discard_terminal_sync: false,
            abandonment_recorded: false,
            abandoned_sync_manifest_written: false,
            abandoned_sync_jobs: Vec::new(),
            target_config: String::new(),
            target_options: super::super::parse_options(&[]).unwrap(),
            target_context: Some(super::super::InitContext {
                login_host: Ipv4Addr::new(192, 168, 2, 2),
                login_uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
                login_uid: 501,
                remote_binary: "/usr/local/bin/macluster".into(),
                share_uuid: "00000000-0000-4000-8000-000000000001".into(),
            }),
            mode: ResetMode::ClearToUninitialized,
            archive_dir: "/tmp/macluster/archive".into(),
            completed_steps: Default::default(),
            detail: None,
        }
    }

    #[test]
    fn legacy_reset_journal_without_force_policy_defaults_to_safe_mode() {
        let mut value = serde_json::to_value(journal()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("discard_terminal_sync");

        let restored: ResetJournal = serde_json::from_value(value).unwrap();

        assert!(!restored.discard_terminal_sync);
    }

    #[test]
    fn reset_journal_keeps_force_policy_when_resumed_without_cli_flag() {
        let mut current = journal();
        current.discard_terminal_sync = true;

        let bytes = serde_json::to_vec(&current).unwrap();
        let restored: ResetJournal = serde_json::from_slice(&bytes).unwrap();
        let resumed_options = super::super::parse_options(&[]).unwrap();
        super::validate_resume_options(&restored.target_options, &resumed_options).unwrap();

        assert!(restored.discard_terminal_sync);
        assert!(!resumed_options.force);
    }

    #[test]
    fn escalating_reset_to_force_preserves_operation_archive_and_progress() {
        let mut current = journal();
        current.id = "existing-reset-operation".into();
        current.archive_dir = "/tmp/macluster/archive/existing".into();
        current.completed_steps.insert("mounts:node-a".into());
        let id = current.id.clone();
        let archive_dir = current.archive_dir.clone();
        let completed_steps = current.completed_steps.clone();

        enable_force_reset(&mut current);

        assert!(current.discard_terminal_sync);
        assert_eq!(current.id, id);
        assert_eq!(current.archive_dir, archive_dir);
        assert_eq!(current.completed_steps, completed_steps);
    }

    #[test]
    fn force_archive_writes_abandoned_sync_manifest_idempotently() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-abandoned-sync-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        let archive = root.join("archive");
        let old_source = test_config_source("old", "00000000-0000-4000-8000-000000000001");
        let old_config = old_source.as_bytes();
        fs::write(&config, old_config).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("controller.sqlite3"), b"old controller state").unwrap();
        let journal_path = journal_path(&config);

        let mut value = serde_json::to_value(journal()).unwrap();
        value["phase"] = serde_json::Value::String("ARCHIVING".into());
        value["config_path"] = serde_json::Value::String(config.to_string_lossy().into_owned());
        value["state_dir"] = serde_json::Value::String(state.to_string_lossy().into_owned());
        value["old_config"] = serde_json::Value::String(String::from_utf8_lossy(old_config).into());
        value["old_config_sha256"] =
            serde_json::Value::String(macluster_protocol::framing::sha256_hex(old_config).unwrap());
        value["archive_dir"] = serde_json::Value::String(archive.to_string_lossy().into_owned());
        value["discard_terminal_sync"] = serde_json::Value::Bool(true);
        value["abandonment_recorded"] = serde_json::Value::Bool(true);
        value["abandoned_sync_jobs"] = serde_json::json!([{
            "job_id": 28,
            "state": "CANCELLED",
            "node": "mini01-a",
            "start_token": "00000000-0000-4000-8000-000000000028",
            "snapshot_sync_pending": true,
            "log_sync_pending": false
        }]);
        let mut journal: ResetJournal = serde_json::from_value(value).unwrap();
        journal.mark_completed("log-sync-stopped:local");

        advance_archive_phase(&mut journal, &journal_path).unwrap();
        advance_archive_phase(&mut journal, &journal_path).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(archive.join("abandoned-sync.json")).unwrap())
                .unwrap();
        assert_eq!(manifest[0]["job_id"], 28);
        assert_eq!(manifest[0]["snapshot_sync_pending"], true);
        assert_eq!(
            fs::read(archive.join("controller/controller.sqlite3")).unwrap(),
            b"old controller state"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_abandonment_manifest_is_rechecked_and_must_exist() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-abandoned-recovery-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let archive = root.join("archive");
        fs::create_dir_all(&archive).unwrap();
        let mut reset = journal();
        reset.archive_dir = archive.to_string_lossy().into_owned();
        reset.abandonment_recorded = true;
        reset.abandoned_sync_jobs = vec![AbandonedSyncJob {
            job_id: 42,
            state: JobState::Cancelled,
            node: Some(NodeId::new("mini01-a").unwrap()),
            start_token: None,
            snapshot_sync_pending: true,
            log_sync_pending: false,
        }];
        archive_abandoned_sync_manifest(&reset).unwrap();
        reset.mark_completed("archive:abandoned-sync");

        verify_archived_abandoned_sync_manifest(&reset).unwrap();
        let manifest = archive.join("abandoned-sync.json");
        fs::write(&manifest, b"[]\n").unwrap();
        assert!(verify_archived_abandoned_sync_manifest(&reset).is_err());
        fs::remove_file(&manifest).unwrap();
        assert!(verify_archived_abandoned_sync_manifest(&reset).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn force_escalation_after_normal_manifest_step_creates_the_manifest() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-force-escalated-archive-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let archive = root.join("archive");
        fs::create_dir_all(&archive).unwrap();
        let mut reset = journal();
        reset.phase = "ARCHIVING".into();
        reset.archive_dir = archive.to_string_lossy().into_owned();
        reset.mark_completed("archive:abandoned-sync");

        // This is a normal reset that completed the no-manifest step before
        // being explicitly upgraded to force during archive recovery.
        enable_force_reset(&mut reset);
        reset.abandonment_recorded = true;
        let path = root.join("reset-journal.json");

        ensure_abandoned_sync_manifest(&mut reset, &path).unwrap();

        assert!(reset.abandoned_sync_manifest_written);
        assert!(reset.is_completed("archive:abandoned-sync"));
        assert_eq!(
            fs::read(archive.join("abandoned-sync.json")).unwrap(),
            serde_json::to_vec_pretty(&reset.abandoned_sync_jobs).unwrap()
        );
        ensure_abandoned_sync_manifest(&mut reset, &path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn force_abandonment_manifest_tracks_only_terminal_pending_sync_jobs() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-abandoned-capture-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let storage = Storage::open(&root).unwrap();
        let terminal = storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: Some(NodeId::new("mini01-a").unwrap()),
                    name: "terminal pending logs".into(),
                    cwd: "/Users/Shared/macluster".into(),
                    stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
                    stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Interactive,
                    snapshot: None,
                },
            )
            .unwrap();
        storage.request_cancel(terminal.id, false).unwrap();
        storage.set_log_sync_pending(terminal.id, true).unwrap();
        let snapshot = storage.stage_snapshot(b"echo pending\n").unwrap();
        storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: Some(NodeId::new("mini01-b").unwrap()),
                    name: "queued pending snapshot".into(),
                    cwd: "/Users/Shared/macluster".into(),
                    stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
                    stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Batch,
                    snapshot: Some(snapshot),
                },
            )
            .unwrap();
        drop(storage);

        let abandoned = terminal_sync_abandonments(&root).unwrap();

        assert_eq!(abandoned.len(), 1);
        assert_eq!(abandoned[0].job_id, terminal.id);
        assert_eq!(abandoned[0].state, JobState::Cancelled);
        assert!(abandoned[0].log_sync_pending);
        assert!(!abandoned[0].snapshot_sync_pending);
        fs::remove_dir_all(root).unwrap();
    }

    fn export(uuid: &str, node: &str, path: &str, client: &str) -> ManagedExportSpec {
        ManagedExportSpec {
            share_uuid: uuid.into(),
            node_id: node.into(),
            source_root: path.into(),
            client_ip: client.into(),
        }
    }

    #[test]
    fn reset_blocks_when_terminal_job_output_log_sync_is_pending() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-log-sync-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let storage = Storage::open(&root).unwrap();
        let job = storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: Some(NodeId::new("mini01-a").unwrap()),
                    name: "cancelled output sync".into(),
                    cwd: "/Users/Shared/macluster".into(),
                    stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
                    stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Interactive,
                    snapshot: None,
                },
            )
            .unwrap();
        storage.request_cancel(job.id, false).unwrap();
        storage.set_log_sync_pending(job.id, true).unwrap();
        assert_eq!(
            storage.get_job(job.id).unwrap().unwrap().state,
            JobState::Cancelled
        );
        drop(storage);

        let blockers = job_blockers(&root, false).unwrap();

        assert_eq!(
            blockers,
            vec![format!("job {} output log sync is pending", job.id)]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn force_reset_ignores_sync_for_terminal_jobs_but_keeps_nonterminal_blockers() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-force-sync-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let storage = Storage::open(&root).unwrap();
        let terminal = storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: Some(NodeId::new("mini01-a").unwrap()),
                    name: "terminal pending logs".into(),
                    cwd: "/Users/Shared/macluster".into(),
                    stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
                    stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Interactive,
                    snapshot: None,
                },
            )
            .unwrap();
        storage.request_cancel(terminal.id, false).unwrap();
        storage.set_log_sync_pending(terminal.id, true).unwrap();
        let snapshot = storage.stage_snapshot(b"echo pending\n").unwrap();
        let pending = storage
            .submit_once(
                RequestId(Id128::random()),
                JobSpec {
                    storage_namespace: None,
                    queue: QueueName::new("mini01").unwrap(),
                    node: Some(NodeId::new("mini01-a").unwrap()),
                    name: "pending task".into(),
                    cwd: "/Users/Shared/macluster".into(),
                    stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
                    stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
                    walltime_secs: None,
                    env: BTreeMap::new(),
                    mode: JobMode::Batch,
                    snapshot: Some(snapshot),
                },
            )
            .unwrap();
        drop(storage);

        let blockers = job_blockers(&root, true).unwrap();

        assert!(blockers.contains(&format!("job {} is Pending", pending.id)));
        assert!(blockers.contains(&format!("job {} snapshot sync is pending", pending.id)));
        fs::remove_dir_all(root).unwrap();
    }

    fn terminal_remote_job() -> AbandonedSyncJob {
        AbandonedSyncJob {
            job_id: 47,
            state: JobState::Completed,
            node: Some(NodeId::new("mini01-a").unwrap()),
            start_token: Some(macluster_protocol::identifiers::StartToken(
                Id128::parse("01234567-89ab-cdef-0123-456789abcdef").unwrap(),
            )),
            snapshot_sync_pending: false,
            log_sync_pending: true,
        }
    }

    fn terminal_remote_status() -> ExecutionStatus {
        let job = terminal_remote_job();
        ExecutionStatus {
            start_token: job.start_token.unwrap(),
            job_id: job.job_id,
            phase: RuntimePhase::Idle,
            terminal_state: Some(job.state),
            boot_id: "boot-1".into(),
            runner_pid: None,
            child_pid: None,
            exit_code: Some(0),
            end_reason: None,
            log_sync_pending: true,
        }
    }

    #[test]
    fn reset_force_accepts_only_identity_matched_terminal_remote_logs() {
        let abandoned = terminal_remote_job();
        let status = terminal_remote_status();

        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(status.clone())),
                true,
                std::slice::from_ref(&abandoned),
            )
            .is_ok()
        );
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(status.clone())),
                false,
                std::slice::from_ref(&abandoned),
            )
            .is_err()
        );

        let mut active = status.clone();
        active.phase = RuntimePhase::Running;
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(active)),
                true,
                std::slice::from_ref(&abandoned),
            )
            .is_err()
        );

        let mut wrong_token = status.clone();
        wrong_token.start_token = macluster_protocol::identifiers::StartToken::random();
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(wrong_token)),
                true,
                std::slice::from_ref(&abandoned),
            )
            .is_err()
        );

        let mut wrong_job_id = status.clone();
        wrong_job_id.job_id += 1;
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(wrong_job_id)),
                true,
                std::slice::from_ref(&abandoned),
            )
            .is_err()
        );

        let mut wrong_terminal_state = status.clone();
        wrong_terminal_state.terminal_state = Some(JobState::Failed);
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(wrong_terminal_state)),
                true,
                std::slice::from_ref(&abandoned),
            )
            .is_err()
        );

        assert!(
            check_reset_remote_status(
                "mini01-b",
                Ok(Some(status)),
                true,
                std::slice::from_ref(&abandoned),
            )
            .is_err()
        );

        let mut identity_missing = abandoned;
        identity_missing.start_token = None;
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Ok(Some(terminal_remote_status())),
                true,
                std::slice::from_ref(&identity_missing),
            )
            .is_err()
        );
    }

    #[test]
    fn reset_remote_status_keeps_not_found_idle_and_propagates_unreachable_errors() {
        assert!(check_reset_remote_status("mini01-a", Ok(None), true, &[]).is_ok());
        assert!(
            check_reset_remote_status(
                "mini01-a",
                Err((1, "node is unreachable".into())),
                true,
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn reset_unmount_match_requires_exact_server_source_mount_and_nfs_type() {
        let output = "192.168.2.1:/Volumes/Storage/macluster on /Users/Shared/macluster (nfs, nodev, nosuid)\n";
        assert!(mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!mount_matches(
            output,
            "192.168.2.1",
            Path::new("/Users/Shared/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!mount_matches(
            "192.168.2.1:/Volumes/Storage/macluster on /Users/Shared/macluster (apfs, local)\n",
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));
        assert!(!mount_matches(
            "192.168.2.1:/Volumes/Storage/macluster on /Users/Shared/macluster (nfs4, nodev)\n",
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/macluster"),
        ));

        let stacked = concat!(
            "192.168.2.1:/Volumes/Storage/macluster on /Users/Shared/macluster (nfs, nodev)\n",
            "192.168.2.9:/unrelated on /Users/Shared/macluster (nfs, nodev)\n",
        );
        let expected = mount_matches(
            stacked,
            "192.168.2.1",
            Path::new("/Volumes/Storage/macluster"),
            Path::new("/Users/Shared/macluster"),
        );
        assert!(!expected, "a stacked destination is not one exact mount");
        assert!(
            mount_conflict(
                stacked,
                "192.168.2.1",
                Path::new("/Volumes/Storage/macluster"),
                Path::new("/Users/Shared/macluster"),
            ),
            "a second mount at the same destination must block reset"
        );
        assert!(
            !mount_conflict(
                "/dev/disk5s1 on /Volumes/Data (apfs, local, journaled)\n",
                "192.168.2.1",
                Path::new("/Volumes/Data"),
                Path::new("/Volumes/Data"),
            ),
            "an unrelated local volume at a configured target must be preserved, not block reset"
        );
        assert!(
            !mount_conflict(
                "192.168.2.9:/other on /Volumes/Data (nfs, nodev)\n",
                "192.168.2.1",
                Path::new("/Volumes/Data"),
                Path::new("/Volumes/Data"),
            ),
            "a different NFS source is not ours to unmount and must remain untouched"
        );

        let unmount_step = super::reset_mount_unmount_step(
            "192.168.2.1:/Volumes/Storage/macluster",
            Path::new("/Users/Shared/macluster"),
        );
        assert!(unmount_step.contains("/usr/bin/awk"));
        assert!(unmount_step.contains("expected) /sbin/umount"));
        assert!(unmount_step.contains("mount changed or is stacked"));
        assert!(!unmount_step.contains("grep -F"));
    }

    #[test]
    fn reset_alias_inspection_reports_permission_denied_instead_of_absence() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-protected-alias-{}",
            Id128::random()
        ));
        let protected = root.join("protected");
        fs::create_dir_all(&protected).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let alias_path = protected.join("alias");
        std::os::unix::fs::symlink(&source, &alias_path).unwrap();
        let alias = AliasSpec {
            server_id: "login-01".into(),
            server: test_config("test", "00000000-0000-4000-8000-000000000001").nodes["login-01"]
                .clone(),
            source_root: source,
            mount_root: alias_path,
            committed: true,
        };

        fs::set_permissions(&protected, fs::Permissions::from_mode(0)).unwrap();
        let result = super::alias_is_exact(&alias);
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "an inaccessible alias must not look absent"
        );
        assert_eq!(fs::read_link(alias.mount_root).unwrap(), alias.source_root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_marker_removal_reports_permission_denied_instead_of_success() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-protected-marker-{}",
            Id128::random()
        ));
        let protected = root.join("protected");
        fs::create_dir_all(&protected).unwrap();
        let marker_path = protected.join(".macluster-share-id");
        let share_uuid = "00000000-0000-4000-8000-000000000001";
        fs::write(&marker_path, share_uuid).unwrap();
        let marker = super::MarkerSpec {
            server_id: "login-01".into(),
            server: test_config("test", share_uuid).nodes["login-01"].clone(),
            source_root: protected.clone(),
            share_uuid: share_uuid.into(),
            label: "primary".into(),
        };

        fs::set_permissions(&protected, fs::Permissions::from_mode(0)).unwrap();
        let result = super::remove_marker(&marker);
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "an inaccessible marker must not count as removed"
        );
        assert_eq!(fs::read_to_string(marker_path).unwrap(), share_uuid);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_removes_only_exact_adjacent_managed_export_pairs() {
        let exports = concat!(
            "# operator-managed cluster export\n",
            "/Users/Shared/macluster -network 192.168.2.0 -mask 255.255.255.0\n",
            "# macluster-managed share-uuid node-a\n",
            "/Volumes/Storage/macluster 192.168.2.2\n",
            "# keep this other managed resource\n",
            "/Users/Shared/tools 192.168.2.2\n",
        );
        let (updated, removed) = remove_managed_exports(
            exports,
            &[export(
                "share-uuid",
                "node-a",
                "/Volumes/Storage/macluster",
                "192.168.2.2",
            )],
        )
        .expect("filter exact managed export pair");

        assert!(removed);
        assert!(updated.contains("# operator-managed cluster export"));
        assert!(updated.contains("/Users/Shared/macluster -network"));
        assert!(updated.contains("# keep this other managed resource"));
        assert!(!updated.contains("# macluster-managed share-uuid node-a"));
    }

    #[test]
    fn reset_export_cleanup_accepts_duplicate_identical_share_records() {
        let exports =
            "# macluster-managed share-uuid node-a\n/Volumes/Storage/macluster 192.168.2.2\n";
        let spec = export(
            "share-uuid",
            "node-a",
            "/Volumes/Storage/macluster",
            "192.168.2.2",
        );
        let (updated, removed) =
            remove_managed_exports(exports, &[spec.clone(), spec]).expect("dedupe exact resource");
        assert!(removed);
        assert!(updated.is_empty());
    }

    #[test]
    fn reset_refuses_a_managed_marker_whose_adjacent_rule_changed() {
        let exports = concat!(
            "# macluster-managed share-uuid node-a\n",
            "/Volumes/Other 192.168.2.2\n",
        );
        assert!(
            remove_managed_exports(
                exports,
                &[export(
                    "share-uuid",
                    "node-a",
                    "/Volumes/Storage/macluster",
                    "192.168.2.2",
                )],
            )
            .is_err()
        );
    }

    #[test]
    fn reset_marker_cleanup_requires_matching_share_uuid() {
        assert!(managed_marker_matches("share-uuid\n", "share-uuid"));
        assert!(!managed_marker_matches("another-share\n", "share-uuid"));
        assert!(!managed_marker_matches("", "share-uuid"));
    }

    #[test]
    fn reset_cleans_failed_share_exports_and_markers_without_removing_original_directory() {
        let root =
            std::env::temp_dir().join(format!("macluster-reset-pending-alias-{}", Id128::random()));
        let project = root.join("project");
        let source = project.join("Users/operator/project");
        let primary = root.join("primary");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&primary).unwrap();
        fs::write(
            project.join("project.txt"),
            "project content must survive reset",
        )
        .unwrap();
        let primary_uuid = "00000000-0000-4000-8000-000000000001";
        let pending_uuid = "00000000-0000-4000-8000-000000000002";
        fs::write(primary.join(".macluster-share-id"), primary_uuid).unwrap();
        fs::write(source.join(".macluster-share-id"), pending_uuid).unwrap();
        let mut config = test_config("test", primary_uuid);
        config.shared_root = primary.clone();
        let server = config.nodes["login-01"].clone();
        let mut client = server.clone();
        client.host = "192.168.2.1".into();
        config.nodes.insert("arm-a".into(), client);
        let mut plan = ResetPlan {
            nodes: config.nodes.clone(),
            active_nodes: Default::default(),
            known_uuids: Default::default(),
            mounts: Vec::new(),
            exports: BTreeMap::new(),
            markers: BTreeMap::new(),
            aliases: Vec::new(),
            remote_configs: Vec::new(),
            remote_agent_states: Vec::new(),
        };
        plan.add_share(
            "login-01",
            &server,
            &primary,
            &primary,
            primary_uuid,
            "primary",
        );
        let operation = crate::node_admin::ResetAdminOperation {
            id: "failed-share".into(),
            action: "share".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "login-01".into(),
            endpoint: format!(
                "share:project:login-01:{}:{}",
                source.display(),
                project.display()
            ),
            machine_uuid: Some(pending_uuid.into()),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some("config-digest".into()),
            candidate_config_sha256: None,
            client_setup_may_have_run: false,
        };
        plan.add_pending_admin_resources(
            &config,
            vec![operation],
            &BTreeMap::new(),
            "config-digest",
        )
        .unwrap();
        plan.preflight_aliases()
            .expect("failed alias creation must not block resetting its NFS rules");
        let exports = format!(
            "# operator-managed\n/Volumes/Other 192.168.2.9\n# macluster-managed {primary_uuid} arm-a\n{} 192.168.2.1\n# macluster-managed {pending_uuid} arm-a\n{} 192.168.2.1\n",
            primary.display(),
            source.display()
        );
        let (cleaned, removed) =
            remove_managed_exports(&exports, &plan.exports["login-01"].specs).unwrap();
        assert!(removed);
        assert_eq!(cleaned, "# operator-managed\n/Volumes/Other 192.168.2.9\n");
        for alias in &plan.aliases {
            super::remove_alias(alias).unwrap();
        }
        for marker in plan.markers.values() {
            super::remove_marker(marker).unwrap();
        }
        assert_eq!(
            fs::read_to_string(project.join("project.txt")).unwrap(),
            "project content must survive reset"
        );
        assert!(!source.join(".macluster-share-id").exists());
        assert!(!primary.join(".macluster-share-id").exists());
        assert!(project.is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_removes_exact_share_aliases_and_preserves_unrelated_pending_links() {
        let root = std::env::temp_dir().join(format!("macluster-reset-alias-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        let target = root.join("alias");
        let other = root.join("other-source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("keep.txt"), "shared data").unwrap();
        let mut alias = super::AliasSpec {
            server_id: "login-01".into(),
            server: test_config("test", "00000000-0000-4000-8000-000000000001").nodes["login-01"]
                .clone(),
            source_root: source.clone(),
            mount_root: target.clone(),
            committed: false,
        };
        std::os::unix::fs::symlink(&other, &target).unwrap();
        super::remove_alias(&alias).unwrap();
        assert_eq!(fs::read_link(&target).unwrap(), other);
        alias.committed = true;
        assert!(super::remove_alias(&alias).is_err());
        assert_eq!(fs::read_link(&target).unwrap(), other);
        fs::remove_file(&target).unwrap();
        for committed in [false, true] {
            alias.committed = committed;
            std::os::unix::fs::symlink(&source, &target).unwrap();
            super::remove_alias(&alias).unwrap();
            assert!(fs::symlink_metadata(&target).is_err());
            assert_eq!(
                fs::read_to_string(source.join("keep.txt")).unwrap(),
                "shared data"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persistent_reset_journal_blocks_normal_cluster_commands() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-barrier-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "[cluster]\n").unwrap();
        let state_dir = root.join("state");
        let mut reset = journal();
        reset.config_path = config.to_string_lossy().into_owned();
        reset.state_dir = state_dir.to_string_lossy().into_owned();
        fs::write(journal_path(&config), serde_json::to_vec(&reset).unwrap()).unwrap();

        let error = ensure_no_reset_in_progress(&config, &state_dir).unwrap_err();
        assert!(error.1.contains("phase CLEANING"));
        assert!(error.1.contains("macluster init"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_reset_journal_phase_is_rejected_and_preserved() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-unknown-phase-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "[cluster]\n").unwrap();
        let state_dir = root.join("state");
        let mut reset = journal();
        reset.config_path = config.to_string_lossy().into_owned();
        reset.state_dir = state_dir.to_string_lossy().into_owned();
        reset.phase = "FUTURE_PHASE".into();
        let path = journal_path(&config);
        fs::write(&path, serde_json::to_vec(&reset).unwrap()).unwrap();

        let error = ensure_no_reset_in_progress(&config, &state_dir).unwrap_err();

        assert!(error.1.contains("unknown phase"));
        assert!(path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_cleanup_progress_is_idempotent() {
        let mut journal = journal();
        assert!(!journal.is_completed("mount:login:primary"));
        journal.mark_completed("mount:login:primary");
        journal.mark_completed("mount:login:primary");
        assert!(journal.is_completed("mount:login:primary"));
        assert_eq!(journal.completed_steps.len(), 1);
    }

    #[test]
    fn reset_groups_mount_export_and_alias_cleanup_per_mac() {
        use macluster_core::config::{NodeConfig, Transport};

        let node = NodeConfig {
            host: "192.0.2.10".into(),
            transport: Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("operator".into()),
            ssh_port: Some(22),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: None,
            execution_uid: None,
        };
        let second_node = node.clone();
        let plan = ResetPlan {
            nodes: BTreeMap::new(),
            active_nodes: Default::default(),
            known_uuids: BTreeMap::new(),
            mounts: vec![
                MountSpec {
                    node_id: "mini01-a".into(),
                    node: node.clone(),
                    server_host: "192.0.2.10".into(),
                    source_root: "/Users/Shared/macluster".into(),
                    mount_root: "/Users/Shared/macluster".into(),
                    label: "primary".into(),
                },
                MountSpec {
                    node_id: "mini01-c".into(),
                    node: second_node,
                    server_host: "192.0.2.10".into(),
                    source_root: "/Users/Shared/macluster".into(),
                    mount_root: "/Users/Shared/macluster".into(),
                    label: "legacy-alias".into(),
                },
            ],
            exports: BTreeMap::from([(
                "mini01-a".into(),
                ExportGroup {
                    server: node.clone(),
                    specs: vec![ManagedExportSpec {
                        share_uuid: "share-uuid".into(),
                        node_id: "mini01-b".into(),
                        source_root: "/Users/Shared/macluster".into(),
                        client_ip: "192.0.2.11".into(),
                    }],
                },
            )]),
            markers: BTreeMap::new(),
            aliases: vec![AliasSpec {
                server_id: "mini01-b".into(),
                server: node,
                source_root: "/Users/Shared/macluster-shares/tools".into(),
                mount_root: "/Users/operator/tools".into(),
                committed: false,
            }],
            remote_configs: Vec::new(),
            remote_agent_states: Vec::new(),
        };

        let journal = journal();
        let batches = cleanup_batches(&journal, &plan);

        let key = cleanup_batch_key(&plan.mounts[0].node);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[&key].mounts.len(), 2);
        assert_eq!(batches[&key].nodes.len(), 3);
        assert_eq!(batches[&key].exports.len(), 1);
        assert_eq!(batches[&key].aliases.len(), 1);
    }

    #[test]
    fn reset_export_update_can_be_followed_by_alias_cleanup_in_one_script() {
        let alias = AliasSpec {
            server_id: "storage-01".into(),
            server: test_config("test", "00000000-0000-4000-8000-000000000001").nodes["login-01"]
                .clone(),
            source_root: Path::new("/Users/Shared/macluster-shares/tools").to_path_buf(),
            mount_root: Path::new("/Users/Shared/tools").to_path_buf(),
            committed: false,
        };
        let update = crate::node_admin::nfs_exports_update_commands(
            "/Users/Shared/macluster 192.0.2.11\n",
            &"0".repeat(64),
            "reset-test",
        )
        .unwrap();
        let script = format!("set -e\n{}{}", update, super::alias_cleanup_script(&alias));

        let output = std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "combined reset cleanup script is invalid: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn reset_recovers_both_current_and_legacy_pending_share_endpoints() {
        let (id, server, source, mount) = parse_pending_share_endpoint(
            "share:tools:storage-01:/Volumes/Data/tools:/Users/Shared/tools",
            "storage-01",
        )
        .unwrap();
        assert_eq!(id, "tools");
        assert_eq!(server, "storage-01");
        assert_eq!(source, Path::new("/Volumes/Data/tools"));
        assert_eq!(mount, Path::new("/Users/Shared/tools"));

        let (id, server, source, mount) =
            parse_pending_share_endpoint("share:tools:/Users/Shared/tools-source", "storage-01")
                .unwrap();
        assert_eq!(id, "tools");
        assert_eq!(server, "storage-01");
        assert_eq!(source, Path::new("/Users/Shared/tools-source"));
        assert_eq!(mount, Path::new("/Users/Shared/macluster-shares/tools"));
    }

    #[test]
    fn reset_rejects_pending_share_endpoint_with_unsafe_paths() {
        assert!(
            parse_pending_share_endpoint(
                "share:tools:storage-01:/Volumes/../Data:/Users/Shared/tools",
                "storage-01",
            )
            .is_err()
        );
    }

    #[test]
    fn reset_uses_cluster_scoped_remote_config_for_pending_nodes() {
        assert_eq!(
            pending_remote_config_path("/Users/worker", "00000000-0000-4000-8000-000000000123")
                .unwrap(),
            "/Users/worker/.config/macluster/clusters/00000000-0000-4000-8000-000000000123/config.toml"
        );
        assert!(pending_remote_config_path("/Users/../worker", "bad-uuid").is_err());
    }

    #[test]
    fn reset_uses_recorded_agent_path_and_refuses_another_machine_path() {
        let uuid = "00000000-0000-4000-8000-000000000123";
        let config = test_config("test", uuid);
        let mut node = config.nodes["login-01"].clone();
        let expected = crate::node_admin::remote_agent_config_path(
            "/Users/worker",
            uuid,
            node.machine_uuid.as_deref().unwrap(),
        );
        node.remote_config = Some(expected.clone());
        assert_eq!(
            super::pending_agent_config_path("/Users/worker", uuid, &node).unwrap(),
            expected
        );
        node.remote_config = Some(expected.replace(
            node.machine_uuid.as_deref().unwrap(),
            "00000000-0000-4000-8000-000000000099",
        ));
        assert!(super::pending_agent_config_path("/Users/worker", uuid, &node).is_err());
        node.remote_config = None;
        assert_eq!(
            super::pending_agent_config_path("/Users/worker", uuid, &node).unwrap(),
            pending_remote_config_path("/Users/worker", uuid).unwrap()
        );
    }

    #[test]
    fn reset_skips_agent_command_for_uncommitted_pending_nodes() {
        use macluster_core::config::NodeConfig;

        let mut state = RemoteAgentStateSpec {
            node_id: "pending".into(),
            node: NodeConfig {
                host: "192.0.2.10".into(),
                transport: macluster_core::config::Transport::Ssh,
                remote_binary: "/usr/local/bin/macluster".into(),
                ssh_user: Some("worker".into()),
                ssh_port: Some(22),
                ssh_identity_file: None,
                remote_config: None,
                machine_uuid: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
                execution_uid: None,
            },
            path: "/Users/worker/Library/Application Support/macluster/agent".into(),
            archive: "/Users/worker/archive/agent".into(),
            stop_publisher: false,
        };

        assert!(
            remote_publisher_stop_command(
                &state,
                "00000000-0000-4000-8000-000000000123",
                "00000000-0000-4000-8000-000000000124"
            )
            .is_none()
        );

        let spec = ResetPlan::remote_agent_state_spec(
            false,
            "pending",
            &state.node,
            "/Users/worker",
            "00000000-0000-4000-8000-000000000124",
        )
        .unwrap();
        assert!(
            spec.is_none(),
            "pending B must never schedule archival of account-global A state"
        );
        let root =
            std::env::temp_dir().join(format!("macluster-pending-reset-{}", Id128::random()));
        let foreign_live = root.join("agent");
        write_owned_idle_agent_state(&foreign_live, "00000000-0000-4000-8000-000000000001");
        let before = fs::read(foreign_live.join("agent-state.json")).unwrap();
        let pending = ResetPlan::remote_agent_state_spec(
            false,
            "pending-b",
            &state.node,
            root.to_str().unwrap(),
            "00000000-0000-4000-8000-000000000124",
        )
        .unwrap();
        assert!(pending.is_none());
        assert_eq!(
            fs::read(foreign_live.join("agent-state.json")).unwrap(),
            before
        );
        assert!(
            !root
                .join("Library/Application Support/macluster/macluster-archive")
                .exists()
        );
        fs::remove_dir_all(root).unwrap();
        let owned_spec = ResetPlan::remote_agent_state_spec(
            true,
            "pending",
            &state.node,
            "/Users/worker",
            "00000000-0000-4000-8000-000000000124",
        )
        .unwrap()
        .unwrap();
        let archive_command = super::remote_agent_state_archive_command(
            &owned_spec,
            "00000000-0000-4000-8000-000000000123",
            true,
        );
        assert!(archive_command.contains("internal archive-agent-state --share-id"));
        assert!(archive_command.ends_with(" --discard-terminal-sync"));
        assert!(!archive_command.contains("/bin/mv"));

        state.stop_publisher = true;
        let command = remote_publisher_stop_command(
            &state,
            "00000000-0000-4000-8000-000000000123",
            "00000000-0000-4000-8000-000000000124",
        )
        .unwrap();
        assert!(command.starts_with("/usr/local/bin/macluster --state-dir"));
        assert!(command.contains("internal stop-log-sync"));
    }

    #[test]
    fn reset_pending_add_reconciles_exports_after_setup_started_before_flags_saved() {
        let config = test_config("test", "00000000-0000-4000-8000-000000000001");
        let machine_uuid = crate::node_admin::local_platform_uuid().unwrap();
        let operation = crate::node_admin::ResetAdminOperation {
            id: "pending-add".into(),
            action: "add".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "pending".into(),
            endpoint: "local@192.0.2.9:22".into(),
            machine_uuid: Some(machine_uuid),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some("config-digest".into()),
            candidate_config_sha256: None,
            client_setup_may_have_run: true,
        };
        let mut plan = ResetPlan {
            nodes: config.nodes.clone(),
            active_nodes: config.nodes.keys().cloned().collect(),
            known_uuids: BTreeMap::new(),
            mounts: Vec::new(),
            exports: BTreeMap::new(),
            markers: BTreeMap::new(),
            aliases: Vec::new(),
            remote_configs: Vec::new(),
            remote_agent_states: Vec::new(),
        };

        plan.add_pending_admin_resources(
            &config,
            vec![operation],
            &BTreeMap::new(),
            "config-digest",
        )
        .unwrap();

        assert_eq!(plan.exports["login-01"].specs.len(), 1);
        assert_eq!(plan.exports["login-01"].specs[0].node_id, "pending");
    }

    #[test]
    fn reset_pending_client_add_includes_source_prefix_alias_cleanup() {
        let mut config = test_config("test", "00000000-0000-4000-8000-000000000001");
        config.shares.insert(
            "tools".into(),
            macluster_core::config::ShareConfig {
                server: NodeId::new("login-01").unwrap(),
                source_root: std::path::PathBuf::from("/Volumes/Tools"),
                mount_root: std::path::PathBuf::from("/Users/Shared/tools"),
                share_uuid: "00000000-0000-4000-8000-000000000002".into(),
            },
        );
        let machine_uuid = crate::node_admin::local_platform_uuid().unwrap();
        let operation = crate::node_admin::ResetAdminOperation {
            id: "pending-add".into(),
            action: "add".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "pending".into(),
            endpoint: "local@192.0.2.9:22".into(),
            machine_uuid: Some(machine_uuid),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some("config-digest".into()),
            candidate_config_sha256: None,
            client_setup_may_have_run: true,
        };
        let mut plan = ResetPlan {
            nodes: config.nodes.clone(),
            active_nodes: config.nodes.keys().cloned().collect(),
            known_uuids: BTreeMap::new(),
            mounts: Vec::new(),
            exports: BTreeMap::new(),
            markers: BTreeMap::new(),
            aliases: Vec::new(),
            remote_configs: Vec::new(),
            remote_agent_states: Vec::new(),
        };

        plan.add_pending_admin_resources(
            &config,
            vec![operation],
            &BTreeMap::new(),
            "config-digest",
        )
        .unwrap();

        assert!(plan.aliases.iter().any(|alias| {
            alias.server_id == "pending"
                && alias.source_root == Path::new("/Users/Shared/tools")
                && alias.mount_root == Path::new("/Volumes/Tools")
                && !alias.committed
        }));
    }

    #[test]
    fn reset_only_trusts_pending_admin_operations_matching_active_config_digest() {
        let operation = crate::node_admin::ResetAdminOperation {
            id: "operation-1".into(),
            action: "add".into(),
            connection_endpoint: None,
            remote_config_path: None,
            node_id: "mini01-a".into(),
            endpoint: "operator@192.168.2.1:22".into(),
            machine_uuid: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            phase: "SETUP_PENDING".into(),
            old_config_sha256: Some("old-digest".into()),
            candidate_config_sha256: Some("candidate-digest".into()),
            client_setup_may_have_run: true,
        };
        assert!(admin_operation_matches_digest(&operation, "old-digest"));
        assert!(admin_operation_matches_digest(
            &operation,
            "candidate-digest"
        ));
        assert!(!admin_operation_matches_digest(&operation, "other-digest"));
    }

    #[test]
    fn reset_rejects_old_config_or_state_inside_shared_storage() {
        assert!(
            ensure_old_paths_are_outside_shared_root(
                Path::new("/Users/me/.config/macluster/config.toml"),
                Path::new("/Users/me/Library/Application Support/macluster"),
                Path::new("/Users/Shared/macluster"),
            )
            .is_ok()
        );
        assert!(
            ensure_old_paths_are_outside_shared_root(
                Path::new("/Users/Shared/macluster/config.toml"),
                Path::new("/Users/me/state"),
                Path::new("/Users/Shared/macluster"),
            )
            .is_err()
        );
        assert!(
            ensure_old_paths_are_outside_shared_root(
                Path::new("/Users/me/config.toml"),
                Path::new("/Users/Shared/macluster/state"),
                Path::new("/Users/Shared/macluster"),
            )
            .is_err()
        );
        assert!(
            ensure_old_paths_are_outside_shared_root(
                Path::new("/Users/me/state/config.toml"),
                Path::new("/Users/me/state"),
                Path::new("/Users/Shared/macluster"),
            )
            .is_err()
        );
    }

    #[test]
    fn reset_remote_config_identity_uses_share_uuid_and_primary_paths() {
        let old = test_config("old-name", "00000000-0000-4000-8000-000000000001");
        let same_cluster = test_config("renamed-copy", "00000000-0000-4000-8000-000000000001");
        let other_cluster = test_config("old-name", "00000000-0000-4000-8000-000000000002");
        assert!(belongs_to_cluster(&same_cluster, &old));
        assert!(!belongs_to_cluster(&other_cluster, &old));
    }

    #[test]
    fn completed_reset_journal_is_removed_by_normal_command_guard() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-complete-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "[cluster]\n").unwrap();
        let state_dir = root.join("state");
        let mut journal = journal();
        journal.phase = "COMPLETE".into();
        journal.config_path = config.to_string_lossy().into_owned();
        journal.state_dir = state_dir.to_string_lossy().into_owned();
        let path = journal_path(&config);
        fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
        ensure_no_reset_in_progress(&config, &state_dir).unwrap();
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_reset_journal_with_mismatched_binding_is_not_removed() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-complete-binding-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        fs::write(&config, "[cluster]\n").unwrap();
        let state_dir = root.join("state");
        let mut reset = journal();
        reset.phase = "COMPLETE".into();
        reset.config_path = config.to_string_lossy().into_owned();
        reset.state_dir = root.join("other-state").to_string_lossy().into_owned();
        let path = journal_path(&config);
        fs::write(&path, serde_json::to_vec(&reset).unwrap()).unwrap();

        let error = ensure_no_reset_in_progress(&config, &state_dir).unwrap_err();

        assert!(error.1.contains("different config or state path"));
        assert!(path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_config_archive_is_idempotent_and_rejects_changed_input() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-archive-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("config.toml");
        let destination = root.join("archive/config.toml");
        let expected = b"old cluster config\n";
        fs::write(&source, expected).unwrap();
        let digest = macluster_protocol::framing::sha256_hex(expected).unwrap();

        super::archive_file_exact(&source, &destination, &digest, "cluster config").unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), expected);
        super::archive_file_exact(&source, &destination, &digest, "cluster config").unwrap();

        fs::write(&source, b"changed config\n").unwrap();
        assert!(
            super::archive_file_exact(&source, &destination, &digest, "cluster config").is_err()
        );
        assert_eq!(fs::read(&source).unwrap(), b"changed config\n");
        fs::remove_dir_all(root).unwrap();
    }

    fn write_owned_idle_agent_state(path: &Path, namespace: &str) {
        fs::create_dir_all(path).unwrap();
        fs::write(
            path.join("agent-state.json"),
            serde_json::to_vec(&serde_json::json!({
                "owner_namespace": namespace,
                "controller": {
                    "controller_uuid": "00000000-0000-4000-8000-000000000099",
                    "epoch": 1
                }
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn agent_archive_uses_namespace_proof_and_preserves_foreign_or_unknown_state() {
        let root =
            std::env::temp_dir().join(format!("macluster-reset-agent-state-{}", Id128::random()));
        let namespace = "00000000-0000-4000-8000-000000000001";
        let foreign = "00000000-0000-4000-8000-000000000002";
        let live = root.join("agent");
        let archive = root.join("archive");
        write_owned_idle_agent_state(&live, foreign);
        let original = fs::read(live.join("agent-state.json")).unwrap();
        assert_eq!(
            macluster_agent::admin::archive_idle_namespace(&live, &archive, namespace, false)
                .unwrap(),
            macluster_agent::admin::ArchiveOutcome::PreservedForeign
        );
        assert_eq!(fs::read(live.join("agent-state.json")).unwrap(), original);
        assert!(!archive.exists());
        fs::write(live.join("agent-state.json"), b"{}").unwrap();
        assert_eq!(
            macluster_agent::admin::archive_idle_namespace(&live, &archive, namespace, true)
                .unwrap(),
            macluster_agent::admin::ArchiveOutcome::PreservedForeign
        );
        assert!(!archive.exists());
        write_owned_idle_agent_state(&live, namespace);
        assert_eq!(
            macluster_agent::admin::archive_idle_namespace(&live, &archive, namespace, false)
                .unwrap(),
            macluster_agent::admin::ArchiveOutcome::Archived
        );
        assert!(archive.join("agent-state.json").exists());
        assert_eq!(
            macluster_agent::admin::archive_idle_namespace(&live, &archive, namespace, false)
                .unwrap(),
            macluster_agent::admin::ArchiveOutcome::Absent
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_publisher_quiesce_preserves_foreign_mixed_and_unknown_agent_state() {
        let namespace = "00000000-0000-4000-8000-000000000001";
        for kind in ["foreign", "mixed", "unknown", "foreign-shutdown"] {
            let root =
                std::env::temp_dir().join(format!("macluster-reset-quiesce-{}", Id128::random()));
            let live = root.join("agent");
            let owner = if kind == "mixed" {
                namespace
            } else {
                "00000000-0000-4000-8000-000000000002"
            };
            write_owned_idle_agent_state(&live, owner);
            if kind == "unknown" {
                fs::write(live.join("agent-state.json"), b"{}").unwrap();
            } else if kind == "mixed" {
                fs::create_dir_all(live.join("jobs/77")).unwrap();
                fs::write(live.join("jobs/77/script.sh"), b"unknown namespace").unwrap();
            } else if kind == "foreign-shutdown" {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(live.join("agent-state.json")).unwrap())
                        .unwrap();
                value["log_sync_shutdown"] =
                    serde_json::json!("00000000-0000-4000-8000-000000000088");
                fs::write(
                    live.join("agent-state.json"),
                    serde_json::to_vec(&value).unwrap(),
                )
                .unwrap();
            }
            let before = fs::read(live.join("agent-state.json")).unwrap();
            let mut saved = journal();
            saved.id = "00000000-0000-4000-8000-000000000077".into();
            saved.local_agent_state = Some(live.to_string_lossy().into_owned());
            super::quiesce_local_publisher(&saved, namespace).unwrap();
            assert_eq!(
                fs::read(live.join("agent-state.json")).unwrap(),
                before,
                "{kind} publisher shutdown barrier must remain unchanged"
            );
            assert_eq!(
                macluster_agent::admin::archive_idle_namespace(
                    &live,
                    &root.join("archive"),
                    namespace,
                    true
                )
                .unwrap(),
                macluster_agent::admin::ArchiveOutcome::PreservedForeign
            );
            assert_eq!(fs::read(live.join("agent-state.json")).unwrap(), before);
            assert!(!root.join("archive").exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn archive_command_fallback_only_accepts_exact_old_internal_command_error() {
        use std::os::unix::process::ExitStatusExt;
        let mut output = std::process::Output {
            status: std::process::ExitStatus::from_raw(2 << 8),
            stdout: Vec::new(),
            stderr: b"macluster: unknown internal command\n".to_vec(),
        };
        assert!(super::archive_command_is_unsupported(&output));
        output.stderr = b"ssh: unknown internal command\n".to_vec();
        assert!(!super::archive_command_is_unsupported(&output));
        output.stderr = b"macluster: unknown internal command\n".to_vec();
        output.status = std::process::ExitStatus::from_raw(1 << 8);
        assert!(!super::archive_command_is_unsupported(&output));
        output.stderr = format!("macluster: {}", macluster_agent::AgentError::Busy).into_bytes();
        assert!(super::archive_command_is_owned_busy(&output));
        output.stderr = b"I/O error: connection closed".to_vec();
        assert!(!super::archive_command_is_owned_busy(&output));
    }

    #[test]
    fn completed_reset_archives_old_state_and_leaves_no_active_config() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-empty-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        let local_agent_state = root.join("agent");
        let archive = root.join("archive");
        let old_source = test_config_source("old", "00000000-0000-4000-8000-000000000001");
        let old_config = old_source.as_bytes();
        fs::write(&config, old_config).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("jobs.db"), b"old jobs").unwrap();
        write_owned_idle_agent_state(&local_agent_state, "00000000-0000-4000-8000-000000000001");
        let agent_bytes = fs::read(local_agent_state.join("agent-state.json")).unwrap();
        let binding = super::binding_path(&config);
        fs::write(&binding, format!("{}\n", state.display())).unwrap();

        let mut journal = journal();
        journal.phase = "ARCHIVING".into();
        journal.mark_completed("log-sync-stopped:local");
        journal.config_path = config.to_string_lossy().into_owned();
        journal.state_dir = state.to_string_lossy().into_owned();
        journal.old_config = String::from_utf8(old_config.to_vec()).unwrap();
        journal.old_config_sha256 = macluster_protocol::framing::sha256_hex(old_config).unwrap();
        journal.local_agent_state = Some(local_agent_state.to_string_lossy().into_owned());
        journal.archive_dir = archive.to_string_lossy().into_owned();
        journal.mode = ResetMode::ClearToUninitialized;
        journal.target_config.clear();
        let journal_file = journal_path(&config);
        fs::write(&journal_file, serde_json::to_vec(&journal).unwrap()).unwrap();

        let transition = advance_archive_phase(&mut journal, &journal_file).unwrap();

        assert_eq!(transition, ArchiveTransition::CompletedUninitialized);
        assert!(!config.exists());
        assert!(!state.exists());
        // The Agent leaves a fenced tombstone so an old controller cannot
        // resume against the account-global location after reset.
        assert!(local_agent_state.exists());
        assert!(!binding.exists());
        assert!(!journal_file.exists());
        assert_eq!(fs::read(archive.join("config.toml")).unwrap(), old_config);
        assert_eq!(
            fs::read(archive.join("controller/jobs.db")).unwrap(),
            b"old jobs"
        );
        assert_eq!(
            fs::read(archive.join("agent-local-state/agent-state.json")).unwrap(),
            agent_bytes
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_reset_journal_still_advances_to_saved_target_install() {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-legacy-install-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        let archive = root.join("archive");
        let old_source = test_config_source("old", "00000000-0000-4000-8000-000000000001");
        let old_config = old_source.as_bytes();
        fs::write(&config, old_config).unwrap();
        fs::create_dir_all(&state).unwrap();

        let mut journal = journal();
        journal.phase = "ARCHIVING".into();
        journal.mark_completed("log-sync-stopped:local");
        journal.config_path = config.to_string_lossy().into_owned();
        journal.state_dir = state.to_string_lossy().into_owned();
        journal.old_config = String::from_utf8(old_config.to_vec()).unwrap();
        journal.old_config_sha256 = macluster_protocol::framing::sha256_hex(old_config).unwrap();
        journal.archive_dir = archive.to_string_lossy().into_owned();
        journal.mode = ResetMode::RebuildAfterCleanup;
        journal.target_config = "saved target config".into();
        let journal_file = journal_path(&config);
        fs::write(&journal_file, serde_json::to_vec(&journal).unwrap()).unwrap();

        let transition = advance_archive_phase(&mut journal, &journal_file).unwrap();

        assert_eq!(transition, ArchiveTransition::InstallTarget);
        assert_eq!(journal.phase, "INSTALLING");
        assert!(journal_file.exists());
        assert!(!config.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_moved_node_uses_saved_connection_but_original_export_address() {
        for configured in [true, false] {
            let mut config = test_config("test", "00000000-0000-4000-8000-000000000001");
            let server = config.nodes["login-01"].clone();
            let mut worker = server.clone();
            worker.transport = super::Transport::Ssh;
            worker.host = "192.0.2.10".into();
            worker.ssh_user = Some("operator".into());
            worker.ssh_port = Some(22);
            worker.remote_config = Some(crate::node_admin::remote_agent_config_path(
                "/Users/operator",
                &config.share_uuid,
                worker.machine_uuid.as_deref().unwrap(),
            ));
            if configured {
                config.nodes.insert("worker".into(), worker.clone());
            }
            let mut plan = ResetPlan {
                nodes: config.nodes.clone(),
                active_nodes: Default::default(),
                known_uuids: Default::default(),
                mounts: Vec::new(),
                exports: BTreeMap::new(),
                markers: BTreeMap::new(),
                aliases: Vec::new(),
                remote_configs: Vec::new(),
                remote_agent_states: Vec::new(),
            };
            plan.add_share(
                "login-01",
                &server,
                &config.shared_root,
                &config.shared_root,
                &config.share_uuid,
                "primary",
            );
            if configured {
                plan.aliases.push(super::AliasSpec {
                    server_id: "worker".into(),
                    server: worker.clone(),
                    source_root: "/Users/operator/software".into(),
                    mount_root: "/Users/Shared/software".into(),
                    committed: true,
                });
            }
            let operation = crate::node_admin::ResetAdminOperation {
                id: "moved-worker".into(),
                action: "remove".into(),
                node_id: "worker".into(),
                endpoint: "operator@192.0.2.10:22".into(),
                connection_endpoint: Some("operator@192.0.2.20:2222".into()),
                remote_config_path: worker.remote_config.clone(),
                machine_uuid: worker.machine_uuid.clone(),
                phase: if configured {
                    "REMOVAL_PENDING"
                } else {
                    "SYNC_PENDING"
                }
                .into(),
                old_config_sha256: Some(
                    if configured {
                        "config-digest"
                    } else {
                        "old-config"
                    }
                    .into(),
                ),
                candidate_config_sha256: (!configured).then(|| "config-digest".into()),
                client_setup_may_have_run: false,
            };
            plan.add_pending_admin_resources(
                &config,
                vec![operation],
                &BTreeMap::new(),
                "config-digest",
            )
            .unwrap();
            assert_eq!(plan.nodes["worker"].host, "192.0.2.20");
            assert_eq!(plan.nodes["worker"].ssh_port, Some(2222));
            assert_eq!(plan.nodes["worker"].remote_config, worker.remote_config);
            let mounts: Vec<_> = plan
                .mounts
                .iter()
                .filter(|mount| mount.node_id == "worker")
                .collect();
            assert_eq!(mounts.len(), 1);
            assert_eq!(mounts[0].node.host, "192.0.2.20");
            assert_eq!(plan.exports["login-01"].specs[0].client_ip, "192.0.2.10");
            assert!(
                plan.aliases
                    .iter()
                    .filter(|alias| alias.server_id == "worker")
                    .all(|alias| alias.server.host == "192.0.2.20")
            );
        }
    }

    #[test]
    fn reset_journals_without_mode_keep_the_legacy_rebuild_behavior() {
        let mut value = serde_json::to_value(journal()).unwrap();
        value
            .as_object_mut()
            .expect("journal serializes as an object")
            .remove("mode");

        let legacy: ResetJournal = serde_json::from_value(value).unwrap();

        assert_eq!(legacy.mode, ResetMode::RebuildAfterCleanup);
        assert!(legacy.target_context.is_some());
    }

    fn test_config(name: &str, uuid: &str) -> macluster_core::config::ClusterConfig {
        macluster_core::config::ClusterConfig::parse(&test_config_source(name, uuid)).unwrap()
    }

    fn test_config_source(name: &str, uuid: &str) -> String {
        format!(
            "[cluster]\nname = \"{name}\"\nlogin_node = \"login-01\"\ndefault_queue = \"default\"\nshared_root = \"/Users/Shared/macluster\"\nshare_uuid = \"{uuid}\"\nstorage_server = \"login-01\"\nprotocol_version = 1\n\n[queues.default]\nnodes = [\"login-01\"]\nscheduler = \"fifo\"\n\n[nodes.login-01]\nhost = \"192.168.2.2\"\ntransport = \"local\"\nremote_binary = \"/usr/local/bin/macluster\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n"
        )
    }
}
