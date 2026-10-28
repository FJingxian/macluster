//! Detached supervisor for a single whole-node task.

mod interactive;
mod task_logs;

pub fn serve_attach_stdio<R, W>(
    input: &mut R,
    output: &mut W,
    state_dir: &Path,
    node_id: &str,
    job_id: u64,
    token: StartToken,
) -> Result<(), AgentError>
where
    R: std::io::Read + std::os::fd::AsRawFd,
    W: std::io::Write + std::os::fd::AsRawFd,
{
    interactive::serve_attach_stdio(input, output, state_dir, node_id, job_id, token)
}

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use macluster_protocol::{
    framing::sha256_hex,
    identifiers::{Id128, StartToken},
    types::{
        ACTIVE_ENV_PREFIX_ENV, EXPLICIT_TASK_PATH_ENV, JobState, RuntimePhase,
        VERBOSE_TASK_LOG_ENV, VERBOSE_TASK_LOG_FILES,
    },
};

use crate::{AgentError, AgentRecord, active_record, local_script_path, write_active};

const BASE_TASK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const LOCAL_JOB_LOG_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const LOCAL_JOB_LOG_PAYLOADS: &[&str] = &[
    "script.sh",
    "stdout.log",
    "stderr.log",
    "monitor.log",
    "resources.jsonl",
    "summary.json",
    "stdout.segments",
    "stderr.segments",
    "monitor.segments",
    "resources.segments",
];
const RESERVED_VERBOSE_OUTPUT_ERROR: &str = "task output path is reserved for verbose task logs; choose a different stdout/stderr destination";
const TASK_GATE_SCRIPT: &str = "gate=$1; shift; tries=0; while [ ! -e \"$gate\" ]; do tries=$((tries + 1)); [ \"$tries\" -lt 1000 ] || exit 125; /bin/sleep 0.01; done; /bin/rm -f \"$gate\"; exec \"$@\"";

/// Bound synchronized per-task log spools on this node while preserving the
/// small execution receipts that the controller may still need for recovery.
pub(crate) fn prune_synced_log_payloads(
    state_dir: &Path,
    current: &AgentRecord,
) -> io::Result<usize> {
    let jobs_root = state_dir.join("jobs");
    let entries = match fs::read_dir(&jobs_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut eligible = Vec::new();
    for entry in entries {
        let entry = entry?;
        let Some(job_id) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u64>().ok())
        else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let mut terminal_at = None;
        for receipt in fs::read_dir(entry.path())? {
            let receipt = receipt?;
            let name = receipt.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("execution-") || !name.ends_with(".json") {
                continue;
            }
            let receipt_meta = fs::symlink_metadata(receipt.path())?;
            if !receipt_meta.is_file() || receipt_meta.file_type().is_symlink() {
                continue;
            }
            let Ok(record) = serde_json::from_slice::<AgentRecord>(&fs::read(receipt.path())?)
            else {
                continue;
            };
            if record.job_id == job_id
                && record.controller.controller_uuid == current.controller.controller_uuid
                && record.share_uuid == current.share_uuid
                && record.terminal_state.is_some()
                && !record.log_sync_pending
            {
                terminal_at = Some(terminal_at.map_or(record.started_unix_ms, |time: u64| {
                    time.min(record.started_unix_ms)
                }));
            }
        }
        if let Some(terminal_at) = terminal_at {
            let directory = entry.path();
            let bytes = local_log_payload_size(&directory)?;
            if bytes > 0 {
                eligible.push((terminal_at, job_id, directory, bytes));
            }
        }
    }
    let mut total = eligible
        .iter()
        .fold(0_u64, |sum, (_, _, _, bytes)| sum.saturating_add(*bytes));
    if total <= LOCAL_JOB_LOG_LIMIT_BYTES {
        return Ok(0);
    }
    eligible.sort_by_key(|(started, job_id, _, _)| (*started, *job_id));
    let mut pruned = 0;
    for (_, _, directory, _bytes) in eligible {
        if total <= LOCAL_JOB_LOG_LIMIT_BYTES {
            break;
        }
        let _lock = match LogSyncLock::acquire(&directory.join(".log-sync.lock")) {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        };
        let bytes = local_log_payload_size(&directory)?;
        remove_local_log_payloads(&directory)?;
        total = total.saturating_sub(bytes);
        pruned += 1;
    }
    Ok(pruned)
}

fn local_log_payload_size(directory: &Path) -> io::Result<u64> {
    let mut total = 0_u64;
    for name in LOCAL_JOB_LOG_PAYLOADS {
        total = total.saturating_add(local_tree_size(&directory.join(name))?);
    }
    Ok(total)
}

fn local_tree_size(path: &Path) -> io::Result<u64> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let mut total = 0_u64;
        for entry in fs::read_dir(path)? {
            total = total.saturating_add(local_tree_size(&entry?.path())?);
        }
        Ok(total)
    } else {
        Ok(metadata.len())
    }
}

fn remove_local_log_payloads(directory: &Path) -> io::Result<()> {
    for name in LOCAL_JOB_LOG_PAYLOADS {
        let path = directory.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub fn run(state_dir: &Path, job_id: u64, token: StartToken) -> Result<(), AgentError> {
    let record = wait_for_authorization(state_dir, job_id, token)?;
    match run_authorized(state_dir, job_id, token, record) {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Ok(mut record) = active_record(state_dir, job_id, token)
                && record.child_pid.is_none()
                && !record.terminal()
            {
                record.phase = RuntimePhase::Idle;
                record.terminal_state = Some(JobState::Failed);
                record.end_reason = Some(format!("runner failed before starting task: {error}"));
                let _ = write_active(state_dir, record);
            }
            Err(error)
        }
    }
}

fn run_authorized(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    mut record: AgentRecord,
) -> Result<(), AgentError> {
    if record.spec.mode == macluster_protocol::types::JobMode::Interactive {
        return interactive::run_authorized(state_dir, job_id, token, record);
    }
    let shared_root = PathBuf::from(&record.shared_root).canonicalize()?;
    if verbose_output_conflict(
        &record,
        &shared_root,
        &[
            Path::new(&record.spec.stdout_path),
            Path::new(&record.spec.stderr_path),
        ],
    )? {
        return fail_record(state_dir, record, RESERVED_VERBOSE_OUTPUT_ERROR);
    }
    let output_roots = permitted_output_roots(&record, &shared_root)?;
    let local_dir = state_dir.join("jobs").join(job_id.to_string());
    fs::create_dir_all(&local_dir)?;
    fs::set_permissions(&local_dir, fs::Permissions::from_mode(0o700))?;
    let stdout_local = local_dir.join("stdout.log");
    let stderr_local = local_dir.join("stderr.log");
    let stdout_path = resolve_output(&record.spec.stdout_path, job_id, &output_roots)?;
    let stderr_path = resolve_output(&record.spec.stderr_path, job_id, &output_roots)?;
    if verbose_output_conflict(&record, &shared_root, &[&stdout_path, &stderr_path])? {
        return fail_record(state_dir, record, RESERVED_VERBOSE_OUTPUT_ERROR);
    }
    if stdout_path == stderr_path {
        return fail_record(
            state_dir,
            record,
            "stdout and stderr resolve to the same path",
        );
    }
    if stdout_path.exists() || stderr_path.exists() {
        return fail_record(state_dir, record, "output path already exists");
    }

    let verbose_logs = record
        .spec
        .env
        .get(VERBOSE_TASK_LOG_ENV)
        .is_some_and(|value| value == "1");
    let (stdout, stderr) = if verbose_logs {
        (Stdio::piped(), Stdio::piped())
    } else {
        let stdout = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stdout_local)?;
        let stderr = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&stderr_local)?;
        (Stdio::from(stdout), Stdio::from(stderr))
    };
    let script_path = local_script_path(state_dir, job_id);
    let task_command = build_task_command(&script_path)?;
    let gate_path = local_dir.join(format!(".task-gate-{}", Id128::random()));
    let mut command = gated_task_command(task_command, &gate_path);
    configure_task_environment(&mut command, job_id, &record)?;
    command
        .current_dir(&record.spec.cwd)
        .stdout(stdout)
        .stderr(stderr)
        .stdin(Stdio::null())
        .process_group(0);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return fail_record(state_dir, record, &format!("could not start task: {error}"));
        }
    };
    let child_pid = child.id();
    let mut log_session = if verbose_logs {
        let Some(stdout) = child.stdout.take() else {
            signal_group(child_pid, libc::SIGKILL);
            let _ = child.wait();
            return fail_record(
                state_dir,
                record,
                "verbose task stdout pipe was unavailable",
            );
        };
        let Some(stderr) = child.stderr.take() else {
            signal_group(child_pid, libc::SIGKILL);
            let _ = child.wait();
            return fail_record(
                state_dir,
                record,
                "verbose task stderr pipe was unavailable",
            );
        };
        match task_logs::TaskLogSession::start(
            &local_dir,
            record.controller.controller_uuid.to_string(),
            record.share_uuid.clone(),
            job_id,
            token,
            stdout,
            stderr,
        ) {
            Ok(session) => Some(session),
            Err(error) => {
                signal_group(child_pid, libc::SIGKILL);
                let _ = child.wait();
                return fail_record(
                    state_dir,
                    record,
                    &format!("could not start verbose task logging: {error}"),
                );
            }
        }
    } else {
        None
    };
    let Some(child_start_id) = super::wait_for_process_start_identity(child_pid) else {
        signal_group(child_pid, libc::SIGKILL);
        let _ = child.wait();
        if let Some(session) = log_session.take() {
            let _ = session.finish();
        }
        return fail_record(state_dir, record, "could not verify task process identity");
    };
    record.child_pid = Some(child_pid);
    record.child_start_id = Some(child_start_id);
    record.phase = RuntimePhase::Running;
    if let Err(error) = write_active(state_dir, record.clone()) {
        signal_group(child_pid, libc::SIGKILL);
        let _ = child.wait();
        if let Some(session) = log_session.take() {
            let _ = session.finish();
        }
        return Err(error);
    }
    if let Err(error) = release_task_gate(&gate_path) {
        signal_group(child_pid, libc::SIGKILL);
        let _ = child.wait();
        if let Some(session) = log_session.take() {
            let _ = session.finish();
        }
        let _ = fs::remove_file(&gate_path);
        return fail_record(
            state_dir,
            record,
            &format!("could not release task start gate: {error}"),
        );
    }

    let mut result = match monitor_task(
        state_dir,
        &mut child,
        job_id,
        token,
        child_pid,
        record.spec.walltime_secs,
        log_session.as_mut(),
    ) {
        Ok(result) => result,
        Err(error) => {
            signal_group(child_pid, libc::SIGTERM);
            let began = Instant::now();
            while child.try_wait()?.is_none() && began.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(25));
            }
            let status = if let Some(status) = child.try_wait()? {
                status
            } else {
                signal_group(child_pid, libc::SIGKILL);
                child.wait()?
            };
            TaskResult {
                state: JobState::Failed,
                exit_code: status.code(),
                reason: Some(format!("task monitor failed: {error}")),
            }
        }
    };
    if let Some(session) = log_session.take() {
        match session.finish() {
            Ok(completion) => {
                if let Some(reason) = completion.raw_capture_failed {
                    result.state = JobState::Failed;
                    result.reason = Some(format!("raw task log capture failed: {reason}"));
                }
                if let Some(reason) = completion.annotation_failed {
                    eprintln!("macluster-agent: enhanced task log failed: {reason}");
                }
            }
            Err(error) => {
                eprintln!("macluster-agent: could not seal enhanced task logs: {error}");
            }
        }
    }
    crate::finalize_active(
        state_dir,
        job_id,
        token,
        result.state,
        result.exit_code,
        result.reason,
    )?;
    Ok(())
}

fn configure_task_environment(
    command: &mut Command,
    job_id: u64,
    record: &AgentRecord,
) -> Result<(), AgentError> {
    let cargo_target = cargo_target_directory(record)?;
    let cargo_home = cargo_home_directory(record)?;
    let ccache = compiler_cache_directory(record, "CCACHE_DIR", "ccache")?;
    let sccache = compiler_cache_directory(record, "SCCACHE_DIR", "sccache")?;
    if cargo_target_is_managed(record) {
        ensure_private_cache(&cargo_target, "cargo-target")?;
    }
    if cargo_home_is_managed(record) {
        ensure_private_cache(&cargo_home, "cargo-home")?;
    }
    if compiler_cache_is_managed(record, "CCACHE_DIR") {
        ensure_private_cache(&ccache, "ccache")?;
    }
    if compiler_cache_is_managed(record, "SCCACHE_DIR") {
        ensure_private_cache(&sccache, "sccache")?;
    }
    command
        .env_clear()
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("USER", std::env::var_os("USER").unwrap_or_default())
        .env("TMPDIR", std::env::temp_dir())
        .env("TMP", std::env::temp_dir())
        .env("TEMP", std::env::temp_dir())
        .env("PATH", task_path(record))
        .env("MCLUSTER_JOB_ID", job_id.to_string())
        .env("MCLUSTER_JOB_NAME", &record.spec.name)
        .env("MCLUSTER_QUEUE", record.spec.queue.as_str())
        .env("MCLUSTER_NODE", &record.node_id)
        .env("MCLUSTER_CPUS", logical_cpu_count().to_string())
        .env("MCLUSTER_SUBMIT_DIR", &record.spec.cwd);
    for (key, value) in &record.spec.env {
        if key != "PATH"
            && key != EXPLICIT_TASK_PATH_ENV
            && key != ACTIVE_ENV_PREFIX_ENV
            && key != "CARGO_TARGET_DIR"
            && key != "CARGO_HOME"
            && key != "CCACHE_DIR"
            && key != "SCCACHE_DIR"
            && !key.starts_with("MCLUSTER_")
        {
            command.env(key, value);
        }
    }
    command.env("CARGO_TARGET_DIR", cargo_target);
    command.env("CARGO_HOME", cargo_home);
    command.env("CCACHE_DIR", ccache);
    command.env("SCCACHE_DIR", sccache);
    command.env("PWD", &record.spec.cwd);
    if let Some(logname) = std::env::var_os("LOGNAME") {
        command.env("LOGNAME", logname);
    }
    Ok(())
}

fn cargo_target_directory(record: &AgentRecord) -> Result<PathBuf, AgentError> {
    if let Some(path) = record
        .spec
        .env
        .get("CARGO_TARGET_DIR")
        .filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    managed_cache_directory(record, "cargo-target", true)
}

fn cargo_target_is_managed(record: &AgentRecord) -> bool {
    record
        .spec
        .env
        .get("CARGO_TARGET_DIR")
        .is_none_or(|value| value.is_empty())
}

fn cargo_home_directory(record: &AgentRecord) -> Result<PathBuf, AgentError> {
    if let Some(path) = record
        .spec
        .env
        .get("CARGO_HOME")
        .filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    managed_cache_directory(record, "cargo-home", false)
}

fn cargo_home_is_managed(record: &AgentRecord) -> bool {
    record
        .spec
        .env
        .get("CARGO_HOME")
        .is_none_or(|value| value.is_empty())
}

fn compiler_cache_directory(
    record: &AgentRecord,
    env_key: &str,
    cache_kind: &str,
) -> Result<PathBuf, AgentError> {
    if let Some(path) = record
        .spec
        .env
        .get(env_key)
        .filter(|value| !value.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    managed_cache_directory(record, cache_kind, false)
}

fn compiler_cache_is_managed(record: &AgentRecord, env_key: &str) -> bool {
    record
        .spec
        .env
        .get(env_key)
        .is_none_or(|value| value.is_empty())
}

fn managed_cache_directory(
    record: &AgentRecord,
    cache_kind: &str,
    include_project: bool,
) -> Result<PathBuf, AgentError> {
    if cache_kind.is_empty()
        || !cache_kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AgentError::State("invalid managed cache kind".into()));
    }
    let namespace = record
        .spec
        .storage_namespace
        .map(|namespace| namespace.to_string())
        .or_else(|| record.share_uuid.clone())
        .ok_or_else(|| {
            AgentError::State(format!(
                "job has no storage namespace for {cache_kind} cache"
            ))
        })?;
    let mut key = String::new();
    if include_project {
        let working_directory = Path::new(&record.spec.cwd).canonicalize()?;
        key.push_str(&working_directory.display().to_string());
        key.push('\0');
    }
    for (name, value) in &record.spec.env {
        if is_toolchain_cache_variable(name) {
            key.push_str(name);
            key.push('=');
            key.push_str(value);
            key.push('\0');
        }
    }
    let digest = sha256_hex(key.as_bytes()).map_err(|error| {
        AgentError::State(format!("could not hash {cache_kind} cache key: {error}"))
    })?;
    let temp_root = std::env::temp_dir().canonicalize()?;
    Ok(temp_root
        .join("macluster")
        .join(cache_kind)
        .join(namespace)
        .join(digest))
}

fn is_toolchain_cache_variable(key: &str) -> bool {
    matches!(
        key,
        "PATH"
            | "CC"
            | "CXX"
            | "CPP"
            | "AR"
            | "AS"
            | "LD"
            | "RANLIB"
            | "NM"
            | "STRIP"
            | "FC"
            | "F77"
            | "F90"
            | "RUSTC"
            | "RUSTFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_HOME"
            | "RUSTUP_HOME"
            | "SDKROOT"
            | "DEVELOPER_DIR"
            | "CFLAGS"
            | "CPPFLAGS"
            | "CXXFLAGS"
            | "LDFLAGS"
            | "FFLAGS"
            | "FCFLAGS"
            | "OBJCFLAGS"
            | "OBJCXXFLAGS"
    ) || key == ACTIVE_ENV_PREFIX_ENV
        || key.ends_with("_FLAGS")
        || key.ends_with("_PATH")
        || key.ends_with("_DIR")
        || key.ends_with("_ROOT")
        || key.ends_with("_PREFIX")
        || key.ends_with("_SYSROOT")
        || key.ends_with("_TOOLCHAIN")
        || key.ends_with("_COMPILER")
        || key.ends_with("_LINKER")
        || key.starts_with("CMAKE_")
        || key.starts_with("CARGO_TARGET_")
        || key.starts_with("PKG_CONFIG")
}

fn ensure_private_cache(path: &Path, cache_kind: &str) -> Result<(), AgentError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    let temp_root = std::env::temp_dir().canonicalize()?;
    let managed_root = temp_root.join("macluster").join(cache_kind);
    let relative = path.strip_prefix(&temp_root).map_err(|_| {
        AgentError::State(format!(
            "automatic {cache_kind} cache path {} is outside the node temporary directory",
            path.display()
        ))
    })?;
    if !path.starts_with(&managed_root) {
        return Err(AgentError::State(format!(
            "automatic {cache_kind} cache path {} is outside {}",
            path.display(),
            managed_root.display()
        )));
    }

    let mut current = temp_root.clone();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(AgentError::State(
                "automatic Cargo cache path contains an invalid component".into(),
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(AgentError::State(format!(
                        "{cache_kind} cache path component {} is not a real directory",
                        current.display()
                    )));
                }
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(AgentError::State(format!(
                        "{cache_kind} cache directory {} must be owned by this account and private (mode 0700)",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(0o700).create(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current)?;
                        if !metadata.is_dir()
                            || metadata.file_type().is_symlink()
                            || metadata.uid() != unsafe { libc::geteuid() }
                            || metadata.permissions().mode() & 0o077 != 0
                        {
                            return Err(AgentError::State(format!(
                                "{cache_kind} cache directory {} was concurrently created without safe ownership or permissions",
                                current.display()
                            )));
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn task_path(record: &AgentRecord) -> String {
    let submitter_paths: Vec<String> = record
        .spec
        .env
        .get("PATH")
        .into_iter()
        .flat_map(|path| path.split(':'))
        .filter(|path| !path.is_empty())
        .filter(|path| task_path_entry_is_shared_or_system(path, record))
        .map(str::to_owned)
        .collect();
    let explicit_path = record
        .spec
        .env
        .get(EXPLICIT_TASK_PATH_ENV)
        .is_some_and(|value| value == "1");
    if explicit_path {
        return submitter_paths.join(":");
    }
    let mut shared_paths = vec![record.shared_root.clone()];
    shared_paths.push(
        Path::new(&record.shared_root)
            .join("bin")
            .to_string_lossy()
            .into_owned(),
    );
    shared_paths.extend(record.tool_paths.iter().cloned());
    let mut registered_bins = vec![
        Path::new(&record.shared_root)
            .join("bin")
            .to_string_lossy()
            .into_owned(),
    ];
    registered_bins.extend(
        record
            .tool_paths
            .iter()
            .filter(|path| {
                Path::new(path)
                    .file_name()
                    .is_some_and(|name| name == "bin")
            })
            .cloned(),
    );
    let selected_shared_environment = submitter_paths.iter().any(|path| {
        let path = Path::new(path);
        path.file_name().is_some_and(|name| name == "bin")
            && registered_bins.iter().any(|registered_bin| {
                Path::new(registered_bin)
                    .parent()
                    .is_some_and(|registered_root| path.starts_with(registered_root))
            })
    });

    let mut paths = Vec::new();
    let mut append_unique = |path: String| {
        if !paths.contains(&path) {
            paths.push(path);
        }
    };
    if selected_shared_environment {
        for path in &submitter_paths {
            append_unique(path.clone());
        }
    } else {
        for path in &registered_bins {
            append_unique(path.clone());
        }
        for path in &submitter_paths {
            append_unique(path.clone());
        }
    }
    for path in shared_paths {
        append_unique(path);
    }
    for path in BASE_TASK_PATH.split(':') {
        append_unique(path.to_owned());
    }
    paths.join(":")
}

fn task_path_entry_is_shared_or_system(path: &str, record: &AgentRecord) -> bool {
    const SYSTEM_PATH_ENTRIES: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    if SYSTEM_PATH_ENTRIES.contains(&path) {
        return true;
    }

    let path = Path::new(path);
    path.starts_with(&record.shared_root)
        || record
            .tool_paths
            .iter()
            .any(|root| path.starts_with(Path::new(root)))
}

pub(super) fn gated_task_command(task: Command, gate_path: &Path) -> Command {
    let program = task.get_program().to_os_string();
    let args: Vec<_> = task.get_args().map(|arg| arg.to_os_string()).collect();
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(TASK_GATE_SCRIPT)
        .arg("macluster-task-gate")
        .arg(gate_path)
        .arg(program)
        .args(args);
    command
}

pub(super) fn release_task_gate(path: &Path) -> io::Result<()> {
    let gate = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    drop(gate);
    Ok(())
}

struct TaskResult {
    state: JobState,
    exit_code: Option<i32>,
    reason: Option<String>,
}

fn monitor_task(
    state_dir: &Path,
    child: &mut Child,
    job_id: u64,
    token: StartToken,
    pgid: u32,
    walltime: Option<u64>,
    mut log_session: Option<&mut task_logs::TaskLogSession>,
) -> Result<TaskResult, AgentError> {
    let start = continuous_time_ns();
    let timeout = walltime.map(|seconds| u128::from(seconds).saturating_mul(1_000_000_000));
    let mut termination: Option<(JobState, String, Instant)> = None;
    let mut next_sample = Instant::now();
    let mut last_output_at = next_sample;
    let mut last_heartbeat_at = next_sample;
    let mut observed_output_bytes = 0;
    if let Some(session) = log_session.as_deref_mut() {
        session.initialize_sample(pgid);
        next_sample += Duration::from_secs(5);
    }
    loop {
        if let Some(session) = log_session.as_deref_mut() {
            if let Some(reason) = session.raw_error() {
                if termination.is_none() {
                    let reason = format!("raw task log capture failed: {reason}");
                    crate::mark_termination_cause(
                        state_dir,
                        job_id,
                        token,
                        JobState::Failed,
                        &reason,
                    )?;
                    termination = Some((JobState::Failed, reason, Instant::now()));
                    signal_group(pgid, libc::SIGTERM);
                }
            }
            let now = Instant::now();
            let output_bytes = session.output_bytes();
            if output_bytes != observed_output_bytes {
                observed_output_bytes = output_bytes;
                last_output_at = now;
            }
            if now >= next_sample {
                session.sample(pgid);
                next_sample = now + Duration::from_secs(5);
            }
            if now.duration_since(last_output_at) >= Duration::from_secs(5)
                && now.duration_since(last_heartbeat_at) >= Duration::from_secs(5)
            {
                session.heartbeat();
                last_heartbeat_at = now;
            }
        }
        let record = active_record(state_dir, job_id, token)?;
        if termination.is_none() {
            if let Some(cause) = record.termination_cause {
                let reason = record
                    .end_reason
                    .clone()
                    .unwrap_or_else(|| "task termination requested".into());
                termination = Some((cause, reason, Instant::now()));
                signal_group(
                    pgid,
                    if cause == JobState::Cancelled && record.force_cancel {
                        libc::SIGKILL
                    } else {
                        libc::SIGTERM
                    },
                );
            } else if timeout
                .is_some_and(|timeout| continuous_time_ns().saturating_sub(start) >= timeout)
            {
                crate::mark_termination_cause(
                    state_dir,
                    job_id,
                    token,
                    JobState::Timeout,
                    "walltime limit reached",
                )?;
                termination = Some((
                    JobState::Timeout,
                    "walltime limit reached".into(),
                    Instant::now(),
                ));
                signal_group(pgid, libc::SIGTERM);
            }
        }

        if termination
            .as_ref()
            .is_some_and(|(state, _, _)| *state == JobState::Cancelled)
            && record.force_cancel
        {
            signal_group(pgid, libc::SIGKILL);
        }

        if let Some(status) = child.try_wait()? {
            if let Some((state, reason, began)) = termination.as_ref() {
                if *state != JobState::Cancelled || !record.force_cancel {
                    terminate_group(pgid, *began);
                }
                return Ok(TaskResult {
                    state: *state,
                    exit_code: status.code(),
                    reason: Some(reason.clone()),
                });
            }
            if group_exists(pgid) {
                terminate_group(pgid, Instant::now());
                return Ok(TaskResult { state: JobState::Failed, exit_code: status.code(), reason: Some("task exited while background descendants remained; descendant processes were terminated".into()) });
            }
            return Ok(if status.success() {
                TaskResult {
                    state: JobState::Completed,
                    exit_code: status.code(),
                    reason: None,
                }
            } else {
                TaskResult {
                    state: JobState::Failed,
                    exit_code: status.code(),
                    reason: Some(format_exit(status)),
                }
            });
        }

        if let Some((state, reason, began)) = termination.as_ref() {
            if *state == JobState::Cancelled && record.force_cancel {
                let status = child.wait()?;
                return Ok(TaskResult {
                    state: *state,
                    exit_code: status.code(),
                    reason: Some(reason.clone()),
                });
            }
            if began.elapsed() >= Duration::from_secs(30) {
                signal_group(pgid, libc::SIGKILL);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn terminate_group(pgid: u32, began: Instant) {
    if !group_exists(pgid) {
        return;
    }
    signal_group(pgid, libc::SIGTERM);
    while group_exists(pgid) && began.elapsed() < Duration::from_secs(30) {
        thread::sleep(Duration::from_millis(100));
    }
    if group_exists(pgid) {
        signal_group(pgid, libc::SIGKILL);
    }
}

fn signal_group(pgid: u32, signal: i32) -> bool {
    let Ok(pgid) = i32::try_from(pgid) else {
        return false;
    };
    unsafe { libc::kill(-pgid, signal) == 0 }
}

fn group_exists(pgid: u32) -> bool {
    let Ok(pgid) = i32::try_from(pgid) else {
        return false;
    };
    if unsafe { libc::kill(-pgid, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn wait_for_authorization(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
) -> Result<AgentRecord, AgentError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let record = active_record(state_dir, job_id, token)?;
        if record.authorized {
            return Ok(record);
        }
        if record.terminal() {
            return Err(AgentError::State(
                "execution was revoked before launch".into(),
            ));
        }
        if Instant::now() >= deadline {
            return Err(AgentError::State("runner launch gate timed out".into()));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn permitted_output_roots(
    record: &AgentRecord,
    primary_root: &Path,
) -> Result<Vec<PathBuf>, AgentError> {
    let mut roots = vec![primary_root.to_path_buf()];
    for share in &record.named_shares {
        let mount_root = Path::new(&share.mount_root);
        if Path::new(&record.spec.stdout_path).starts_with(mount_root)
            || Path::new(&record.spec.stderr_path).starts_with(mount_root)
        {
            let root = crate::verify_agent_named_share(&record.node_id, share)?;
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
    }
    Ok(roots)
}

fn project_output_directory(path: &Path) -> Result<PathBuf, AgentError> {
    let mut ancestor = path;
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        suffix.push(
            ancestor
                .file_name()
                .ok_or_else(|| AgentError::State("output parent cannot be resolved".into()))?
                .to_os_string(),
        );
        ancestor = ancestor
            .parent()
            .ok_or_else(|| AgentError::State("output parent cannot be resolved".into()))?;
    }
    let mut projected = ancestor.canonicalize()?;
    for component in suffix.iter().rev() {
        projected.push(component);
    }
    Ok(projected)
}

fn resolve_output(
    path: &str,
    job_id: u64,
    shared_roots: &[PathBuf],
) -> Result<PathBuf, AgentError> {
    let expanded = PathBuf::from(path.replace("%j", &job_id.to_string()));
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        shared_roots
            .first()
            .ok_or_else(|| AgentError::State("no shared output root is configured".into()))?
            .join(expanded)
    };
    if absolute
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(AgentError::State(
            "output path contains a parent-directory component".into(),
        ));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| AgentError::State("output path has no parent".into()))?;
    let projected_parent = project_output_directory(parent)?;
    if !shared_roots
        .iter()
        .any(|root| projected_parent.starts_with(root))
    {
        return Err(AgentError::State(
            "output path escaped all configured shared roots".into(),
        ));
    }
    fs::create_dir_all(parent)?;
    let resolved_parent = parent.canonicalize()?;
    if !shared_roots
        .iter()
        .any(|root| resolved_parent.starts_with(root))
    {
        return Err(AgentError::State(
            "output path escaped all configured shared roots".into(),
        ));
    }
    Ok(resolved_parent.join(
        absolute
            .file_name()
            .ok_or_else(|| AgentError::State("output path has no filename".into()))?,
    ))
}

pub(super) fn sync_pending_logs(
    state_dir: &Path,
    record: &AgentRecord,
    mut progress: impl FnMut(),
) -> io::Result<()> {
    let local_job_dir = state_dir.join("jobs").join(record.job_id.to_string());
    fs::create_dir_all(&local_job_dir)?;
    fs::set_permissions(&local_job_dir, fs::Permissions::from_mode(0o700))?;
    let _lock = LogSyncLock::acquire(&local_job_dir.join(".log-sync.lock"))?;
    // Serialize before even looking at the share: mount/marker verification
    // itself can block on NFS and must not accumulate duplicate workers.
    crate::verify_record_primary_share(record)
        .map_err(|error| io::Error::other(error.to_string()))?;

    let shared_root = PathBuf::from(&record.shared_root).canonicalize()?;
    let output_roots = permitted_output_roots(record, &shared_root)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let stdout = resolve_output(&record.spec.stdout_path, record.job_id, &output_roots)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let stderr = resolve_output(&record.spec.stderr_path, record.job_id, &output_roots)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if stdout == stderr {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stdout and stderr resolve to the same path",
        ));
    }
    sync_log_with_progress(&local_job_dir.join("stdout.log"), &stdout, &mut progress)?;
    sync_log_with_progress(&local_job_dir.join("stderr.log"), &stderr, &mut progress)?;
    if record
        .spec
        .env
        .get(VERBOSE_TASK_LOG_ENV)
        .is_some_and(|value| value == "1")
    {
        let job_dir = record.spec.shared_job_dir(&shared_root, record.job_id);
        for name in VERBOSE_TASK_LOG_FILES {
            let local = local_job_dir.join(name);
            let requested = job_dir.join(name);
            let shared = resolve_output(&requested.to_string_lossy(), record.job_id, &output_roots)
                .map_err(|error| io::Error::other(error.to_string()))?;
            publish_sidecar_atomically(&local, &shared, &mut progress)?;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn publish_logs_for_test(
    state_dir: &Path,
    mut record: AgentRecord,
) -> Result<(), AgentError> {
    record.log_sync_pending = sync_pending_logs(state_dir, &record, || {}).is_err();
    record.log_sync_retry_after_unix_ms = record
        .log_sync_pending
        .then(|| crate::now_ms().saturating_add(crate::LOG_SYNC_RETRY_DELAY_MS));
    write_active(state_dir, record)
}

#[cfg(test)]
fn sync_log(local: &Path, shared: &Path) -> io::Result<()> {
    sync_log_with_progress(local, shared, &mut || {})
}

fn sync_log_with_progress(
    local: &Path,
    shared: &Path,
    progress: &mut dyn FnMut(),
) -> io::Result<()> {
    let mut local = File::open(local)?;
    let shared_metadata = match fs::symlink_metadata(shared) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let local_len = local.metadata()?.len();

    let Some(metadata) = shared_metadata else {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(shared)?;
        copy_log_contents(&mut local, &mut output, progress)?;
        output.sync_all()?;
        return Ok(());
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared output is not a regular file",
        ));
    }
    if metadata.len() > local_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared output is longer than the retained local output",
        ));
    }
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(shared)?;
    if !output.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared output is not a regular file",
        ));
    }
    let mut remaining = metadata.len();
    let mut local_chunk = [0_u8; 64 * 1024];
    let mut shared_chunk = [0_u8; 64 * 1024];
    while remaining > 0 {
        let count = remaining.min(local_chunk.len() as u64) as usize;
        local.read_exact(&mut local_chunk[..count])?;
        output.read_exact(&mut shared_chunk[..count])?;
        if local_chunk[..count] != shared_chunk[..count] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "shared output does not match the retained local output prefix",
            ));
        }
        remaining -= count as u64;
        progress();
    }
    if metadata.len() == local_len {
        // A previous attempt may have written all bytes but failed fsync.
        return output.sync_all();
    }
    local.seek(SeekFrom::Start(metadata.len()))?;
    output.seek(SeekFrom::End(0))?;
    copy_log_contents(&mut local, &mut output, progress)?;
    output.sync_all()
}

fn publish_sidecar_atomically(
    local: &Path,
    shared: &Path,
    progress: &mut dyn FnMut(),
) -> io::Result<()> {
    let local_metadata = fs::symlink_metadata(local)?;
    if local_metadata.file_type().is_symlink() || !local_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local task sidecar is not a regular file",
        ));
    }
    if shared.exists() {
        return compare_files(local, shared, progress);
    }
    let parent = shared
        .parent()
        .ok_or_else(|| io::Error::other("shared sidecar has no parent"))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        shared
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("sidecar"),
        Id128::random()
    ));
    let mut input = File::open(local)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)?;
    let copy_result =
        copy_log_contents(&mut input, &mut output, progress).and_then(|()| output.sync_all());
    if let Err(error) = copy_result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    match fs::hard_link(&temp, shared) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temp);
            return compare_files(local, shared, progress);
        }
        Err(error) => {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
    }
    fs::remove_file(&temp)?;
    File::open(parent)?.sync_all()
}

fn compare_files(left: &Path, right: &Path, progress: &mut dyn FnMut()) -> io::Result<()> {
    let metadata = fs::symlink_metadata(right)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "shared task sidecar is not a regular file",
        ));
    }
    let mut left = File::open(left)?;
    let mut right = File::open(right)?;
    if left.metadata()?.len() != right.metadata()?.len() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "shared task sidecar already exists with different contents",
        ));
    }
    let mut left_bytes = [0_u8; 64 * 1024];
    let mut right_bytes = [0_u8; 64 * 1024];
    loop {
        let left_count = left.read(&mut left_bytes)?;
        let right_count = right.read(&mut right_bytes)?;
        if left_count != right_count || left_bytes[..left_count] != right_bytes[..right_count] {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "shared task sidecar already exists with different contents",
            ));
        }
        if left_count == 0 {
            return Ok(());
        }
        progress();
    }
}

fn copy_log_contents(
    input: &mut File,
    output: &mut File,
    progress: &mut dyn FnMut(),
) -> io::Result<()> {
    let mut bytes = [0_u8; 64 * 1024];
    loop {
        let count = match input.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        output.write_all(&bytes[..count])?;
        progress();
    }
}

struct LogSyncLock(File);

impl LogSyncLock {
    fn acquire(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another process is synchronizing this job's logs",
                ));
            }
            return Err(error);
        }
        Ok(Self(file))
    }
}

impl Drop for LogSyncLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub(super) fn stop_orphan_task_group(pid: u32, expected_start_id: &str) -> bool {
    use crate::{ProcessIdentity, process_identity};

    let pgid = pid;
    match process_identity(pid, expected_start_id) {
        ProcessIdentity::Match => {
            let Ok(pid_i32) = i32::try_from(pid) else {
                return false;
            };
            if unsafe { libc::getpgid(pid_i32) } != pid_i32 {
                return false;
            }
        }
        // With no leader there is no start identity to verify. The old group
        // may have disappeared and its numeric ID been reused in the interim.
        ProcessIdentity::Gone => {
            return !group_exists(pgid) || group_has_only_zombies(pgid) == Some(true);
        }
        ProcessIdentity::Reused | ProcessIdentity::Unverifiable => return false,
    }
    if !group_exists(pgid) {
        return true;
    }

    signal_group(pgid, libc::SIGTERM);
    let grace_deadline = Instant::now() + Duration::from_secs(2);
    while group_exists(pgid) && Instant::now() < grace_deadline {
        if process_identity(pid, expected_start_id) == ProcessIdentity::Reused {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
    if !group_exists(pgid) {
        return true;
    }
    if group_has_only_zombies(pgid) == Some(true) {
        return true;
    }
    if process_identity(pid, expected_start_id) != ProcessIdentity::Match {
        return false;
    }
    signal_group(pgid, libc::SIGKILL);
    // Signal delivery is asynchronous: logs must not be published, nor the
    // node released, until the group has actually stopped executing.
    let kill_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if !group_exists(pgid) || group_has_only_zombies(pgid) == Some(true) {
            return true;
        }
        if process_identity(pid, expected_start_id) == ProcessIdentity::Reused
            || Instant::now() >= kill_deadline
        {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn group_has_only_zombies(pgid: u32) -> Option<bool> {
    let output = Command::new("/bin/ps")
        .args(["-axo", "pid=,pgid=,stat="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut found = false;
    for line in String::from_utf8(output.stdout).ok()?.lines() {
        let mut fields = line.split_whitespace();
        let _pid = fields.next()?.parse::<u32>().ok()?;
        let process_group = fields.next()?.parse::<u32>().ok()?;
        let status = fields.next()?;
        if process_group == pgid {
            found = true;
            if !status.starts_with('Z') {
                return Some(false);
            }
        }
    }
    found.then_some(true)
}

fn build_task_command(script: &Path) -> Result<Command, AgentError> {
    let bytes = fs::read(script)?;
    let first_line = bytes
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if let Some(shebang) = first_line.strip_prefix(b"#!") {
        let line = std::str::from_utf8(shebang)
            .map_err(|_| AgentError::State("script shebang is not UTF-8".into()))?;
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(interpreter) = fields.first() else {
            return Err(AgentError::State("script has an empty shebang".into()));
        };
        let mut command = Command::new(interpreter);
        command.args(&fields[1..]).arg(script);
        Ok(command)
    } else {
        let mut command = Command::new("/bin/bash");
        command.arg(script);
        Ok(command)
    }
}

fn logical_cpu_count() -> u32 {
    Command::new("/usr/sbin/sysctl")
        .args(["-n", "hw.logicalcpu"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(1)
}

fn format_exit(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "task terminated by a signal".into(),
        |code| format!("task exited with status {code}"),
    )
}

#[cfg(target_vendor = "apple")]
fn continuous_time_ns() -> u128 {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }
    let ticks = unsafe { mach_continuous_time() };
    let mut timebase = Timebase { numer: 0, denom: 0 };
    if unsafe { mach_timebase_info(&mut timebase) } != 0 || timebase.denom == 0 {
        return ticks as u128;
    }
    (ticks as u128).saturating_mul(timebase.numer as u128) / timebase.denom as u128
}

#[cfg(not(target_vendor = "apple"))]
fn continuous_time_ns() -> u128 {
    use std::sync::OnceLock;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}

fn verbose_output_conflict(
    record: &AgentRecord,
    shared_root: &Path,
    outputs: &[&Path],
) -> Result<bool, AgentError> {
    if record
        .spec
        .env
        .get(VERBOSE_TASK_LOG_ENV)
        .map(String::as_str)
        != Some("1")
    {
        return Ok(false);
    }
    if outputs.iter().any(|output| {
        [shared_root, Path::new(&record.shared_root)]
            .into_iter()
            .any(|root| record.spec.verbose_log_output_conflicts(root, output))
    }) {
        return Ok(true);
    }
    let directory =
        project_output_directory(&record.spec.shared_job_dir(shared_root, record.job_id))?;
    for output in outputs {
        let expanded = PathBuf::from(
            output
                .to_string_lossy()
                .replace("%j", &record.job_id.to_string()),
        );
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            shared_root.join(expanded)
        };
        let parent = absolute
            .parent()
            .ok_or_else(|| AgentError::State("output path has no parent".into()))?;
        let projected = project_output_directory(parent)?.join(
            absolute
                .file_name()
                .ok_or_else(|| AgentError::State("output path has no filename".into()))?,
        );
        if record
            .spec
            .verbose_log_output_conflicts_in(&directory, &projected)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn fail_record(state_dir: &Path, mut record: AgentRecord, reason: &str) -> Result<(), AgentError> {
    record.phase = RuntimePhase::Idle;
    record.terminal_state = Some(JobState::Failed);
    record.end_reason = Some(reason.to_owned());
    record.child_pid = None;
    record.child_start_id = None;
    crate::write_active(state_dir, record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use macluster_protocol::{
        identifiers::{ControllerUuid, Id128, QueueName},
        types::{ControllerEpoch, JobMode, JobSpec, SnapshotRef},
    };
    use std::{
        collections::BTreeMap,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn shebang_selects_interpreter_and_default_uses_bash() {
        let root = std::env::temp_dir().join(format!(
            "macluster-runner-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let script = root.join("script.sh");
        fs::write(&script, "#!/usr/bin/env python3\nprint('x')\n").unwrap();
        let command = build_task_command(&script).unwrap();
        assert_eq!(command.get_program(), "/usr/bin/env");
        assert_eq!(command.get_args().next().unwrap(), "python3");
        fs::write(&script, "echo x\n").unwrap();
        let command = build_task_command(&script).unwrap();
        assert_eq!(command.get_program(), "/bin/bash");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn task_gate_blocks_user_code_until_identity_can_be_persisted() {
        let root = std::env::temp_dir().join(format!(
            "macluster-task-gate-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let gate = root.join("ready");
        let output = root.join("ran");
        let mut task = Command::new("/bin/sh");
        task.args(["-c", "printf ran > \"$1\"", "test-task"])
            .arg(&output);
        let mut command = gated_task_command(task, &gate);
        command.process_group(0);
        let mut child = command.spawn().unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(!output.exists());

        release_task_gate(&gate).unwrap();
        assert!(child.wait().unwrap().success());
        assert_eq!(fs::read(&output).unwrap(), b"ran");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_path_expands_job_id_and_rejects_symlink_escape() {
        let root = std::env::temp_dir().join(format!(
            "macluster-output-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(root.join("jobs")).unwrap();
        let root = root.canonicalize().unwrap();
        assert_eq!(
            resolve_output(
                root.join("jobs/%j/out.log").to_str().unwrap(),
                42,
                std::slice::from_ref(&root)
            )
            .unwrap(),
            root.join("jobs/42/out.log")
        );
        #[cfg(unix)]
        std::os::unix::fs::symlink(std::env::temp_dir(), root.join("escape")).unwrap();
        #[cfg(unix)]
        assert!(
            resolve_output(
                root.join("escape/out.log").to_str().unwrap(),
                42,
                std::slice::from_ref(&root)
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn log_sync_retries_a_matching_partial_file_without_duplicating_output() {
        let (root, state_dir, _token) = ready_state("echo unused\n", None);
        let local_job = state_dir.join("jobs/1");
        let shared_job = root.join("shared/jobs/1");
        let local = local_job.join("stdout.log");
        let shared = shared_job.join("stdout.log");
        fs::create_dir_all(&shared_job).unwrap();
        fs::write(&local, b"first\nsecond\n").unwrap();
        fs::write(&shared, b"first\n").unwrap();

        sync_log(&local, &shared).unwrap();
        sync_log(&local, &shared).unwrap();

        assert_eq!(fs::read(shared).unwrap(), b"first\nsecond\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_retained_log_is_not_reported_as_synchronized() {
        let (root, state_dir, _token) = ready_state("echo unused\n", None);
        let shared = root.join("shared/jobs/1/stdout.log");
        assert!(sync_log(&state_dir.join("jobs/1/stdout.log"), &shared).is_err());
        assert!(!shared.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn log_sync_refuses_to_append_to_a_conflicting_file() {
        let (root, state_dir, _token) = ready_state("echo unused\n", None);
        let local_job = state_dir.join("jobs/1");
        let shared_job = root.join("shared/jobs/1");
        let local = local_job.join("stdout.log");
        let shared = shared_job.join("stdout.log");
        fs::create_dir_all(&shared_job).unwrap();
        fs::write(&local, b"expected output\n").unwrap();
        fs::write(&shared, b"different\n").unwrap();

        assert!(sync_log(&local, &shared).is_err());
        assert_eq!(fs::read(shared).unwrap(), b"different\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn per_job_log_sync_lock_is_nonblocking_and_exclusive() {
        let root = std::env::temp_dir().join(format!(
            "macluster-log-lock-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(".log-sync.lock");
        let first = LogSyncLock::acquire(&path).unwrap();
        assert_eq!(
            LogSyncLock::acquire(&path).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first);
        assert!(LogSyncLock::acquire(&path).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn orphan_task_group_is_stopped_only_for_the_recorded_process_identity() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let start_id = crate::wait_for_process_start_identity(child.id()).unwrap();
        assert_eq!(
            crate::process_identity(child.id(), &start_id),
            crate::ProcessIdentity::Match
        );
        assert_eq!(
            unsafe { libc::getpgid(child.id() as i32) },
            child.id() as i32
        );
        assert!(group_exists(child.id()));

        assert!(stop_orphan_task_group(child.id(), &start_id));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "task process did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn orphan_recovery_waits_for_sigkill_to_take_effect() {
        let root = std::env::temp_dir().join(format!("macluster-orphan-kill-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let ready = root.join("ready");
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' TERM; printf ready > \"$1\"; while :; do :; done",
                "test-orphan",
            ])
            .arg(&ready)
            .process_group(0)
            .spawn()
            .unwrap();
        let start_id = crate::wait_for_process_start_identity(child.id()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !ready.exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let stopped = stop_orphan_task_group(child.id(), &start_id);
        let exited_at_return = child.try_wait().unwrap().is_some();
        if !exited_at_return {
            let _ = child.kill();
            let _ = child.wait();
        }
        fs::remove_dir_all(root).unwrap();
        assert!(stopped);
        assert!(
            exited_at_return,
            "recovery returned before SIGKILL stopped the task"
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn missing_leader_identity_does_not_authorize_killing_a_live_group() {
        let mut leader = Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 & /bin/sleep 0.05; exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = leader.id();
        leader.wait().unwrap();
        assert!(group_exists(pgid));
        let stopped = stop_orphan_task_group(pgid, "identity-of-an-unrelated-previous-task");
        let remained_live = group_has_only_zombies(pgid) == Some(false);
        signal_group(pgid, libc::SIGKILL);
        assert!(
            !stopped,
            "a missing leader cannot establish process-group identity"
        );
        assert!(remained_live, "recovery signalled an unverified group");
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn orphan_descendants_require_manual_cleanup_without_a_verifiable_leader() {
        let mut leader = Command::new("/bin/sh")
            .args(["-c", "/bin/sleep 30 & exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let pgid = leader.id();
        let start_id = crate::wait_for_process_start_identity(pgid).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(leader.wait().unwrap().success());
        assert_eq!(
            crate::process_identity(pgid, &start_id),
            crate::ProcessIdentity::Gone
        );
        assert!(group_exists(pgid));
        assert_eq!(group_has_only_zombies(pgid), Some(false));

        assert!(!stop_orphan_task_group(pgid, &start_id));
        assert_eq!(group_has_only_zombies(pgid), Some(false));
        // This test owns the fixture group and may explicitly clean it up.
        signal_group(pgid, libc::SIGKILL);
        let deadline = Instant::now() + Duration::from_secs(3);
        while group_exists(pgid) && group_has_only_zombies(pgid) != Some(true) {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(25));
        }
        assert!(stop_orphan_task_group(pgid, &start_id));
    }

    fn ready_state(script: &str, timeout: Option<u64>) -> (PathBuf, PathBuf, StartToken) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-runner-it-{}-{nonce}",
            std::process::id()
        ));
        let state_dir = root.join("agent");
        let shared = root.join("shared");
        let job_dir = state_dir.join("jobs/1");
        fs::create_dir_all(&job_dir).unwrap();
        fs::create_dir_all(shared.join("projects")).unwrap();
        fs::write(
            shared.join(".macluster-share-id"),
            "00000000-0000-4000-8000-000000000001\n",
        )
        .unwrap();
        fs::write(job_dir.join("script.sh"), script).unwrap();
        let shared = shared.canonicalize().unwrap();
        let token = StartToken(Id128::random());
        let spec = JobSpec {
            storage_namespace: None,
            queue: QueueName::new("mini01").unwrap(),
            node: None,
            name: "test".into(),
            cwd: shared.join("projects").to_string_lossy().into_owned(),
            stdout_path: shared
                .join("jobs/%j/stdout.log")
                .to_string_lossy()
                .into_owned(),
            stderr_path: shared
                .join("jobs/%j/stderr.log")
                .to_string_lossy()
                .into_owned(),
            walltime_secs: timeout,
            env: BTreeMap::new(),
            mode: JobMode::Batch,
            snapshot: Some(SnapshotRef {
                sha256: "a".repeat(64),
                size_bytes: script.len() as u64,
            }),
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
            phase: RuntimePhase::Launching,
            authorized: true,
            runner_pid: Some(std::process::id()),
            runner_start_id: crate::process_start_identity(std::process::id()),
            child_pid: None,
            child_start_id: None,
            task_start_gated: true,
            share_uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            storage_node_id: Some("mini01-a".into()),
            storage_host: Some("127.0.0.1".into()),
            storage_source_root: Some(shared.to_string_lossy().into_owned()),
            terminal_state: None,
            exit_code: None,
            end_reason: None,
            termination_cause: None,
            cancel_requested: false,
            force_cancel: false,
            boot_id: "boot".into(),
            log_sync_pending: false,
            log_sync_retry_after_unix_ms: None,
            started_unix_ms: 1,
        };
        let store = crate::AgentStore {
            controller: Some(record.controller),
            active: Some(record),
            tombstones: Vec::new(),
            log_sync_shutdown: None,
            ..Default::default()
        };
        crate::write_store(&state_dir, &store).unwrap();
        (root, state_dir, token)
    }

    #[test]
    fn regression_verbose_output_collision_is_rejected_without_pending_sync() {
        for (path, stderr) in [
            ("monitor.log", false),
            ("resources.jsonl", true),
            ("summary.json", false),
            ("monitor.log/child.log", false),
            ("MONITOR.LOG", false),
            ("", false),
        ] {
            let (root, state_dir, token) =
                ready_state("#!/bin/sh\necho task-ran > started\n", None);
            let mut record = crate::active_record(&state_dir, 1, token).unwrap();
            record
                .spec
                .env
                .insert(VERBOSE_TASK_LOG_ENV.into(), "1".into());
            if path.is_empty() {
                record.spec.stderr_path = root
                    .join("shared/projects/custom.stderr")
                    .to_string_lossy()
                    .into_owned();
            }
            let output = record
                .spec
                .shared_job_dir(&root.join("shared"), 1)
                .join(path)
                .to_string_lossy()
                .into_owned();
            if stderr {
                record.spec.stderr_path = output;
            } else {
                record.spec.stdout_path = output;
            }
            crate::write_active(&state_dir, record).unwrap();
            run(&state_dir, 1, token).unwrap();
            let record = crate::active_record(&state_dir, 1, token).unwrap();
            let started = root.join("shared/projects/started").exists();
            fs::remove_dir_all(root).unwrap();
            assert_eq!(record.terminal_state, Some(JobState::Failed));
            assert!(
                record
                    .end_reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("reserved")
            );
            assert!(!record.log_sync_pending);
            assert!(!started);
        }
    }

    #[test]
    fn regression_verbose_output_collision_through_metadata_alias_is_rejected() {
        for job_alias in [false, true] {
            let (root, state_dir, token) =
                ready_state("#!/bin/sh\necho task-ran > started\n", None);
            let shared = root.join("shared");
            let target = shared.join("logdata");
            fs::create_dir(&target).unwrap();
            if job_alias {
                fs::create_dir(shared.join("jobs")).unwrap();
                std::os::unix::fs::symlink(&target, shared.join("jobs/1")).unwrap();
            } else {
                std::os::unix::fs::symlink(&target, shared.join("jobs")).unwrap();
            }
            let mut record = crate::active_record(&state_dir, 1, token).unwrap();
            record
                .spec
                .env
                .insert(VERBOSE_TASK_LOG_ENV.into(), "1".into());
            record.spec.stdout_path = target
                .join(if job_alias {
                    "monitor.log"
                } else {
                    "1/monitor.log"
                })
                .to_string_lossy()
                .into_owned();
            crate::write_active(&state_dir, record).unwrap();
            run(&state_dir, 1, token).unwrap();
            let record = crate::active_record(&state_dir, 1, token).unwrap();
            let started = shared.join("projects/started").exists();
            fs::remove_dir_all(root).unwrap();
            assert_eq!(record.terminal_state, Some(JobState::Failed));
            assert!(!record.log_sync_pending);
            assert!(!started);
        }
    }

    #[test]
    fn verbose_custom_output_name_outside_metadata_publishes_normally() {
        let (root, state_dir, token) = ready_state("#!/bin/sh\necho log-content\n", None);
        let mut record = crate::active_record(&state_dir, 1, token).unwrap();
        record
            .spec
            .env
            .insert(VERBOSE_TASK_LOG_ENV.into(), "1".into());
        let output = root.join("shared/projects/monitor.log");
        record.spec.stdout_path = output.to_string_lossy().into_owned();
        crate::write_active(&state_dir, record).unwrap();
        run(&state_dir, 1, token).unwrap();
        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Completed));
        publish_logs_for_test(&state_dir, record).unwrap();
        assert!(
            !crate::active_record(&state_dir, 1, token)
                .unwrap()
                .log_sync_pending
        );
        assert_eq!(fs::read_to_string(output).unwrap(), "log-content\n");
        assert!(
            fs::read_to_string(root.join("shared/jobs/1/monitor.log"))
                .unwrap()
                .contains("[stdout] log-content")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detached_runner_retains_logs_for_background_publication_after_exit() {
        let (root, state_dir, token) =
            ready_state("#!/bin/bash\necho task-output\necho task-error >&2\n", None);
        run(&state_dir, 1, token).unwrap();
        let state = crate::read_store(&state_dir).unwrap();
        let record = state.active.unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Completed));
        assert!(record.log_sync_pending);
        assert!(!root.join("shared/jobs/1/stdout.log").exists());
        publish_logs_for_test(&state_dir, record).unwrap();
        let record = crate::read_store(&state_dir).unwrap().active.unwrap();
        assert!(root.join("shared/jobs/1/stdout.log").exists());
        assert_eq!(
            fs::read_to_string(root.join("shared/jobs/1/stdout.log")).unwrap(),
            "task-output\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("shared/jobs/1/stderr.log")).unwrap(),
            "task-error\n"
        );
        assert!(!record.log_sync_pending);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    #[ignore = "manual no-output task benchmark; run with --ignored --nocapture"]
    fn benchmark_empty_task_resource_logging_overhead() {
        fn run_case(verbose: bool) -> (f64, f64, Option<serde_json::Value>, u64) {
            let (root, state_dir, token) = ready_state("#!/bin/bash\n/bin/sleep 8\n", None);
            if verbose {
                let mut record = crate::active_record(&state_dir, 1, token).unwrap();
                record
                    .spec
                    .env
                    .insert(VERBOSE_TASK_LOG_ENV.to_owned(), "1".to_owned());
                record.spec.env.insert(
                    macluster_protocol::types::VERBOSE_TASK_LOG_ROOT_ENV.to_owned(),
                    root.join("shared").to_string_lossy().into_owned(),
                );
                crate::write_active(&state_dir, record).unwrap();
            }

            let cpu_before = test_process_cpu_seconds();
            let began = Instant::now();
            run(&state_dir, 1, token).unwrap();
            let wall_seconds = began.elapsed().as_secs_f64();
            let cpu_seconds = (test_process_cpu_seconds() - cpu_before).max(0.0);
            let job_dir = state_dir.join("jobs/1");
            let summary = verbose.then(|| {
                serde_json::from_slice::<serde_json::Value>(
                    &fs::read(job_dir.join("summary.json")).unwrap(),
                )
                .unwrap()
            });
            let extra_log_bytes = ["monitor.log", "resources.jsonl", "summary.json"]
                .into_iter()
                .map(|name| fs::metadata(job_dir.join(name)).map_or(0, |metadata| metadata.len()))
                .sum();
            fs::remove_dir_all(root).unwrap();
            (wall_seconds, cpu_seconds, summary, extra_log_bytes)
        }

        fn test_process_cpu_seconds() -> f64 {
            let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
            assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) }, 0);
            let seconds =
                |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1_000_000.0;
            seconds(usage.ru_utime) + seconds(usage.ru_stime)
        }

        let baseline = run_case(false);
        let verbose = run_case(true);
        let summary = verbose.2.as_ref().unwrap();
        println!(
            "empty task baseline: wall={:.2}s runner_cpu={:.4}s; verbose: wall={:.2}s runner_cpu={:.4}s sampler_cpu={:.4}s sampled_rss_growth={}B samples={} additional_logs={}B",
            baseline.0,
            baseline.1,
            verbose.0,
            verbose.1,
            summary["runner_cpu_user_seconds"].as_f64().unwrap_or(0.0)
                + summary["runner_cpu_system_seconds"].as_f64().unwrap_or(0.0),
            summary["runner_peak_rss_sampled_growth_bytes"]
                .as_u64()
                .map_or_else(|| "N/A".to_owned(), |value| value.to_string()),
            summary["samples"].as_u64().unwrap_or(0),
            verbose.3,
        );
        assert!(verbose.2.is_some());
    }

    #[test]
    fn walltime_expiry_is_recorded_as_timeout() {
        let (root, state_dir, token) = ready_state("#!/bin/bash\nsleep 5\n", Some(1));
        run(&state_dir, 1, token).unwrap();
        let record = crate::read_store(&state_dir).unwrap().active.unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Timeout));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancel_and_exit_are_linearized_by_the_durable_record() {
        let (root, state_dir, token) = ready_state("echo x\n", None);
        crate::mark_termination_cause(
            &state_dir,
            1,
            token,
            JobState::Cancelled,
            "cancelled by user",
        )
        .unwrap();
        let cancelled =
            crate::finalize_active(&state_dir, 1, token, JobState::Completed, Some(0), None)
                .unwrap();
        assert_eq!(cancelled.terminal_state, Some(JobState::Cancelled));
        fs::remove_dir_all(root).unwrap();

        let (root, state_dir, token) = ready_state("echo x\n", None);
        let completed =
            crate::finalize_active(&state_dir, 1, token, JobState::Completed, Some(0), None)
                .unwrap();
        assert_eq!(completed.terminal_state, Some(JobState::Completed));
        crate::cancel_job(completed.controller, token, 1, false, &state_dir).unwrap();
        assert_eq!(
            crate::read_store(&state_dir)
                .unwrap()
                .active
                .unwrap()
                .terminal_state,
            Some(JobState::Completed)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn force_cancel_escalates_an_existing_graceful_cancel() {
        let (root, state_dir, token) = ready_state(
            "#!/bin/bash\ntrap '' TERM\nwhile :; do /bin/sleep 1; done\n",
            None,
        );
        let controller = crate::read_store(&state_dir)
            .unwrap()
            .active
            .unwrap()
            .controller;
        let thread_state_dir = state_dir.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let runner = thread::spawn(move || {
            let _ = sender.send(run(&thread_state_dir, 1, token));
        });

        let launch_deadline = Instant::now() + Duration::from_secs(3);
        while crate::active_record(&state_dir, 1, token)
            .unwrap()
            .child_pid
            .is_none()
        {
            assert!(Instant::now() < launch_deadline, "task did not start");
            thread::sleep(Duration::from_millis(20));
        }
        crate::cancel_job(controller, token, 1, false, &state_dir).unwrap();
        thread::sleep(Duration::from_millis(200));
        crate::cancel_job(controller, token, 1, true, &state_dir).unwrap();

        let result = receiver.recv_timeout(Duration::from_secs(5));
        if result.is_err()
            && let Ok(record) = crate::active_record(&state_dir, 1, token)
            && let Some(pid) = record.child_pid
        {
            signal_group(pid, libc::SIGKILL);
        }
        assert!(result.is_ok(), "forced cancellation did not stop the task");
        result.unwrap().unwrap();
        runner.join().unwrap();
        let final_record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(final_record.terminal_state, Some(JobState::Cancelled));
        fs::remove_dir_all(root).unwrap();
    }
}
