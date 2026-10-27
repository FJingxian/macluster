//! Detached publication workers. Scheduling touches local state only.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::config::ClusterConfig;
use macluster_protocol::identifiers::{Id128, StartToken};
use serde::{Deserialize, Serialize};

use crate::{
    AgentError, AgentRecord, LOG_SYNC_RETRY_DELAY_MS, StateLock, commit_log_sync_result,
    hydrate_record_storage_identity, now_ms, read_store, runner, write_store,
};

pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub(super) fn schedule(state_dir: &Path, config: &ClusterConfig) -> Result<(), AgentError> {
    schedule_with(state_dir, config, |job_id, token| {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--state-dir")
            .arg(state_dir)
            .args(["internal", "log-sync", "--job-id"])
            .arg(job_id.to_string())
            .arg("--start-token")
            .arg(token.to_string())
            .current_dir(state_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The SSH request process can exit without closing this worker's
        // session. The watchdog may signal only this private process group.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let _ = thread::Builder::new()
            .name("log-sync-reaper".into())
            .spawn(move || {
                let _ = child.wait();
            });
        Ok(())
    })
}

#[derive(Deserialize, Serialize)]
struct WorkerOwner {
    pid: u32,
    start_id: String,
    boot_id: String,
    job_id: u64,
    start_token: StartToken,
}

struct Registration {
    owner_path: PathBuf,
    _lifecycle: File,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.owner_path);
    }
}

fn lifecycle_file(state: &Path) -> io::Result<File> {
    let metadata = fs::symlink_metadata(state)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other("agent state is not a real directory"));
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(state.join("log-sync-lifecycle.lock"))
}

fn try_lock(file: &File, mode: i32) -> io::Result<bool> {
    if unsafe { libc::flock(file.as_raw_fd(), mode | libc::LOCK_NB) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

fn register_worker(
    state: &Path,
    job_id: u64,
    token: StartToken,
) -> Result<(AgentRecord, Registration), AgentError> {
    let lifecycle = lifecycle_file(state)?;
    if !try_lock(&lifecycle, libc::LOCK_SH)? {
        return Err(AgentError::Busy);
    }
    let _state_lock = StateLock::acquire_existing(state)?;
    let store = read_store(state)?;
    if store.log_sync_shutdown.is_some() {
        return Err(AgentError::State(
            "log publication is stopped for cluster reset".into(),
        ));
    }
    let snapshot = store
        .active
        .filter(|record| record.job_id == job_id && record.start_token == token)
        .ok_or_else(|| AgentError::State("active execution identity changed".into()))?;
    if !snapshot.terminal() {
        return Err(AgentError::Busy);
    }
    let pid = std::process::id();
    let owner = WorkerOwner {
        pid,
        start_id: crate::process_start_identity(pid)
            .ok_or_else(|| AgentError::State("cannot verify log publisher identity".into()))?,
        boot_id: crate::boot_id(),
        job_id,
        start_token: token,
    };
    let registry = state.join("log-sync-workers");
    fs::create_dir_all(&registry)?;
    let owner_path = registry.join(format!("{pid}-{}.json", Id128::random()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&owner_path)?;
    file.write_all(
        &serde_json::to_vec(&owner).map_err(|error| AgentError::State(error.to_string()))?,
    )?;
    file.sync_all()?;
    Ok((
        snapshot,
        Registration {
            owner_path,
            _lifecycle: lifecycle,
        },
    ))
}

fn job_locks_released(state: &Path) -> io::Result<bool> {
    let jobs = match fs::read_dir(state.join("jobs")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };
    for entry in jobs {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let lock = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(entry.path().join(".log-sync.lock"))
        {
            Ok(lock) => lock,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !try_lock(&lock, libc::LOCK_EX)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Persist a reset barrier, stop only verified publication workers, then prove
/// all publication/lifecycle locks were released before reset may archive state.
pub fn quiesce(
    state: &Path,
    expected_share: Id128,
    reset_id: Id128,
    timeout: Duration,
) -> Result<(), AgentError> {
    if !state.exists() {
        return Ok(());
    }
    let lifecycle = lifecycle_file(state)?;
    {
        let _lock = StateLock::acquire_existing(state)?;
        let mut store = read_store(state)?;
        if store.pending_handoff.is_some() {
            return Err(AgentError::Busy);
        }
        if !crate::admin::namespace_owned(state, &store, &expected_share.to_string())? {
            // Foreign and unknown account state belongs to another reset. Do
            // not set its shutdown barrier or signal its publication workers.
            return Ok(());
        }
        if crate::admin::records(state, &store)?
            .iter()
            .any(|record| !record.terminal())
        {
            return Err(AgentError::Busy);
        }
        if store
            .log_sync_shutdown
            .is_some_and(|existing| existing != reset_id)
        {
            return Err(AgentError::State(
                "log publication is fenced by a different reset; resume the original reset".into(),
            ));
        }
        store.log_sync_shutdown = Some(reset_id);
        write_store(state, &store)?;
    }
    let registry = state.join("log-sync-workers");
    let deadline = Instant::now() + timeout;
    let boot = crate::boot_id();
    loop {
        if try_lock(&lifecycle, libc::LOCK_EX)? {
            if job_locks_released(state)? {
                if registry.exists() {
                    fs::remove_dir_all(&registry)?;
                }
                return Ok(());
            }
            unsafe {
                libc::flock(lifecycle.as_raw_fd(), libc::LOCK_UN);
            }
        }
        if let Ok(entries) = fs::read_dir(&registry) {
            for entry in entries {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .is_none_or(|extension| extension != "json")
                {
                    continue;
                }
                if !entry.file_type()?.is_file() {
                    return Err(AgentError::State("invalid publisher identity file".into()));
                }
                let owner: WorkerOwner =
                    serde_json::from_slice(&fs::read(entry.path())?).map_err(|error| {
                        AgentError::State(format!("invalid publisher identity: {error}"))
                    })?;
                if owner.boot_id == boot
                    && crate::process_identity(owner.pid, &owner.start_id)
                        == crate::ProcessIdentity::Match
                    && unsafe { libc::getsid(owner.pid as i32) } == owner.pid as i32
                    && unsafe { libc::getpgid(owner.pid as i32) } == owner.pid as i32
                {
                    if unsafe { libc::kill(-(owner.pid as i32), libc::SIGKILL) } != 0
                        && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                    {
                        return Err(io::Error::last_os_error().into());
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(AgentError::State("a log publisher still holds files open; reset remains fenced, restore NFS connectivity and retry the same reset".into()));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn schedule_with(
    state_dir: &Path,
    config: &ClusterConfig,
    launch: impl FnOnce(u64, StartToken) -> io::Result<()>,
) -> Result<(), AgentError> {
    let snapshot = {
        let _lock = StateLock::acquire(state_dir)?;
        let mut store = read_store(state_dir)?;
        if store.log_sync_shutdown.is_some() {
            return Ok(());
        }
        let Some(record) = store.active.as_mut().filter(|record| {
            record.terminal()
                && record.log_sync_pending
                && record
                    .log_sync_retry_after_unix_ms
                    .is_none_or(|after| after <= now_ms())
        }) else {
            return Ok(());
        };
        hydrate_record_storage_identity(record, config);
        record.log_sync_retry_after_unix_ms =
            Some(now_ms().saturating_add(LOG_SYNC_RETRY_DELAY_MS));
        let snapshot = record.clone();
        write_store(state_dir, &store)?;
        snapshot
    };
    // Path comparison is local; mounting, marker reads and all other shared
    // filesystem operations belong exclusively to the worker.
    if Path::new(&snapshot.shared_root) != config.shared_root {
        return Err(AgentError::State(
            "task output root differs from the configured primary share".into(),
        ));
    }
    if let Err(error) = launch(snapshot.job_id, snapshot.start_token) {
        let message = error.to_string();
        commit_log_sync_result(state_dir, snapshot, Err(error))
            .map_err(|error| AgentError::State(error.to_string()))?;
        return Err(AgentError::State(format!(
            "could not launch log publisher: {message}"
        )));
    }
    Ok(())
}

/// Entry point for the internal CLI worker. Never runs in the Status process.
pub fn run(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    idle_timeout: Duration,
) -> Result<(), AgentError> {
    if idle_timeout.is_zero() {
        return Err(AgentError::State(
            "log publication idle timeout must be positive".into(),
        ));
    }
    let pid = unsafe { libc::getpid() };
    if unsafe { libc::getsid(0) } != pid || unsafe { libc::getpgrp() } != pid {
        return Err(AgentError::State(
            "log publisher requires its own detached session".into(),
        ));
    }
    let (snapshot, _registration) = register_worker(state_dir, job_id, token)?;
    if !snapshot.terminal() {
        return Err(AgentError::State(
            "cannot publish logs for a running task".into(),
        ));
    }
    if !snapshot.log_sync_pending {
        return Ok(());
    }

    let progress = Arc::new(AtomicU64::new(0));
    let (finished, completion) = mpsc::channel();
    let watchdog_progress = Arc::clone(&progress);
    let watchdog_snapshot = snapshot.clone();
    let watchdog_state = state_dir.to_owned();
    let watchdog = thread::Builder::new()
        .name("log-sync-watchdog".into())
        .spawn(move || {
            let tick = (idle_timeout / 4)
                .min(Duration::from_secs(1))
                .max(Duration::from_millis(1));
            let mut last_progress = Instant::now();
            let mut previous = 0;
            loop {
                match completion.recv_timeout(tick) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
                let current = watchdog_progress.load(Ordering::Relaxed);
                if current != previous {
                    previous = current;
                    last_progress = Instant::now();
                }
                if last_progress.elapsed() >= idle_timeout {
                    let _ = commit_log_sync_result(
                        &watchdog_state,
                        watchdog_snapshot,
                        Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "log publication made no progress before its idle deadline",
                        )),
                    );
                    // A hard-mounted NFS call may not exit immediately on SIGKILL.
                    // Its still-open flock prevents another worker entering NFS.
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    return;
                }
            }
        })?;

    let result = runner::sync_pending_logs(state_dir, &snapshot, || {
        progress.fetch_add(1, Ordering::Relaxed);
    });
    let error = result.as_ref().err().map(ToString::to_string);
    let _ = finished.send(());
    let _ = watchdog.join();
    commit_log_sync_result(state_dir, snapshot, result)
        .map_err(|error| AgentError::State(error.to_string()))?;
    match error {
        Some(error) => Err(AgentError::State(error)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{status_config, status_fixture};
    use macluster_protocol::types::JobState;

    #[test]
    fn concurrent_status_requests_schedule_only_one_launch_per_retry_interval() {
        let (root, state, _token, shared) =
            status_fixture("coalesced-workers", "boot", Some(JobState::Completed), true);
        let config = status_config(&shared);
        let launches = AtomicU64::new(0);
        thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    schedule_with(&state, &config, |_, _| {
                        launches.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    })
                    .unwrap()
                });
            }
        });
        assert_eq!(launches.load(Ordering::Relaxed), 1);
        assert!(read_store(&state).unwrap().active.unwrap().log_sync_pending);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_refuses_active_tasks_without_setting_a_shutdown_barrier() {
        let (root, state, _token, _shared) = status_fixture("reset-active", "boot", None, false);
        let result = quiesce(
            &state,
            Id128::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            Id128::random(),
            Duration::from_millis(50),
        );
        assert!(matches!(result, Err(AgentError::Busy)));
        assert!(read_store(&state).unwrap().log_sync_shutdown.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_does_not_signal_a_reused_registry_pid() {
        let (root, state, token, _shared) =
            status_fixture("reset-stale-owner", "boot", Some(JobState::Completed), true);
        let lifecycle = lifecycle_file(&state).unwrap();
        assert!(try_lock(&lifecycle, libc::LOCK_SH).unwrap());
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut unrelated = command.spawn().unwrap();
        let registry = state.join("log-sync-workers");
        fs::create_dir_all(&registry).unwrap();
        fs::write(
            registry.join("stale.json"),
            serde_json::to_vec(&WorkerOwner {
                pid: unrelated.id(),
                start_id: "wrong-start-identity".into(),
                boot_id: crate::boot_id(),
                job_id: 1,
                start_token: token,
            })
            .unwrap(),
        )
        .unwrap();
        let result = quiesce(
            &state,
            Id128::parse("00000000-0000-4000-8000-000000000001").unwrap(),
            Id128::random(),
            Duration::from_millis(75),
        );
        let alive = unrelated.try_wait().unwrap().is_none();
        let _ = unrelated.kill();
        let _ = unrelated.wait();
        drop(lifecycle);
        fs::remove_dir_all(root).unwrap();
        assert!(
            result.is_err(),
            "reset must wait for the unregistered lifecycle holder"
        );
        assert!(alive, "a stale registry entry killed an unrelated process");
    }

    #[test]
    fn launch_failure_keeps_pending_state_and_backs_off() {
        let (root, state, _token, shared) = status_fixture(
            "worker-launch-failure",
            "boot",
            Some(JobState::Completed),
            true,
        );
        let config = status_config(&shared);
        assert!(
            schedule_with(&state, &config, |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "agent executable unavailable",
                ))
            })
            .is_err()
        );
        let active = read_store(&state).unwrap().active.unwrap();
        assert!(active.log_sync_pending);
        assert!(active.log_sync_retry_after_unix_ms.unwrap() > now_ms());
        schedule_with(&state, &config, |_, _| panic!("retry backoff was ignored")).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
