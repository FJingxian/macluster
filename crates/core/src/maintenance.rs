//! Cross-process exclusion for configuration mutations.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResetBarrierPolicy {
    pub discard_terminal_sync: bool,
}

pub fn maintenance_barrier_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".macluster-maintenance.json");
    config_path.with_file_name(name)
}

pub fn read_maintenance_barrier(
    path: &Path,
    expected_config: &Path,
    expected_state: &Path,
) -> io::Result<bool> {
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "maintenance barrier is not a regular file",
        ));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        // The flock, rather than the marker's continued existence, indicates
        // whether maintenance is running. A process crash releases its lock
        // while leaving the marker behind.
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::WouldBlock {
        return Err(error);
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let barrier: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let version = barrier
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "maintenance barrier has no version",
            )
        })?;
    if version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported maintenance barrier version {version}"),
        ));
    }
    barrier
        .get("owner_pid")
        .and_then(serde_json::Value::as_u64)
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "maintenance barrier has an invalid owner PID",
            )
        })?;
    let config_path = barrier
        .get("config_path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "maintenance barrier has no config path",
            )
        })?;
    let state_dir = barrier
        .get("state_dir")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "maintenance barrier has no state directory",
            )
        })?;
    if normalized_path(Path::new(config_path)) != normalized_path(expected_config)
        || normalized_path(Path::new(state_dir)) != normalized_path(expected_state)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "maintenance barrier belongs to a different config or state directory",
        ));
    }
    Ok(true)
}

pub fn read_reset_barrier_policy(
    path: &Path,
    expected_config: &Path,
    expected_state: &Path,
) -> io::Result<Option<ResetBarrierPolicy>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let journal: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let version = journal
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "reset journal has no version")
        })?;
    if version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported reset journal version {version}"),
        ));
    }
    let phase = journal
        .get("phase")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "reset journal has no phase"))?;
    if !matches!(
        phase,
        "DRAINING" | "CLEANING" | "REMOTE_CONFIGS" | "ARCHIVING" | "INSTALLING" | "COMPLETE"
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown reset journal phase {phase}"),
        ));
    }
    let config_path = journal
        .get("config_path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "reset journal has no config path",
            )
        })?;
    let state_dir = journal
        .get("state_dir")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "reset journal has no state directory",
            )
        })?;
    if normalized_path(Path::new(config_path)) != normalized_path(expected_config)
        || normalized_path(Path::new(state_dir)) != normalized_path(expected_state)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reset journal belongs to a different config or state directory",
        ));
    }
    let discard_terminal_sync = match journal.get("discard_terminal_sync") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "reset journal force policy is not a boolean",
            )
        })?,
    };
    Ok(Some(ResetBarrierPolicy {
        discard_terminal_sync,
    }))
}

fn normalized_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

#[derive(Debug)]
pub struct MaintenanceLock {
    _file: File,
}

impl MaintenanceLock {
    /// Hold a shared lock for a controller lifetime. It waits for an active
    /// node maintenance operation to finish before loading configuration.
    pub fn shared(config_path: &Path) -> io::Result<Self> {
        Self::acquire(config_path, libc::LOCK_SH)
    }

    /// Hold a shared lock only if no exclusive maintenance operation is active.
    pub fn try_shared(config_path: &Path) -> io::Result<Self> {
        Self::acquire(config_path, libc::LOCK_SH | libc::LOCK_NB)
    }

    /// Node mutations must fail promptly while a controller or submit command
    /// is using this configuration.
    pub fn exclusive(config_path: &Path) -> io::Result<Self> {
        Self::acquire(config_path, libc::LOCK_EX | libc::LOCK_NB)
    }

    /// Acquire the same per-config lock before first creation of the config.
    /// The lock path is derived from a canonical parent so competing first-run
    /// initializers agree on one lock even though the config does not exist yet.
    pub fn exclusive_for_creation(config_path: &Path) -> io::Result<Self> {
        let file_name = config_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "config path has no filename")
        })?;
        let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let parent = fs::canonicalize(parent)?;
        Self::acquire_resolved(&parent.join(file_name), libc::LOCK_EX | libc::LOCK_NB)
    }

    /// Bind the cluster configuration to one local job-state directory so a
    /// later node removal cannot silently inspect a different database.
    pub fn bind_state_dir(config_path: &Path, state_dir: &Path) -> io::Result<()> {
        let config_path = fs::canonicalize(config_path)?;
        fs::create_dir_all(state_dir)?;
        let state_dir = fs::canonicalize(state_dir)?;
        let marker = binding_path(&config_path);
        if marker.exists() {
            let bound = fs::read_to_string(&marker)?;
            if bound.trim() != state_dir.to_string_lossy() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "cluster config is bound to state directory '{}', not '{}'",
                        bound.trim(),
                        state_dir.display()
                    ),
                ));
            }
            return Ok(());
        }
        let temp = marker.with_file_name(format!(
            ".{}.{}.tmp",
            marker.file_name().unwrap_or_default().to_string_lossy(),
            std::process::id()
        ));
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC)
                .open(&temp)?;
            writeln!(file, "{}", state_dir.display())?;
            file.sync_all()?;
            match fs::hard_link(&temp, &marker) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    let bound = fs::read_to_string(&marker)?;
                    if bound.trim() != state_dir.to_string_lossy() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "cluster config is already bound to state directory '{}'",
                                bound.trim()
                            ),
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
            File::open(marker.parent().expect("config path has a parent"))?.sync_all()?;
            Ok(())
        })();
        let _ = fs::remove_file(temp);
        result
    }

    /// Check an existing state-directory binding without creating one. This
    /// is used by read-only node listing so it cannot hide pending operations
    /// by pointing at another state directory.
    pub fn verify_state_dir_binding(config_path: &Path, state_dir: &Path) -> io::Result<()> {
        let config_path = fs::canonicalize(config_path)?;
        let marker = binding_path(&config_path);
        if !marker.exists() {
            return Ok(());
        }
        let requested = fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
        let bound = fs::read_to_string(marker)?;
        if bound.trim() != requested.to_string_lossy() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cluster config is bound to state directory '{}', not '{}'",
                    bound.trim(),
                    requested.display()
                ),
            ));
        }
        Ok(())
    }

    fn acquire(config_path: &Path, operation: libc::c_int) -> io::Result<Self> {
        let config_path = fs::canonicalize(config_path)?;
        Self::acquire_resolved(&config_path, operation)
    }

    fn acquire_resolved(config_path: &Path, operation: libc::c_int) -> io::Result<Self> {
        let lock_path = lock_path(&config_path);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(lock_path)?;
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { _file: file })
    }
}

fn lock_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".macluster.lock");
    config_path.with_file_name(name)
}

fn binding_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".macluster.state-dir");
    config_path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::{
        MaintenanceLock, maintenance_barrier_path, read_maintenance_barrier,
        read_reset_barrier_policy,
    };
    use std::{fs, io, os::fd::AsRawFd, path::PathBuf};

    #[test]
    fn exclusive_creation_lock_supports_a_config_that_does_not_exist_yet() {
        let root = std::env::temp_dir().join(format!(
            "macluster-maintenance-create-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = PathBuf::from(&root).join("config.toml");

        let lock = MaintenanceLock::exclusive_for_creation(&config).unwrap();
        let second = MaintenanceLock::exclusive_for_creation(&config).unwrap_err();
        assert_eq!(second.kind(), io::ErrorKind::WouldBlock);
        drop(lock);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn maintenance_barrier_is_bound_to_its_config_and_state() {
        let root = std::env::temp_dir().join(format!(
            "macluster-maintenance-barrier-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config = root.join("config.toml");
        let state = root.join("state");
        let barrier = maintenance_barrier_path(&config);
        fs::write(
            &barrier,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "config_path": config,
                "state_dir": state,
                "owner_pid": 1234
            }))
            .unwrap(),
        )
        .unwrap();

        let owner = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&barrier)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        assert!(read_maintenance_barrier(&barrier, &config, &state).unwrap());
        assert!(read_maintenance_barrier(&barrier, &root.join("other.toml"), &state).is_err());
        assert!(read_maintenance_barrier(&barrier, &config, &root.join("other-state")).is_err());
        drop(owner);
        assert!(!read_maintenance_barrier(&barrier, &config, &state).unwrap());

        fs::remove_dir_all(root).unwrap();
    }

    fn reset_paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "macluster-reset-policy-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("controller");
        fs::write(&config, "[cluster]\n").unwrap();
        fs::create_dir_all(&state).unwrap();
        let barrier = root.join("config.toml.macluster-reset.json");
        (root, barrier, config, state)
    }

    fn write_reset_policy(
        barrier: &std::path::Path,
        config: &std::path::Path,
        state: &std::path::Path,
        contents: serde_json::Value,
    ) {
        let mut value = contents;
        value["version"] = serde_json::json!(1);
        value["phase"] = serde_json::json!("DRAINING");
        value["config_path"] = serde_json::json!(config.to_string_lossy().to_string());
        value["state_dir"] = serde_json::json!(state.to_string_lossy().to_string());
        fs::write(barrier, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    #[test]
    fn reset_barrier_policy_is_absent_without_a_journal() {
        let (root, barrier, config, state) = reset_paths();

        assert_eq!(
            read_reset_barrier_policy(&barrier, &config, &state).unwrap(),
            None
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_barrier_policy_reads_force_and_defaults_old_journals_to_false() {
        let (root, barrier, config, state) = reset_paths();
        write_reset_policy(
            &barrier,
            &config,
            &state,
            serde_json::json!({"discard_terminal_sync": true}),
        );
        assert_eq!(
            read_reset_barrier_policy(&barrier, &config, &state)
                .unwrap()
                .unwrap()
                .discard_terminal_sync,
            true
        );

        write_reset_policy(&barrier, &config, &state, serde_json::json!({}));
        assert_eq!(
            read_reset_barrier_policy(&barrier, &config, &state)
                .unwrap()
                .unwrap()
                .discard_terminal_sync,
            false
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reset_barrier_policy_rejects_malformed_or_mismatched_journals() {
        let (root, barrier, config, state) = reset_paths();
        fs::write(&barrier, b"not-json").unwrap();
        assert!(read_reset_barrier_policy(&barrier, &config, &state).is_err());

        write_reset_policy(
            &barrier,
            &config,
            &state,
            serde_json::json!({"discard_terminal_sync": true}),
        );
        let wrong_config = root.join("other.toml");
        assert!(read_reset_barrier_policy(&barrier, &wrong_config, &state).is_err());
        let wrong_state = root.join("other-state");
        assert!(read_reset_barrier_policy(&barrier, &config, &wrong_state).is_err());

        let mut unsupported = serde_json::json!({"discard_terminal_sync": true});
        unsupported["version"] = serde_json::json!(2);
        unsupported["phase"] = serde_json::json!("DRAINING");
        unsupported["config_path"] = serde_json::json!(config.to_string_lossy().to_string());
        unsupported["state_dir"] = serde_json::json!(state.to_string_lossy().to_string());
        fs::write(&barrier, serde_json::to_vec(&unsupported).unwrap()).unwrap();
        assert!(read_reset_barrier_policy(&barrier, &config, &state).is_err());
        unsupported["version"] = serde_json::json!(1);
        unsupported["phase"] = serde_json::json!("UNKNOWN");
        fs::write(&barrier, serde_json::to_vec(&unsupported).unwrap()).unwrap();
        assert!(read_reset_barrier_policy(&barrier, &config, &state).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
