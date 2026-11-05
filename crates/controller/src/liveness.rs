//! Small durable liveness hints shared by the controller and `mnode -l`.
//!
//! Only transitions to/from unreachable are written, so the periodic node
//! monitor does not produce a steady stream of filesystem writes.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "node-liveness.json";
const LOCK_FILE: &str = "node-liveness.lock";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeLiveness {
    pub identity_key: String,
    pub unreachable_since_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_transition_unix_ms: u64,
}

#[derive(Clone, Debug)]
pub struct NodeObservation {
    pub node_id: String,
    pub identity_key: String,
    pub reachable: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct LivenessFile {
    cluster_uuid: String,
    nodes: BTreeMap<String, NodeLiveness>,
}

/// Read the persisted offline timestamps for one cluster namespace.
pub fn read(state_dir: &Path, cluster_uuid: &str) -> io::Result<BTreeMap<String, NodeLiveness>> {
    with_locked_file(state_dir, cluster_uuid, |state, _| Ok(state.nodes.clone()))
}

/// Record node observations in one locked update and return their current
/// transition records. Healthy records are small tombstones that prevent a
/// stale concurrent offline observation from restarting the grace period.
pub fn observe_many(
    state_dir: &Path,
    cluster_uuid: &str,
    observations: &[NodeObservation],
    observed_unix_ms: u64,
) -> io::Result<BTreeMap<String, NodeLiveness>> {
    with_locked_file(state_dir, cluster_uuid, |state, changed| {
        let mut result = BTreeMap::new();
        for observation in observations {
            let mut old = state.nodes.get(&observation.node_id).cloned();
            let same_machine = old.as_ref().is_some_and(|record| {
                same_identity(Some(&record.identity_key), Some(&observation.identity_key))
            });
            if !same_machine && old.is_some() {
                state.nodes.remove(&observation.node_id);
                *changed = true;
                old = None;
            }
            if old
                .as_ref()
                .is_some_and(|record| observed_unix_ms < record.last_transition_unix_ms)
            {
                result.insert(observation.node_id.clone(), old.expect("checked above"));
                continue;
            }
            let record = if observation.reachable {
                NodeLiveness {
                    identity_key: observation.identity_key.clone(),
                    unreachable_since_unix_ms: None,
                    last_transition_unix_ms: old.as_ref().map_or(observed_unix_ms, |record| {
                        if record.unreachable_since_unix_ms.is_some() {
                            observed_unix_ms
                        } else {
                            record.last_transition_unix_ms
                        }
                    }),
                }
            } else if old
                .as_ref()
                .is_some_and(|record| record.unreachable_since_unix_ms.is_some())
            {
                old.as_ref().expect("checked above").clone()
            } else {
                NodeLiveness {
                    identity_key: observation.identity_key.clone(),
                    unreachable_since_unix_ms: Some(observed_unix_ms),
                    last_transition_unix_ms: observed_unix_ms,
                }
            };
            if old.as_ref() != Some(&record) {
                state
                    .nodes
                    .insert(observation.node_id.clone(), record.clone());
                *changed = true;
            }
            result.insert(observation.node_id.clone(), record);
        }
        Ok(result)
    })
}

fn same_identity(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

fn with_locked_file<T>(
    state_dir: &Path,
    cluster_uuid: &str,
    operation: impl FnOnce(&mut LivenessFile, &mut bool) -> io::Result<T>,
) -> io::Result<T> {
    fs::create_dir_all(state_dir)?;
    let lock_path = state_dir.join(LOCK_FILE);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let path = state_dir.join(STATE_FILE);
    let mut state = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "node liveness file has unsafe ownership or permissions",
                ));
            }
            let mut bytes = Vec::new();
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)?
                .read_to_end(&mut bytes)?;
            serde_json::from_slice::<LivenessFile>(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => LivenessFile::default(),
        Err(error) => return Err(error),
    };
    let namespace_changed = state.cluster_uuid != cluster_uuid;
    if namespace_changed {
        state = LivenessFile {
            cluster_uuid: cluster_uuid.to_owned(),
            nodes: BTreeMap::new(),
        };
    }
    let mut changed = namespace_changed;
    let result = operation(&mut state, &mut changed)?;
    if changed {
        write_atomic(&path, &state)?;
    }
    Ok(result)
}

fn write_atomic(path: &Path, state: &LivenessFile) -> io::Result<()> {
    let directory = path.parent().expect("state file has a parent");
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(
        ".{STATE_FILE}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, state)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(directory)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "macluster-liveness-{}",
            macluster_protocol::identifiers::Id128::random()
        ))
    }

    #[test]
    fn offline_grace_survives_repeated_probes_and_clears_on_recovery() {
        let root = temp_dir();
        let online = NodeObservation {
            node_id: "compute-001".into(),
            identity_key: "machine-uuid-1".into(),
            reachable: true,
        };
        let offline = NodeObservation {
            reachable: false,
            ..online.clone()
        };

        observe_many(&root, "cluster-1", &[online], 100).unwrap();
        let first = observe_many(&root, "cluster-1", &[offline.clone()], 200).unwrap();
        assert_eq!(first["compute-001"].unreachable_since_unix_ms, Some(200));
        let repeated = observe_many(&root, "cluster-1", &[offline.clone()], 300).unwrap();
        assert_eq!(repeated["compute-001"].unreachable_since_unix_ms, Some(200));
        assert_eq!(
            read(&root, "cluster-1").unwrap()["compute-001"].unreachable_since_unix_ms,
            Some(200)
        );

        let recovered = NodeObservation {
            reachable: true,
            ..offline.clone()
        };
        let online_record = observe_many(&root, "cluster-1", &[recovered.clone()], 400).unwrap();
        assert_eq!(online_record["compute-001"].unreachable_since_unix_ms, None);
        let stale = observe_many(&root, "cluster-1", &[offline], 350).unwrap();
        assert_eq!(stale["compute-001"].unreachable_since_unix_ms, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn liveness_is_scoped_to_the_cluster_namespace() {
        let root = temp_dir();
        let offline = NodeObservation {
            node_id: "compute-001".into(),
            identity_key: "machine-uuid-1".into(),
            reachable: false,
        };
        observe_many(&root, "cluster-1", &[offline], 100).unwrap();
        assert!(read(&root, "cluster-2").unwrap().is_empty());
        let _ = fs::remove_dir_all(root);
    }
}
