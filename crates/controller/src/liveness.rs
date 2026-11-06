//! Small durable liveness hints shared by the controller and `mnode -l`.
//!
//! Only health refreshes and liveness transitions are written, so the
//! periodic node monitor does not produce a steady stream of filesystem writes.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use macluster_protocol::types::NodeHealth;
use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "node-liveness.json";
const LOCK_FILE: &str = "node-liveness.lock";
pub const OFFLINE_AFTER_FAILURES: u8 = 3;
pub const RECENTLY_ONLINE_TTL_MS: u64 = 90_000;
const MIN_FAILURE_PROBE_INTERVAL_MS: u64 = 3_000;
const LAST_SEEN_PERSIST_INTERVAL_MS: u64 = 60_000;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeLiveness {
    pub identity_key: String,
    pub unreachable_since_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_transition_unix_ms: u64,
    #[serde(default)]
    pub consecutive_failures: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failed_probe_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reachable_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<NodeHealth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_sampled_unix_ms: Option<u64>,
}

impl NodeLiveness {
    pub fn is_confirmed_offline(&self) -> bool {
        self.consecutive_failures >= OFFLINE_AFTER_FAILURES
            && self.unreachable_since_unix_ms.is_some()
    }

    /// Whether a recent successful probe still makes this node visible as
    /// available. One or two missed probes remain inside the reconnect grace
    /// period; a confirmed outage or an expired reachability record does not.
    pub fn was_recently_reachable(&self, expected_identity: &str, now_ms: u64) -> bool {
        self.identity_key.eq_ignore_ascii_case(expected_identity)
            && !self.is_confirmed_offline()
            && self.unreachable_since_unix_ms.is_none()
            && self
                .last_reachable_unix_ms
                .is_some_and(|sampled| now_ms.saturating_sub(sampled) <= RECENTLY_ONLINE_TTL_MS)
    }
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

/// Read persisted node liveness and the latest Agent health snapshot.
pub fn read(state_dir: &Path, cluster_uuid: &str) -> io::Result<BTreeMap<String, NodeLiveness>> {
    with_locked_file(state_dir, cluster_uuid, |state, changed| {
        // Older versions persisted unreachable_since before the three-miss
        // threshold existed. Convert those records back into reconnecting
        // observations so an upgrade does not keep nodes hidden indefinitely.
        for record in state.nodes.values_mut() {
            if record.unreachable_since_unix_ms.is_some()
                && record.consecutive_failures < OFFLINE_AFTER_FAILURES
            {
                record.unreachable_since_unix_ms = None;
                record.consecutive_failures = record.consecutive_failures.max(1);
                record.last_failed_probe_unix_ms = Some(record.last_transition_unix_ms);
                *changed = true;
            }
            if record.last_reachable_unix_ms.is_none() && record.unreachable_since_unix_ms.is_none()
            {
                record.last_reachable_unix_ms = Some(record.last_transition_unix_ms);
                *changed = true;
            }
        }
        Ok(state.nodes.clone())
    })
}

/// Record node observations in one locked update and return their current
/// state. A node is confirmed offline only after three consecutive misses.
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
            let previous = old.as_ref();
            if !observation.reachable
                && previous
                    .and_then(|record| record.last_failed_probe_unix_ms)
                    .is_some_and(|last| {
                        observed_unix_ms.saturating_sub(last) < MIN_FAILURE_PROBE_INTERVAL_MS
                    })
            {
                result.insert(observation.node_id.clone(), old.expect("checked above"));
                continue;
            }
            let (
                consecutive_failures,
                unreachable_since_unix_ms,
                last_transition_unix_ms,
                last_reachable_unix_ms,
                last_failed_probe_unix_ms,
            ) = if observation.reachable {
                (
                    0,
                    None,
                    previous.map_or(observed_unix_ms, |record| {
                        if record.consecutive_failures > 0
                            || record.unreachable_since_unix_ms.is_some()
                        {
                            observed_unix_ms
                        } else {
                            record.last_transition_unix_ms
                        }
                    }),
                    Some(previous.map_or(observed_unix_ms, |record| {
                        record
                            .last_reachable_unix_ms
                            .map_or(observed_unix_ms, |last_seen| {
                                if observed_unix_ms.saturating_sub(last_seen)
                                    >= LAST_SEEN_PERSIST_INTERVAL_MS
                                {
                                    observed_unix_ms
                                } else {
                                    last_seen
                                }
                            })
                    })),
                    None,
                )
            } else {
                let failures = previous.map_or(1, |record| {
                    record
                        .consecutive_failures
                        .saturating_add(1)
                        .min(OFFLINE_AFTER_FAILURES)
                });
                let offline_since = previous
                    .and_then(|record| record.unreachable_since_unix_ms)
                    .or_else(|| (failures >= OFFLINE_AFTER_FAILURES).then_some(observed_unix_ms));
                let crossed_offline_threshold = previous.is_none_or(|record| {
                    record.unreachable_since_unix_ms.is_none() && offline_since.is_some()
                });
                (
                    failures,
                    offline_since,
                    if crossed_offline_threshold {
                        observed_unix_ms
                    } else {
                        previous.map_or(observed_unix_ms, |record| record.last_transition_unix_ms)
                    },
                    previous.and_then(|record| record.last_reachable_unix_ms),
                    Some(observed_unix_ms),
                )
            };
            let record = NodeLiveness {
                identity_key: observation.identity_key.clone(),
                unreachable_since_unix_ms,
                last_transition_unix_ms,
                consecutive_failures,
                last_failed_probe_unix_ms,
                last_reachable_unix_ms,
                health: previous.and_then(|record| record.health.clone()),
                health_sampled_unix_ms: previous.and_then(|record| record.health_sampled_unix_ms),
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

/// Save the most recent authenticated Agent health response for fast local
/// status commands. It also confirms that the node has returned after an
/// outage; execution safety still comes from fresh Status probes.
pub fn update_health(
    state_dir: &Path,
    cluster_uuid: &str,
    node_id: &str,
    identity_key: &str,
    health: NodeHealth,
    sampled_unix_ms: u64,
) -> io::Result<()> {
    with_locked_file(state_dir, cluster_uuid, |state, changed| {
        let previous = state.nodes.get(node_id).cloned();
        let same_machine = previous
            .as_ref()
            .is_some_and(|record| same_identity(Some(&record.identity_key), Some(identity_key)));
        let mut record = if same_machine {
            previous.expect("checked above")
        } else {
            NodeLiveness {
                identity_key: identity_key.to_owned(),
                unreachable_since_unix_ms: None,
                last_transition_unix_ms: sampled_unix_ms,
                consecutive_failures: 0,
                last_failed_probe_unix_ms: None,
                last_reachable_unix_ms: Some(sampled_unix_ms),
                health: None,
                health_sampled_unix_ms: None,
            }
        };
        if record
            .health_sampled_unix_ms
            .is_some_and(|previous_ms| sampled_unix_ms < previous_ms)
        {
            return Ok(());
        }
        let recovered =
            record.unreachable_since_unix_ms.is_some() || record.consecutive_failures > 0;
        record.unreachable_since_unix_ms = None;
        record.consecutive_failures = 0;
        record.last_failed_probe_unix_ms = None;
        if recovered {
            record.last_transition_unix_ms = sampled_unix_ms;
        }
        record.health = Some(health);
        record.health_sampled_unix_ms = Some(sampled_unix_ms);
        record.last_reachable_unix_ms = Some(sampled_unix_ms);
        if state.nodes.get(node_id) != Some(&record) {
            state.nodes.insert(node_id.to_owned(), record);
            *changed = true;
        }
        Ok(())
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
    fn liveness_requires_three_failed_probes_and_clears_on_recovery() {
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
        let first = observe_many(&root, "cluster-1", &[offline.clone()], 3_100).unwrap();
        assert_eq!(first["compute-001"].consecutive_failures, 1);
        assert_eq!(first["compute-001"].unreachable_since_unix_ms, None);
        let repeated = observe_many(&root, "cluster-1", &[offline.clone()], 6_100).unwrap();
        assert_eq!(repeated["compute-001"].consecutive_failures, 2);
        assert_eq!(repeated["compute-001"].unreachable_since_unix_ms, None);
        let confirmed = observe_many(&root, "cluster-1", &[offline.clone()], 9_100).unwrap();
        assert_eq!(confirmed["compute-001"].consecutive_failures, 3);
        assert_eq!(
            confirmed["compute-001"].unreachable_since_unix_ms,
            Some(9_100)
        );
        let repeated_offline =
            observe_many(&root, "cluster-1", &[offline.clone()], 12_100).unwrap();
        assert_eq!(
            repeated_offline["compute-001"].unreachable_since_unix_ms,
            Some(9_100)
        );

        let recovered = NodeObservation {
            reachable: true,
            ..offline.clone()
        };
        let online_record = observe_many(&root, "cluster-1", &[recovered.clone()], 15_100).unwrap();
        assert_eq!(online_record["compute-001"].unreachable_since_unix_ms, None);
        assert_eq!(online_record["compute-001"].consecutive_failures, 0);
        let stale = observe_many(&root, "cluster-1", &[offline], 14_100).unwrap();
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
