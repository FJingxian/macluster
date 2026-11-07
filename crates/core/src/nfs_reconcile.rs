//! Durable records for NFS state that must be reconciled after a node returns.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use macluster_protocol::{identifiers::Id128, nfs_admin::NfsExportCleanup};
use serde::{Deserialize, Serialize};

pub const DEFERRED_SHARE_CLEANUP_FILE: &str = "deferred-share-cleanup.json";
pub const DEFERRED_SHARE_CLEANUP_BACKUP_FILE: &str = "deferred-share-cleanup.json.bak";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeferredShareClientCleanup {
    pub share_id: String,
    pub node_id: String,
    pub source_root: String,
    pub mount_root: String,
    pub server_host: String,
    pub share_uuid: String,
    pub machine_uuid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeferredShareMarkerCleanup {
    pub share_id: String,
    pub node_id: String,
    pub source_root: String,
    pub share_uuid: String,
    pub machine_uuid: Option<String>,
    #[serde(default)]
    pub alias_target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeferredShareExportCleanup {
    pub share_id: String,
    pub node_id: String,
    pub source_root: String,
    pub client_ip: String,
    pub client_node_id: String,
    pub share_uuid: String,
    pub machine_uuid: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeferredShareCleanupState {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub entries: BTreeMap<String, DeferredShareClientCleanup>,
    #[serde(default)]
    pub marker_entries: BTreeMap<String, DeferredShareMarkerCleanup>,
    #[serde(default)]
    pub exports: BTreeMap<String, DeferredShareExportCleanup>,
}

pub fn client_cleanup_key(share_id: &str, node_id: &str, share_uuid: &str) -> String {
    format!("{share_id}/{node_id}/{share_uuid}")
}

pub fn marker_cleanup_key(share_id: &str, node_id: &str, share_uuid: &str) -> String {
    format!("marker/{share_id}/{node_id}/{share_uuid}")
}

pub fn export_cleanup_key(
    share_id: &str,
    node_id: &str,
    client_node_id: &str,
    share_uuid: &str,
) -> String {
    format!("export/{share_id}/{node_id}/{client_node_id}/{share_uuid}")
}

impl DeferredShareCleanupState {
    pub fn remove_client_cleanup_exact(&mut self, expected: &DeferredShareClientCleanup) -> bool {
        let key = client_cleanup_key(&expected.share_id, &expected.node_id, &expected.share_uuid);
        if self.entries.get(&key) == Some(expected) {
            return self.entries.remove(&key).is_some();
        }
        // Earlier versions keyed this journal by share/node without the UUID.
        // Acknowledge that exact old record by its serialized value, while
        // leaving any newer generation for the same share and node untouched.
        let legacy_key = format!("{}/{}", expected.share_id, expected.node_id);
        if self.entries.get(&legacy_key) == Some(expected) {
            return self.entries.remove(&legacy_key).is_some();
        }
        false
    }

    pub fn remove_marker_cleanup_exact(&mut self, expected: &DeferredShareMarkerCleanup) -> bool {
        let key = self
            .marker_entries
            .iter()
            .find(|(_, entry)| *entry == expected)
            .map(|(key, _)| key.clone());
        key.is_some_and(|key| self.marker_entries.remove(&key).is_some())
    }

    pub fn remove_export_cleanup_exact(&mut self, expected: &DeferredShareExportCleanup) -> bool {
        let key = export_cleanup_key(
            &expected.share_id,
            &expected.node_id,
            &expected.client_node_id,
            &expected.share_uuid,
        );
        if self.exports.get(&key) == Some(expected) {
            return self.exports.remove(&key).is_some();
        }
        false
    }

    pub fn export_requests_for_node(&self, node_id: &str) -> Vec<NfsExportCleanup> {
        self.exports
            .values()
            .filter(|entry| entry.node_id == node_id)
            .map(|entry| NfsExportCleanup {
                root: entry.source_root.clone(),
                client_ip: entry.client_ip.clone(),
                share_uuid: entry.share_uuid.clone(),
                node_id: entry.client_node_id.clone(),
            })
            .collect()
    }

    pub fn remove_client_cleanup(
        &mut self,
        share_id: &str,
        node_id: &str,
        share_uuid: &str,
    ) -> bool {
        let key = client_cleanup_key(share_id, node_id, share_uuid);
        let matches = self.entries.get(&key).is_some_and(|entry| {
            entry.share_id == share_id && entry.node_id == node_id && entry.share_uuid == share_uuid
        });
        matches && self.entries.remove(&key).is_some()
    }

    pub fn remove_marker_cleanup(
        &mut self,
        share_id: &str,
        node_id: &str,
        source_root: &str,
        share_uuid: &str,
    ) -> bool {
        let key = self
            .marker_entries
            .iter()
            .find(|(_, entry)| {
                entry.share_id == share_id
                    && entry.node_id == node_id
                    && entry.source_root == source_root
                    && entry.share_uuid == share_uuid
            })
            .map(|(key, _)| key.clone());
        key.is_some_and(|key| self.marker_entries.remove(&key).is_some())
    }

    pub fn load_from_dir(state_dir: &Path) -> io::Result<Self> {
        let primary_path = state_dir.join(DEFERRED_SHARE_CLEANUP_FILE);
        let backup_path = state_dir.join(DEFERRED_SHARE_CLEANUP_BACKUP_FILE);
        match read_journal(&primary_path) {
            Ok(Some(state)) => {
                let backup_matches =
                    matches!(read_journal(&backup_path), Ok(Some(backup)) if backup == state);
                if !backup_matches {
                    restore_journal(&backup_path, &state)?;
                }
                Ok(state)
            }
            Ok(None) => match read_journal(&backup_path) {
                Ok(Some(state)) => {
                    restore_journal(&primary_path, &state)?;
                    Ok(state)
                }
                Ok(None) => Ok(Self::default()),
                Err(backup_error) => Err(backup_error),
            },
            Err(primary_error) => match read_journal(&backup_path) {
                Ok(Some(state)) => {
                    restore_journal(&primary_path, &state)?;
                    Ok(state)
                }
                Ok(None) => Err(primary_error),
                Err(backup_error) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "both deferred NFS cleanup journal copies are unreadable ({}: {}; {}: {})",
                        primary_path.display(),
                        primary_error,
                        backup_path.display(),
                        backup_error
                    ),
                )),
            },
        }
    }

    pub fn save_to_dir(&self, state_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(state_dir)?;
        let primary_path = state_dir.join(DEFERRED_SHARE_CLEANUP_FILE);
        let backup_path = state_dir.join(DEFERRED_SHARE_CLEANUP_BACKUP_FILE);
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        // Commit the primary first. If the process stops between writes, the
        // committed primary is still authoritative; if it is later damaged,
        // the backup from the previous successful save remains available.
        atomic_write_journal(&primary_path, &bytes)?;
        atomic_write_journal(&backup_path, &bytes)?;
        File::open(state_dir)?.sync_all()
    }
}

fn read_journal(path: &Path) -> io::Result<Option<DeferredShareCleanupState>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn restore_journal(path: &Path, state: &DeferredShareCleanupState) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    atomic_write_journal(path, &bytes)
}

fn atomic_write_journal(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("cleanup journal path has no parent"))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        DEFERRED_SHARE_CLEANUP_FILE,
        Id128::random()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        use std::io::Write;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        DEFERRED_SHARE_CLEANUP_FILE, DeferredShareCleanupState, DeferredShareClientCleanup,
        DeferredShareExportCleanup, DeferredShareMarkerCleanup, client_cleanup_key,
        export_cleanup_key, marker_cleanup_key,
    };

    #[test]
    fn exact_export_cleanup_ack_leaves_other_clients_and_share_generations() {
        let expected = DeferredShareExportCleanup {
            share_id: "archive".into(),
            node_id: "storage".into(),
            source_root: "/Volumes/archive".into(),
            client_ip: "192.0.2.8".into(),
            client_node_id: "worker-008".into(),
            share_uuid: "uuid-old".into(),
            machine_uuid: Some("machine-storage".into()),
        };
        let other_client = DeferredShareExportCleanup {
            client_ip: "192.0.2.9".into(),
            client_node_id: "worker-009".into(),
            ..expected.clone()
        };
        let new_generation = DeferredShareExportCleanup {
            share_uuid: "uuid-new".into(),
            ..expected.clone()
        };
        let mut state = DeferredShareCleanupState::default();
        for entry in [&expected, &other_client, &new_generation] {
            state.exports.insert(
                export_cleanup_key(
                    &entry.share_id,
                    &entry.node_id,
                    &entry.client_node_id,
                    &entry.share_uuid,
                ),
                entry.clone(),
            );
        }

        assert!(state.remove_export_cleanup_exact(&expected));
        assert!(!state.remove_export_cleanup_exact(&expected));
        assert_eq!(state.exports.len(), 2);
        assert!(state.exports.contains_key(&export_cleanup_key(
            "archive",
            "storage",
            "worker-009",
            "uuid-old"
        )));
        assert!(state.exports.contains_key(&export_cleanup_key(
            "archive",
            "storage",
            "worker-008",
            "uuid-new"
        )));
    }

    #[test]
    fn exact_ack_removal_preserves_other_share_generations_and_marker_entries() {
        let mut state = DeferredShareCleanupState {
            version: 1,
            entries: [
                (
                    client_cleanup_key("data", "worker", "uuid-old"),
                    DeferredShareClientCleanup {
                        share_id: "data".into(),
                        node_id: "worker".into(),
                        source_root: "/srv/old".into(),
                        mount_root: "/mnt/data".into(),
                        server_host: "192.0.2.1".into(),
                        share_uuid: "uuid-old".into(),
                        machine_uuid: Some("machine-1".into()),
                    },
                ),
                (
                    client_cleanup_key("data", "worker", "uuid-new"),
                    DeferredShareClientCleanup {
                        share_id: "data".into(),
                        node_id: "worker".into(),
                        source_root: "/srv/new".into(),
                        mount_root: "/mnt/data".into(),
                        server_host: "192.0.2.1".into(),
                        share_uuid: "uuid-new".into(),
                        machine_uuid: Some("machine-1".into()),
                    },
                ),
            ]
            .into_iter()
            .collect(),
            marker_entries: [(
                marker_cleanup_key("data", "storage", "uuid-old"),
                DeferredShareMarkerCleanup {
                    share_id: "data".into(),
                    node_id: "storage".into(),
                    source_root: "/srv/old".into(),
                    share_uuid: "uuid-old".into(),
                    machine_uuid: Some("machine-2".into()),
                    alias_target: None,
                },
            )]
            .into_iter()
            .collect(),
            exports: Default::default(),
        };

        assert!(state.remove_client_cleanup("data", "worker", "uuid-old"));
        assert!(!state.remove_client_cleanup("data", "worker", "uuid-old"));
        assert!(
            state
                .entries
                .contains_key(&client_cleanup_key("data", "worker", "uuid-new"))
        );
        assert!(
            state
                .marker_entries
                .contains_key(&marker_cleanup_key("data", "storage", "uuid-old"))
        );
        assert!(state.remove_marker_cleanup("data", "storage", "/srv/old", "uuid-old"));
        assert!(state.marker_entries.is_empty());
    }

    #[test]
    fn legacy_journal_without_marker_entries_deserializes() {
        let legacy = br#"{"version":1,"entries":{}}"#;
        let state: DeferredShareCleanupState = serde_json::from_slice(legacy).unwrap();
        assert!(state.marker_entries.is_empty());
    }

    #[test]
    fn exact_ack_removes_legacy_client_key_without_removing_a_newer_generation() {
        let legacy = br#"{
            "version":1,
            "entries":{
                "data/worker":{"share_id":"data","node_id":"worker","source_root":"/srv/old","mount_root":"/mnt/data","server_host":"192.0.2.1","share_uuid":"uuid-old","machine_uuid":"machine-1"},
                "data/worker/uuid-new":{"share_id":"data","node_id":"worker","source_root":"/srv/new","mount_root":"/mnt/data","server_host":"192.0.2.1","share_uuid":"uuid-new","machine_uuid":"machine-1"}
            }
        }"#;
        let mut state: DeferredShareCleanupState = serde_json::from_slice(legacy).unwrap();
        let old = DeferredShareClientCleanup {
            share_id: "data".into(),
            node_id: "worker".into(),
            source_root: "/srv/old".into(),
            mount_root: "/mnt/data".into(),
            server_host: "192.0.2.1".into(),
            share_uuid: "uuid-old".into(),
            machine_uuid: Some("machine-1".into()),
        };

        assert!(state.remove_client_cleanup_exact(&old));
        assert!(!state.entries.contains_key("data/worker"));
        assert!(state.entries.contains_key("data/worker/uuid-new"));
    }

    #[test]
    fn exact_cleanup_ack_does_not_remove_a_replaced_journal_record() {
        let mut state = DeferredShareCleanupState::default();
        let expected = DeferredShareClientCleanup {
            share_id: "data".into(),
            node_id: "worker".into(),
            source_root: "/srv/old".into(),
            mount_root: "/mnt/data".into(),
            server_host: "192.0.2.1".into(),
            share_uuid: "uuid-old".into(),
            machine_uuid: Some("machine-1".into()),
        };
        let mut replaced = expected.clone();
        replaced.source_root = "/srv/replaced".into();
        state.entries.insert(
            client_cleanup_key("data", "worker", "uuid-old"),
            replaced.clone(),
        );

        assert!(!state.remove_client_cleanup_exact(&expected));
        assert_eq!(
            state
                .entries
                .get(&client_cleanup_key("data", "worker", "uuid-old")),
            Some(&replaced)
        );
    }

    #[test]
    fn journal_round_trip_keeps_client_and_marker_cleanup_records() {
        let root = std::env::temp_dir().join(format!(
            "macluster-nfs-journal-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        let mut state = DeferredShareCleanupState {
            version: 1,
            ..DeferredShareCleanupState::default()
        };
        let client = DeferredShareClientCleanup {
            share_id: "data".into(),
            node_id: "worker".into(),
            source_root: "/srv/data".into(),
            mount_root: "/mnt/data".into(),
            server_host: "192.0.2.1".into(),
            share_uuid: "uuid-client".into(),
            machine_uuid: Some("machine-worker".into()),
        };
        state
            .entries
            .insert(client_cleanup_key("data", "worker", "uuid-client"), client);
        let marker = DeferredShareMarkerCleanup {
            share_id: "data".into(),
            node_id: "storage".into(),
            source_root: "/srv/data".into(),
            share_uuid: "uuid-marker".into(),
            machine_uuid: Some("machine-storage".into()),
            alias_target: None,
        };
        state
            .marker_entries
            .insert(marker_cleanup_key("data", "storage", "uuid-marker"), marker);

        state.save_to_dir(&root).unwrap();
        assert_eq!(
            DeferredShareCleanupState::load_from_dir(&root).unwrap(),
            state
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupted_primary_journal_recovers_from_the_latest_backup() {
        let root = std::env::temp_dir().join(format!(
            "macluster-nfs-journal-recovery-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        let mut state = DeferredShareCleanupState::default();
        let first = DeferredShareClientCleanup {
            share_id: "first".into(),
            node_id: "worker".into(),
            source_root: "/srv/first".into(),
            mount_root: "/mnt/first".into(),
            server_host: "192.0.2.1".into(),
            share_uuid: "uuid-first".into(),
            machine_uuid: Some("machine-worker".into()),
        };
        state
            .entries
            .insert(client_cleanup_key("first", "worker", "uuid-first"), first);
        state.save_to_dir(&root).unwrap();

        let second = DeferredShareClientCleanup {
            share_id: "second".into(),
            node_id: "worker".into(),
            source_root: "/srv/second".into(),
            mount_root: "/mnt/second".into(),
            server_host: "192.0.2.1".into(),
            share_uuid: "uuid-second".into(),
            machine_uuid: Some("machine-worker".into()),
        };
        state.entries.insert(
            client_cleanup_key("second", "worker", "uuid-second"),
            second.clone(),
        );
        state.save_to_dir(&root).unwrap();
        std::fs::write(root.join(DEFERRED_SHARE_CLEANUP_FILE), b"truncated json").unwrap();

        let recovered = DeferredShareCleanupState::load_from_dir(&root).unwrap();
        assert!(recovered.entries.contains_key(&client_cleanup_key(
            "second",
            "worker",
            "uuid-second"
        )));
        assert_eq!(recovered.entries.len(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loading_a_valid_primary_repairs_a_stale_backup_before_recovery_can_need_it() {
        let root = std::env::temp_dir().join(format!(
            "macluster-nfs-journal-repair-backup-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        let mut old = DeferredShareCleanupState::default();
        old.entries.insert(
            client_cleanup_key("old", "worker", "uuid-old"),
            DeferredShareClientCleanup {
                share_id: "old".into(),
                node_id: "worker".into(),
                source_root: "/srv/old".into(),
                mount_root: "/mnt/old".into(),
                server_host: "192.0.2.1".into(),
                share_uuid: "uuid-old".into(),
                machine_uuid: Some("machine-worker".into()),
            },
        );
        old.save_to_dir(&root).unwrap();
        let latest = DeferredShareCleanupState::default();
        let bytes = serde_json::to_vec_pretty(&latest).unwrap();
        super::atomic_write_journal(&root.join(DEFERRED_SHARE_CLEANUP_FILE), &bytes).unwrap();

        assert_eq!(
            DeferredShareCleanupState::load_from_dir(&root).unwrap(),
            latest
        );
        assert_eq!(
            super::read_journal(&root.join(super::DEFERRED_SHARE_CLEANUP_BACKUP_FILE))
                .unwrap()
                .unwrap(),
            latest
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn an_empty_cleanup_journal_is_persisted_to_prevent_stale_backup_resurrection() {
        let root = std::env::temp_dir().join(format!(
            "macluster-nfs-journal-empty-{}-{}",
            std::process::id(),
            macluster_protocol::identifiers::Id128::random()
        ));
        let mut state = DeferredShareCleanupState::default();
        state.entries.insert(
            client_cleanup_key("data", "worker", "uuid-data"),
            DeferredShareClientCleanup {
                share_id: "data".into(),
                node_id: "worker".into(),
                source_root: "/srv/data".into(),
                mount_root: "/mnt/data".into(),
                server_host: "192.0.2.1".into(),
                share_uuid: "uuid-data".into(),
                machine_uuid: Some("machine-worker".into()),
            },
        );
        state.save_to_dir(&root).unwrap();
        state.entries.clear();
        state.save_to_dir(&root).unwrap();
        std::fs::write(root.join(DEFERRED_SHARE_CLEANUP_FILE), b"broken").unwrap();

        let recovered = DeferredShareCleanupState::load_from_dir(&root).unwrap();
        assert!(recovered.entries.is_empty());
        assert!(recovered.marker_entries.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }
}
