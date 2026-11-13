use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use macluster_protocol::{identifiers::Id128, smb_credential::SmbCredentialKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::nfs_reconcile::DeferredSmbCredentialCleanup;

const VERSION: u32 = 1;
pub const GLOBAL_SMB_CLEANUP_FILE: &str = "smb-credential-cleanup.json";

pub fn smb_cleanup_retry_delay(attempts: u32) -> Duration {
    Duration::from_secs(match attempts {
        0 | 1 => 15,
        2 => 30,
        3 => 60,
        _ => 300,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GlobalSmbCredentialCleanup {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub nodes: BTreeMap<String, DeferredSmbCredentialCleanup>,
    #[serde(default)]
    pub masters: BTreeMap<String, SmbCredentialKey>,
}

impl Default for GlobalSmbCredentialCleanup {
    fn default() -> Self {
        Self {
            version: VERSION,
            nodes: BTreeMap::new(),
            masters: BTreeMap::new(),
        }
    }
}

impl GlobalSmbCredentialCleanup {
    pub fn default_path() -> io::Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not absolute"))?;
        Ok(home
            .join("Library/Application Support/macluster")
            .join(GLOBAL_SMB_CLEANUP_FILE))
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    version: VERSION,
                    ..Self::default()
                });
            }
            Err(error) => return Err(error),
        };
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if state.version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported global SMB cleanup journal version",
            ));
        }
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension(format!("{}.tmp", Id128::random()));
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn remember_node(&mut self, entry: DeferredSmbCredentialCleanup) {
        self.version = VERSION;
        if let Some(pending) = self.nodes.get_mut(&entry.node_id)
            && pending.machine_uuid == entry.machine_uuid
        {
            pending.node = entry.node;
            pending.wait_for_unmount |= entry.wait_for_unmount;
            pending.attempts = pending.attempts.max(entry.attempts);
            pending.next_retry_unix_ms =
                if pending.next_retry_unix_ms == 0 || entry.next_retry_unix_ms == 0 {
                    0
                } else {
                    pending.next_retry_unix_ms.min(entry.next_retry_unix_ms)
                };
            if entry.last_error_kind.is_some() {
                pending.last_error_kind = entry.last_error_kind;
            }
            if entry.last_error_summary.is_some() {
                pending.last_error_summary = entry.last_error_summary;
            }
            for share in entry.shares {
                if !pending
                    .shares
                    .iter()
                    .any(|candidate| candidate.share_uuid == share.share_uuid)
                {
                    pending.shares.push(share);
                }
            }
            pending
                .shares
                .sort_by(|left, right| left.share_uuid.cmp(&right.share_uuid));
            for endpoint in entry.endpoints {
                if !pending.endpoints.contains(&endpoint) {
                    pending.endpoints.push(endpoint);
                }
            }
            pending.endpoints.sort();
            return;
        }
        self.nodes.insert(entry.node_id.clone(), entry);
    }

    pub fn has_due_cleanup(&self, now_unix_ms: u64) -> bool {
        self.nodes
            .values()
            .any(|entry| entry.next_retry_unix_ms == 0 || entry.next_retry_unix_ms <= now_unix_ms)
    }

    pub fn remember_master(&mut self, key: SmbCredentialKey) {
        self.version = VERSION;
        self.masters.insert(key.service_name(), key);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{GlobalSmbCredentialCleanup, smb_cleanup_retry_delay};
    use macluster_protocol::{
        identifiers::{Id128, NodeId},
        smb_credential::SmbCredentialKey,
    };

    #[test]
    fn empty_global_journal_is_versioned_and_round_trips_atomically() {
        let root = std::env::temp_dir().join(format!(
            "macluster-global-smb-cleanup-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(super::GLOBAL_SMB_CLEANUP_FILE);
        let state = GlobalSmbCredentialCleanup::default();
        state.save(&path).unwrap();
        assert_eq!(GlobalSmbCredentialCleanup::load(&path).unwrap(), state);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn retired_node_and_master_cleanup_survive_without_secret_material() {
        let key = SmbCredentialKey {
            cluster_uuid: Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            server_id: NodeId::new("nas-01").unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        };
        let mut state = GlobalSmbCredentialCleanup::default();
        state.remember_node(crate::nfs_reconcile::DeferredSmbCredentialCleanup {
            node_id: "retired-a".into(),
            machine_uuid: Some("machine-a".into()),
            node: crate::config::NodeConfig {
                host: "192.0.2.2".into(),
                transport: crate::config::Transport::Ssh,
                remote_binary: "/usr/local/bin/macluster".into(),
                ssh_user: Some("worker".into()),
                ssh_port: Some(22),
                ssh_identity_file: None,
                remote_config: None,
                machine_uuid: Some("machine-a".into()),
                execution_uid: Some(501),
            },
            shares: vec![crate::config::ShareConfig {
                protocol: crate::storage_uri::StorageProtocol::Smb,
                server: NodeId::new("nas-01").unwrap(),
                source_root: "/data".into(),
                mount_root: "/Users/Shared/data".into(),
                share_uuid: "00000000-0000-4000-8000-000000000123".into(),
                smb_user: Some("smb-user".into()),
                allow_existing_contents: false,
            }],
            endpoints: vec![key.endpoint()],
            wait_for_unmount: true,
            attempts: 0,
            next_retry_unix_ms: 0,
            last_error_kind: None,
            last_error_summary: None,
        });
        state.remember_master(key.clone());

        let encoded = serde_json::to_vec(&state).unwrap();
        let decoded: GlobalSmbCredentialCleanup = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert!(!String::from_utf8(encoded).unwrap().contains("password"));
    }

    #[test]
    fn repeated_node_cleanup_retains_every_pending_share() {
        let node = crate::config::NodeConfig {
            host: "192.0.2.2".into(),
            transport: crate::config::Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("worker".into()),
            ssh_port: Some(22),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: Some("machine-a".into()),
            execution_uid: Some(501),
        };
        let share = |uuid: &str, root: &str| crate::config::ShareConfig {
            protocol: crate::storage_uri::StorageProtocol::Smb,
            server: NodeId::new("nas-01").unwrap(),
            source_root: root.into(),
            mount_root: format!("/Users/Shared/{root}").into(),
            share_uuid: uuid.into(),
            smb_user: Some("smb-user".into()),
            allow_existing_contents: false,
        };
        let mut state = GlobalSmbCredentialCleanup::default();
        let entry = |share_uuid: &str, wait_for_unmount: bool| {
            crate::nfs_reconcile::DeferredSmbCredentialCleanup {
                node_id: "worker".into(),
                machine_uuid: Some("machine-a".into()),
                node: node.clone(),
                shares: vec![share(
                    share_uuid,
                    if share_uuid.ends_with("1111") {
                        "data-a"
                    } else {
                        "data-b"
                    },
                )],
                endpoints: Vec::new(),
                wait_for_unmount,
                attempts: 0,
                next_retry_unix_ms: 0,
                last_error_kind: None,
                last_error_summary: None,
            }
        };

        state.remember_node(entry("00000000-0000-4000-8000-0000000001111", false));
        state.remember_node(entry("00000000-0000-4000-8000-0000000002222", true));

        let pending = &state.nodes["worker"];
        assert_eq!(pending.shares.len(), 2);
        assert!(pending.wait_for_unmount);
    }

    #[test]
    fn cleanup_retry_delay_is_bounded() {
        assert_eq!(smb_cleanup_retry_delay(1), Duration::from_secs(15));
        assert_eq!(smb_cleanup_retry_delay(2), Duration::from_secs(30));
        assert_eq!(smb_cleanup_retry_delay(3), Duration::from_secs(60));
        assert_eq!(smb_cleanup_retry_delay(4), Duration::from_secs(300));
        assert_eq!(smb_cleanup_retry_delay(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn future_node_cleanup_is_not_due() {
        let node = crate::config::NodeConfig {
            host: "192.0.2.2".into(),
            transport: crate::config::Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("worker".into()),
            ssh_port: Some(22),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: Some("machine-a".into()),
            execution_uid: Some(501),
        };
        let mut state = GlobalSmbCredentialCleanup::default();
        state.remember_node(crate::nfs_reconcile::DeferredSmbCredentialCleanup {
            node_id: "worker".into(),
            machine_uuid: Some("machine-a".into()),
            node,
            shares: Vec::new(),
            endpoints: Vec::new(),
            wait_for_unmount: true,
            attempts: 1,
            next_retry_unix_ms: 2_000,
            last_error_kind: Some(crate::nfs_reconcile::SmbCleanupFailureKind::Busy),
            last_error_summary: Some("mount busy".into()),
        });

        assert!(!state.has_due_cleanup(1_000));
        assert!(state.has_due_cleanup(2_000));
    }

    #[test]
    fn merging_a_due_entry_keeps_cleanup_immediately_due() {
        let node = crate::config::NodeConfig {
            host: "192.0.2.2".into(),
            transport: crate::config::Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("worker".into()),
            ssh_port: Some(22),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: Some("machine".into()),
            execution_uid: Some(501),
        };
        let entry =
            |attempts, next_retry_unix_ms| crate::nfs_reconcile::DeferredSmbCredentialCleanup {
                node_id: "worker".into(),
                machine_uuid: Some("machine".into()),
                node: node.clone(),
                shares: Vec::new(),
                endpoints: Vec::new(),
                wait_for_unmount: true,
                attempts,
                next_retry_unix_ms,
                last_error_kind: None,
                last_error_summary: None,
            };
        let mut state = GlobalSmbCredentialCleanup::default();
        state.remember_node(entry(1, 10_000));
        state.remember_node(entry(0, 0));

        assert!(state.has_due_cleanup(1_000));
        assert_eq!(state.nodes["worker"].next_retry_unix_ms, 0);
    }
}
