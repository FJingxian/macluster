use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use macluster_protocol::{identifiers::Id128, smb_credential::SmbCredentialKey};
use serde::{Deserialize, Serialize};

use crate::nfs_reconcile::DeferredSmbCredentialCleanup;

const VERSION: u32 = 1;
pub const GLOBAL_SMB_CLEANUP_FILE: &str = "smb-credential-cleanup.json";

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

    pub fn remember_master(&mut self, key: SmbCredentialKey) {
        self.version = VERSION;
        self.masters.insert(key.service_name(), key);
    }
}

#[cfg(test)]
mod tests {
    use super::GlobalSmbCredentialCleanup;
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
            }
        };

        state.remember_node(entry("00000000-0000-4000-8000-0000000001111", false));
        state.remember_node(entry("00000000-0000-4000-8000-0000000002222", true));

        let pending = &state.nodes["worker"];
        assert_eq!(pending.shares.len(), 2);
        assert!(pending.wait_for_unmount);
    }
}
