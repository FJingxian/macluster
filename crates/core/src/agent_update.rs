//! Receipts for Agent binaries refreshed automatically by the resident controller.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Mutex,
};

use macluster_protocol::identifiers::Id128;
use serde::{Deserialize, Serialize};

pub const AUTO_AGENT_UPDATE_RECEIPT_FILE: &str = "agent-auto-updates.json";
const AUTO_AGENT_UPDATE_RECEIPT_SCHEMA: u32 = 1;
const MAX_RECEIPT_BYTES: u64 = 256 * 1024;
static RECEIPT_UPSERT_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoAgentUpdateEntry {
    pub remote_binary: String,
    pub machine_uuid: String,
    pub execution_uid: u32,
    pub connection_fingerprint: String,
    pub build_id: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AutoAgentUpdateReceipts {
    pub schema: u32,
    #[serde(default)]
    pub nodes: BTreeMap<String, AutoAgentUpdateEntry>,
}

impl Default for AutoAgentUpdateReceipts {
    fn default() -> Self {
        Self {
            schema: AUTO_AGENT_UPDATE_RECEIPT_SCHEMA,
            nodes: BTreeMap::new(),
        }
    }
}

impl AutoAgentUpdateReceipts {
    pub fn upsert_node_to_dir(
        root: &Path,
        node_id: impl Into<String>,
        entry: AutoAgentUpdateEntry,
    ) -> io::Result<()> {
        let _guard = RECEIPT_UPSERT_LOCK
            .lock()
            .map_err(|_| io::Error::other("Agent update receipt lock is poisoned"))?;
        let mut receipts = Self::load_from_dir(root)?;
        receipts.nodes.insert(node_id.into(), entry);
        receipts.save_to_dir(root)
    }

    pub fn load_from_dir(root: &Path) -> io::Result<Self> {
        let root_metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        if !root_metadata.is_dir()
            || root_metadata.file_type().is_symlink()
            || root_metadata.uid() != unsafe { libc::geteuid() }
            || root_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent update receipt directory is unsafe",
            ));
        }
        let path = root.join(AUTO_AGENT_UPDATE_RECEIPT_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_RECEIPT_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent update receipt is unsafe",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Agent update receipt exceeds its size limit",
            ));
        }
        let receipt: Self = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if receipt.schema != AUTO_AGENT_UPDATE_RECEIPT_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported Agent update receipt schema",
            ));
        }
        Ok(receipt)
    }

    pub fn save_to_dir(&self, root: &Path) -> io::Result<()> {
        fs::create_dir_all(root)?;
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Agent update receipt directory is unsafe",
            ));
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Agent update receipt exceeds its size limit",
            ));
        }
        let target = root.join(AUTO_AGENT_UPDATE_RECEIPT_FILE);
        let temporary = root.join(format!(
            ".{AUTO_AGENT_UPDATE_RECEIPT_FILE}.{}.tmp",
            Id128::random()
        ));
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &target)?;
            File::open(root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_receipts_round_trip_atomically() {
        let root =
            std::env::temp_dir().join(format!("macluster-update-receipt-{}", Id128::random()));
        let mut receipt = AutoAgentUpdateReceipts::default();
        receipt.nodes.insert(
            "worker-001".into(),
            AutoAgentUpdateEntry {
                remote_binary:
                    "/Users/operator/.local/share/macluster/clusters/cluster/bin/hash/macluster"
                        .into(),
                machine_uuid: "machine-uuid".into(),
                execution_uid: 501,
                connection_fingerprint: "connection".into(),
                build_id: "0.1.0-src-test".into(),
                sha256: "a".repeat(64),
            },
        );
        receipt.save_to_dir(&root).unwrap();
        assert_eq!(
            AutoAgentUpdateReceipts::load_from_dir(&root).unwrap(),
            receipt
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupted_update_receipts_are_not_trusted() {
        let root =
            std::env::temp_dir().join(format!("macluster-update-receipt-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(AUTO_AGENT_UPDATE_RECEIPT_FILE);
        fs::write(&path, b"not json").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            AutoAgentUpdateReceipts::load_from_dir(&root)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_agent_update_receipts_do_not_overwrite_other_nodes() {
        let root = std::env::temp_dir().join(format!(
            "macluster-update-receipt-concurrent-{}",
            Id128::random()
        ));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        std::thread::scope(|scope| {
            for index in 0..16 {
                let root = root.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    let node_id = format!("worker-{index:03}");
                    let entry = AutoAgentUpdateEntry {
                        remote_binary: format!(
                            "/Users/operator/.local/share/macluster/clusters/cluster/bin/{index:064x}/macluster"
                        ),
                        machine_uuid: format!("machine-{index}"),
                        execution_uid: 501,
                        connection_fingerprint: format!("connection-{index}"),
                        build_id: "0.1.0-src-test".into(),
                        sha256: format!("{index:064x}"),
                    };
                    barrier.wait();
                    AutoAgentUpdateReceipts::upsert_node_to_dir(&root, node_id, entry).unwrap();
                });
            }
        });

        let receipts = AutoAgentUpdateReceipts::load_from_dir(&root).unwrap();
        assert_eq!(receipts.nodes.len(), 16);
        fs::remove_dir_all(root).unwrap();
    }
}
