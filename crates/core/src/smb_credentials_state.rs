use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use macluster_protocol::{identifiers::Id128, smb_credential::SmbKeychainEndpoint};
use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "smb-credentials.json";
const STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeCredentialEntry {
    pub server: String,
    pub account: String,
    pub generation: u64,
    pub cluster_uuid: Id128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeKeychainState {
    pub version: u32,
    #[serde(default)]
    pub entries: BTreeMap<String, NodeCredentialEntry>,
}

impl Default for NodeKeychainState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

impl NodeKeychainState {
    pub fn load(state_dir: &Path) -> io::Result<Self> {
        let path = state_dir.join(STATE_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error),
        };
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if state.version != STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SMB keychain state version",
            ));
        }
        for (key, entry) in &state.entries {
            let endpoint = SmbKeychainEndpoint {
                server: entry.server.clone(),
                account: entry.account.clone(),
            };
            endpoint
                .validate()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if key != &entry_key(&endpoint) || entry.generation == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid SMB keychain state entry",
                ));
            }
        }
        Ok(state)
    }

    pub fn save(&self, state_dir: &Path) -> io::Result<()> {
        fs::create_dir_all(state_dir)?;
        let parent = state_dir;
        let temporary = parent.join(format!(".{STATE_FILE}.{}.tmp", Id128::random()));
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
            fs::rename(&temporary, parent.join(STATE_FILE))?;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

pub fn entry_key(endpoint: &SmbKeychainEndpoint) -> String {
    format!("{}/{}", endpoint.server, endpoint.account)
}

pub fn credential_needs_store(
    state_generation: Option<u64>,
    incoming_generation: u64,
    item_present: bool,
) -> bool {
    !item_present || state_generation.is_none_or(|generation| generation < incoming_generation)
}

pub fn record_generation(
    state_dir: &Path,
    cluster_uuid: Id128,
    endpoint: &SmbKeychainEndpoint,
    generation: u64,
) -> io::Result<()> {
    endpoint
        .validate()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if generation == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SMB credential generation must be greater than zero",
        ));
    }
    let mut state = NodeKeychainState::load(state_dir)?;
    state.entries.insert(
        entry_key(endpoint),
        NodeCredentialEntry {
            server: endpoint.server.clone(),
            account: endpoint.account.clone(),
            generation,
            cluster_uuid,
        },
    );
    state.save(state_dir)
}

pub fn remove_endpoint(state_dir: &Path, endpoint: &SmbKeychainEndpoint) -> io::Result<bool> {
    let mut state = NodeKeychainState::load(state_dir)?;
    let removed = state.entries.remove(&entry_key(endpoint)).is_some();
    if removed {
        state.save(state_dir)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use macluster_protocol::{identifiers::Id128, smb_credential::SmbKeychainEndpoint};

    use super::{NodeKeychainState, entry_key, record_generation, remove_endpoint};

    fn endpoint() -> SmbKeychainEndpoint {
        SmbKeychainEndpoint {
            server: "192.0.2.20".into(),
            account: "smb-user".into(),
        }
    }

    #[test]
    fn generation_state_round_trips_without_secret_and_is_mode_0600() {
        let root = std::env::temp_dir().join(format!(
            "macluster-smb-state-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let cluster = Id128::random();
        std::fs::create_dir_all(&root).unwrap();
        record_generation(&root, cluster, &endpoint(), 7).unwrap();

        let state = NodeKeychainState::load(&root).unwrap();
        let entry = state.entries.get(&entry_key(&endpoint())).unwrap();
        assert_eq!(entry.generation, 7);
        assert_eq!(entry.cluster_uuid, cluster);
        let bytes = std::fs::read_to_string(root.join("smb-credentials.json")).unwrap();
        assert!(!bytes.contains("password"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("smb-credentials.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_keychain_item_is_detected_even_when_state_generation_matches() {
        assert!(super::credential_needs_store(Some(7), 7, false));
        assert!(!super::credential_needs_store(Some(7), 7, true));
    }

    #[test]
    fn remove_endpoint_updates_the_journal_atomically() {
        let root = std::env::temp_dir().join(format!(
            "macluster-smb-state-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        std::fs::create_dir_all(&root).unwrap();
        record_generation(&root, Id128::random(), &endpoint(), 1).unwrap();

        assert!(remove_endpoint(&root, &endpoint()).unwrap());
        assert!(
            !NodeKeychainState::load(&root)
                .unwrap()
                .entries
                .contains_key(&entry_key(&endpoint()))
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
