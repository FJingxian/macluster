use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use macluster_protocol::{control::ClientDescriptor, identifiers::Id128};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientProfile {
    pub version: u32,
    pub cluster_uuid: String,
    pub cluster_name: String,
    pub binding_digest: String,
    pub namespace: String,
    pub descriptor_generation: u64,
    pub controller_host: String,
    pub controller_user: String,
    pub controller_port: u16,
    pub known_hosts_path: String,
    pub identity_file: String,
    pub remote_uid: u32,
    pub remote_binary: String,
    pub remote_config: String,
    pub remote_state_dir: String,
    #[serde(default)]
    pub mounts_enabled: bool,
    #[serde(default)]
    pub nfs_client_id: String,
    #[serde(default)]
    pub nfs_client_ip: String,
    pub last_used_unix_ms: u64,
    #[serde(default)]
    pub descriptor: Option<ClientDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientSelection {
    Explicit(ClientProfile),
    LastUsed(ClientProfile),
    Sole(ClientProfile),
    None,
}

#[derive(Clone, Debug)]
pub struct ClientProfileStore {
    root: PathBuf,
}

impl ClientProfileStore {
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn current() -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        Ok(Self::at(
            home.join("Library/Application Support/macluster/clients"),
        ))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(&self, cluster_uuid: &str) -> io::Result<PathBuf> {
        let uuid = Id128::parse(cluster_uuid)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(self.root.join(format!("{uuid}.json")))
    }

    pub fn save(&self, profile: &ClientProfile) -> io::Result<()> {
        self.prepare_root()?;
        validate_profile(profile)?;
        let path = self.path_for(&profile.cluster_uuid)?;
        let temp = self.root.join(format!(".profile-{}.tmp", Id128::random()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            serde_json::to_writer(&mut file, profile)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temp, &path)?;
            fs::File::open(&self.root)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn load(&self, cluster: &str) -> io::Result<ClientProfile> {
        let path = match self.path_for(cluster) {
            Ok(path) => path,
            Err(_) => self
                .load_all()?
                .into_iter()
                .find(|profile| profile.cluster_name == cluster)
                .map(|profile| self.path_for(&profile.cluster_uuid))
                .transpose()?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "profile not found"))?,
        };
        self.load_path(&path)
    }

    pub fn load_all(&self) -> io::Result<Vec<ClientProfile>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut profiles = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            profiles.push(self.load_path(&entry.path())?);
        }
        profiles.sort_by(|left, right| left.cluster_uuid.cmp(&right.cluster_uuid));
        Ok(profiles)
    }

    pub fn select(&self, explicit: Option<&str>) -> io::Result<ClientSelection> {
        let profiles = self.load_all()?;
        if let Some(value) = explicit {
            let matches = profiles
                .into_iter()
                .filter(|profile| {
                    profile.cluster_uuid.eq_ignore_ascii_case(value)
                        || profile.cluster_name == value
                })
                .collect::<Vec<_>>();
            return match matches.len() {
                1 => Ok(ClientSelection::Explicit(matches[0].clone())),
                0 => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("cluster profile '{value}' was not found"),
                )),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cluster name '{value}' is ambiguous; use the UUID"),
                )),
            };
        }
        if profiles.len() == 1 {
            return Ok(ClientSelection::Sole(profiles[0].clone()));
        }
        if let Some(profile) = profiles
            .into_iter()
            .max_by_key(|profile| profile.last_used_unix_ms)
        {
            return Ok(ClientSelection::LastUsed(profile));
        }
        Ok(ClientSelection::None)
    }

    pub fn mark_used(&self, cluster_uuid: &str) -> io::Result<()> {
        let mut profile = self.load(cluster_uuid)?;
        profile.last_used_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        self.save(&profile)
    }

    pub fn remove(&self, cluster_uuid: &str) -> io::Result<()> {
        let path = self.path_for(cluster_uuid)?;
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn prepare_root(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)?;
        let metadata = fs::symlink_metadata(&self.root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "client profile directory is unsafe",
            ));
        }
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
    }

    fn load_path(&self, path: &Path) -> io::Result<ClientProfile> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("unsafe client profile {}", path.display()),
            ));
        }
        let profile: ClientProfile = serde_json::from_slice(&fs::read(path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        validate_profile(&profile)?;
        Ok(profile)
    }
}

fn validate_profile(profile: &ClientProfile) -> io::Result<()> {
    if profile.version != 1
        || Id128::parse(&profile.cluster_uuid).is_err()
        || profile.cluster_name.trim().is_empty()
        || profile.binding_digest.len() != 64
        || profile.namespace.is_empty()
        || profile.controller_host.trim().is_empty()
        || profile.controller_user.trim().is_empty()
        || profile.controller_port == 0
        || profile.known_hosts_path.is_empty()
        || profile.identity_file.is_empty()
        || profile.remote_binary.is_empty()
        || profile.remote_config.is_empty()
        || profile.remote_state_dir.is_empty()
        || (profile.mounts_enabled
            && (profile.nfs_client_id.is_empty()
                || profile.nfs_client_id.len() > 64
                || !profile
                    .nfs_client_id
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !profile
                    .nfs_client_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                || profile.nfs_client_ip.parse::<std::net::Ipv4Addr>().is_err()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client profile is incomplete or invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use macluster_protocol::identifiers::Id128;

    use super::{ClientProfile, ClientProfileStore, ClientSelection};

    fn profile(uuid: &str, last_used_unix_ms: u64) -> ClientProfile {
        ClientProfile {
            version: 1,
            cluster_uuid: uuid.into(),
            cluster_name: "home".into(),
            binding_digest: "b".repeat(64),
            namespace: uuid.into(),
            descriptor_generation: 7,
            controller_host: "192.0.2.1".into(),
            controller_user: "mac".into(),
            controller_port: 22,
            known_hosts_path: "/tmp/known_hosts".into(),
            identity_file: "/tmp/id_ed25519".into(),
            remote_uid: 501,
            remote_binary: "/opt/homebrew/bin/macluster".into(),
            remote_config: "/Users/mac/.config/macluster/config.toml".into(),
            remote_state_dir: "/Users/mac/Library/Application Support/macluster/controller".into(),
            mounts_enabled: true,
            nfs_client_id: "client-240edfcc".into(),
            nfs_client_ip: "192.0.2.10".into(),
            last_used_unix_ms,
            descriptor: None,
        }
    }

    fn temp_store() -> (std::path::PathBuf, ClientProfileStore) {
        let root = std::env::temp_dir().join(format!("macluster-profile-{}", Id128::random()));
        let store = ClientProfileStore::at(root.join("clients"));
        (root, store)
    }

    #[test]
    fn profile_store_uses_private_atomic_files() {
        let (root, store) = temp_store();
        let value = profile("f779bcf5-ea85-5caa-9579-74b395f3cce5", 10);
        store.save(&value).unwrap();

        let path = store.path_for(&value.cluster_uuid).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(store.root())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
                .count(),
            0
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_store_rejects_unsafe_permissions_and_symlinks() {
        let (root, store) = temp_store();
        let value = profile("82d02835-f6ab-52b4-aaab-f90cafde9981", 10);
        store.save(&value).unwrap();
        let path = store.path_for(&value.cluster_uuid).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load(&value.cluster_uuid).is_err());

        fs::remove_file(&path).unwrap();
        let target = root.join("target");
        fs::write(&target, serde_json::to_vec(&value).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(store.load(&value.cluster_uuid).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sole_and_last_used_profiles_select_automatically() {
        let (root, store) = temp_store();
        let first = profile("55fb9b02-ce96-5a69-8ad3-356563eff27b", 20);
        let second = profile("2309b054-e9f7-5754-864b-cecca129b1f0", 30);
        store.save(&first).unwrap();
        assert!(matches!(
            store.select(None).unwrap(),
            ClientSelection::Sole(value) if value.cluster_uuid == first.cluster_uuid
        ));
        store.save(&second).unwrap();
        assert!(matches!(
            store.select(None).unwrap(),
            ClientSelection::LastUsed(value) if value.cluster_uuid == second.cluster_uuid
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_cluster_override_rejects_unknown_profile() {
        let (root, store) = temp_store();
        let value = profile("31453411-ce55-5f85-a7c0-004215710bad", 10);
        store.save(&value).unwrap();
        assert!(matches!(
            store.select(Some("home")).unwrap(),
            ClientSelection::Explicit(profile) if profile.cluster_uuid == value.cluster_uuid
        ));
        assert!(store.select(Some("missing")).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn remove_profile_deletes_only_client_metadata() {
        let (root, store) = temp_store();
        fs::create_dir_all(&root).unwrap();
        let value = profile("b02ebbef-3864-59c0-8f3c-dd67edfc521f", 10);
        let unrelated = root.join("keep.txt");
        fs::write(&unrelated, "keep").unwrap();
        store.save(&value).unwrap();
        store.remove(&value.cluster_uuid).unwrap();
        assert!(!store.path_for(&value.cluster_uuid).unwrap().exists());
        assert_eq!(fs::read_to_string(unrelated).unwrap(), "keep");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mounted_profile_rejects_an_unsafe_nfs_client_identity() {
        let (root, store) = temp_store();
        let mut value = profile("1eab1da8-e7c1-553e-8bf5-acde7f7388dc", 10);
        value.nfs_client_id = "bad\nclient".into();
        assert!(store.save(&value).is_err());
        assert!(!store.path_for(&value.cluster_uuid).unwrap().exists());
        fs::remove_dir_all(root).unwrap();
    }
}
