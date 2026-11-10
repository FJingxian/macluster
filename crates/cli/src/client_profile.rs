use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use macluster_protocol::{control::ClientDescriptor, identifiers::Id128};
use serde::{Deserialize, Serialize};

pub const CLIENT_PROFILE_VERSION: u32 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientLeavePhase {
    Requested,
    MountsDetached,
    NfsRevoked,
    KeyRevoked,
    LocalCredentialsRemoved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RetiredClientAccess {
    pub controller_host: String,
    pub controller_user: String,
    pub controller_port: u16,
    pub known_hosts_path: String,
    pub identity_file: String,
    #[serde(default)]
    pub public_key: Option<String>,
    pub nfs_client_id: String,
    pub nfs_client_ip: String,
    pub nfs_revocation_pending: bool,
    pub key_revocation_pending: bool,
    pub control_master_close_pending: bool,
}

impl RetiredClientAccess {
    pub fn from_profile(profile: &ClientProfile) -> Self {
        let public_key = fs::read_to_string(format!("{}.pub", profile.identity_file))
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| {
                let fields = value.split_whitespace().collect::<Vec<_>>();
                fields.len() >= 2
                    && fields[0] == "ssh-ed25519"
                    && !value.chars().any(char::is_control)
            });
        Self {
            controller_host: profile.controller_host.clone(),
            controller_user: profile.controller_user.clone(),
            controller_port: profile.controller_port,
            known_hosts_path: profile.known_hosts_path.clone(),
            identity_file: profile.identity_file.clone(),
            public_key,
            nfs_client_id: profile.nfs_client_id.clone(),
            nfs_client_ip: profile.nfs_client_ip.clone(),
            nfs_revocation_pending: profile.mounts_enabled,
            key_revocation_pending: true,
            control_master_close_pending: true,
        }
    }

    pub fn has_pending_cleanup(&self) -> bool {
        self.nfs_revocation_pending
            || self.key_revocation_pending
            || self.control_master_close_pending
    }

    pub fn nfs_cleanup_from_profile(profile: &ClientProfile) -> Self {
        let mut retired = Self::from_profile(profile);
        retired.key_revocation_pending = false;
        retired.control_master_close_pending = false;
        retired
    }

    pub fn is_nfs_only(&self) -> bool {
        !self.key_revocation_pending && !self.control_master_close_pending
    }
}

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
    #[serde(default)]
    pub mounted_descriptor: Option<ClientDescriptor>,
    #[serde(default)]
    pub transition_mount_descriptors: Vec<ClientDescriptor>,
    #[serde(default)]
    pub retired_access: Vec<RetiredClientAccess>,
    #[serde(default)]
    pub leave_phase: Option<ClientLeavePhase>,
}

impl ClientProfile {
    pub fn installed_mount_descriptor(&self) -> Option<&ClientDescriptor> {
        if self.leave_has_completed(ClientLeavePhase::MountsDetached) {
            return None;
        }
        if let Some(descriptor) = self.mounted_descriptor.as_ref() {
            return Some(descriptor);
        }
        // Version 1 profiles predate separate observed and installed
        // descriptors, so their current descriptor is the only available
        // migration source.
        (self.version == 1 && !self.leave_has_completed(ClientLeavePhase::MountsDetached))
            .then(|| self.descriptor.as_ref())
            .flatten()
    }

    pub fn leave_has_completed(&self, phase: ClientLeavePhase) -> bool {
        self.leave_phase.is_some_and(|completed| completed >= phase)
    }

    pub fn mount_cleanup_descriptors(&self) -> Vec<&ClientDescriptor> {
        self.mounted_descriptor
            .iter()
            .chain(self.transition_mount_descriptors.iter())
            .collect()
    }

    pub fn has_pending_retired_access(&self) -> bool {
        self.retired_access
            .iter()
            .any(RetiredClientAccess::has_pending_cleanup)
    }

    pub fn supersede_nfs_cleanup_for(&mut self, client_id: &str) -> bool {
        let before = self.retired_access.len();
        self.retired_access
            .retain(|retired| !(retired.is_nfs_only() && retired.nfs_client_id == client_id));
        self.retired_access.len() != before
    }
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
            match self.load_path(&entry.path()) {
                Ok(profile) => profiles.push(profile),
                Err(error) => {
                    // An unrelated damaged or future-version profile must not
                    // make every other joined cluster unusable.
                    eprintln!(
                        "Warning: ignoring unusable client profile {}: {error}",
                        entry.path().display()
                    );
                }
            }
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
    if !matches!(profile.version, 1 | 2 | CLIENT_PROFILE_VERSION)
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
        || !profile.retired_access.iter().all(validate_retired_access)
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

fn validate_retired_access(access: &RetiredClientAccess) -> bool {
    let user_valid = !access.controller_user.is_empty()
        && access.controller_user.len() <= 64
        && access
            .controller_user
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                } else {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                }
            });
    let identity_path = Path::new(&access.identity_file);
    let known_hosts_path = Path::new(&access.known_hosts_path);
    let private_macluster_path = |path: &Path| {
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            && path.to_string_lossy().contains("/.ssh/macluster/")
    };
    user_valid
        && !access.controller_host.trim().is_empty()
        && access.controller_port != 0
        && private_macluster_path(identity_path)
        && private_macluster_path(known_hosts_path)
        && access.nfs_client_id.len() <= 64
        && access
            .nfs_client_id
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && access
            .nfs_client_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && access.nfs_client_ip.parse::<std::net::Ipv4Addr>().is_ok()
        && access.public_key.as_deref().is_none_or(|public_key| {
            let fields = public_key.split_whitespace().collect::<Vec<_>>();
            fields.len() >= 2
                && fields[0] == "ssh-ed25519"
                && !public_key.contains('\n')
                && !public_key.chars().any(char::is_control)
        })
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use macluster_protocol::control::ClientDescriptor;
    use macluster_protocol::identifiers::Id128;

    use super::{ClientLeavePhase, ClientProfile, ClientProfileStore, ClientSelection};

    fn profile(uuid: &str, last_used_unix_ms: u64) -> ClientProfile {
        ClientProfile {
            version: 2,
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
            mounted_descriptor: None,
            transition_mount_descriptors: vec![],
            retired_access: vec![],
            leave_phase: None,
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

    #[test]
    fn version_two_does_not_assume_an_observed_descriptor_is_mounted() {
        let mut value = profile("8a052047-94e7-5b3d-acce-289a8d952877", 10);
        value.descriptor = Some(ClientDescriptor {
            cluster_uuid: value.cluster_uuid.clone(),
            cluster_name: value.cluster_name.clone(),
            default_queue: "default".parse().unwrap(),
            config_generation: 1,
            controller_build_id: "test".into(),
            controller_uid: 501,
            capabilities: vec![],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![],
            queues: vec![],
        });
        assert!(value.installed_mount_descriptor().is_none());
        value.version = 1;
        assert_eq!(
            value
                .installed_mount_descriptor()
                .map(|descriptor| descriptor.config_generation),
            Some(1)
        );
        value.leave_phase = Some(ClientLeavePhase::MountsDetached);
        assert!(value.installed_mount_descriptor().is_none());
        value.mounted_descriptor = value.descriptor.clone();
        assert!(value.installed_mount_descriptor().is_none());
    }

    #[test]
    fn leave_progress_survives_profile_reload_and_skips_completed_phases() {
        let (root, store) = temp_store();
        let mut value = profile("c44b1afa-4c7f-5c80-bea0-422074469b1d", 10);
        value.leave_phase = Some(ClientLeavePhase::Requested);
        store.save(&value).unwrap();

        let requested = store.load(&value.cluster_uuid).unwrap();
        assert!(requested.leave_has_completed(ClientLeavePhase::Requested));
        assert!(!requested.leave_has_completed(ClientLeavePhase::MountsDetached));

        value.leave_phase = Some(ClientLeavePhase::KeyRevoked);
        store.save(&value).unwrap();
        let key_revoked = store.load(&value.cluster_uuid).unwrap();
        assert!(key_revoked.leave_has_completed(ClientLeavePhase::MountsDetached));
        assert!(key_revoked.leave_has_completed(ClientLeavePhase::KeyRevoked));
        assert!(!key_revoked.leave_has_completed(ClientLeavePhase::LocalCredentialsRemoved));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_unrelated_profile_does_not_block_a_valid_profile() {
        let (root, store) = temp_store();
        let value = profile("1a14b395-11da-5e54-b02e-7a269d5f9649", 10);
        store.save(&value).unwrap();
        let corrupt = store
            .root()
            .join("393e5a76-165b-5459-9bc2-fe1d1434115c.json");
        fs::write(&corrupt, b"{not-json").unwrap();
        fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(matches!(
            store.select(None).unwrap(),
            ClientSelection::Sole(profile) if profile.cluster_uuid == value.cluster_uuid
        ));
        assert!(store.load("393e5a76-165b-5459-9bc2-fe1d1434115c").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_mount_transition_keeps_both_layouts_for_cleanup() {
        let mut value = profile("f540a484-44ca-5fcd-ab86-d42ecd145bc7", 10);
        let installed = ClientDescriptor {
            cluster_uuid: value.cluster_uuid.clone(),
            cluster_name: value.cluster_name.clone(),
            default_queue: "default".parse().unwrap(),
            config_generation: 1,
            controller_build_id: "test".into(),
            controller_uid: 501,
            capabilities: vec![],
            primary_mount_root: "/Users/Shared/macluster".into(),
            primary_source_root: "/Users/Shared/macluster-v1".into(),
            primary_source_host: "192.0.2.1".into(),
            shares: vec![],
            queues: vec![],
        };
        let mut attempted = installed.clone();
        attempted.primary_source_root = "/Users/Shared/macluster-v2".into();
        value.mounted_descriptor = Some(installed);
        value.transition_mount_descriptors = vec![attempted];

        let cleanup = value.mount_cleanup_descriptors();
        assert_eq!(cleanup.len(), 2);
        assert_eq!(
            cleanup
                .iter()
                .map(|descriptor| descriptor.primary_source_root.as_str())
                .collect::<Vec<_>>(),
            vec!["/Users/Shared/macluster-v1", "/Users/Shared/macluster-v2"]
        );
    }

    #[test]
    fn endpoint_migration_preserves_every_retired_identity_phase() {
        let (root, store) = temp_store();
        let mut value = profile("53b6c8f4-d47d-51de-9b5b-61184fb37997", 10);
        value.known_hosts_path = "/Users/mac/.ssh/macluster/e40edfcc/known_hosts-endpoint".into();
        value.identity_file = "/Users/mac/.ssh/macluster/node-endpoint".into();
        let retired = super::RetiredClientAccess::from_profile(&value);
        assert_eq!(retired.controller_host, value.controller_host);
        assert_eq!(retired.identity_file, value.identity_file);
        assert_eq!(retired.nfs_client_id, value.nfs_client_id);
        assert!(retired.nfs_revocation_pending);
        assert!(retired.key_revocation_pending);
        assert!(retired.control_master_close_pending);
        assert!(retired.has_pending_cleanup());
        value.retired_access = vec![retired];
        store.save(&value).unwrap();
        let loaded = store.load(&value.cluster_uuid).unwrap();
        assert_eq!(loaded.retired_access, value.retired_access);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn control_only_conversion_retains_only_the_old_nfs_cleanup() {
        let value = profile("fdd66df7-0069-5a26-a59f-8206555b8d7a", 10);
        let retired = super::RetiredClientAccess::nfs_cleanup_from_profile(&value);
        assert!(retired.nfs_revocation_pending);
        assert!(!retired.key_revocation_pending);
        assert!(!retired.control_master_close_pending);
    }

    #[test]
    fn nfs_only_cleanup_is_superseded_by_a_full_rejoin() {
        let mut value = profile("fcadfc37-b22a-5c24-a254-8db9208c9326", 10);
        value.nfs_client_id = "client-current".into();
        value.retired_access = vec![super::RetiredClientAccess::nfs_cleanup_from_profile(&value)];
        assert!(value.supersede_nfs_cleanup_for("client-current"));
        assert!(value.retired_access.is_empty());
    }

    #[test]
    fn retired_access_records_a_public_key_before_local_cleanup() {
        let (root, _) = temp_store();
        fs::create_dir_all(&root).unwrap();
        let identity = root.join("node-client");
        fs::write(
            format!("{}.pub", identity.display()),
            "ssh-ed25519 AAAA-client macluster-client\n",
        )
        .unwrap();
        let mut value = profile("668d42da-f734-51cb-a45e-770682db4e2e", 10);
        value.identity_file = identity.to_string_lossy().into_owned();
        let retired = super::RetiredClientAccess::from_profile(&value);
        assert_eq!(
            retired.public_key.as_deref(),
            Some("ssh-ed25519 AAAA-client macluster-client")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
