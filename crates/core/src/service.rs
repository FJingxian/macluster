use std::{
    fs, io,
    os::fd::AsRawFd,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
};

use macluster_protocol::{
    framing::{FrameError, sha256_hex},
    identifiers::Id128,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{ClusterConfig, ConfigError};

const SOCKET_ROOT: &str = "/private/tmp";
const MAX_UNIX_PATH_BYTES: usize = 104;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("cannot resolve cluster config {path}: {source}")]
    ConfigPath { path: PathBuf, source: io::Error },
    #[error("cannot read cluster config {path}: {source}")]
    ConfigRead { path: PathBuf, source: io::Error },
    #[error("invalid cluster config: {0}")]
    Config(#[from] ConfigError),
    #[error("cannot resolve controller state directory {path}: {source}")]
    StatePath { path: PathBuf, source: io::Error },
    #[error("controller state path is not a directory: {0}")]
    StateNotDirectory(PathBuf),
    #[error("cannot derive service binding digest: {0}")]
    Digest(#[from] FrameError),
    #[error("cannot inspect private control socket root {path}: {source}")]
    SocketRoot { path: PathBuf, source: io::Error },
    #[error("control socket root is not a private temporary directory: {0}")]
    UnsafeSocketRoot(PathBuf),
    #[error("cannot prepare control endpoint directory {path}: {source}")]
    EndpointDirectory { path: PathBuf, source: io::Error },
    #[error("control endpoint directory is not owned by uid {uid} with mode 0700: {path}")]
    UnsafeEndpointDirectory { path: PathBuf, uid: u32 },
    #[error("control socket path is too long for a Unix-domain socket: {0}")]
    EndpointPathTooLong(PathBuf),
    #[error("cannot prepare controller service directory {path}: {source}")]
    ServiceDirectory { path: PathBuf, source: io::Error },
    #[error("controller service directory is not private and owned by uid {1}: {0}")]
    UnsafeServiceDirectory(PathBuf, u32),
    #[error("cannot access controller service intent {path}: {source}")]
    ServiceIntentIo { path: PathBuf, source: io::Error },
    #[error("controller service intent at {path} is not a private regular file")]
    UnsafeServiceIntent { path: PathBuf },
    #[error("controller service intent at {path} belongs to a different service binding")]
    ServiceIntentBinding { path: PathBuf },
    #[error("controller service intent at {path} is invalid: {source}")]
    ServiceIntentFormat {
        path: PathBuf,
        source: serde_json::Error,
    },
}

/// Whether ordinary CLI calls may start the user's LaunchAgent.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceIntent {
    #[default]
    Auto,
    Stopped,
    Resetting,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ServiceIntentRecord {
    version: u32,
    binding_digest: String,
    intent: ServiceIntent,
}

/// A private, binding-scoped atomic store for the controller's desired state.
#[derive(Clone, Debug)]
pub struct ServiceIntentStore {
    path: PathBuf,
    binding_digest: String,
    uid: u32,
}

impl ServiceIntentStore {
    pub fn open(binding: &ServiceBinding) -> Result<Self, ServiceError> {
        let directory = binding.state_dir.join("service");
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(ServiceError::ServiceDirectory {
                    path: directory,
                    source,
                });
            }
        }
        prepare_private_directory(&directory, binding.uid)?;
        Ok(Self {
            path: directory.join("intent.json"),
            binding_digest: binding.binding_digest.clone(),
            uid: binding.uid,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn read(&self) -> Result<ServiceIntent, ServiceError> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ServiceIntent::Auto),
            Err(source) => Err(ServiceError::ServiceIntentIo {
                path: self.path.clone(),
                source,
            }),
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != self.uid
                    || metadata.permissions().mode() & 0o777 != 0o600
                {
                    return Err(ServiceError::UnsafeServiceIntent {
                        path: self.path.clone(),
                    });
                }
                let bytes =
                    fs::read(&self.path).map_err(|source| ServiceError::ServiceIntentIo {
                        path: self.path.clone(),
                        source,
                    })?;
                let record: ServiceIntentRecord =
                    serde_json::from_slice(&bytes).map_err(|source| {
                        ServiceError::ServiceIntentFormat {
                            path: self.path.clone(),
                            source,
                        }
                    })?;
                if record.version != 1 || record.binding_digest != self.binding_digest {
                    return Err(ServiceError::ServiceIntentBinding {
                        path: self.path.clone(),
                    });
                }
                Ok(record.intent)
            }
        }
    }

    pub fn write(&self, intent: ServiceIntent) -> Result<(), ServiceError> {
        let directory = self.path.parent().expect("service intent has a parent");
        validate_private_directory(directory, self.uid)?;
        let temporary = directory.join(format!(".intent-{}.tmp", Id128::random()));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|source| ServiceError::ServiceIntentIo {
                    path: temporary.clone(),
                    source,
                })?;
            let record = ServiceIntentRecord {
                version: 1,
                binding_digest: self.binding_digest.clone(),
                intent,
            };
            serde_json::to_writer(&mut file, &record).map_err(|source| {
                ServiceError::ServiceIntentFormat {
                    path: temporary.clone(),
                    source,
                }
            })?;
            file.sync_all()
                .map_err(|source| ServiceError::ServiceIntentIo {
                    path: temporary.clone(),
                    source,
                })?;
            fs::rename(&temporary, &self.path).map_err(|source| ServiceError::ServiceIntentIo {
                path: self.path.clone(),
                source,
            })?;
            fs::File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| ServiceError::ServiceIntentIo {
                    path: directory.to_path_buf(),
                    source,
                })?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn validate_private_directory(path: &Path, uid: u32) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ServiceError::ServiceDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ServiceError::UnsafeServiceDirectory(
            path.to_path_buf(),
            uid,
        ));
    }
    Ok(())
}

fn prepare_private_directory(path: &Path, uid: u32) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ServiceError::ServiceDirectory {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(ServiceError::UnsafeServiceDirectory(
            path.to_path_buf(),
            uid,
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ServiceError::ServiceDirectory {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    validate_private_directory(path, uid)
}

/// Identifies one local controller instance without relying on a PID or socket file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBinding {
    config_path: PathBuf,
    state_dir: PathBuf,
    namespace: String,
    uid: u32,
    binding_digest: String,
}

impl ServiceBinding {
    pub fn load(config_path: &Path, state_dir: &Path) -> Result<Self, ServiceError> {
        let config_path =
            config_path
                .canonicalize()
                .map_err(|source| ServiceError::ConfigPath {
                    path: config_path.to_path_buf(),
                    source,
                })?;
        if !config_path.is_file() {
            return Err(ServiceError::ConfigRead {
                path: config_path,
                source: io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"),
            });
        }
        let config_text =
            fs::read_to_string(&config_path).map_err(|source| ServiceError::ConfigRead {
                path: config_path.clone(),
                source,
            })?;
        let config = ClusterConfig::parse(&config_text)?;
        let namespace = Id128::parse(&config.share_uuid)
            .map_err(|_| ServiceError::Config(ConfigError::InvalidShareUuid))?
            .to_string();

        let state_dir = state_dir
            .canonicalize()
            .map_err(|source| ServiceError::StatePath {
                path: state_dir.to_path_buf(),
                source,
            })?;
        let state_metadata =
            fs::symlink_metadata(&state_dir).map_err(|source| ServiceError::StatePath {
                path: state_dir.clone(),
                source,
            })?;
        if !state_metadata.is_dir() {
            return Err(ServiceError::StateNotDirectory(state_dir));
        }

        let uid = unsafe { libc::geteuid() };
        let mut binding_parts = Vec::new();
        append_binding_part(
            &mut binding_parts,
            config_path.as_os_str().as_encoded_bytes(),
        );
        append_binding_part(&mut binding_parts, state_dir.as_os_str().as_encoded_bytes());
        append_binding_part(&mut binding_parts, namespace.as_bytes());
        append_binding_part(&mut binding_parts, &uid.to_be_bytes());
        let binding_digest = sha256_hex(&binding_parts)?;

        Ok(Self {
            config_path,
            state_dir,
            namespace,
            uid,
            binding_digest,
        })
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    pub fn endpoint_dir(&self) -> PathBuf {
        PathBuf::from(SOCKET_ROOT).join(format!("macluster-{}", self.uid))
    }

    pub fn endpoint_path(&self) -> PathBuf {
        self.endpoint_dir()
            .join(format!("{}.sock", self.binding_digest))
    }

    /// Create or validate the private parent directory used by controller IPC.
    pub fn prepare_endpoint_dir(&self) -> Result<PathBuf, ServiceError> {
        let root = PathBuf::from(SOCKET_ROOT);
        let root_metadata =
            fs::symlink_metadata(&root).map_err(|source| ServiceError::SocketRoot {
                path: root.clone(),
                source,
            })?;
        if !root_metadata.is_dir()
            || root_metadata.file_type().is_symlink()
            || root_metadata.uid() != 0
            || root_metadata.permissions().mode() & 0o1000 == 0
        {
            return Err(ServiceError::UnsafeSocketRoot(root));
        }

        let directory = self.endpoint_dir();
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(ServiceError::EndpointDirectory {
                    path: directory,
                    source,
                });
            }
        }
        let metadata =
            fs::symlink_metadata(&directory).map_err(|source| ServiceError::EndpointDirectory {
                path: directory.clone(),
                source,
            })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != self.uid {
            return Err(ServiceError::UnsafeEndpointDirectory {
                path: directory,
                uid: self.uid,
            });
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(
                |source| ServiceError::EndpointDirectory {
                    path: directory.clone(),
                    source,
                },
            )?;
        }
        let verified =
            fs::symlink_metadata(&directory).map_err(|source| ServiceError::EndpointDirectory {
                path: directory.clone(),
                source,
            })?;
        if !verified.is_dir()
            || verified.file_type().is_symlink()
            || verified.uid() != self.uid
            || verified.permissions().mode() & 0o777 != 0o700
        {
            return Err(ServiceError::UnsafeEndpointDirectory {
                path: directory,
                uid: self.uid,
            });
        }
        let endpoint = self.endpoint_path();
        if endpoint.as_os_str().as_encoded_bytes().len() >= MAX_UNIX_PATH_BYTES {
            return Err(ServiceError::EndpointPathTooLong(endpoint));
        }
        Ok(self.endpoint_dir())
    }
}

fn append_binding_part(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}

pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::{ServiceBinding, ServiceIntent, ServiceIntentStore, append_binding_part};
    use macluster_protocol::identifiers::Id128;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

    fn config_text(shared: &PathBuf) -> String {
        format!(
            "[cluster]\nname=\"service-test\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"ssh\"\n",
            shared.display()
        )
    }

    #[test]
    fn binding_digest_and_endpoint_are_stable_for_the_same_inputs() {
        let root = std::env::temp_dir().join(format!("macluster-service-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(&config, config_text(&root)).unwrap();

        let first = ServiceBinding::load(&config, &state).unwrap();
        let second = ServiceBinding::load(&config, &state).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.endpoint_path(), second.endpoint_path());
        assert_eq!(first.binding_digest().len(), 64);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn binding_digest_uses_length_delimited_fields() {
        let mut left = Vec::new();
        append_binding_part(&mut left, b"ab");
        append_binding_part(&mut left, b"c");
        let mut right = Vec::new();
        append_binding_part(&mut right, b"a");
        append_binding_part(&mut right, b"bc");
        assert_ne!(left, right);
    }

    #[test]
    fn service_intent_defaults_to_auto_and_round_trips_atomically() {
        let root = std::env::temp_dir().join(format!("macluster-intent-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(&config, config_text(&root)).unwrap();
        let binding = ServiceBinding::load(&config, &state).unwrap();
        let store = ServiceIntentStore::open(&binding).unwrap();

        assert_eq!(store.read().unwrap(), ServiceIntent::Auto);
        store.write(ServiceIntent::Stopped).unwrap();
        assert_eq!(store.read().unwrap(), ServiceIntent::Stopped);
        store.write(ServiceIntent::Resetting).unwrap();
        assert_eq!(store.read().unwrap(), ServiceIntent::Resetting);
        assert_eq!(
            fs::symlink_metadata(store.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn service_intent_is_bound_to_config_and_state_identity() {
        let root =
            std::env::temp_dir().join(format!("macluster-intent-binding-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let config = root.join("config.toml");
        let alternate_config = root.join("alternate.toml");
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::write(&config, config_text(&root)).unwrap();
        fs::write(&alternate_config, config_text(&root)).unwrap();
        let original = ServiceBinding::load(&config, &state).unwrap();
        let alternate = ServiceBinding::load(&alternate_config, &state).unwrap();
        ServiceIntentStore::open(&original)
            .unwrap()
            .write(ServiceIntent::Stopped)
            .unwrap();

        assert!(
            ServiceIntentStore::open(&alternate)
                .unwrap()
                .read()
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
