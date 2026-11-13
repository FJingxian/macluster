use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use macluster_protocol::smb_credential::{
    MAX_SMB_CREDENTIAL_FRAME_BYTES, SMB_CREDENTIAL_SERVICE_VERSION, SecretString, SmbCredentialKey,
    SmbCredentialOperation, SmbCredentialReply, SmbCredentialReplyBody, SmbCredentialRequest,
    StoredSmbCredential,
};
use thiserror::Error;

use macluster_core::config::ClusterConfig;

pub const SMB_CREDENTIAL_SOCKET_PATH: &str = "/var/run/org.macluster.smb-credential.sock";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct CredentialHelperClient {
    socket: PathBuf,
    timeout: Duration,
}

impl CredentialHelperClient {
    pub fn system() -> Self {
        Self::new(SMB_CREDENTIAL_SOCKET_PATH, CLIENT_TIMEOUT)
    }

    pub fn new(socket: impl Into<PathBuf>, timeout: Duration) -> Self {
        Self {
            socket: socket.into(),
            timeout,
        }
    }

    pub fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Put {
            key: key.clone(),
            password: password.clone(),
        })? {
            SmbCredentialReplyBody::Credential(credential) => Ok(credential),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "put",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn get(
        &self,
        key: &SmbCredentialKey,
    ) -> Result<Option<StoredSmbCredential>, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Get { key: key.clone() })? {
            SmbCredentialReplyBody::Credential(credential) => Ok(Some(credential)),
            SmbCredentialReplyBody::Missing => Ok(None),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "get",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn import(
        &self,
        key: &SmbCredentialKey,
        credential: &StoredSmbCredential,
    ) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Import {
            key: key.clone(),
            credential: credential.clone(),
        })? {
            SmbCredentialReplyBody::Credential(_) => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "import",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn delete(&self, key: &SmbCredentialKey) -> Result<bool, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Delete { key: key.clone() })? {
            SmbCredentialReplyBody::Deleted(deleted) => Ok(deleted),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "delete",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn provision_login_keychain(
        &self,
        key: &SmbCredentialKey,
        generation: u64,
        password: &SecretString,
    ) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::ProvisionLogin {
            key: key.clone(),
            generation,
            password: password.clone(),
        })? {
            SmbCredentialReplyBody::Provisioned => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "provision_login",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn delete_login_keychain(
        &self,
        key: &SmbCredentialKey,
    ) -> Result<bool, SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::DeleteLogin { key: key.clone() })? {
            SmbCredentialReplyBody::Deleted(deleted) => Ok(deleted),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "delete_login",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn mount_smb(
        &self,
        key: &SmbCredentialKey,
        source: &str,
        target: &str,
        logical: &str,
        logical_target: &str,
    ) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::MountSmb {
            key: key.clone(),
            source: source.to_owned(),
            target: target.to_owned(),
            logical: logical.to_owned(),
            logical_target: logical_target.to_owned(),
        })? {
            SmbCredentialReplyBody::Mounted => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "mount_smb",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn unmount_smb(
        &self,
        target: &str,
        logical: &str,
        logical_target: &str,
        force: bool,
    ) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::UnmountSmb {
            target: target.to_owned(),
            logical: logical.to_owned(),
            logical_target: logical_target.to_owned(),
            force,
        })? {
            SmbCredentialReplyBody::Unmounted => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "unmount_smb",
                reply: reply_name(&other),
            }),
        }
    }

    pub fn ping(&self) -> Result<(), SmbCredentialClientError> {
        match self.call(SmbCredentialOperation::Ping)? {
            SmbCredentialReplyBody::Pong => Ok(()),
            other => Err(SmbCredentialClientError::UnexpectedReply {
                operation: "ping",
                reply: reply_name(&other),
            }),
        }
    }

    fn call(
        &self,
        operation: SmbCredentialOperation,
    ) -> Result<SmbCredentialReplyBody, SmbCredentialClientError> {
        call_at(&self.socket, self.timeout, operation)
    }
}

pub trait MasterCredentialReader {
    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String>;
}

impl MasterCredentialReader for CredentialHelperClient {
    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
        CredentialHelperClient::get(self, key).map_err(|error| error.to_string())
    }
}

pub fn load_smb_credential_provisions(
    config: &ClusterConfig,
    reader: &dyn MasterCredentialReader,
) -> Result<Vec<macluster_protocol::smb_credential::SmbCredentialProvision>, String> {
    let (provisions, missing) = load_available_smb_credential_provisions(config, reader)?;
    if let Some(server) = missing.first() {
        return Err(format!("master credential is missing for {server}"));
    }
    Ok(provisions)
}

/// Controller reconciliation must not let an unavailable SMB secret prevent
/// unrelated primary/NFS recovery. Consumers still receive an explicit list of
/// missing servers so SMB-dependent jobs remain unschedulable.
pub fn load_available_smb_credential_provisions(
    config: &ClusterConfig,
    reader: &dyn MasterCredentialReader,
) -> Result<
    (
        Vec<macluster_protocol::smb_credential::SmbCredentialProvision>,
        Vec<macluster_protocol::identifiers::NodeId>,
    ),
    String,
> {
    let cluster_uuid = macluster_protocol::identifiers::Id128::parse(&config.share_uuid)
        .map_err(|error| error.to_string())?;
    let mut keys = std::collections::BTreeMap::new();
    for share in config
        .shares
        .values()
        .filter(|share| share.protocol == macluster_core::storage_uri::StorageProtocol::Smb)
    {
        let account = share.smb_user.as_deref().ok_or_else(|| {
            format!(
                "SMB share on server '{}' has no configured account",
                share.server
            )
        })?;
        let server = config
            .nodes
            .get(share.server.as_str())
            .ok_or_else(|| format!("SMB server '{}' is not configured", share.server))?;
        let key = SmbCredentialKey {
            cluster_uuid,
            server_id: share.server.clone(),
            server_host: server.host.clone(),
            account: account.to_owned(),
        };
        key.validate().map_err(|error| error.to_string())?;
        keys.insert(key.service_name(), key);
    }
    let mut provisions = Vec::new();
    let mut missing = Vec::new();
    for key in keys.into_values() {
        match reader.get(&key)? {
            Some(credential) => {
                provisions.push(macluster_protocol::smb_credential::SmbCredentialProvision {
                    key,
                    credential,
                });
            }
            None => missing.push(key.server_id),
        }
    }
    Ok((provisions, missing))
}

pub fn export_smb_masters(
    config: &ClusterConfig,
    helper: &dyn MasterCredentialReader,
) -> Result<Vec<macluster_protocol::smb_credential::SmbCredentialProvision>, String> {
    load_smb_credential_provisions(config, helper)
}

pub fn put_smb_credential(
    key: &SmbCredentialKey,
    password: &SecretString,
) -> Result<StoredSmbCredential, SmbCredentialClientError> {
    CredentialHelperClient::system().put(key, password)
}

pub fn get_smb_credential(
    key: &SmbCredentialKey,
) -> Result<Option<StoredSmbCredential>, SmbCredentialClientError> {
    CredentialHelperClient::system().get(key)
}

pub fn import_smb_credential(
    key: &SmbCredentialKey,
    credential: &StoredSmbCredential,
) -> Result<(), SmbCredentialClientError> {
    CredentialHelperClient::system().import(key, credential)
}

pub fn delete_smb_credential(key: &SmbCredentialKey) -> Result<bool, SmbCredentialClientError> {
    CredentialHelperClient::system().delete(key)
}

pub fn ping_smb_credential() -> Result<(), SmbCredentialClientError> {
    CredentialHelperClient::system().ping()
}

fn call_at(
    socket: &Path,
    timeout: Duration,
    operation: SmbCredentialOperation,
) -> Result<SmbCredentialReplyBody, SmbCredentialClientError> {
    let request = SmbCredentialRequest::new(operation);
    request
        .validate()
        .map_err(|error| SmbCredentialClientError::InvalidRequest(error.to_string()))?;
    let bytes = serde_json::to_vec(&request).map_err(|_| {
        SmbCredentialClientError::InvalidRequest("request serialization failed".into())
    })?;
    if bytes.len() > MAX_SMB_CREDENTIAL_FRAME_BYTES {
        return Err(SmbCredentialClientError::FrameTooLarge);
    }
    let mut stream = UnixStream::connect(socket).map_err(SmbCredentialClientError::Io)?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(SmbCredentialClientError::Io)?;
    stream
        .write_all(&bytes)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|error| classify_io(error, timeout))?;
    let mut reply_bytes = Vec::new();
    stream
        .take(MAX_SMB_CREDENTIAL_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut reply_bytes)
        .map_err(|error| classify_io(error, timeout))?;
    if reply_bytes.len() > MAX_SMB_CREDENTIAL_FRAME_BYTES {
        return Err(SmbCredentialClientError::FrameTooLarge);
    }
    let reply: SmbCredentialReply =
        serde_json::from_slice(&reply_bytes).map_err(|_| SmbCredentialClientError::InvalidReply)?;
    if reply.service_version != SMB_CREDENTIAL_SERVICE_VERSION {
        return Err(SmbCredentialClientError::ServiceVersion {
            expected: SMB_CREDENTIAL_SERVICE_VERSION,
            actual: reply.service_version,
        });
    }
    reply.result.map_err(SmbCredentialClientError::Remote)
}

fn classify_io(error: std::io::Error, timeout: Duration) -> SmbCredentialClientError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        SmbCredentialClientError::Timeout(timeout)
    } else {
        SmbCredentialClientError::Io(error)
    }
}

fn reply_name(reply: &SmbCredentialReplyBody) -> &'static str {
    match reply {
        SmbCredentialReplyBody::Pong => "pong",
        SmbCredentialReplyBody::Credential(_) => "credential",
        SmbCredentialReplyBody::Missing => "missing",
        SmbCredentialReplyBody::Deleted(_) => "deleted",
        SmbCredentialReplyBody::Provisioned => "provisioned",
        SmbCredentialReplyBody::Mounted => "mounted",
        SmbCredentialReplyBody::Unmounted => "unmounted",
    }
}

#[derive(Debug, Error)]
pub enum SmbCredentialClientError {
    #[error("SMB credential helper I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("SMB credential helper timed out after {0:?}")]
    Timeout(Duration),
    #[error("SMB credential request is invalid: {0}")]
    InvalidRequest(String),
    #[error("SMB credential helper returned an invalid reply")]
    InvalidReply,
    #[error("SMB credential helper frame exceeds the configured limit")]
    FrameTooLarge,
    #[error("SMB credential helper service version {actual} does not match {expected}")]
    ServiceVersion {
        expected: &'static str,
        actual: String,
    },
    #[error("SMB credential helper rejected the request: {0}")]
    Remote(String),
    #[error("SMB credential helper returned {reply} for {operation}")]
    UnexpectedReply {
        operation: &'static str,
        reply: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        os::unix::net::UnixListener,
        path::PathBuf,
        time::Duration,
    };

    use macluster_core::config::ClusterConfig;
    use macluster_protocol::{
        identifiers::{Id128, NodeId},
        smb_credential::{
            MAX_SMB_CREDENTIAL_FRAME_BYTES, SMB_CREDENTIAL_SERVICE_VERSION, SecretString,
            SmbCredentialKey, SmbCredentialOperation, SmbCredentialReply, SmbCredentialReplyBody,
            SmbCredentialRequest, StoredSmbCredential,
        },
    };

    use super::{
        CredentialHelperClient, MasterCredentialReader, SmbCredentialClientError,
        load_smb_credential_provisions,
    };

    fn socket_path() -> (PathBuf, PathBuf) {
        let root = PathBuf::from("/tmp").join(format!(
            "mc-cred-{}-{}",
            std::process::id(),
            &Id128::random().to_string()[..8]
        ));
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join("credential.sock");
        (root, socket)
    }

    fn key() -> SmbCredentialKey {
        SmbCredentialKey {
            cluster_uuid: Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            server_id: NodeId::new("nas-01").unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        }
    }

    fn read_request(stream: &mut std::os::unix::net::UnixStream) -> SmbCredentialRequest {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn write_reply(stream: &mut std::os::unix::net::UnixStream, body: SmbCredentialReplyBody) {
        stream
            .write_all(&serde_json::to_vec(&SmbCredentialReply::success(body)).unwrap())
            .unwrap();
    }

    #[test]
    fn helper_client_round_trips_put_get_import_delete_and_missing() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let mut stored: Option<StoredSmbCredential> = None;
            for _ in 0..7 {
                let (mut stream, _) = listener.accept().unwrap();
                match read_request(&mut stream).operation {
                    SmbCredentialOperation::Put { password, .. } => {
                        stored = Some(StoredSmbCredential {
                            generation: 1,
                            password,
                        });
                        write_reply(
                            &mut stream,
                            SmbCredentialReplyBody::Credential(stored.as_ref().unwrap().clone()),
                        );
                    }
                    SmbCredentialOperation::Get { .. } => {
                        write_reply(
                            &mut stream,
                            stored
                                .as_ref()
                                .map(|credential| {
                                    SmbCredentialReplyBody::Credential(credential.clone())
                                })
                                .unwrap_or(SmbCredentialReplyBody::Missing),
                        );
                    }
                    SmbCredentialOperation::Import { credential, .. } => {
                        stored = Some(credential.clone());
                        write_reply(&mut stream, SmbCredentialReplyBody::Credential(credential));
                    }
                    SmbCredentialOperation::Delete { .. } => {
                        let removed = stored.take().is_some();
                        write_reply(&mut stream, SmbCredentialReplyBody::Deleted(removed));
                    }
                    SmbCredentialOperation::Ping => {
                        write_reply(&mut stream, SmbCredentialReplyBody::Pong);
                    }
                    SmbCredentialOperation::ProvisionLogin { password, .. } => {
                        assert_eq!(password.as_secret(), "test-secret-one");
                        write_reply(&mut stream, SmbCredentialReplyBody::Provisioned);
                    }
                    SmbCredentialOperation::DeleteLogin { .. } => {
                        write_reply(&mut stream, SmbCredentialReplyBody::Deleted(true));
                    }
                    SmbCredentialOperation::MountSmb { .. } => {
                        write_reply(&mut stream, SmbCredentialReplyBody::Mounted);
                    }
                    SmbCredentialOperation::UnmountSmb { .. } => {
                        write_reply(&mut stream, SmbCredentialReplyBody::Unmounted);
                    }
                }
            }
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        assert_eq!(client.get(&key()).unwrap(), None);
        assert_eq!(
            client
                .put(&key(), &SecretString::new("test-secret-one"))
                .unwrap()
                .generation,
            1
        );
        assert_eq!(
            client.get(&key()).unwrap().unwrap().password.as_secret(),
            "test-secret-one"
        );
        client
            .import(
                &key(),
                &StoredSmbCredential {
                    generation: 9,
                    password: SecretString::new("test-secret-nine"),
                },
            )
            .unwrap();
        assert_eq!(client.get(&key()).unwrap().unwrap().generation, 9);
        assert!(client.delete(&key()).unwrap());
        assert_eq!(client.get(&key()).unwrap(), None);

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_rejects_service_version_mismatch_without_secret_text() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            stream
                .write_all(
                    &serde_json::to_vec(&SmbCredentialReply {
                        service_version: "wrong-version".into(),
                        result: Err("do-not-log-test-secret".into()),
                    })
                    .unwrap(),
                )
                .unwrap();
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        let error = client
            .put(&key(), &SecretString::new("test-secret"))
            .unwrap_err();
        assert!(matches!(
            error,
            SmbCredentialClientError::ServiceVersion { .. }
        ));
        assert!(!format!("{error:?}").contains("test-secret"));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_bounds_replies_before_decoding() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            let _ = stream.write_all(&vec![b'x'; MAX_SMB_CREDENTIAL_FRAME_BYTES + 1]);
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        let error = client.get(&key()).unwrap_err();
        assert!(matches!(error, SmbCredentialClientError::FrameTooLarge));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_uses_the_current_service_version_in_requests() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            assert_eq!(request.service_version, SMB_CREDENTIAL_SERVICE_VERSION);
            write_reply(&mut stream, SmbCredentialReplyBody::Pong);
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        client.ping().unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn helper_client_provisions_mounts_and_deletes_the_node_credential() {
        let (root, path) = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut provision_stream, _) = listener.accept().unwrap();
            match read_request(&mut provision_stream).operation {
                SmbCredentialOperation::ProvisionLogin {
                    key: provision_key,
                    generation,
                    password,
                } => {
                    assert_eq!(provision_key, key());
                    assert_eq!(generation, 7);
                    assert_eq!(password.as_secret(), "test-secret");
                }
                operation => panic!("unexpected operation: {operation:?}"),
            }
            write_reply(&mut provision_stream, SmbCredentialReplyBody::Provisioned);
            drop(provision_stream);

            let (mut delete_stream, _) = listener.accept().unwrap();
            match read_request(&mut delete_stream).operation {
                SmbCredentialOperation::DeleteLogin { key: delete_key } => {
                    assert_eq!(delete_key, key())
                }
                operation => panic!("unexpected operation: {operation:?}"),
            }
            write_reply(&mut delete_stream, SmbCredentialReplyBody::Deleted(false));
            drop(delete_stream);

            let (mut mount_stream, _) = listener.accept().unwrap();
            match read_request(&mut mount_stream).operation {
                SmbCredentialOperation::MountSmb {
                    key: mount_key,
                    source,
                    target,
                    logical,
                    logical_target,
                } => {
                    assert_eq!(mount_key, key());
                    assert_eq!(source, "//smb-user@192.0.2.20/Partition_2");
                    assert_eq!(target, "/Users/Shared/.macluster-mounts/share-1");
                    assert_eq!(logical, "/Users/operator/data");
                    assert_eq!(logical_target, "/Users/Shared/.macluster-mounts/share-1");
                }
                operation => panic!("unexpected operation: {operation:?}"),
            }
            write_reply(&mut mount_stream, SmbCredentialReplyBody::Mounted);
            drop(mount_stream);

            let (mut unmount_stream, _) = listener.accept().unwrap();
            match read_request(&mut unmount_stream).operation {
                SmbCredentialOperation::UnmountSmb {
                    target,
                    logical,
                    logical_target,
                    force,
                } => {
                    assert_eq!(target, "/Users/Shared/.macluster-mounts/share-1");
                    assert_eq!(logical, "/Users/operator/data");
                    assert_eq!(logical_target, "/Users/Shared/.macluster-mounts/share-1");
                    assert!(!force);
                }
                operation => panic!("unexpected operation: {operation:?}"),
            }
            write_reply(&mut unmount_stream, SmbCredentialReplyBody::Unmounted);
        });

        let client = CredentialHelperClient::new(path, Duration::from_secs(2));
        client
            .provision_login_keychain(&key(), 7, &SecretString::new("test-secret"))
            .unwrap();
        assert!(!client.delete_login_keychain(&key()).unwrap());
        client
            .mount_smb(
                &key(),
                "//smb-user@192.0.2.20/Partition_2",
                "/Users/Shared/.macluster-mounts/share-1",
                "/Users/operator/data",
                "/Users/Shared/.macluster-mounts/share-1",
            )
            .unwrap();
        client
            .unmount_smb(
                "/Users/Shared/.macluster-mounts/share-1",
                "/Users/operator/data",
                "/Users/Shared/.macluster-mounts/share-1",
                false,
            )
            .unwrap();

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    struct MapReader {
        credentials: BTreeMap<String, StoredSmbCredential>,
    }

    impl MasterCredentialReader for MapReader {
        fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
            Ok(self.credentials.get(&key.service_name()).cloned())
        }
    }

    #[test]
    fn reconnect_provisions_are_loaded_by_unique_scoped_master_key() {
        let config = ClusterConfig::parse(
            "[cluster]\nname = \"test\"\ndefault_queue = \"compute\"\nlogin_node = \"login\"\nshared_root = \"/Users/Shared/macluster\"\nshare_uuid = \"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"\nstorage_server = \"nas-01\"\nprotocol_version = 1\n\n[queues.compute]\nnodes = [\"login\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.nas-01]\nhost = \"192.0.2.20\"\ntransport = \"storage\"\n\n[shares.one]\nprotocol = \"smb\"\nserver = \"nas-01\"\nsource_root = \"/data\"\nmount_root = \"/Users/Shared/data\"\nshare_uuid = \"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\"\nsmb_user = \"smb-user\"\n\n[shares.two]\nprotocol = \"smb\"\nserver = \"nas-01\"\nsource_root = \"/cluster-user\"\nmount_root = \"/Users/Shared/cluster-user\"\nshare_uuid = \"cccccccc-cccc-4ccc-8ccc-cccccccccccc\"\nsmb_user = \"smb-user\"\n",
        )
        .unwrap();
        let key = SmbCredentialKey {
            cluster_uuid: Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            server_id: NodeId::new("nas-01").unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        };
        let stored = StoredSmbCredential {
            generation: 8,
            password: SecretString::new("test-secret"),
        };
        let reader = MapReader {
            credentials: BTreeMap::from([(key.service_name(), stored.clone())]),
        };

        let provisions = load_smb_credential_provisions(&config, &reader).unwrap();
        assert_eq!(provisions.len(), 1);
        assert_eq!(provisions[0].key, key);
        assert_eq!(provisions[0].credential, stored);
        assert!(!format!("{provisions:?}").contains("test-secret"));

        let missing = MapReader {
            credentials: BTreeMap::new(),
        };
        let error = super::export_smb_masters(&config, &missing)
            .expect_err("missing master must fail export");
        assert!(error.contains("missing"));
        assert!(!error.contains("test-secret"));

        let (provisions, missing_servers) =
            super::load_available_smb_credential_provisions(&config, &missing).unwrap();
        assert!(provisions.is_empty());
        assert_eq!(missing_servers.len(), 1);
        assert_eq!(missing_servers[0].as_str(), "nas-01");
    }
}
