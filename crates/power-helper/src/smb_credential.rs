#[cfg(test)]
use std::collections::BTreeMap;
use std::{
    collections::VecDeque,
    fs,
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use macluster_core::smb_keychain::MacKeychain;
use macluster_protocol::{
    identifiers::Id128,
    smb_credential::{
        MAX_SMB_CREDENTIAL_FRAME_BYTES, SecretString, SmbCredentialKey, SmbCredentialOperation,
        SmbCredentialReply, SmbCredentialReplyBody, SmbCredentialRequest, StoredSmbCredential,
    },
};

const SOCKET: &str = "/var/run/org.macluster.smb-credential.sock";
const CLUSTER_PIN: &str = "/Library/PrivilegedHelperTools/org.macluster.update/cluster-id";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const FAILURE_WINDOW: Duration = Duration::from_secs(1);
const MAX_FAILURES_PER_WINDOW: usize = 8;

trait SecretStore: Send + Sync {
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>, String>;
    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), String>;
    fn delete(&self, service: &str, account: &str) -> Result<bool, String>;
}

struct SystemSecretStore {
    keychain: Mutex<Option<MacKeychain>>,
}

impl SystemSecretStore {
    fn new() -> Self {
        Self {
            keychain: Mutex::new(None),
        }
    }

    fn with_keychain<T>(
        &self,
        operation: impl FnOnce(&MacKeychain) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut keychain = self
            .keychain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if keychain.is_none() {
            *keychain = Some(MacKeychain::system().map_err(|error| error.to_string())?);
        }
        operation(keychain.as_ref().expect("System Keychain was initialized"))
    }
}

impl SecretStore for SystemSecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>, String> {
        self.with_keychain(|keychain| {
            keychain
                .get_generic_secret(service, account)
                .map_err(|error| error.to_string())
        })
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), String> {
        self.with_keychain(|keychain| {
            keychain
                .set_generic_secret(service, account, &SecretString::new(value))
                .map_err(|error| error.to_string())
        })
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, String> {
        self.with_keychain(|keychain| {
            keychain
                .delete_generic_secret(service, account)
                .map_err(|error| error.to_string())
        })
    }
}

impl<T: SecretStore + ?Sized> SecretStore for Arc<T> {
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>, String> {
        (**self).get(service, account)
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), String> {
        (**self).set(service, account, value)
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, String> {
        (**self).delete(service, account)
    }
}

trait CredentialVault: Send + Sync {
    fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, String>;
    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String>;
    fn import(
        &self,
        key: &SmbCredentialKey,
        credential: &StoredSmbCredential,
    ) -> Result<(), String>;
    fn delete(&self, key: &SmbCredentialKey) -> Result<bool, String>;
}

struct KeychainCredentialVault<S> {
    store: S,
}

impl<S> KeychainCredentialVault<S> {
    fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: SecretStore> CredentialVault for KeychainCredentialVault<S> {
    fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, String> {
        key.validate().map_err(|error| error.to_string())?;
        let current = self
            .get(key)?
            .map(|credential| credential.generation)
            .unwrap_or(0);
        let generation = current
            .checked_add(1)
            .ok_or_else(|| "SMB credential generation is exhausted".to_owned())?;
        let credential = StoredSmbCredential {
            generation,
            password: password.clone(),
        };
        credential.validate().map_err(|error| error.to_string())?;
        self.persist(key, &credential)?;
        Ok(credential)
    }

    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
        key.validate().map_err(|error| error.to_string())?;
        let Some(encoded) = self
            .store
            .get(&key.service_name(), &key.keychain_account())?
        else {
            return Ok(None);
        };
        let credential: StoredSmbCredential = serde_json::from_str(encoded.as_secret())
            .map_err(|_| "stored SMB credential is malformed".to_owned())?;
        credential.validate().map_err(|error| error.to_string())?;
        Ok(Some(credential))
    }

    fn import(
        &self,
        key: &SmbCredentialKey,
        credential: &StoredSmbCredential,
    ) -> Result<(), String> {
        key.validate().map_err(|error| error.to_string())?;
        credential.validate().map_err(|error| error.to_string())?;
        self.persist(key, credential)
    }

    fn delete(&self, key: &SmbCredentialKey) -> Result<bool, String> {
        key.validate().map_err(|error| error.to_string())?;
        self.store
            .delete(&key.service_name(), &key.keychain_account())
    }
}

impl<T: CredentialVault + ?Sized> CredentialVault for Arc<T> {
    fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, String> {
        (**self).put(key, password)
    }

    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
        (**self).get(key)
    }

    fn import(
        &self,
        key: &SmbCredentialKey,
        credential: &StoredSmbCredential,
    ) -> Result<(), String> {
        (**self).import(key, credential)
    }

    fn delete(&self, key: &SmbCredentialKey) -> Result<bool, String> {
        (**self).delete(key)
    }
}

impl<S: SecretStore> KeychainCredentialVault<S> {
    fn persist(
        &self,
        key: &SmbCredentialKey,
        credential: &StoredSmbCredential,
    ) -> Result<(), String> {
        let encoded = serde_json::to_string(credential)
            .map_err(|_| "could not serialize SMB credential".to_owned())?;
        self.store
            .set(&key.service_name(), &key.keychain_account(), &encoded)
    }
}

pub(crate) fn start(peer_uid: libc::uid_t) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("SMB credential socket must run as root".into());
    }
    if !authorized_peer(peer_uid, peer_uid) {
        return Err("configured SMB credential UID must be non-root".into());
    }
    let store = SystemSecretStore::new();
    let vault = Arc::new(KeychainCredentialVault::new(store));
    let listener = bind_socket(peer_uid)?;
    let failures = Arc::new(FailureLimiter::default());
    thread::Builder::new()
        .name("macluster-smb-credential".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                let mut stream = match incoming {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("macluster-power: accept SMB credential client: {error}");
                        continue;
                    }
                };
                let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
                let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
                if let Err(error) =
                    serve_client_with_limiter(&mut stream, peer_uid, &vault, &failures)
                {
                    eprintln!("macluster-power: SMB credential request failed: {error}");
                }
            }
        })
        .map_err(|error| format!("start SMB credential socket worker: {error}"))?;
    Ok(())
}

fn bind_socket(peer_uid: libc::uid_t) -> Result<UnixListener, String> {
    let socket = Path::new(SOCKET);
    match fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(socket)
                .map_err(|error| format!("remove stale SMB credential socket: {error}"))?;
        }
        Ok(_) => {
            return Err(format!(
                "refusing to replace non-socket {}",
                socket.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect SMB credential socket: {error}")),
    }
    let listener = UnixListener::bind(socket)
        .map_err(|error| format!("bind SMB credential socket: {error}"))?;
    let account = unsafe { libc::getpwuid(peer_uid) };
    if account.is_null() {
        let _ = fs::remove_file(socket);
        return Err("configured SMB credential account no longer exists".into());
    }
    let socket_c = std::ffi::CString::new(SOCKET).expect("socket path has no NUL");
    if unsafe { libc::chown(socket_c.as_ptr(), peer_uid, (*account).pw_gid) } != 0 {
        let error = io::Error::last_os_error();
        let _ = fs::remove_file(socket);
        return Err(format!(
            "assign SMB credential socket to cluster account: {error}"
        ));
    }
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("protect SMB credential socket: {error}"))?;
    Ok(listener)
}

#[cfg(test)]
fn serve_client_with(
    stream: &mut UnixStream,
    expected_uid: libc::uid_t,
    pinned_cluster: Id128,
    vault: &dyn CredentialVault,
) -> Result<(), String> {
    let actual_uid =
        peer_uid_for(stream).map_err(|error| format!("inspect socket peer: {error}"))?;
    if !authorized_peer(actual_uid, expected_uid) {
        return write_reply(
            stream,
            SmbCredentialReply::failure("unauthorized local user"),
        );
    }
    let bytes = read_limited(stream)?;
    let request: SmbCredentialRequest =
        serde_json::from_slice(&bytes).map_err(|_| "invalid SMB credential request".to_owned())?;
    match process_request(request, pinned_cluster, vault) {
        Ok(body) => write_reply(stream, SmbCredentialReply::success(body)),
        Err(error) => write_reply(stream, SmbCredentialReply::failure(error.to_string())),
    }
}

fn serve_client_with_limiter(
    stream: &mut UnixStream,
    expected_uid: libc::uid_t,
    vault: &dyn CredentialVault,
    failures: &FailureLimiter,
) -> Result<(), String> {
    let actual_uid =
        peer_uid_for(stream).map_err(|error| format!("inspect socket peer: {error}"))?;
    if !authorized_peer(actual_uid, expected_uid) {
        if !failures.record(Instant::now()) {
            let _ = write_reply(
                stream,
                SmbCredentialReply::failure("too many failed SMB credential requests"),
            );
            return Ok(());
        }
        return write_reply(
            stream,
            SmbCredentialReply::failure("unauthorized local user"),
        );
    }
    let bytes = read_limited(stream)?;
    let request: SmbCredentialRequest =
        serde_json::from_slice(&bytes).map_err(|_| "invalid SMB credential request".to_owned())?;
    let result = if matches!(request.operation, SmbCredentialOperation::Ping) {
        process_request(request, Id128::random(), vault)
    } else {
        read_pinned_cluster(Path::new(CLUSTER_PIN))
            .map_err(SecretFailure::Cluster)
            .and_then(|pinned| process_request(request, pinned, vault))
    };
    match result {
        Ok(body) => write_reply(stream, SmbCredentialReply::success(body)),
        Err(error) => {
            failures.record(Instant::now());
            write_reply(stream, SmbCredentialReply::failure(error.to_string()))
        }
    }
}

fn process_request(
    request: SmbCredentialRequest,
    pinned_cluster: Id128,
    vault: &dyn CredentialVault,
) -> Result<SmbCredentialReplyBody, SecretFailure> {
    request.validate().map_err(SecretFailure::Validation)?;
    validate_cluster(&request.operation, pinned_cluster).map_err(SecretFailure::Cluster)?;
    match request.operation {
        SmbCredentialOperation::Ping => Ok(SmbCredentialReplyBody::Pong),
        SmbCredentialOperation::Put { key, password } => vault
            .put(&key, &password)
            .map(SmbCredentialReplyBody::Credential)
            .map_err(SecretFailure::Operation),
        SmbCredentialOperation::Get { key } => vault
            .get(&key)
            .map(|credential| {
                credential
                    .map(SmbCredentialReplyBody::Credential)
                    .unwrap_or(SmbCredentialReplyBody::Missing)
            })
            .map_err(SecretFailure::Operation),
        SmbCredentialOperation::Import { key, credential } => {
            vault
                .import(&key, &credential)
                .map_err(SecretFailure::Operation)?;
            Ok(SmbCredentialReplyBody::Credential(credential))
        }
        SmbCredentialOperation::Delete { key } => vault
            .delete(&key)
            .map(SmbCredentialReplyBody::Deleted)
            .map_err(SecretFailure::Operation),
    }
}

#[derive(Debug)]
enum SecretFailure {
    Validation(macluster_protocol::smb_credential::SmbCredentialValidationError),
    Cluster(String),
    Operation(String),
}

impl std::fmt::Display for SecretFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(formatter),
            Self::Cluster(error) | Self::Operation(error) => formatter.write_str(error),
        }
    }
}

fn validate_cluster(
    operation: &SmbCredentialOperation,
    pinned_cluster: Id128,
) -> Result<(), String> {
    let key = match operation {
        SmbCredentialOperation::Ping => return Ok(()),
        SmbCredentialOperation::Put { key, .. }
        | SmbCredentialOperation::Get { key }
        | SmbCredentialOperation::Import { key, .. }
        | SmbCredentialOperation::Delete { key } => key,
    };
    key.validate().map_err(|error| error.to_string())?;
    if key.cluster_uuid != pinned_cluster {
        return Err("SMB credential key belongs to a different cluster".into());
    }
    Ok(())
}

fn read_pinned_cluster(path: &Path) -> Result<Id128, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("read cluster pin: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 128
    {
        return Err("cluster pin has unsafe ownership, type, permissions, or size".into());
    }
    let value = fs::read_to_string(path).map_err(|error| format!("read cluster pin: {error}"))?;
    let value = value.trim();
    let parsed =
        Id128::parse(value).map_err(|_| "cluster pin is not a canonical UUID".to_owned())?;
    if parsed.to_string() != value {
        return Err("cluster pin is not a canonical UUID".into());
    }
    Ok(parsed)
}

fn read_limited(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    stream
        .take(MAX_SMB_CREDENTIAL_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read SMB credential request: {error}"))?;
    if bytes.len() > MAX_SMB_CREDENTIAL_FRAME_BYTES {
        return Err("SMB credential request exceeds the frame limit".into());
    }
    Ok(bytes)
}

fn write_reply(stream: &mut UnixStream, reply: SmbCredentialReply) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(&reply).map_err(|_| "serialize SMB credential reply".to_owned())?;
    if bytes.len() > MAX_SMB_CREDENTIAL_FRAME_BYTES {
        return Err("SMB credential reply exceeds the frame limit".into());
    }
    stream
        .write_all(&bytes)
        .map_err(|error| format!("write SMB credential response: {error}"))
}

fn peer_uid_for(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result =
        unsafe { libc::getpeereid(std::os::fd::AsRawFd::as_raw_fd(stream), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn authorized_peer(actual_uid: libc::uid_t, expected_uid: libc::uid_t) -> bool {
    actual_uid == expected_uid && expected_uid != 0
}

#[derive(Default)]
struct FailureLimiter {
    failures: Mutex<VecDeque<Instant>>,
}

impl FailureLimiter {
    fn record(&self, now: Instant) -> bool {
        let mut failures = self
            .failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while failures
            .front()
            .is_some_and(|instant| now.duration_since(*instant) > FAILURE_WINDOW)
        {
            failures.pop_front();
        }
        if failures.len() >= MAX_FAILURES_PER_WINDOW {
            return false;
        }
        failures.push_back(now);
        true
    }
}

#[cfg(test)]
#[derive(Default)]
struct MemorySecretStore {
    entries: Arc<Mutex<BTreeMap<(String, String), String>>>,
}

#[cfg(test)]
impl SecretStore for MemorySecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>, String> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(&(service.to_owned(), account.to_owned()))
            .map(|value| SecretString::new(value.clone())))
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), String> {
        self.entries
            .lock()
            .unwrap()
            .insert((service.to_owned(), account.to_owned()), value.to_owned());
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, String> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .remove(&(service.to_owned(), account.to_owned()))
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        sync::Arc,
    };

    use macluster_protocol::{
        identifiers::{Id128, NodeId},
        smb_credential::{
            SecretString, SmbCredentialKey, SmbCredentialOperation, SmbCredentialProvision,
            SmbCredentialReply, SmbCredentialReplyBody, SmbCredentialRequest, StoredSmbCredential,
        },
    };

    use super::{
        CredentialVault, KeychainCredentialVault, MemorySecretStore, read_pinned_cluster,
        serve_client_with,
    };

    fn cluster() -> Id128 {
        Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }

    fn key(server_id: &str) -> SmbCredentialKey {
        SmbCredentialKey {
            cluster_uuid: cluster(),
            server_id: NodeId::new(server_id).unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        }
    }

    fn request(operation: SmbCredentialOperation) -> SmbCredentialRequest {
        SmbCredentialRequest::new(operation)
    }

    fn call(
        request: &SmbCredentialRequest,
        expected_uid: libc::uid_t,
        pinned_cluster: Id128,
        vault: &dyn CredentialVault,
    ) -> SmbCredentialReply {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client
            .write_all(&serde_json::to_vec(request).unwrap())
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        serve_client_with(&mut server, expected_uid, pinned_cluster, vault).unwrap();
        drop(server);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn reply_credential(reply: SmbCredentialReply) -> StoredSmbCredential {
        match reply.result.unwrap() {
            SmbCredentialReplyBody::Credential(credential) => credential,
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    #[test]
    fn ping_rejects_wrong_peer_uid() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(store);
        let reply = call(
            &request(SmbCredentialOperation::Ping),
            unsafe { libc::geteuid() } + 1,
            cluster(),
            &vault,
        );

        assert!(reply.result.is_err());
        assert!(reply.result.unwrap_err().contains("unauthorized"));
    }

    #[test]
    fn missing_or_foreign_cluster_pin_rejects_secret_operations() {
        let root = std::env::temp_dir().join(format!(
            "macluster-pin-test-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("cluster-id");
        assert!(read_pinned_cluster(&path).is_err());
        std::fs::write(&path, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb\n").unwrap();
        assert!(
            read_pinned_cluster(&path).is_err(),
            "a user-owned cluster pin is not trusted"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn put_rejects_cluster_uuid_other_than_pinned_update_cluster() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(Arc::clone(&store));
        let request = request(SmbCredentialOperation::Put {
            key: key("nas-01"),
            password: SecretString::new("test-secret"),
        });
        let reply = call(
            &request,
            unsafe { libc::geteuid() },
            Id128::parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").unwrap(),
            &vault,
        );

        assert!(reply.result.is_err());
        assert!(store.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn put_then_get_returns_generation_one_and_secret() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(Arc::clone(&store));
        let put = call(
            &request(SmbCredentialOperation::Put {
                key: key("nas-01"),
                password: SecretString::new("test-secret"),
            }),
            unsafe { libc::geteuid() },
            cluster(),
            &vault,
        );
        assert_eq!(reply_credential(put).generation, 1);

        let get = call(
            &request(SmbCredentialOperation::Get { key: key("nas-01") }),
            unsafe { libc::geteuid() },
            cluster(),
            &vault,
        );
        let credential = reply_credential(get);
        assert_eq!(credential.generation, 1);
        assert_eq!(credential.password.as_secret(), "test-secret");
    }

    #[test]
    fn get_missing_credential_returns_a_typed_missing_reply() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(store);
        let reply = call(
            &request(SmbCredentialOperation::Get {
                key: key("missing"),
            }),
            unsafe { libc::geteuid() },
            cluster(),
            &vault,
        );

        assert_eq!(reply.result.unwrap(), SmbCredentialReplyBody::Missing);
    }

    #[test]
    fn put_again_increments_generation_and_replaces_value() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(store);
        let first = vault
            .put(&key("nas-01"), &SecretString::new("test-secret-one"))
            .unwrap();
        let second = vault
            .put(&key("nas-01"), &SecretString::new("test-secret-two"))
            .unwrap();

        assert_eq!(first.generation, 1);
        assert_eq!(second.generation, 2);
        assert_eq!(
            vault
                .get(&key("nas-01"))
                .unwrap()
                .unwrap()
                .password
                .as_secret(),
            "test-secret-two"
        );
    }

    #[test]
    fn import_preserves_generation_and_next_put_increments_it() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(store);
        let imported = StoredSmbCredential {
            generation: 17,
            password: SecretString::new("test-secret"),
        };
        vault.import(&key("nas-01"), &imported).unwrap();

        assert_eq!(vault.get(&key("nas-01")).unwrap().unwrap(), imported);
        assert_eq!(
            vault
                .put(&key("nas-01"), &SecretString::new("test-secret-next"))
                .unwrap()
                .generation,
            18
        );
    }

    #[test]
    fn delete_removes_only_the_exact_key_and_reply_debug_is_redacted() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(store);
        let first = key("nas-01");
        let second = key("nas-02");
        vault
            .put(&first, &SecretString::new("test-secret-one"))
            .unwrap();
        vault
            .put(&second, &SecretString::new("test-secret-two"))
            .unwrap();
        let reply = call(
            &request(SmbCredentialOperation::Delete { key: first.clone() }),
            unsafe { libc::geteuid() },
            cluster(),
            &vault,
        );

        assert_eq!(reply.result.unwrap(), SmbCredentialReplyBody::Deleted(true));
        assert!(vault.get(&first).unwrap().is_none());
        assert!(vault.get(&second).unwrap().is_some());
        let credential = SmbCredentialProvision {
            key: second,
            credential: vault
                .get(&key("nas-02"))
                .unwrap()
                .expect("second credential remains"),
        };
        assert!(!format!("{credential:?}").contains("test-secret-two"));
    }
}
