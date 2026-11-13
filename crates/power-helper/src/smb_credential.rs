#[cfg(test)]
use std::collections::BTreeMap;
use std::{
    collections::VecDeque,
    ffi::CStr,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use macluster_core::smb_keychain::MacKeychain;
use macluster_protocol::{
    framing::sha256_hex,
    identifiers::Id128,
    smb_credential::{
        MAX_SMB_CREDENTIAL_FRAME_BYTES, SecretString, SmbCredentialKey, SmbCredentialOperation,
        SmbCredentialReply, SmbCredentialReplyBody, SmbCredentialRequest, StoredSmbCredential,
    },
};

const SOCKET: &str = "/var/run/org.macluster.smb-credential.sock";
const CLUSTER_PIN: &str = "/Library/PrivilegedHelperTools/org.macluster.update/cluster-id";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
const SMB_SESSION_TIMEOUT: Duration = Duration::from_secs(20);
const SMB_UNMOUNT_TIMEOUT: Duration = Duration::from_secs(10);
const FAILURE_WINDOW: Duration = Duration::from_secs(1);
const MAX_FAILURES_PER_WINDOW: usize = 8;
const SMB_BACKING_ROOT: &str = "/Users/Shared/.macluster-mounts";

trait SecretStore: Send + Sync {
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>, String>;
    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), String>;
    fn delete(&self, service: &str, account: &str) -> Result<bool, String>;
    fn initial_generation(&self) -> u64 {
        1
    }
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

    fn initial_generation(&self) -> u64 {
        (**self).initial_generation()
    }
}

const FILE_VAULT_ROOT: &str = "/Library/PrivilegedHelperTools/org.macluster.credentials";
const FILE_VAULT_MAX_BYTES: u64 = 32 * 1024;

#[derive(serde::Deserialize, serde::Serialize)]
struct FileVaultRecord {
    version: u8,
    service: String,
    account: String,
    secret: SecretString,
}

struct FileSecretStore {
    root: PathBuf,
    owner_uid: u32,
    legacy: Option<Arc<dyn SecretStore>>,
}

impl FileSecretStore {
    fn system() -> Self {
        Self {
            root: PathBuf::from(FILE_VAULT_ROOT),
            owner_uid: 0,
            legacy: Some(Arc::new(SystemSecretStore::new())),
        }
    }

    #[cfg(test)]
    fn for_test(root: PathBuf, owner_uid: u32) -> Self {
        Self {
            root,
            owner_uid,
            legacy: None,
        }
    }

    fn ensure_root(&self) -> Result<(), String> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != self.owner_uid
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(
                        "SMB credential vault has unsafe ownership, type, or permissions".into(),
                    );
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&self.root)
                    .map_err(|error| format!("create SMB credential vault: {error}"))?;
                let metadata = fs::symlink_metadata(&self.root)
                    .map_err(|error| format!("inspect SMB credential vault: {error}"))?;
                if !metadata.is_dir()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != self.owner_uid
                {
                    return Err("new SMB credential vault has unsafe ownership or type".into());
                }
                fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("protect SMB credential vault: {error}"))?;
            }
            Err(error) => return Err(format!("inspect SMB credential vault: {error}")),
        }
        Ok(())
    }

    fn item_path(&self, service: &str, account: &str) -> Result<PathBuf, String> {
        if service.is_empty()
            || account.is_empty()
            || service.len() > 256
            || account.len() > 256
            || service.contains('\0')
            || account.contains('\0')
        {
            return Err("SMB credential vault key is invalid".into());
        }
        let digest = sha256_hex(format!("{service}\0{account}").as_bytes())
            .map_err(|error| error.to_string())?;
        Ok(self.root.join(format!("{digest}.json")))
    }

    fn read_record(
        &self,
        path: &Path,
        service: &str,
        account: &str,
    ) -> Result<Option<SecretString>, String> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("inspect SMB credential vault item: {error}")),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != self.owner_uid
            || metadata.mode() & 0o077 != 0
            || metadata.len() == 0
            || metadata.len() > FILE_VAULT_MAX_BYTES
        {
            return Err(
                "SMB credential vault item has unsafe ownership, type, permissions, or size".into(),
            );
        }
        let bytes =
            fs::read(path).map_err(|error| format!("read SMB credential vault item: {error}"))?;
        let record: FileVaultRecord = serde_json::from_slice(&bytes)
            .map_err(|_| "SMB credential vault item is malformed".to_owned())?;
        if record.version != 1 || record.service != service || record.account != account {
            return Err("SMB credential vault item identity does not match its key".into());
        }
        Ok(Some(record.secret))
    }

    fn write_record(
        &self,
        path: &Path,
        service: &str,
        account: &str,
        value: &str,
    ) -> Result<(), String> {
        let record = FileVaultRecord {
            version: 1,
            service: service.to_owned(),
            account: account.to_owned(),
            secret: SecretString::new(value),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|_| "serialize SMB credential vault item".to_owned())?;
        if bytes.len() as u64 > FILE_VAULT_MAX_BYTES {
            return Err("SMB credential vault item exceeds its size limit".into());
        }
        let temp = self
            .root
            .join(format!(".tmp-{}-{}", std::process::id(), Id128::random()));
        let result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)
                .map_err(|error| format!("create SMB credential vault item: {error}"))?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| format!("write SMB credential vault item: {error}"))?;
            fs::rename(&temp, path)
                .map_err(|error| format!("commit SMB credential vault item: {error}"))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
        }
        result
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>, String> {
        self.ensure_root()?;
        let path = self.item_path(service, account)?;
        if let Some(secret) = self.read_record(&path, service, account)? {
            return Ok(Some(secret));
        }
        let Some(legacy) = &self.legacy else {
            return Ok(None);
        };
        match legacy.get(service, account) {
            Ok(Some(secret)) => {
                self.write_record(&path, service, account, secret.as_secret())?;
                Ok(Some(secret))
            }
            Ok(None) | Err(_) => Ok(None),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), String> {
        self.ensure_root()?;
        let path = self.item_path(service, account)?;
        self.write_record(&path, service, account, value)?;
        if let Some(legacy) = &self.legacy {
            let _ = legacy.delete(service, account);
        }
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, String> {
        self.ensure_root()?;
        let path = self.item_path(service, account)?;
        let file_deleted = match fs::remove_file(&path) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(format!("delete SMB credential vault item: {error}")),
        };
        let legacy_deleted = self
            .legacy
            .as_ref()
            .and_then(|legacy| legacy.delete(service, account).ok())
            .unwrap_or(false);
        Ok(file_deleted || legacy_deleted)
    }

    fn initial_generation(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .max(1) as u64
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
        let generation = match self.get(key)? {
            Some(current) => current
                .generation
                .checked_add(1)
                .ok_or_else(|| "SMB credential generation is exhausted".to_owned())?,
            None => self.store.initial_generation().max(1),
        };
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
    let store = FileSecretStore::system();
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
                        eprintln!("macluster: accept SMB credential client: {error}");
                        continue;
                    }
                };
                let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
                let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
                if let Err(error) =
                    serve_client_with_limiter(&mut stream, peer_uid, &vault, &failures)
                {
                    eprintln!("macluster: SMB credential request failed: {error}");
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
    match process_request(request, pinned_cluster, vault, actual_uid) {
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
        process_request(request, Id128::random(), vault, actual_uid)
    } else {
        read_pinned_cluster(Path::new(CLUSTER_PIN))
            .map_err(SecretFailure::Cluster)
            .and_then(|pinned| process_request(request, pinned, vault, actual_uid))
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
    peer_uid: libc::uid_t,
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
        SmbCredentialOperation::ProvisionLogin {
            key,
            generation,
            password,
        } => {
            let credential = StoredSmbCredential {
                generation,
                password,
            };
            vault
                .import(&key, &credential)
                .map(|()| SmbCredentialReplyBody::Provisioned)
                .map_err(SecretFailure::Operation)
        }
        SmbCredentialOperation::DeleteLogin { key } => vault
            .delete(&key)
            .map(SmbCredentialReplyBody::Deleted)
            .map_err(SecretFailure::Operation),
        SmbCredentialOperation::MountSmb {
            key,
            source,
            target,
            logical,
            logical_target,
        } => mount_smb_from_vault(
            peer_uid,
            vault,
            &key,
            &source,
            &target,
            &logical,
            &logical_target,
        )
        .map(|()| SmbCredentialReplyBody::Mounted)
        .map_err(SecretFailure::Operation),
        SmbCredentialOperation::UnmountSmb {
            target,
            logical,
            logical_target,
            force,
        } => unmount_smb(peer_uid, &target, &logical, &logical_target, force)
            .map(|()| SmbCredentialReplyBody::Unmounted)
            .map_err(SecretFailure::Operation),
    }
}

fn smb_session_account(uid: libc::uid_t) -> Result<(String, String), String> {
    if uid == 0 {
        return Err("SMB session operations require a non-root user".into());
    }
    let account = unsafe { libc::getpwuid(uid) };
    if account.is_null() {
        return Err("SMB session user no longer exists".into());
    }
    let user = unsafe { CStr::from_ptr((*account).pw_name) }
        .to_string_lossy()
        .into_owned();
    let home = unsafe { CStr::from_ptr((*account).pw_dir) }
        .to_string_lossy()
        .into_owned();
    if user.is_empty()
        || !Path::new(&home).is_absolute()
        || home.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("SMB session account metadata is invalid".into());
    }
    Ok((user, home))
}

fn smb_mount_arguments(
    uid: libc::uid_t,
    user: &str,
    source: &str,
    target: &str,
    guest: bool,
) -> Vec<String> {
    let mut arguments = vec![
        "asuser".into(),
        uid.to_string(),
        "/usr/bin/sudo".into(),
        "-u".into(),
        user.into(),
        "-H".into(),
        "/sbin/mount_smbfs".into(),
    ];
    if guest {
        arguments.push("-N".into());
    }
    arguments.extend([
        "-o".into(),
        if guest {
            "nopassprompt,nobrowse,forcenewsession".into()
        } else {
            "nobrowse,forcenewsession".into()
        },
        source.into(),
        target.into(),
    ]);
    arguments
}

fn direct_storage_subnet_route_arguments<'a>(
    network: &'a str,
    netmask: &'a str,
    interface: &'a str,
) -> [&'a str; 8] {
    [
        "-n",
        "add",
        "-net",
        network,
        "-netmask",
        netmask,
        "-interface",
        interface,
    ]
}

fn route_delete_arguments<'a>(host: &'a str, interface: &'a str) -> [&'a str; 6] {
    ["-n", "delete", "-host", host, "-ifscope", interface]
}

fn arp_delete_arguments(host: &str) -> [&str; 2] {
    ["-d", host]
}

fn smb_tcp_endpoint_reachable(host: &str, port: u16, timeout: Duration) -> bool {
    let Ok(server) = host.parse::<Ipv4Addr>() else {
        return false;
    };
    TcpStream::connect_timeout(&SocketAddr::from((server, port)), timeout).is_ok()
}

fn route_output_is_direct(output: &str) -> bool {
    !output
        .lines()
        .any(|line| line.trim_start().starts_with("gateway:"))
}

fn route_output_uses_interface(output: &str, interface: &str) -> bool {
    output.lines().any(|line| {
        line.trim_start()
            .strip_prefix("interface:")
            .is_some_and(|value| value.trim() == interface)
    })
}

fn same_subnet_direct_route(server: Ipv4Addr) -> Option<(String, Ipv4Addr, Ipv4Addr)> {
    let mut interfaces = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut interfaces) } != 0 {
        return None;
    }
    let mut best: Option<(u32, String, Ipv4Addr, Ipv4Addr)> = None;
    let mut current = interfaces;
    while !current.is_null() {
        let interface = unsafe { &*current };
        current = interface.ifa_next;
        if interface.ifa_addr.is_null()
            || interface.ifa_netmask.is_null()
            || unsafe { (*interface.ifa_addr).sa_family as i32 } != libc::AF_INET
            || interface.ifa_flags & libc::IFF_LOOPBACK as u32 != 0
        {
            continue;
        }
        let name = unsafe { CStr::from_ptr(interface.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if !["en", "bridge", "anpi", "ap", "pdp_ip"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let address = unsafe { &*(interface.ifa_addr as *const libc::sockaddr_in) };
        let netmask = unsafe { &*(interface.ifa_netmask as *const libc::sockaddr_in) };
        let address = Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
        let netmask = Ipv4Addr::from(u32::from_be(netmask.sin_addr.s_addr));
        let mask = u32::from(netmask);
        if mask == 0 || u32::from(server) & mask != u32::from(address) & mask {
            continue;
        }
        let prefix = mask.leading_ones();
        if best
            .as_ref()
            .is_none_or(|(best_prefix, _, _, _)| prefix > *best_prefix)
        {
            best = Some((
                prefix,
                name,
                Ipv4Addr::from(u32::from(address) & mask),
                netmask,
            ));
        }
    }
    unsafe { libc::freeifaddrs(interfaces) };
    best.map(|(_, interface, network, netmask)| (interface, network, netmask))
}

fn ensure_same_subnet_storage_route(server_host: &str) -> Result<(), String> {
    let server = server_host
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("SMB server host '{server_host}' is not an IPv4 address"))?;
    if smb_tcp_endpoint_reachable(server_host, 445, Duration::from_millis(750)) {
        return Ok(());
    }
    let Some((interface, network, netmask)) = same_subnet_direct_route(server) else {
        return Ok(());
    };
    // An unreachable server can still have a stale host route marked direct.
    // Remove only that exact host route, then restore the connected subnet
    // route that lets macOS build the scoped neighbor entry.
    let _ = Command::new("/sbin/route")
        .args(route_delete_arguments(server_host, &interface))
        .output();
    let network = network.to_string();
    let netmask = netmask.to_string();
    let added = Command::new("/sbin/route")
        .args(direct_storage_subnet_route_arguments(
            &network, &netmask, &interface,
        ))
        .output()
        .map_err(|error| {
            format!("add direct SMB subnet route {network}/{netmask} through {interface}: {error}")
        })?;
    if !added.status.success()
        && !String::from_utf8_lossy(&added.stderr)
            .to_ascii_lowercase()
            .contains("file exists")
    {
        return Err(format!(
            "add direct SMB subnet route {network}/{netmask} through {interface} exited with {}: {}",
            added.status,
            String::from_utf8_lossy(&added.stderr).trim()
        ));
    }
    let _ = Command::new("/usr/sbin/arp")
        .args(arp_delete_arguments(server_host))
        .output();
    let verified = Command::new("/sbin/route")
        .args(["-n", "get", "-host", server_host])
        .output()
        .map_err(|error| format!("verify the route to SMB server {server_host}: {error}"))?;
    let verified_text = String::from_utf8_lossy(&verified.stdout);
    if verified.status.success()
        && route_output_is_direct(&verified_text)
        && route_output_uses_interface(&verified_text, &interface)
        && smb_tcp_endpoint_reachable(server_host, 445, Duration::from_secs(1))
    {
        Ok(())
    } else {
        Err(format!(
            "SMB server {server_host} is not reachable through direct route {network}/{netmask} on {interface}"
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmbMountAction {
    Keep,
    Replace,
}

fn smb_mount_action(active: bool, readable: bool) -> SmbMountAction {
    if active && readable {
        SmbMountAction::Keep
    } else {
        SmbMountAction::Replace
    }
}

trait SmbMountBackend {
    fn is_active(&mut self, target: &str) -> Result<bool, String>;
    fn verify_readable(&mut self, target: &str) -> Result<(), String>;
    fn unmount(&mut self, target: &str, logical: &str, logical_target: &str) -> Result<(), String>;
    fn mount(&mut self, source: &str, target: &str) -> Result<(), String>;
    fn ensure_alias(&mut self, logical: &str, logical_target: &str) -> Result<(), String>;
}

struct RealSmbMountBackend<'a> {
    uid: libc::uid_t,
    user: &'a str,
    home: &'a str,
    vault: &'a dyn CredentialVault,
    key: &'a SmbCredentialKey,
}

impl SmbMountBackend for RealSmbMountBackend<'_> {
    fn is_active(&mut self, target: &str) -> Result<bool, String> {
        smb_mount_is_active(target)
    }

    fn verify_readable(&mut self, target: &str) -> Result<(), String> {
        verify_smb_mount_readable(self.uid, self.user, self.home, target)
    }

    fn unmount(&mut self, target: &str, logical: &str, logical_target: &str) -> Result<(), String> {
        unmount_smb(self.uid, target, logical, logical_target, false)
    }

    fn mount(&mut self, source: &str, target: &str) -> Result<(), String> {
        ensure_same_subnet_storage_route(&self.key.server_host)?;
        let guest = self.key.account.eq_ignore_ascii_case("guest");
        if guest {
            let output = Command::new("/bin/launchctl")
                .args(smb_mount_arguments(
                    self.uid, self.user, source, target, true,
                ))
                .env_clear()
                .env("HOME", self.home)
                .env("USER", self.user)
                .env("LOGNAME", self.user)
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::null())
                .output()
                .map_err(|error| format!("mount guest SMB share: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "mount guest SMB share exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            return Ok(());
        }
        let credential = self.vault.get(self.key)?.ok_or_else(|| {
            "SMB credential is not available on this node; rerun mnode".to_owned()
        })?;
        let mut command = CommandBuilder::new("/bin/launchctl");
        command.args(smb_mount_arguments(
            self.uid, self.user, source, target, false,
        ));
        command.env_clear();
        command.env("HOME", self.home);
        command.env("USER", self.user);
        command.env("LOGNAME", self.user);
        command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        command.env("LC_ALL", "C");
        run_smb_mount_pty(command, &credential.password)
    }

    fn ensure_alias(&mut self, logical: &str, logical_target: &str) -> Result<(), String> {
        ensure_smb_logical_alias(logical, logical_target)
    }
}

#[derive(Default, Deserialize, Serialize)]
struct SmbRepairState {
    failures: u32,
    retry_after_unix_ms: u64,
}

fn smb_repair_state(path: &Path) -> SmbRepairState {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn smb_repair_allowed(state_path: &Path, now_ms: u64) -> bool {
    now_ms >= smb_repair_state(state_path).retry_after_unix_ms
}

fn record_smb_repair_failure(state_path: &Path, now_ms: u64) -> Result<(), String> {
    let mut state = smb_repair_state(state_path);
    state.failures = state.failures.saturating_add(1);
    let exponent = state.failures.saturating_sub(1).min(3);
    let delay_ms = 60_000_u64.saturating_mul(1_u64 << exponent).min(300_000);
    state.retry_after_unix_ms = now_ms.saturating_add(delay_ms);
    if let Some(parent) = state_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create SMB repair state directory: {error}"))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("protect SMB repair state directory: {error}"))?;
        }
    }
    let temp = state_path.with_extension("next");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(|error| format!("open SMB repair state: {error}"))?;
    file.write_all(
        &serde_json::to_vec(&state).map_err(|error| format!("encode SMB repair state: {error}"))?,
    )
    .and_then(|()| file.sync_all())
    .map_err(|error| format!("write SMB repair state: {error}"))?;
    fs::rename(&temp, state_path).map_err(|error| format!("commit SMB repair state: {error}"))
}

fn clear_smb_repair_state(state_path: &Path) {
    let _ = fs::remove_file(state_path);
}

fn smb_repair_state_path(target: &str) -> PathBuf {
    let key = sha256_hex(target.as_bytes()).expect("SHA256");
    Path::new("/var/run/org.macluster.smb-repair").join(format!("{key}.json"))
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn reconcile_smb_mount_with_backend(
    source: &str,
    target: &str,
    logical: &str,
    logical_target: &str,
    repair_state: &Path,
    now_ms: u64,
    backend: &mut impl SmbMountBackend,
) -> Result<(), String> {
    let active = backend.is_active(target)?;
    let readable = active && backend.verify_readable(target).is_ok();
    if smb_mount_action(active, readable) == SmbMountAction::Keep {
        return backend.ensure_alias(logical, logical_target);
    }
    if active {
        if !smb_repair_allowed(repair_state, now_ms) {
            return Err(format!(
                "SMB mount {target} was unreadable; replacement is backing off"
            ));
        }
        if let Err(error) = backend.unmount(target, logical, logical_target) {
            let _ = record_smb_repair_failure(repair_state, now_ms);
            return Err(error);
        }
    }
    let result = (|| {
        backend.mount(source, target)?;
        backend.verify_readable(target)?;
        backend.ensure_alias(logical, logical_target)
    })();
    match result {
        Ok(()) => {
            clear_smb_repair_state(repair_state);
            Ok(())
        }
        Err(error) => {
            let _ = record_smb_repair_failure(repair_state, now_ms);
            Err(error)
        }
    }
}

fn mount_smb_from_vault(
    uid: libc::uid_t,
    vault: &dyn CredentialVault,
    key: &SmbCredentialKey,
    source: &str,
    target: &str,
    logical: &str,
    logical_target: &str,
) -> Result<(), String> {
    key.validate().map_err(|error| error.to_string())?;
    let (user, home) = smb_session_account(uid)?;
    let target_path = Path::new(target);
    let metadata = fs::symlink_metadata(target_path)
        .map_err(|error| format!("inspect SMB mount target {target}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != uid {
        return Err(format!(
            "SMB mount target {target} must be a user-owned directory without symlinks"
        ));
    }
    let mut backend = RealSmbMountBackend {
        uid,
        user: &user,
        home: &home,
        vault,
        key,
    };
    reconcile_smb_mount_with_backend(
        source,
        target,
        logical,
        logical_target,
        &smb_repair_state_path(target),
        unix_time_ms(),
        &mut backend,
    )
}

fn smb_mount_is_active(target: &str) -> Result<bool, String> {
    let output = Command::new("/sbin/mount")
        .output()
        .map_err(|error| format!("inspect SMB mounts: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "inspect SMB mounts exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let expected = format!(" on {target} (smbfs,");
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .any(|line| line.contains(&expected)))
}

fn verify_smb_mount_readable(
    uid: libc::uid_t,
    user: &str,
    home: &str,
    target: &str,
) -> Result<(), String> {
    let mut command = Command::new("/bin/launchctl");
    command
        .args([
            "asuser",
            &uid.to_string(),
            "/usr/bin/sudo",
            "-u",
            user,
            "-H",
            "/usr/bin/find",
            target,
            "-maxdepth",
            "1",
            "-print",
            "-quit",
        ])
        .env_clear()
        .env("HOME", home)
        .env("USER", user)
        .env("LOGNAME", user)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = run_bounded_process_group(command, Duration::from_secs(5))
        .map_err(|error| format!("verify SMB mount {target}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "SMB mount {target} was created but is not readable (status {status})"
        ))
    }
}

fn unmount_smb(
    uid: libc::uid_t,
    target: &str,
    logical: &str,
    logical_target: &str,
    force: bool,
) -> Result<(), String> {
    let (user, home) = smb_session_account(uid)?;
    unmount_smb_with(logical, logical_target, || {
        if smb_mount_is_active(target)? {
            let mut command = Command::new("/bin/launchctl");
            command.args([
                "asuser",
                &uid.to_string(),
                "/usr/bin/sudo",
                "-u",
                &user,
                "-H",
                "/sbin/umount",
            ]);
            command.args(smb_unmount_arguments(target, force));
            command
                .env_clear()
                .env("HOME", &home)
                .env("USER", &user)
                .env("LOGNAME", &user)
                .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let status = run_bounded_process_group(command, SMB_UNMOUNT_TIMEOUT)
                .map_err(|error| format!("unmount SMB share {target}: {error}"))?;
            if !status.success() {
                return Err(format!("unmount SMB share {target} exited with {status}"));
            }
        }
        Ok(())
    })
}

fn smb_unmount_arguments(target: &str, force: bool) -> Vec<&str> {
    if force {
        vec!["-f", target]
    } else {
        vec![target]
    }
}

fn unmount_smb_with(
    logical: &str,
    logical_target: &str,
    unmount_physical: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let unmount_result = unmount_physical();
    let alias_result = remove_smb_logical_alias(logical, logical_target);
    match (unmount_result, alias_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(unmount), Err(alias)) => Err(format!("{unmount}; {alias}")),
    }
}

fn run_bounded_process_group(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::ExitStatus, String> {
    let mut child = command
        .process_group(0)
        .spawn()
        .map_err(|error| format!("start bounded process group: {error}"))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait for bounded process group: {error}"))?
        {
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            unsafe {
                libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
            }
            let _ = child.wait();
            return Err(format!(
                "operation remained busy after {} seconds; close files and retry",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn ensure_smb_logical_alias(logical: &str, logical_target: &str) -> Result<(), String> {
    if logical == logical_target {
        return Ok(());
    }
    let logical = Path::new(logical);
    match fs::symlink_metadata(logical) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let actual = fs::read_link(logical).map_err(|error| {
                format!("read SMB logical alias {}: {error}", logical.display())
            })?;
            if actual == Path::new(logical_target) {
                return Ok(());
            }
            if is_managed_smb_backing_alias(&actual) {
                fs::remove_file(logical).map_err(|error| {
                    format!(
                        "replace stale SMB logical alias {}: {error}",
                        logical.display()
                    )
                })?;
            } else {
                return Err(format!(
                    "SMB logical alias {} points to {}, not {}",
                    logical.display(),
                    actual.display(),
                    logical_target
                ));
            }
        }
        Ok(metadata) if metadata.is_dir() => {
            let mut entries = fs::read_dir(logical).map_err(|error| {
                format!("inspect SMB logical path {}: {error}", logical.display())
            })?;
            if entries.next().is_some() {
                return Err(format!(
                    "SMB logical path {} is not empty",
                    logical.display()
                ));
            }
            fs::remove_dir(logical)
                .map_err(|error| format!("replace empty SMB logical path: {error}"))?;
        }
        Ok(_) => {
            return Err(format!(
                "SMB logical path {} is not an empty directory or managed symlink",
                logical.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect SMB logical path {}: {error}",
                logical.display()
            ));
        }
    }
    let Some(parent) = logical.parent() else {
        return Err("SMB logical alias has no parent directory".into());
    };
    ensure_real_directory_tree(parent)?;
    std::os::unix::fs::symlink(logical_target, logical).map_err(|error| {
        format!(
            "create SMB logical alias {} -> {}: {error}",
            logical.display(),
            logical_target
        )
    })
}

fn remove_smb_logical_alias(logical: &str, logical_target: &str) -> Result<(), String> {
    if logical == logical_target {
        return Ok(());
    }
    let logical = Path::new(logical);
    match fs::symlink_metadata(logical) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let actual = fs::read_link(logical).map_err(|error| {
                format!("read SMB logical alias {}: {error}", logical.display())
            })?;
            if actual != Path::new(logical_target) && !is_managed_smb_backing_alias(&actual) {
                return Err(format!(
                    "refusing to remove foreign SMB logical alias {} -> {}",
                    logical.display(),
                    actual.display()
                ));
            }
            fs::remove_file(logical)
                .map_err(|error| format!("remove SMB logical alias {}: {error}", logical.display()))
        }
        Ok(_) => Err(format!(
            "refusing to remove non-symlink SMB logical path {}",
            logical.display()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "inspect SMB logical alias {}: {error}",
            logical.display()
        )),
    }
}

fn is_managed_smb_backing_alias(path: &Path) -> bool {
    path.starts_with(SMB_BACKING_ROOT) && path != Path::new(SMB_BACKING_ROOT)
}

fn ensure_real_directory_tree(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => current.push(name),
            _ => return Err("SMB logical directory contains an unsafe path component".into()),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "SMB logical directory component {} is a symlink",
                    current.display()
                ));
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(format!(
                    "SMB logical directory component {} is not a directory",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    format!(
                        "create SMB logical directory {}: {error}",
                        current.display()
                    )
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "inspect SMB logical directory {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn run_smb_mount_pty(command: CommandBuilder, password: &SecretString) -> Result<(), String> {
    let pair = native_pty_system()
        .openpty(PtySize::default())
        .map_err(|error| format!("open SMB mount pseudo-terminal: {error}"))?;
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| format!("start SMB mount operation: {error}"))?;
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("read SMB mount operation: {error}"))?;
    let mut writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("write SMB mount password: {error}"))?;
    drop(pair.slave);
    drop(pair.master);
    let (sender, receiver) = mpsc::channel();
    let reader_thread = thread::spawn(move || {
        let mut buffer = [0_u8; 512];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send(buffer[..count].to_vec()).is_err() {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
    });
    let started = Instant::now();
    let mut sent_password = false;
    let mut prompt_buffer = Zeroizing::new(Vec::new());
    let mut output = Zeroizing::new(Vec::new());
    let status = loop {
        while let Ok(chunk) = receiver.try_recv() {
            output.extend_from_slice(&chunk);
            prompt_buffer.extend_from_slice(&chunk);
            if prompt_buffer.len() > 4096 {
                let excess = prompt_buffer.len() - 1024;
                prompt_buffer.drain(..excess);
            }
            let prompt = String::from_utf8_lossy(&prompt_buffer).to_ascii_lowercase();
            if !sent_password && prompt.contains("password for") {
                writer
                    .write_all(password.as_secret().as_bytes())
                    .and_then(|()| writer.write_all(b"\n"))
                    .and_then(|()| writer.flush())
                    .map_err(|error| format!("write SMB mount password: {error}"))?;
                sent_password = true;
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait for SMB mount operation: {error}"))?
        {
            break status;
        }
        if started.elapsed() >= SMB_SESSION_TIMEOUT {
            let _ = child.kill();
            let detail = String::from_utf8_lossy(&output);
            let redacted = detail.replace(password.as_secret(), "<redacted>");
            return Err(format!(
                "SMB mount operation timed out; output: {}",
                redacted.trim()
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(writer);
    let _ = reader_thread.join();
    if status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output);
        let redacted = detail.replace(password.as_secret(), "<redacted>");
        Err(format!(
            "SMB mount operation exited with {status}: {}",
            redacted.trim()
        ))
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
        SmbCredentialOperation::UnmountSmb { .. } => return Ok(()),
        SmbCredentialOperation::Put { key, .. }
        | SmbCredentialOperation::Get { key }
        | SmbCredentialOperation::Import { key, .. }
        | SmbCredentialOperation::Delete { key }
        | SmbCredentialOperation::ProvisionLogin { key, .. }
        | SmbCredentialOperation::DeleteLogin { key }
        | SmbCredentialOperation::MountSmb { key, .. } => key,
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
        fs,
        io::{Read, Write},
        os::unix::fs::MetadataExt,
        os::unix::net::UnixStream,
        path::Path,
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
        CredentialVault, FileSecretStore, KeychainCredentialVault, MemorySecretStore,
        SMB_UNMOUNT_TIMEOUT, SecretStore, SmbMountAction, SmbMountBackend, arp_delete_arguments,
        direct_storage_subnet_route_arguments, ensure_smb_logical_alias, read_pinned_cluster,
        reconcile_smb_mount_with_backend, record_smb_repair_failure, remove_smb_logical_alias,
        route_delete_arguments, route_output_is_direct, run_bounded_process_group,
        serve_client_with, smb_mount_action, smb_mount_arguments, smb_repair_allowed,
        smb_tcp_endpoint_reachable, smb_unmount_arguments, unmount_smb_with,
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
    fn file_vault_survives_helper_restarts_without_keychain_acl_checks() {
        let root = std::env::temp_dir().join(format!("macluster-file-vault-{}", Id128::random()));
        let owner = unsafe { libc::geteuid() };
        let first = FileSecretStore::for_test(root.clone(), owner);
        first
            .set("org.macluster.smb.test", "user@192.0.2.20", "vault-secret")
            .unwrap();

        let second = FileSecretStore::for_test(root.clone(), owner);
        assert_eq!(
            second
                .get("org.macluster.smb.test", "user@192.0.2.20")
                .unwrap()
                .unwrap()
                .as_secret(),
            "vault-secret"
        );
        let item = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap();
        let metadata = fs::metadata(item).unwrap();
        assert_eq!(metadata.uid(), owner);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_vault_ignores_an_unreadable_legacy_keychain_item() {
        struct Unreadable;
        impl SecretStore for Unreadable {
            fn get(&self, _: &str, _: &str) -> Result<Option<SecretString>, String> {
                Err("Keychain authentication failed".into())
            }
            fn set(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
                Ok(())
            }
            fn delete(&self, _: &str, _: &str) -> Result<bool, String> {
                Ok(false)
            }
        }

        let root = std::env::temp_dir().join(format!("macluster-file-vault-{}", Id128::random()));
        let owner = unsafe { libc::geteuid() };
        let store = FileSecretStore {
            root: root.clone(),
            owner_uid: owner,
            legacy: Some(Arc::new(Unreadable)),
        };
        assert!(
            store
                .get("org.macluster.smb.test", "user@192.0.2.20")
                .unwrap()
                .is_none()
        );
        assert!(store.initial_generation() > 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_vault_migrates_a_readable_legacy_keychain_item_once() {
        let root = std::env::temp_dir().join(format!("macluster-file-vault-{}", Id128::random()));
        let owner = unsafe { libc::geteuid() };
        let legacy = Arc::new(MemorySecretStore::default());
        legacy
            .set("org.macluster.smb.test", "user@192.0.2.20", "legacy-secret")
            .unwrap();
        let store = FileSecretStore {
            root: root.clone(),
            owner_uid: owner,
            legacy: Some(legacy),
        };
        assert_eq!(
            store
                .get("org.macluster.smb.test", "user@192.0.2.20")
                .unwrap()
                .unwrap()
                .as_secret(),
            "legacy-secret"
        );

        let migrated = FileSecretStore::for_test(root.clone(), owner);
        assert_eq!(
            migrated
                .get("org.macluster.smb.test", "user@192.0.2.20")
                .unwrap()
                .unwrap()
                .as_secret(),
            "legacy-secret"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_vault_rejects_symlinked_items() {
        let root = std::env::temp_dir().join(format!("macluster-file-vault-{}", Id128::random()));
        let owner = unsafe { libc::geteuid() };
        let store = FileSecretStore::for_test(root.clone(), owner);
        store
            .set("org.macluster.smb.test", "user@192.0.2.20", "vault-secret")
            .unwrap();
        let item = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap();
        fs::remove_file(&item).unwrap();
        let target = root.join("target");
        fs::write(&target, "foreign").unwrap();
        std::os::unix::fs::symlink(&target, &item).unwrap();

        assert!(
            store
                .get("org.macluster.smb.test", "user@192.0.2.20")
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn smb_mount_uses_the_target_user_without_secret_arguments() {
        let arguments = smb_mount_arguments(
            501,
            "smb-user",
            "//smb-user@192.0.2.20/Partition_2",
            "/Users/Shared/.macluster-mounts/test",
            false,
        );
        assert_eq!(&arguments[..3], ["asuser", "501", "/usr/bin/sudo"]);
        assert_eq!(
            &arguments[3..7],
            ["-u", "smb-user", "-H", "/sbin/mount_smbfs"]
        );
        assert_eq!(
            &arguments[7..],
            [
                "-o",
                "nobrowse,forcenewsession",
                "//smb-user@192.0.2.20/Partition_2",
                "/Users/Shared/.macluster-mounts/test"
            ]
        );
        assert!(!arguments.iter().any(|argument| argument.contains("secret")));

        let guest = smb_mount_arguments(
            501,
            "smb-user",
            "//guest@192.0.2.20/Public",
            "/Users/Shared/.macluster-mounts/public",
            true,
        );
        assert!(guest.iter().any(|argument| argument == "-N"));
        assert!(
            guest
                .iter()
                .any(|argument| argument == "nopassprompt,nobrowse,forcenewsession")
        );
    }

    #[test]
    fn smb_mount_action_replaces_only_missing_or_unreadable_mounts() {
        assert_eq!(smb_mount_action(false, false), SmbMountAction::Replace);
        assert_eq!(smb_mount_action(true, true), SmbMountAction::Keep);
        assert_eq!(smb_mount_action(true, false), SmbMountAction::Replace);
    }

    #[derive(Default)]
    struct FakeSmbMountBackend {
        active: bool,
        readable: bool,
        unmount_busy: bool,
        verify_calls: usize,
        unmount_calls: usize,
        mount_calls: usize,
        alias_calls: usize,
    }

    impl SmbMountBackend for FakeSmbMountBackend {
        fn is_active(&mut self, _target: &str) -> Result<bool, String> {
            Ok(self.active)
        }

        fn verify_readable(&mut self, _target: &str) -> Result<(), String> {
            self.verify_calls += 1;
            if self.readable {
                Ok(())
            } else {
                Err("stale SMB session".into())
            }
        }

        fn unmount(
            &mut self,
            _target: &str,
            _logical: &str,
            _logical_target: &str,
        ) -> Result<(), String> {
            self.unmount_calls += 1;
            if self.unmount_busy {
                return Err("operation remained busy; close files and retry".into());
            }
            self.active = false;
            Ok(())
        }

        fn mount(&mut self, _source: &str, _target: &str) -> Result<(), String> {
            self.mount_calls += 1;
            self.active = true;
            self.readable = true;
            Ok(())
        }

        fn ensure_alias(&mut self, _logical: &str, _logical_target: &str) -> Result<(), String> {
            self.alias_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn stale_active_smb_mount_is_replaced_once() {
        let state = std::env::temp_dir().join(format!("macluster-smb-repair-{}", Id128::random()));
        let mut backend = FakeSmbMountBackend {
            active: true,
            readable: false,
            ..Default::default()
        };

        reconcile_smb_mount_with_backend(
            "//user@nas/share",
            "/mnt/share",
            "/logical/share",
            "/mnt/share",
            &state,
            1_000,
            &mut backend,
        )
        .unwrap();

        assert_eq!(backend.unmount_calls, 1);
        assert_eq!(backend.mount_calls, 1);
        assert_eq!(backend.verify_calls, 2);
        assert_eq!(backend.alias_calls, 1);
        assert!(backend.active);
        assert!(backend.readable);
    }

    #[test]
    fn stale_active_smb_mount_preserves_a_busy_unmount() {
        let state = std::env::temp_dir().join(format!("macluster-smb-repair-{}", Id128::random()));
        let mut backend = FakeSmbMountBackend {
            active: true,
            readable: false,
            unmount_busy: true,
            ..Default::default()
        };

        let error = reconcile_smb_mount_with_backend(
            "//user@nas/share",
            "/mnt/share",
            "/logical/share",
            "/mnt/share",
            &state,
            1_000,
            &mut backend,
        )
        .unwrap_err();

        assert!(error.contains("busy"), "{error}");
        assert_eq!(backend.unmount_calls, 1);
        assert_eq!(backend.mount_calls, 0);
        assert!(backend.active);
        assert!(!backend.readable);
    }

    #[test]
    fn managed_stale_smb_alias_is_replaced_and_removed_without_touching_foreign_links() {
        let root = Path::new("/private/tmp")
            .join(format!("macluster-smb-stale-alias-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let logical = root.join("project");
        let stale = "/Users/Shared/.macluster-mounts/fa87abfd-de27-5001-a250-5bd4d94365eb/project";
        let current =
            "/Users/Shared/.macluster-mounts/e6fe7c50-8ea9-567c-9238-e7fe1799fbf3/project";
        std::os::unix::fs::symlink(stale, &logical).unwrap();

        ensure_smb_logical_alias(&logical.to_string_lossy(), current).unwrap();
        assert_eq!(fs::read_link(&logical).unwrap(), Path::new(current));
        remove_smb_logical_alias(&logical.to_string_lossy(), current).unwrap();
        assert!(!logical.exists());

        std::os::unix::fs::symlink("/tmp/foreign-share", &logical).unwrap();
        let error = remove_smb_logical_alias(&logical.to_string_lossy(), current).unwrap_err();
        assert!(error.contains("foreign SMB logical alias"), "{error}");
        assert_eq!(
            fs::read_link(&logical).unwrap(),
            Path::new("/tmp/foreign-share")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn busy_smb_unmount_removes_the_managed_logical_alias() {
        let root =
            Path::new("/private/tmp").join(format!("macluster-smb-busy-alias-{}", Id128::random()));
        let physical = root.join("physical");
        let logical = root.join("logical");
        fs::create_dir_all(&physical).unwrap();
        std::os::unix::fs::symlink(&physical, &logical).unwrap();

        let error = unmount_smb_with(
            &logical.to_string_lossy(),
            &physical.to_string_lossy(),
            || Err("operation remained busy after 5 seconds".into()),
        )
        .unwrap_err();

        assert!(error.contains("busy"), "{error}");
        assert_eq!(
            fs::symlink_metadata(&logical).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn normal_smb_unmount_uses_ten_seconds_and_force_prefix() {
        assert_eq!(SMB_UNMOUNT_TIMEOUT, std::time::Duration::from_secs(10));
        assert_eq!(
            smb_unmount_arguments("/managed/mount", false),
            vec!["/managed/mount"]
        );
        assert_eq!(
            smb_unmount_arguments("/managed/mount", true),
            vec!["-f", "/managed/mount"]
        );
    }

    #[test]
    fn smb_repair_backoff_grows_and_caps() {
        let state = std::env::temp_dir().join(format!("macluster-smb-repair-{}", Id128::random()));

        assert!(smb_repair_allowed(&state, 1_000));
        record_smb_repair_failure(&state, 1_000).unwrap();
        assert!(!smb_repair_allowed(&state, 30_000));
        assert!(smb_repair_allowed(&state, 61_000));

        record_smb_repair_failure(&state, 61_000).unwrap();
        assert!(!smb_repair_allowed(&state, 180_999));
        assert!(smb_repair_allowed(&state, 181_000));

        for now in [181_000, 361_000, 661_000, 961_000] {
            record_smb_repair_failure(&state, now).unwrap();
        }
        assert!(!smb_repair_allowed(&state, 1_260_999));
        assert!(smb_repair_allowed(&state, 1_261_000));
        fs::remove_file(state).unwrap();
    }

    #[test]
    fn same_subnet_storage_route_is_pinned_to_its_direct_interface() {
        assert_eq!(
            direct_storage_subnet_route_arguments("192.0.2.0", "255.255.255.0", "bridge0"),
            [
                "-n",
                "add",
                "-net",
                "192.0.2.0",
                "-netmask",
                "255.255.255.0",
                "-interface",
                "bridge0"
            ]
        );
        assert!(!route_output_is_direct(
            "route to: 192.0.2.5\n  gateway: 192.0.2.1\n  interface: bridge0\n"
        ));
        assert!(route_output_is_direct(
            "route to: 192.0.2.5\n  interface: bridge0\n  flags: <UP,HOST,DONE>\n"
        ));
        assert_eq!(
            route_delete_arguments("192.0.2.5", "bridge0"),
            [
                "-n",
                "delete",
                "-host",
                "192.0.2.5",
                "-ifscope",
                "bridge0"
            ]
        );
        assert_eq!(arp_delete_arguments("192.0.2.5"), ["-d", "192.0.2.5"]);
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        assert!(smb_tcp_endpoint_reachable(
            "127.0.0.1",
            listener.local_addr().unwrap().port(),
            std::time::Duration::from_millis(500)
        ));
    }

    #[test]
    fn bounded_process_group_timeout_kills_descendants() {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & wait"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let started = std::time::Instant::now();
        let error =
            run_bounded_process_group(command, std::time::Duration::from_millis(300)).unwrap_err();
        assert!(error.contains("busy"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "timeout took too long"
        );
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
    fn provision_login_stores_the_node_credential_for_helper_mounts() {
        let store = Arc::new(MemorySecretStore::default());
        let vault = KeychainCredentialVault::new(Arc::clone(&store));
        let provisioned = call(
            &request(SmbCredentialOperation::ProvisionLogin {
                key: key("nas-01"),
                generation: 17,
                password: SecretString::new("node-secret"),
            }),
            unsafe { libc::geteuid() },
            cluster(),
            &vault,
        );
        assert_eq!(
            provisioned.result.unwrap(),
            SmbCredentialReplyBody::Provisioned
        );

        let credential = reply_credential(call(
            &request(SmbCredentialOperation::Get { key: key("nas-01") }),
            unsafe { libc::geteuid() },
            cluster(),
            &vault,
        ));
        assert_eq!(credential.generation, 17);
        assert_eq!(credential.password.as_secret(), "node-secret");
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
