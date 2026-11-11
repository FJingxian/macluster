use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Cursor, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use macluster_controller::smb_credential::CredentialHelperClient;
use macluster_core::{
    config::{ClusterConfig, NodeConfig, Transport},
    storage_uri::StorageUri,
};
use macluster_protocol::{
    identifiers::{Id128, NodeId},
    smb_credential::{
        MAX_SMB_CREDENTIAL_BYTES, SecretString, SmbCredentialKey, SmbCredentialProvision,
        SmbKeychainEndpoint, StoredSmbCredential,
    },
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::node_admin::AppResult;

const STATE_FILE: &str = "smb-credentials.json";
const SECURITY_BINARY: &str = "/usr/bin/security";
const MOUNT_SMBFS_BINARY: &str = "/sbin/mount_smbfs";
const PTY_TIMEOUT: Duration = Duration::from_secs(20);
const SECURITY_ITEM_NOT_FOUND: i32 = 44;
const SMB_AUTH_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) fn run_internal(args: &[String]) -> AppResult<()> {
    match args.first().map(String::as_str) {
        Some("smb-keychain") => run_node_keychain(&args[1..]),
        Some("smb-master") => run_master_keychain(&args[1..]),
        _ => Err((2, "internal SMB command is missing or unknown".into())),
    }
}

fn run_node_keychain(args: &[String]) -> AppResult<()> {
    match args.first().map(String::as_str) {
        Some("store") => {
            let options = parse_options(
                &args[1..],
                &["--cluster", "--server", "--account", "--generation"],
            )?;
            let cluster = parse_cluster(required(&options, "--cluster")?)?;
            let endpoint = endpoint_from_options(&options)?;
            let generation = parse_generation(required(&options, "--generation")?)?;
            let run = PtySecurityRunner;
            let state_dir = default_state_dir()?;
            let mut stdin = std::io::stdin().lock();
            store_from_reader(
                &state_dir,
                cluster,
                &endpoint,
                generation,
                &mut stdin,
                Arc::new(run),
            )
            .map_err(|error| (1, error.to_string()))?;
            println!(
                "{}",
                serde_json::json!({ "status": "stored", "generation": generation })
            );
            Ok(())
        }
        Some("has") => {
            let options = parse_options(&args[1..], &["--server", "--account"])?;
            let endpoint = endpoint_from_options(&options)?;
            let present = PtySecurityRunner
                .has(&endpoint)
                .map_err(|error| (1, error.to_string()))?;
            println!("{}", serde_json::json!({ "present": present }));
            Ok(())
        }
        Some("delete") => {
            let options = parse_options(&args[1..], &["--server", "--account"])?;
            let endpoint = endpoint_from_options(&options)?;
            let deleted = PtySecurityRunner
                .delete(&endpoint)
                .map_err(|error| (1, error.to_string()))?;
            println!("{}", serde_json::json!({ "deleted": deleted }));
            Ok(())
        }
        _ => Err((
            2,
            "internal smb-keychain command is missing or unknown".into(),
        )),
    }
}

fn run_master_keychain(args: &[String]) -> AppResult<()> {
    match args.first().map(String::as_str) {
        Some("import") => {
            let options = parse_options(
                &args[1..],
                &[
                    "--cluster",
                    "--server-id",
                    "--server",
                    "--account",
                    "--generation",
                ],
            )?;
            let key = key_from_options(&options)?;
            let generation = parse_generation(required(&options, "--generation")?)?;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(MAX_SMB_CREDENTIAL_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| (1, format!("cannot read SMB password: {error}")))?;
            if bytes.len() > MAX_SMB_CREDENTIAL_BYTES {
                return Err((
                    2,
                    format!("SMB password exceeds the {MAX_SMB_CREDENTIAL_BYTES}-byte limit"),
                ));
            }
            let credential = StoredSmbCredential {
                generation,
                password: SecretString::from_bytes(bytes)
                    .map_err(|error| (2, error.to_string()))?,
            };
            CredentialHelperClient::system()
                .import(&key, &credential)
                .map_err(|error| (1, error.to_string()))?;
            println!(
                "{}",
                serde_json::json!({ "status": "imported", "generation": generation })
            );
            Ok(())
        }
        Some("delete") => {
            let options = parse_options(
                &args[1..],
                &["--cluster", "--server-id", "--server", "--account"],
            )?;
            let key = key_from_options(&options)?;
            let deleted = CredentialHelperClient::system()
                .delete(&key)
                .map_err(|error| (1, error.to_string()))?;
            println!("{}", serde_json::json!({ "deleted": deleted }));
            Ok(())
        }
        _ => Err((
            2,
            "internal smb-master command is missing or unknown".into(),
        )),
    }
}

fn parse_options(
    args: &[String],
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, (i32, String)> {
    let mut options = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let option = &args[index];
        if !allowed.contains(&option.as_str()) {
            return Err((2, format!("unknown SMB keychain option '{option}'")));
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| (2, format!("{option} requires a value")))?;
        if options.insert(option.clone(), value.clone()).is_some() {
            return Err((2, format!("{option} may only be specified once")));
        }
        index += 2;
    }
    Ok(options)
}

fn required<'a>(
    options: &'a BTreeMap<String, String>,
    option: &str,
) -> Result<&'a str, (i32, String)> {
    options
        .get(option)
        .map(String::as_str)
        .ok_or_else(|| (2, format!("SMB keychain command requires {option}")))
}

fn parse_cluster(value: &str) -> Result<Id128, (i32, String)> {
    let cluster = Id128::parse(value).map_err(|error| (2, error.to_string()))?;
    if cluster.to_string() != value {
        return Err((2, "cluster UUID must be canonical".into()));
    }
    Ok(cluster)
}

fn parse_generation(value: &str) -> Result<u64, (i32, String)> {
    value
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation > 0)
        .ok_or_else(|| {
            (
                2,
                "SMB credential generation must be greater than zero".into(),
            )
        })
}

fn endpoint_from_options(
    options: &BTreeMap<String, String>,
) -> Result<SmbKeychainEndpoint, (i32, String)> {
    let endpoint = SmbKeychainEndpoint {
        server: required(options, "--server")?.to_owned(),
        account: required(options, "--account")?.to_owned(),
    };
    endpoint
        .validate()
        .map_err(|error| (2, error.to_string()))?;
    Ok(endpoint)
}

fn key_from_options(options: &BTreeMap<String, String>) -> Result<SmbCredentialKey, (i32, String)> {
    let endpoint = endpoint_from_options(options)?;
    let key = SmbCredentialKey {
        cluster_uuid: parse_cluster(required(options, "--cluster")?)?,
        server_id: NodeId::new(required(options, "--server-id")?.to_owned())
            .map_err(|error| (2, error.to_string()))?,
        server_host: endpoint.server,
        account: endpoint.account,
    };
    key.validate().map_err(|error| (2, error.to_string()))?;
    Ok(key)
}

fn default_state_dir() -> AppResult<PathBuf> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| (1, "HOME must be an absolute path".into()))?;
    Ok(home.join("Library/Application Support/macluster"))
}

fn store_from_reader(
    state_dir: &Path,
    cluster_uuid: Id128,
    endpoint: &SmbKeychainEndpoint,
    generation: u64,
    input: &mut impl Read,
    runner: Arc<dyn NodeKeychainCommandRunner>,
) -> Result<(), NodeKeychainError> {
    endpoint
        .validate()
        .map_err(NodeKeychainError::InvalidEndpoint)?;
    if generation == 0 {
        return Err(NodeKeychainError::InvalidGeneration);
    }
    let mut bytes = Vec::new();
    input
        .take(MAX_SMB_CREDENTIAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| NodeKeychainError::Io(error.to_string()))?;
    if bytes.len() > MAX_SMB_CREDENTIAL_BYTES {
        return Err(NodeKeychainError::FrameTooLarge {
            maximum: MAX_SMB_CREDENTIAL_BYTES,
        });
    }
    let password = SecretString::from_bytes(bytes).map_err(NodeKeychainError::InvalidSecret)?;
    runner.store(endpoint, generation, &password)?;
    record_node_generation(state_dir, cluster_uuid, endpoint, generation)
        .map_err(|error| NodeKeychainError::State(error.to_string()))
}

fn record_node_generation(
    state_dir: &Path,
    cluster_uuid: Id128,
    endpoint: &SmbKeychainEndpoint,
    generation: u64,
) -> std::io::Result<()> {
    let mut state = NodeKeychainState::load(state_dir)
        .map_err(|error| std::io::Error::new(error.kind(), error.to_string()))?;
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NodeCredentialEntry {
    server: String,
    account: String,
    generation: u64,
    cluster_uuid: Id128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NodeKeychainState {
    version: u32,
    #[serde(default)]
    entries: BTreeMap<String, NodeCredentialEntry>,
}

impl Default for NodeKeychainState {
    fn default() -> Self {
        Self {
            version: 1,
            entries: BTreeMap::new(),
        }
    }
}

impl NodeKeychainState {
    fn load(state_dir: &Path) -> std::io::Result<Self> {
        let path = state_dir.join(STATE_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error),
        };
        let state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        if state.version != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
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
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            if key != &entry_key(&endpoint) || entry.generation == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid SMB keychain state entry",
                ));
            }
        }
        Ok(state)
    }

    fn save(&self, state_dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join(STATE_FILE);
        let temporary = state_dir.join(format!(".{STATE_FILE}.{}.tmp", Id128::random()));
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            OpenOptions::new().read(true).open(state_dir)?.sync_all()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn entry_key(endpoint: &SmbKeychainEndpoint) -> String {
    format!("{}/{}", endpoint.server, endpoint.account)
}

trait PasswordPrompt {
    fn prompt(&self, endpoint: &SmbKeychainEndpoint) -> Result<SecretString, String>;
}

struct TerminalPasswordPrompt;

impl PasswordPrompt for TerminalPasswordPrompt {
    fn prompt(&self, endpoint: &SmbKeychainEndpoint) -> Result<SecretString, String> {
        let prompt = format!(
            "SMB password for {}@{}: ",
            endpoint.account, endpoint.server
        );
        let password = rpassword::prompt_password(prompt)
            .map_err(|error| format!("cannot read SMB password: {error}"))?;
        SecretString::from_bytes(password.into_bytes()).map_err(|error| error.to_string())
    }
}

trait MasterCredentialStore: Send + Sync {
    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String>;
    fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, String>;
    fn delete(&self, key: &SmbCredentialKey) -> Result<bool, String>;
}

impl MasterCredentialStore for CredentialHelperClient {
    fn get(&self, key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
        CredentialHelperClient::get(self, key).map_err(|error| error.to_string())
    }

    fn put(
        &self,
        key: &SmbCredentialKey,
        password: &SecretString,
    ) -> Result<StoredSmbCredential, String> {
        CredentialHelperClient::put(self, key, password).map_err(|error| error.to_string())
    }

    fn delete(&self, key: &SmbCredentialKey) -> Result<bool, String> {
        CredentialHelperClient::delete(self, key).map_err(|error| error.to_string())
    }
}

pub(crate) trait SmbAuthenticator {
    fn validate(
        &self,
        uri: &StorageUri,
        account: &str,
        password: &SecretString,
    ) -> Result<(), SmbAuthError>;
}

struct PtySmbAuthenticator {
    server_host: String,
}

impl SmbAuthenticator for PtySmbAuthenticator {
    fn validate(
        &self,
        uri: &StorageUri,
        account: &str,
        password: &SecretString,
    ) -> Result<(), SmbAuthError> {
        validate_mount_with_io(
            |source, target| {
                run_password_pty(
                    Path::new("/sbin/mount_smbfs"),
                    &[
                        "-s".to_owned(),
                        source.to_owned(),
                        target.to_string_lossy().into_owned(),
                    ],
                    password,
                    SMB_AUTH_TIMEOUT,
                )
                .map_err(|error| match error {
                    NodeKeychainError::Timeout(_) => SmbAuthError::Timeout,
                    other => SmbAuthError::Pty(other),
                })
            },
            |target| {
                let status = std::process::Command::new("/sbin/umount")
                    .arg(target)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map_err(|error| SmbAuthError::Cleanup(error.to_string()))?;
                if status.success() {
                    Ok(())
                } else {
                    Err(SmbAuthError::Cleanup(format!(
                        "umount exited with {:?}",
                        status.code()
                    )))
                }
            },
            &format!(
                "//{account}@{}/{}",
                self.server_host,
                uri.source
                    .trim_start_matches('/')
                    .split('/')
                    .next()
                    .unwrap_or("")
            ),
        )
    }
}

pub(crate) trait CredentialDistributor: Send + Sync {
    fn ensure_node(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        provision: &SmbCredentialProvision,
    ) -> Result<ProvisionState, DistributionError>;

    fn delete_node(
        &self,
        node_id: &NodeId,
        node: &NodeConfig,
        endpoint: &SmbKeychainEndpoint,
    ) -> Result<(), DistributionError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProvisionState {
    Provisioned,
    Current,
    Deferred(String),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProvisionReport {
    pub provisioned: Vec<NodeId>,
    pub current: Vec<NodeId>,
    pub deferred: Vec<(NodeId, String)>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialPlan {
    pub key: SmbCredentialKey,
    pub credential: StoredSmbCredential,
    pub newly_created: bool,
    pub report: ProvisionReport,
}

pub(crate) fn ensure_smb_mount_credential(
    config_path: &Path,
    _state_dir: &Path,
    uri: &StorageUri,
    options: &crate::node_admin::StorageMountOptions,
) -> AppResult<CredentialPlan> {
    let source = fs::read_to_string(config_path)
        .map_err(|error| (1, format!("cannot read cluster config: {error}")))?;
    let config = ClusterConfig::parse(&source).map_err(|error| (2, error.to_string()))?;
    let account =
        crate::node_admin::resolve_smb_user(&config, &uri.server, options.smb_user.as_deref())
            .map_err(|error| (2, error.to_string()))?;
    let nodes = crate::node_admin::smb_credential_nodes(&config, uri.server.as_str());
    let prompt = TerminalPasswordPrompt;
    let authenticator = PtySmbAuthenticator {
        server_host: config.nodes[uri.server.as_str()].host.clone(),
    };
    let master = CredentialHelperClient::system();
    let distributor = SshCredentialDistributor;
    ensure_smb_mount_credential_with(
        &config,
        uri,
        &account,
        options.update_credential,
        &nodes,
        &prompt,
        &authenticator,
        &master,
        &distributor,
    )
    .map_err(|error| (1, error.to_string()))
}

fn ensure_smb_mount_credential_with(
    config: &ClusterConfig,
    uri: &StorageUri,
    account: &str,
    update_credential: bool,
    nodes: &[(NodeId, NodeConfig)],
    prompt: &dyn PasswordPrompt,
    authenticator: &dyn SmbAuthenticator,
    master: &dyn MasterCredentialStore,
    distributor: &dyn CredentialDistributor,
) -> Result<CredentialPlan, CredentialWorkflowError> {
    let server = config
        .nodes
        .get(uri.server.as_str())
        .ok_or_else(|| CredentialWorkflowError::MissingServer(uri.server.to_string()))?;
    let key = SmbCredentialKey {
        cluster_uuid: Id128::parse(&config.share_uuid)
            .map_err(|error| CredentialWorkflowError::Config(error.to_string()))?,
        server_id: uri.server.clone(),
        server_host: server.host.clone(),
        account: account.to_owned(),
    };
    key.validate()
        .map_err(|error| CredentialWorkflowError::Config(error.to_string()))?;
    let existing = master.get(&key).map_err(CredentialWorkflowError::Master)?;
    let newly_created = existing.is_none();
    let credential = if let Some(existing) = existing.filter(|_| !update_credential) {
        existing
    } else {
        let password = prompt
            .prompt(&key.endpoint())
            .map_err(CredentialWorkflowError::Prompt)?;
        authenticator
            .validate(uri, account, &password)
            .map_err(CredentialWorkflowError::Authentication)?;
        master
            .put(&key, &password)
            .map_err(CredentialWorkflowError::Master)?
    };
    let provision = SmbCredentialProvision {
        key: key.clone(),
        credential: credential.clone(),
    };
    let report = distribute_credential(nodes, &provision, distributor);
    Ok(CredentialPlan {
        key,
        credential,
        newly_created,
        report,
    })
}

fn distribute_credential(
    nodes: &[(NodeId, NodeConfig)],
    provision: &SmbCredentialProvision,
    distributor: &dyn CredentialDistributor,
) -> ProvisionReport {
    let mut results = Vec::with_capacity(nodes.len());
    std::thread::scope(|scope| {
        let handles = nodes
            .chunks(8)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|(node_id, node)| {
                            (
                                node_id.clone(),
                                distributor.ensure_node(node_id, node, provision),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            results.extend(handle.join().unwrap_or_else(|_| Vec::new()));
        }
    });
    let mut report = ProvisionReport::default();
    for (node_id, state) in results {
        match state {
            Ok(ProvisionState::Provisioned) => report.provisioned.push(node_id),
            Ok(ProvisionState::Current) => report.current.push(node_id),
            Ok(ProvisionState::Deferred(reason)) => report.deferred.push((node_id, reason)),
            Err(error) => report.deferred.push((node_id, error.to_string())),
        }
    }
    report.provisioned.sort();
    report.current.sort();
    report.deferred.sort_by(|left, right| left.0.cmp(&right.0));
    report
}

fn rollback_smb_credential_plan(
    plan: &CredentialPlan,
    nodes: &[(NodeId, NodeConfig)],
    master: &dyn MasterCredentialStore,
    distributor: &dyn CredentialDistributor,
) -> Result<(), CredentialWorkflowError> {
    if !plan.newly_created {
        return Ok(());
    }
    master
        .delete(&plan.key)
        .map_err(CredentialWorkflowError::Master)?;
    let endpoint = plan.key.endpoint();
    let mut failures = Vec::new();
    for node_id in &plan.report.provisioned {
        if let Some((_, node)) = nodes.iter().find(|(candidate, _)| candidate == node_id)
            && let Err(error) = distributor.delete_node(node_id, node, &endpoint)
        {
            failures.push(format!("{node_id}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CredentialWorkflowError::Rollback(failures.join(", ")))
    }
}

pub(crate) fn rollback_smb_credential_plan_for_config(
    config_path: &Path,
    plan: &CredentialPlan,
) -> Result<(), String> {
    let source = fs::read_to_string(config_path)
        .map_err(|error| format!("cannot read cluster config: {error}"))?;
    let config = ClusterConfig::parse(&source).map_err(|error| error.to_string())?;
    let nodes = crate::node_admin::smb_credential_nodes(&config, plan.key.server_id.as_str());
    rollback_smb_credential_plan(
        plan,
        &nodes,
        &CredentialHelperClient::system(),
        &SshCredentialDistributor,
    )
    .map_err(|error| error.to_string())
}

fn validate_mount_with_io(
    mount: impl FnOnce(&str, &Path) -> Result<(), SmbAuthError>,
    unmount: impl FnOnce(&Path) -> Result<(), SmbAuthError>,
    source: &str,
) -> Result<(), SmbAuthError> {
    let root = std::env::temp_dir().join(format!(
        "macluster-smb-auth-{}-{}",
        std::process::id(),
        Id128::random()
    ));
    fs::create_dir(&root)
        .map_err(|error| SmbAuthError::Cleanup(format!("create probe directory: {error}")))?;
    fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| SmbAuthError::Cleanup(format!("protect probe directory: {error}")))?;
    let target = root.join("mount");
    fs::create_dir(&target)
        .map_err(|error| SmbAuthError::Cleanup(format!("create mount point: {error}")))?;
    let mount_result = mount(source, &target);
    let unmount_result = unmount(&target);
    let cleanup_result = fs::remove_dir_all(&root)
        .map_err(|error| SmbAuthError::Cleanup(format!("remove probe directory: {error}")));
    match (mount_result, unmount_result, cleanup_result) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) | (Ok(()), Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

struct SshCredentialDistributor;

impl CredentialDistributor for SshCredentialDistributor {
    fn ensure_node(
        &self,
        _node_id: &NodeId,
        node: &NodeConfig,
        provision: &SmbCredentialProvision,
    ) -> Result<ProvisionState, DistributionError> {
        if node.transport == Transport::Local {
            let endpoint = provision.key.endpoint();
            let runner = PtySecurityRunner;
            let state_dir =
                default_state_dir().map_err(|(_, error)| DistributionError::Local(error))?;
            let state = NodeKeychainState::load(&state_dir)
                .map_err(|error| DistributionError::Local(error.to_string()))?;
            let existing = state.entries.get(&entry_key(&endpoint));
            let has_credential = runner
                .has(&endpoint)
                .map_err(|error| DistributionError::Local(error.to_string()))?;
            if has_credential
                && existing.is_some_and(|entry| {
                    entry.cluster_uuid == provision.key.cluster_uuid
                        && entry.generation >= provision.credential.generation
                })
            {
                return Ok(ProvisionState::Current);
            }
            if has_credential && existing.is_none() {
                record_node_generation(
                    &state_dir,
                    provision.key.cluster_uuid,
                    &endpoint,
                    provision.credential.generation,
                )
                .map_err(|error| DistributionError::Local(error.to_string()))?;
                return Ok(ProvisionState::Current);
            }
            let mut input = Cursor::new(
                provision
                    .credential
                    .password
                    .as_secret()
                    .as_bytes()
                    .to_vec(),
            );
            store_from_reader(
                &state_dir,
                provision.key.cluster_uuid,
                &endpoint,
                provision.credential.generation,
                &mut input,
                Arc::new(runner),
            )
            .map_err(|error| DistributionError::Local(error.to_string()))?;
            Ok(ProvisionState::Provisioned)
        } else {
            if !crate::node_admin::node_ssh_endpoint_reachable(node) {
                return Ok(ProvisionState::Deferred(
                    "node is unreachable; credential will be retried after reconnect".into(),
                ));
            }
            match crate::node_admin::provision_smb_credential_on_node(node, provision) {
                Ok(()) => Ok(ProvisionState::Provisioned),
                Err(error) => Ok(ProvisionState::Deferred(error)),
            }
        }
    }

    fn delete_node(
        &self,
        _node_id: &NodeId,
        node: &NodeConfig,
        endpoint: &SmbKeychainEndpoint,
    ) -> Result<(), DistributionError> {
        if node.transport == Transport::Local {
            PtySecurityRunner
                .delete(endpoint)
                .map(|_| ())
                .map_err(|error| DistributionError::Local(error.to_string()))
        } else {
            crate::node_admin::delete_smb_credential_on_node(node, endpoint)
                .map_err(DistributionError::Transport)
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum CredentialWorkflowError {
    #[error("cluster identity is invalid: {0}")]
    Config(String),
    #[error("SMB server node '{0}' is missing")]
    MissingServer(String),
    #[error("SMB password prompt failed: {0}")]
    Prompt(String),
    #[error("SMB authentication failed: {0}")]
    Authentication(#[from] SmbAuthError),
    #[error("SMB master credential operation failed: {0}")]
    Master(String),
    #[error("SMB credential rollback failed: {0}")]
    Rollback(String),
}

#[derive(Debug, Error)]
pub(crate) enum SmbAuthError {
    #[error("SMB authentication timed out")]
    Timeout,
    #[error("SMB authentication process failed: {0}")]
    Pty(NodeKeychainError),
    #[error("SMB authentication cleanup failed: {0}")]
    Cleanup(String),
    #[cfg(test)]
    #[error("SMB server rejected the supplied credentials")]
    Rejected,
}

#[derive(Debug, Error)]
pub(crate) enum DistributionError {
    #[error("local Keychain update failed: {0}")]
    Local(String),
    #[error("node transport failed: {0}")]
    Transport(String),
}

trait NodeKeychainCommandRunner: Send + Sync {
    fn store(
        &self,
        endpoint: &SmbKeychainEndpoint,
        generation: u64,
        password: &SecretString,
    ) -> Result<(), NodeKeychainError>;
    fn has(&self, endpoint: &SmbKeychainEndpoint) -> Result<bool, NodeKeychainError>;
    fn delete(&self, endpoint: &SmbKeychainEndpoint) -> Result<bool, NodeKeychainError>;
}

struct PtySecurityRunner;

impl NodeKeychainCommandRunner for PtySecurityRunner {
    fn store(
        &self,
        endpoint: &SmbKeychainEndpoint,
        _generation: u64,
        password: &SecretString,
    ) -> Result<(), NodeKeychainError> {
        run_security_pty(&security_command(endpoint, "store"), password)
    }

    fn has(&self, endpoint: &SmbKeychainEndpoint) -> Result<bool, NodeKeychainError> {
        run_security_metadata(&security_command(endpoint, "has"))
    }

    fn delete(&self, endpoint: &SmbKeychainEndpoint) -> Result<bool, NodeKeychainError> {
        run_security_metadata(&security_command(endpoint, "delete"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SecurityCommandSpec {
    program: PathBuf,
    args: Vec<String>,
    environment: Vec<(String, OsString)>,
}

fn security_command(endpoint: &SmbKeychainEndpoint, action: &str) -> SecurityCommandSpec {
    let subcommand = match action {
        "has" => "find-internet-password",
        "delete" => "delete-internet-password",
        _ => "add-internet-password",
    };
    let mut args = vec![
        subcommand.to_owned(),
        "-a".into(),
        endpoint.account.clone(),
        "-s".into(),
        endpoint.server.clone(),
        "-r".into(),
        "smb ".into(),
        "-t".into(),
        "dflt".into(),
    ];
    if action == "store" {
        args.extend([
            "-T".into(),
            MOUNT_SMBFS_BINARY.into(),
            "-U".into(),
            "-w".into(),
        ]);
    }
    SecurityCommandSpec {
        program: PathBuf::from(SECURITY_BINARY),
        args,
        environment: Vec::new(),
    }
}

fn run_security_metadata(spec: &SecurityCommandSpec) -> Result<bool, NodeKeychainError> {
    let status = Command::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| NodeKeychainError::Io(error.to_string()))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(SECURITY_ITEM_NOT_FOUND) => Ok(false),
        code => Err(NodeKeychainError::SecurityFailed {
            action: spec.args.first().cloned().unwrap_or_default(),
            code,
            detail: None,
        }),
    }
}

fn run_security_pty(
    spec: &SecurityCommandSpec,
    password: &SecretString,
) -> Result<(), NodeKeychainError> {
    run_password_pty(&spec.program, &spec.args, password, PTY_TIMEOUT)
}

fn run_password_pty(
    program: &Path,
    args: &[String],
    password: &SecretString,
    timeout: Duration,
) -> Result<(), NodeKeychainError> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize::default())
        .map_err(|error| NodeKeychainError::Pty(error.to_string()))?;
    let mut command = CommandBuilder::new(program);
    command.args(args);
    command.env_clear();
    if let Some(home) = env::var_os("HOME") {
        command.env("HOME", home);
    }
    if let Some(user) = env::var_os("USER") {
        command.env("USER", user);
    }
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    command.env("LC_ALL", "C");
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| NodeKeychainError::Pty(error.to_string()))?;
    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| NodeKeychainError::Pty(error.to_string()))?;
    let mut writer = pair
        .master
        .take_writer()
        .map_err(|error| NodeKeychainError::Pty(error.to_string()))?;
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
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
    });
    let started = Instant::now();
    let mut sent_prompts = 0_u8;
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
            let required = if prompt.contains("retype password") {
                2
            } else if prompt.contains("password data for new item")
                || prompt.contains("password:")
                || prompt.contains("password for")
            {
                1
            } else {
                0
            };
            if required > sent_prompts {
                writer
                    .write_all(password.as_secret().as_bytes())
                    .and_then(|()| writer.write_all(b"\n"))
                    .and_then(|()| writer.flush())
                    .map_err(|error| NodeKeychainError::Pty(error.to_string()))?;
                sent_prompts = required;
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| NodeKeychainError::Pty(error.to_string()))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            return Err(NodeKeychainError::Timeout(timeout));
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(writer);
    let _ = reader_thread.join();
    if status.success() {
        Ok(())
    } else {
        Err(NodeKeychainError::SecurityFailed {
            action: args
                .first()
                .cloned()
                .unwrap_or_else(|| program.display().to_string()),
            code: Some(status.exit_code() as i32),
            detail: Some(redact_security_output(&output, password.as_secret())),
        })
    }
}

fn redact_security_output(output: &[u8], secret: &str) -> String {
    let text = String::from_utf8_lossy(output);
    let redacted = if secret.is_empty() {
        text.into_owned()
    } else {
        text.replace(secret, "<redacted>")
    };
    redacted
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .take(512)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub(crate) enum NodeKeychainError {
    #[error("SMB Keychain endpoint is invalid: {0}")]
    InvalidEndpoint(macluster_protocol::smb_credential::SmbCredentialValidationError),
    #[error("SMB credential generation must be greater than zero")]
    InvalidGeneration,
    #[error("SMB password exceeds the {maximum}-byte limit")]
    FrameTooLarge { maximum: usize },
    #[error("SMB password is invalid: {0}")]
    InvalidSecret(macluster_protocol::smb_credential::SmbCredentialValidationError),
    #[error("SMB Keychain I/O failed: {0}")]
    Io(String),
    #[error("SMB Keychain pseudo-terminal failed: {0}")]
    Pty(String),
    #[error("security {action} failed with status {code:?}{}", detail.as_deref().map(|value| format!(": {value}")).unwrap_or_default())]
    SecurityFailed {
        action: String,
        code: Option<i32>,
        detail: Option<String>,
    },
    #[error("SMB Keychain state failed: {0}")]
    State(String),
    #[error("SMB Keychain operation timed out after {0:?}")]
    Timeout(Duration),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::Cursor,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use macluster_core::{
        config::{ClusterConfig, NodeConfig, Transport},
        storage_uri::StorageUri,
    };
    use macluster_protocol::{
        identifiers::{Id128, NodeId},
        smb_credential::{
            MAX_SMB_CREDENTIAL_BYTES, SecretString, SmbCredentialKey, SmbCredentialProvision,
            SmbKeychainEndpoint, StoredSmbCredential,
        },
    };

    use super::{
        CredentialDistributor, CredentialPlan, CredentialWorkflowError, DistributionError,
        MasterCredentialStore, NodeKeychainCommandRunner, NodeKeychainError, NodeKeychainState,
        PasswordPrompt, ProvisionReport, ProvisionState, SmbAuthError, SmbAuthenticator,
        ensure_smb_mount_credential_with, rollback_smb_credential_plan, security_command,
        store_from_reader, validate_mount_with_io,
    };

    #[derive(Default)]
    struct RecordingRunner {
        calls: Mutex<Vec<(SmbKeychainEndpoint, u64)>>,
    }

    impl NodeKeychainCommandRunner for RecordingRunner {
        fn store(
            &self,
            endpoint: &SmbKeychainEndpoint,
            generation: u64,
            _password: &macluster_protocol::smb_credential::SecretString,
        ) -> Result<(), NodeKeychainError> {
            self.calls
                .lock()
                .unwrap()
                .push((endpoint.clone(), generation));
            Ok(())
        }

        fn has(&self, _endpoint: &SmbKeychainEndpoint) -> Result<bool, NodeKeychainError> {
            Ok(false)
        }

        fn delete(&self, _endpoint: &SmbKeychainEndpoint) -> Result<bool, NodeKeychainError> {
            Ok(false)
        }
    }

    fn endpoint() -> SmbKeychainEndpoint {
        SmbKeychainEndpoint {
            server: "192.0.2.20".into(),
            account: "smb-user".into(),
        }
    }

    fn cluster() -> Id128 {
        Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap()
    }

    fn workflow_config() -> ClusterConfig {
        ClusterConfig::parse(
            "[cluster]\nname = \"test\"\ndefault_queue = \"compute\"\nlogin_node = \"login\"\nshared_root = \"/Users/Shared/macluster\"\nshare_uuid = \"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"\nstorage_server = \"nas-01\"\nprotocol_version = 1\n\n[queues.compute]\nnodes = [\"login\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.nas-01]\nhost = \"192.0.2.20\"\ntransport = \"storage\"\n",
        )
        .unwrap()
    }

    fn workflow_nodes() -> Vec<(NodeId, NodeConfig)> {
        [("worker-a", "192.0.2.2"), ("worker-b", "192.0.2.3")]
            .into_iter()
            .map(|(id, host)| {
                (
                    NodeId::new(id).unwrap(),
                    NodeConfig {
                        host: host.into(),
                        transport: Transport::Ssh,
                        remote_binary: "/usr/local/bin/macluster".into(),
                        ssh_user: Some("worker".into()),
                        ssh_port: Some(22),
                        ssh_identity_file: None,
                        remote_config: None,
                        machine_uuid: None,
                        execution_uid: None,
                    },
                )
            })
            .collect()
    }

    struct FakePrompt {
        count: Arc<AtomicUsize>,
        result: Result<SecretString, String>,
    }

    impl PasswordPrompt for FakePrompt {
        fn prompt(&self, _endpoint: &SmbKeychainEndpoint) -> Result<SecretString, String> {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    struct FakeAuthenticator {
        succeed: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl SmbAuthenticator for FakeAuthenticator {
        fn validate(
            &self,
            _uri: &StorageUri,
            _account: &str,
            _password: &SecretString,
        ) -> Result<(), SmbAuthError> {
            self.events.lock().unwrap().push("auth");
            self.succeed.then_some(()).ok_or(SmbAuthError::Rejected)
        }
    }

    #[derive(Default)]
    struct FakeMaster {
        credential: Mutex<Option<StoredSmbCredential>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MasterCredentialStore for FakeMaster {
        fn get(&self, _key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
            Ok(self.credential.lock().unwrap().clone())
        }

        fn put(
            &self,
            _key: &SmbCredentialKey,
            password: &SecretString,
        ) -> Result<StoredSmbCredential, String> {
            self.events.lock().unwrap().push("put");
            let generation = self
                .credential
                .lock()
                .unwrap()
                .as_ref()
                .map_or(1, |credential| credential.generation + 1);
            let credential = StoredSmbCredential {
                generation,
                password: password.clone(),
            };
            *self.credential.lock().unwrap() = Some(credential.clone());
            Ok(credential)
        }

        fn delete(&self, _key: &SmbCredentialKey) -> Result<bool, String> {
            let deleted = self.credential.lock().unwrap().take().is_some();
            self.events.lock().unwrap().push("master-delete");
            Ok(deleted)
        }
    }

    struct FakeDistributor {
        outcomes: Mutex<BTreeMap<String, ProvisionState>>,
        deleted: Mutex<Vec<String>>,
    }

    impl CredentialDistributor for FakeDistributor {
        fn ensure_node(
            &self,
            node_id: &NodeId,
            _node: &NodeConfig,
            _provision: &SmbCredentialProvision,
        ) -> Result<ProvisionState, DistributionError> {
            Ok(self
                .outcomes
                .lock()
                .unwrap()
                .remove(node_id.as_str())
                .unwrap_or(ProvisionState::Current))
        }

        fn delete_node(
            &self,
            node_id: &NodeId,
            _node: &NodeConfig,
            _endpoint: &SmbKeychainEndpoint,
        ) -> Result<(), DistributionError> {
            self.deleted.lock().unwrap().push(node_id.to_string());
            Ok(())
        }
    }

    fn workflow_distributor() -> FakeDistributor {
        FakeDistributor {
            outcomes: Mutex::new(BTreeMap::new()),
            deleted: Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn security_store_command_trusts_mount_smbfs_and_never_contains_password() {
        let spec = security_command(&endpoint(), "store");
        assert_eq!(spec.program, PathBuf::from("/usr/bin/security"));
        assert!(
            spec.args
                .windows(2)
                .any(|args| args[0] == "-T" && args[1] == "/sbin/mount_smbfs")
        );
        assert_eq!(spec.args.last().map(String::as_str), Some("-w"));
        assert!(!spec.args.iter().any(|arg| arg.contains("test-secret")));
        assert!(
            !spec
                .environment
                .iter()
                .any(|(_, value)| value.to_string_lossy().contains("test-secret"))
        );
    }

    #[test]
    fn security_metadata_commands_do_not_request_password_data() {
        assert!(
            security_command(&endpoint(), "has")
                .args
                .iter()
                .any(|arg| arg == "find-internet-password")
        );
        assert!(
            security_command(&endpoint(), "delete")
                .args
                .iter()
                .any(|arg| arg == "delete-internet-password")
        );
        assert!(
            !security_command(&endpoint(), "has")
                .args
                .iter()
                .any(|arg| arg == "-w")
        );
        assert!(
            !security_command(&endpoint(), "delete")
                .args
                .iter()
                .any(|arg| arg == "-w")
        );
    }

    #[test]
    fn node_store_rejects_oversized_stdin_before_running_security() {
        let root = std::env::temp_dir().join(format!(
            "macluster-node-keychain-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut input = Cursor::new(vec![b'x'; MAX_SMB_CREDENTIAL_BYTES + 1]);
        let error = store_from_reader(
            &root,
            cluster(),
            &endpoint(),
            7,
            &mut input,
            Arc::clone(&runner) as Arc<dyn NodeKeychainCommandRunner>,
        )
        .unwrap_err();
        assert!(error.to_string().contains("4096"));
        assert!(runner.calls.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn node_store_persists_generation_without_secret() {
        let root = std::env::temp_dir().join(format!(
            "macluster-node-keychain-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runner = Arc::new(RecordingRunner::default());
        let mut input = Cursor::new(b"test-secret".to_vec());
        store_from_reader(
            &root,
            cluster(),
            &endpoint(),
            11,
            &mut input,
            Arc::clone(&runner) as Arc<dyn NodeKeychainCommandRunner>,
        )
        .unwrap();

        let state = NodeKeychainState::load(&root).unwrap();
        let entry = state
            .entries
            .get("192.0.2.20/smb-user")
            .expect("generation is persisted");
        assert_eq!(entry.generation, 11);
        assert_eq!(entry.cluster_uuid, cluster());
        let bytes = std::fs::read_to_string(root.join("smb-credentials.json")).unwrap();
        assert!(!bytes.contains("test-secret"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn first_run_prompts_once_and_second_run_reuses_the_master() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let nodes = workflow_nodes();
        let prompt_count = Arc::new(AtomicUsize::new(0));
        let prompt = FakePrompt {
            count: Arc::clone(&prompt_count),
            result: Ok(SecretString::new("test-secret")),
        };
        let auth_events = Arc::new(Mutex::new(Vec::new()));
        let auth = FakeAuthenticator {
            succeed: true,
            events: Arc::clone(&auth_events),
        };
        let master = FakeMaster::default();
        let distributor = workflow_distributor();

        let first = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            false,
            &nodes,
            &prompt,
            &auth,
            &master,
            &distributor,
        )
        .unwrap();
        let second = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            false,
            &nodes,
            &prompt,
            &FakeAuthenticator {
                succeed: false,
                events: Arc::clone(&auth_events),
            },
            &master,
            &distributor,
        )
        .unwrap();

        assert_eq!(prompt_count.load(Ordering::SeqCst), 1);
        assert!(first.newly_created);
        assert!(!second.newly_created);
        assert_eq!(first.credential.generation, 1);
        assert_eq!(second.credential.generation, 1);
        assert_eq!(auth_events.lock().unwrap().as_slice(), ["auth"]);
        assert!(!format!("{first:?}").contains("test-secret"));
    }

    #[test]
    fn wrong_password_never_replaces_the_existing_master() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let nodes = workflow_nodes();
        let prompt = FakePrompt {
            count: Arc::new(AtomicUsize::new(0)),
            result: Ok(SecretString::new("wrong-secret")),
        };
        let auth_events = Arc::new(Mutex::new(Vec::new()));
        let auth = FakeAuthenticator {
            succeed: false,
            events: Arc::clone(&auth_events),
        };
        let master = FakeMaster::default();
        let old = StoredSmbCredential {
            generation: 4,
            password: SecretString::new("old-secret"),
        };
        *master.credential.lock().unwrap() = Some(old.clone());

        let error = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            true,
            &nodes,
            &prompt,
            &auth,
            &master,
            &workflow_distributor(),
        )
        .unwrap_err();

        assert!(matches!(error, CredentialWorkflowError::Authentication(_)));
        assert_eq!(master.credential.lock().unwrap().as_ref(), Some(&old));
        assert_eq!(auth_events.lock().unwrap().as_slice(), ["auth"]);
        assert!(master.events.lock().unwrap().is_empty());
        assert!(!format!("{error:?}").contains("wrong-secret"));
    }

    #[test]
    fn partial_fanout_marks_only_failed_nodes_deferred() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let nodes = workflow_nodes();
        let distributor = workflow_distributor();
        distributor.outcomes.lock().unwrap().extend([
            ("worker-a".into(), ProvisionState::Provisioned),
            (
                "worker-b".into(),
                ProvisionState::Deferred("offline".into()),
            ),
        ]);
        let plan = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            false,
            &nodes,
            &FakePrompt {
                count: Arc::new(AtomicUsize::new(0)),
                result: Ok(SecretString::new("test-secret")),
            },
            &FakeAuthenticator {
                succeed: true,
                events: Arc::new(Mutex::new(Vec::new())),
            },
            &FakeMaster::default(),
            &distributor,
        )
        .unwrap();

        assert_eq!(plan.report.provisioned, [NodeId::new("worker-a").unwrap()]);
        assert_eq!(plan.report.deferred.len(), 1);
        assert_eq!(plan.report.deferred[0].0.as_str(), "worker-b");
    }

    #[test]
    fn rotation_authenticates_before_put_and_increments_generation() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let master = FakeMaster {
            credential: Mutex::new(Some(StoredSmbCredential {
                generation: 3,
                password: SecretString::new("old-secret"),
            })),
            events: Arc::clone(&events),
        };
        let prompt = FakePrompt {
            count: Arc::new(AtomicUsize::new(0)),
            result: Ok(SecretString::new("new-secret")),
        };
        let plan = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            true,
            &workflow_nodes(),
            &prompt,
            &FakeAuthenticator {
                succeed: true,
                events: Arc::clone(&events),
            },
            &master,
            &workflow_distributor(),
        )
        .unwrap();

        assert_eq!(plan.credential.generation, 4);
        assert_eq!(events.lock().unwrap().as_slice(), ["auth", "put"]);
    }

    #[test]
    fn rollback_deletes_only_a_new_master_and_nodes_that_received_it() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let nodes = workflow_nodes();
        let master = FakeMaster::default();
        let distributor = workflow_distributor();
        distributor.outcomes.lock().unwrap().extend([
            ("worker-a".into(), ProvisionState::Provisioned),
            ("worker-b".into(), ProvisionState::Current),
        ]);
        let plan: CredentialPlan = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            false,
            &nodes,
            &FakePrompt {
                count: Arc::new(AtomicUsize::new(0)),
                result: Ok(SecretString::new("test-secret")),
            },
            &FakeAuthenticator {
                succeed: true,
                events: Arc::new(Mutex::new(Vec::new())),
            },
            &master,
            &distributor,
        )
        .unwrap();

        rollback_smb_credential_plan(&plan, &nodes, &master, &distributor).unwrap();
        assert!(master.credential.lock().unwrap().is_none());
        assert_eq!(distributor.deleted.lock().unwrap().as_slice(), ["worker-a"]);

        let rotated: CredentialPlan = CredentialPlan {
            newly_created: false,
            ..plan
        };
        rollback_smb_credential_plan(&rotated, &nodes, &master, &distributor).unwrap();
        assert!(distributor.deleted.lock().unwrap().len() == 1);
    }

    #[test]
    fn authenticated_mount_cleanup_runs_after_success_and_timeout() {
        let successful_cleanup = Arc::new(AtomicUsize::new(0));
        validate_mount_with_io(
            |_source, _target| Ok(()),
            {
                let cleanup = Arc::clone(&successful_cleanup);
                move |_target| {
                    cleanup.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            "//smb-user@192.0.2.20/data",
        )
        .unwrap();
        assert_eq!(successful_cleanup.load(Ordering::SeqCst), 1);

        let timeout_cleanup = Arc::new(AtomicUsize::new(0));
        let error = validate_mount_with_io(
            |_source, _target| Err(SmbAuthError::Timeout),
            {
                let cleanup = Arc::clone(&timeout_cleanup);
                move |_target| {
                    cleanup.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            "//smb-user@192.0.2.20/data",
        )
        .unwrap_err();
        assert!(matches!(error, SmbAuthError::Timeout));
        assert_eq!(timeout_cleanup.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn provision_report_defaults_to_empty_and_preserves_no_secret() {
        let report = ProvisionReport::default();
        assert!(report.provisioned.is_empty());
        assert!(report.current.is_empty());
        assert!(report.deferred.is_empty());
        assert!(!format!("{report:?}").contains("test-secret"));
    }

    #[test]
    fn security_pty_feeds_the_same_secret_to_both_security_prompts() {
        let spec = super::SecurityCommandSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec![
                "-c".into(),
                "printf 'password data for new item: '; IFS= read -r first; printf '\\nretype password for new item: '; IFS= read -r second; [ \"$first\" = \"$second\" ]".into(),
            ],
            environment: Vec::new(),
        };
        let secret = macluster_protocol::smb_credential::SecretString::new("test-secret");

        super::run_security_pty(&spec, &secret).unwrap();
    }

    #[test]
    fn security_error_output_redacts_the_secret() {
        let output = b"prompt test-secret failed";
        let redacted = super::redact_security_output(output, "test-secret");
        assert_eq!(redacted, "prompt <redacted> failed");
    }
}
