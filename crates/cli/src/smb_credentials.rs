use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use macluster_controller::smb_credential::CredentialHelperClient;
use macluster_core::{
    config::{ClusterConfig, NodeConfig, Transport},
    nfs_reconcile::SmbCleanupFailureKind,
    smb_credential_cleanup::{GlobalSmbCredentialCleanup, smb_cleanup_retry_delay},
    smb_credentials_state::{record_generation, remove_endpoint},
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
use thiserror::Error;
use zeroize::Zeroizing;

use crate::node_admin::AppResult;

#[cfg(test)]
use std::os::unix::fs::PermissionsExt;

const SECURITY_BINARY: &str = "/usr/bin/security";
const MOUNT_SMBFS_BINARY: &str = "/sbin/mount_smbfs";
#[cfg(test)]
const PTY_TIMEOUT: Duration = Duration::from_secs(20);
const SECURITY_ITEM_NOT_FOUND: i32 = 44;
const SMB_AUTH_TIMEOUT: Duration = Duration::from_secs(20);
const SMB_PASSWORD_ATTEMPTS: u8 = 3;

pub(crate) fn ensure_smb_share_visible(server_host: &str, source: &str) -> Result<(), String> {
    let share = source
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default();
    if share.is_empty() {
        return Err("SMB URI must contain a share name after the server".into());
    }
    let mut command = Command::new("/usr/bin/smbutil");
    command.arg("view");
    command.args(["-N", &format!("//{server_host}")]);
    command.env("LC_ALL", "C");
    let output = match macluster_controller::transport::run_child_bounded(
        command,
        None,
        Duration::from_secs(10),
    ) {
        Ok(output) => output,
        Err(_) => return Ok(()),
    };
    if !output.status.success() {
        // Some servers require authenticated enumeration. In that case the
        // normal credential validation remains authoritative.
        return Ok(());
    }
    let shares = parse_smbutil_shares(&String::from_utf8_lossy(&output.stdout));
    if shares.is_empty()
        || shares
            .iter()
            .any(|available| available.eq_ignore_ascii_case(share))
    {
        return Ok(());
    }
    Err(format!(
        "SMB share '{share}' does not exist on {server_host}. This is not a password error. Available shares: {}. Use `smb://{server_host}/SHARE/...` with one of those names.",
        shares.join(", ")
    ))
}

fn parse_smbutil_shares(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with("Share ")
                || line.starts_with("---")
                || line.ends_with("shares listed")
            {
                return None;
            }
            let (name, disk) = if let Some(index) = line.find(" Disk") {
                (line[..index].trim(), true)
            } else if let Some(index) = line.find(" Pipe") {
                (line[..index].trim(), false)
            } else {
                return None;
            };
            (disk && !name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

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
                &[
                    "--cluster-uuid",
                    "--server-id",
                    "--server",
                    "--account",
                    "--generation",
                ],
            )?;
            let cluster = parse_cluster(required(&options, "--cluster-uuid")?)?;
            let endpoint = endpoint_from_options(&options)?;
            let generation = parse_generation(required(&options, "--generation")?)?;
            let state_dir = default_state_dir()?;
            let stdin = std::io::stdin().lock();
            let mut bytes = Vec::new();
            stdin
                .take(MAX_SMB_CREDENTIAL_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| (1, format!("cannot read SMB password: {error}")))?;
            if bytes.len() > MAX_SMB_CREDENTIAL_BYTES {
                return Err((
                    2,
                    format!("SMB password exceeds the {MAX_SMB_CREDENTIAL_BYTES}-byte limit"),
                ));
            }
            let password =
                SecretString::from_bytes(bytes).map_err(|error| (2, error.to_string()))?;
            let key = SmbCredentialKey {
                cluster_uuid: cluster,
                server_id: NodeId::new(required(&options, "--server-id")?.to_owned())
                    .map_err(|error| (2, error.to_string()))?,
                server_host: endpoint.server.clone(),
                account: endpoint.account.clone(),
            };
            CredentialHelperClient::system()
                .provision_login_keychain(&key, generation, &password)
                .map_err(|error| (1, error.to_string()))?;
            record_node_generation(&state_dir, cluster, &endpoint, generation)
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
            if deleted {
                remove_endpoint(&default_state_dir()?, &endpoint)
                    .map_err(|error| (1, error.to_string()))?;
            }
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
        Some("ping") => {
            if args.len() != 1 {
                return Err((2, "internal smb-master ping takes no options".into()));
            }
            CredentialHelperClient::system()
                .ping()
                .map_err(|error| (1, error.to_string()))?;
            println!("{}", serde_json::json!({ "status": "pong" }));
            Ok(())
        }
        Some("import") => {
            let options = parse_options(
                &args[1..],
                &[
                    "--cluster-uuid",
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
        Some("verify") => {
            let options = parse_options(
                &args[1..],
                &[
                    "--cluster-uuid",
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
            let expected =
                SecretString::from_bytes(bytes).map_err(|error| (2, error.to_string()))?;
            let stored = CredentialHelperClient::system()
                .get(&key)
                .map_err(|error| (1, error.to_string()))?
                .ok_or_else(|| (1, "SMB master credential is missing".into()))?;
            if stored.generation != generation
                || stored.password.as_secret() != expected.as_secret()
            {
                return Err((1, "SMB master credential verification failed".into()));
            }
            println!("{}", serde_json::json!({ "verified": true }));
            Ok(())
        }
        Some("delete") => {
            let options = parse_options(
                &args[1..],
                &["--cluster-uuid", "--server-id", "--server", "--account"],
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
        cluster_uuid: parse_cluster(required(options, "--cluster-uuid")?)?,
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

#[cfg(test)]
fn store_from_reader(
    state_dir: &Path,
    cluster_uuid: Id128,
    endpoint: &SmbKeychainEndpoint,
    generation: u64,
    input: &mut impl Read,
    runner: std::sync::Arc<dyn NodeKeychainCommandRunner>,
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
    record_generation(state_dir, cluster_uuid, endpoint, generation)
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

fn smb_validation_arguments(source: &str) -> Vec<String> {
    vec!["view".into(), "-f".into(), source.into()]
}

impl SmbAuthenticator for PtySmbAuthenticator {
    fn validate(
        &self,
        uri: &StorageUri,
        account: &str,
        password: &SecretString,
    ) -> Result<(), SmbAuthError> {
        let source = format!(
            "//{account}@{}/{}",
            self.server_host,
            uri.source
                .trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or("")
        );
        run_password_pty(
            Path::new("/usr/bin/smbutil"),
            &smb_validation_arguments(&source),
            password,
            SMB_AUTH_TIMEOUT,
        )
        .map_err(|error| match error {
            NodeKeychainError::Timeout(_) => SmbAuthError::Timeout,
            other => SmbAuthError::Pty(other),
        })
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
    #[allow(dead_code)]
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
    state_dir: &Path,
    uri: &StorageUri,
    options: &crate::node_admin::StorageMountOptions,
    account: &str,
) -> AppResult<CredentialPlan> {
    let source = fs::read_to_string(config_path)
        .map_err(|error| (1, format!("cannot read cluster config: {error}")))?;
    let config = ClusterConfig::parse(&source).map_err(|error| (2, error.to_string()))?;
    let local_node_id = config
        .login_node
        .as_ref()
        .map(NodeId::as_str)
        .or_else(|| {
            config
                .nodes
                .iter()
                .find(|(_, node)| node.transport == macluster_core::config::Transport::Local)
                .map(|(id, _)| id.as_str())
        })
        .ok_or_else(|| {
            (
                1,
                "SMB credential helper requires a local login node".into(),
            )
        })?;
    let local_node = config.nodes.get(local_node_id).ok_or_else(|| {
        (
            1,
            format!("local login node '{local_node_id}' is not configured"),
        )
    })?;
    let _ = local_node;
    let nodes = crate::node_admin::smb_credential_nodes(&config, uri.server.as_str());
    let helper_operation = Id128::random().to_string();
    for (node_id, node) in &nodes {
        if node.transport == Transport::Ssh && !crate::node_admin::node_ssh_endpoint_reachable(node)
        {
            continue;
        }
        crate::node_admin::ensure_smb_credential_helper_for_node(
            &config,
            node_id.as_str(),
            node,
            state_dir,
            &helper_operation,
        )
        .map_err(|error| {
            (
                1,
                format!(
                    "cannot prepare the SMB session helper on {node_id} before prompting: {error}"
                ),
            )
        })?;
    }
    let prompt = TerminalPasswordPrompt;
    let authenticator = PtySmbAuthenticator {
        server_host: config.nodes[uri.server.as_str()].host.clone(),
    };
    let master = CredentialHelperClient::system();
    let distributor = SshCredentialDistributor;
    ensure_smb_mount_credential_with(
        &config,
        uri,
        account,
        options.update_credential,
        &nodes,
        &prompt,
        &authenticator,
        &master,
        &distributor,
    )
    .map_err(|error| (1, error.to_string()))
}

#[allow(clippy::too_many_arguments)]
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
    // An explicit credential rotation must not need to read the old secret.
    // The system-keychain ACL may have been invalidated by a helper update,
    // while the privileged store operation can still replace the item.
    let existing = if update_credential {
        None
    } else {
        master.get(&key).map_err(CredentialWorkflowError::Master)?
    };
    let newly_created = existing.is_none();
    let credential = if let Some(existing) = existing.filter(|_| !update_credential) {
        existing
    } else {
        let mut attempt = 0;
        let password = loop {
            attempt += 1;
            let password = prompt
                .prompt(&key.endpoint())
                .map_err(CredentialWorkflowError::Prompt)?;
            match authenticator.validate(uri, account, &password) {
                Ok(()) => break password,
                Err(error)
                    if error.failure_kind() == SmbAuthFailureKind::Authentication
                        && attempt < SMB_PASSWORD_ATTEMPTS =>
                {
                    eprintln!(
                        "SMB authentication failed for {account}@{} (attempt {attempt}/{SMB_PASSWORD_ATTEMPTS}); try again.",
                        key.server_host
                    );
                }
                Err(error) if error.failure_kind() == SmbAuthFailureKind::Authentication => {
                    return Err(CredentialWorkflowError::Authentication(
                        SmbAuthError::InvalidCredentials {
                            attempts: attempt,
                            detail: error.to_string(),
                        },
                    ));
                }
                Err(error) if error.failure_kind() == SmbAuthFailureKind::ShareNotFound => {
                    let share = uri
                        .source
                        .trim_start_matches('/')
                        .split('/')
                        .next()
                        .unwrap_or_default();
                    return Err(CredentialWorkflowError::Authentication(
                        SmbAuthError::ShareNotFound(format!(
                            "SMB share '{share}' was not found on {}. This is not a password error; check the share name with `/usr/bin/smbutil view -N //{}` and use `smb://{}/{}/...`.",
                            key.server_host, key.server_host, key.server_host, share
                        )),
                    ));
                }
                Err(error) if error.failure_kind() == SmbAuthFailureKind::MountConflict => {
                    return Err(CredentialWorkflowError::Authentication(
                        SmbAuthError::MountConflict(format!(
                            "{}; the same SMB source appears to be mounted through another server name or account. Run `mnode -l`, accept the mount reuse prompt, or unmount the existing source before retrying.",
                            error
                        )),
                    ));
                }
                Err(error) => return Err(CredentialWorkflowError::Authentication(error)),
            }
        };
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

fn provision_before_commit_with<T>(
    config: &ClusterConfig,
    node_id: &NodeId,
    node: &NodeConfig,
    reader: &dyn macluster_controller::smb_credential::MasterCredentialReader,
    distributor: &dyn CredentialDistributor,
    commit: impl FnOnce() -> T,
) -> (Vec<String>, T) {
    let mut warnings = Vec::new();
    match macluster_controller::smb_credential::load_smb_credential_provisions(config, reader) {
        Ok(provisions) => {
            for provision in provisions {
                match distributor.ensure_node(node_id, node, &provision) {
                    Ok(ProvisionState::Provisioned | ProvisionState::Current) => {}
                    Ok(ProvisionState::Deferred(error)) => warnings.push(error),
                    Err(error) => warnings.push(error.to_string()),
                }
            }
        }
        Err(error) => warnings.push(error),
    }
    let committed = commit();
    (warnings, committed)
}

pub(crate) fn provision_smb_credentials_for_enrollment<T>(
    config: &ClusterConfig,
    node_id: &NodeId,
    node: &NodeConfig,
    commit: impl FnOnce() -> T,
) -> (Vec<String>, T) {
    provision_before_commit_with(
        config,
        node_id,
        node,
        &CredentialHelperClient::system(),
        &SshCredentialDistributor,
        commit,
    )
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CredentialCleanupReport {
    pub removed_master: bool,
    pub removed_nodes: Vec<NodeId>,
    pub deferred: Vec<(String, String)>,
}

pub(crate) fn cleanup_smb_credential_if_unused(
    config: &ClusterConfig,
    key: &SmbCredentialKey,
) -> Result<CredentialCleanupReport, String> {
    cleanup_smb_credential_if_unused_with(config, key, &CredentialHelperClient::system())
}

pub(crate) fn delete_master_credential(key: &SmbCredentialKey) -> Result<bool, String> {
    CredentialHelperClient::system()
        .delete(key)
        .map_err(|error| error.to_string())
}

fn cleanup_smb_credential_if_unused_with(
    config: &ClusterConfig,
    key: &SmbCredentialKey,
    master: &dyn MasterCredentialStore,
) -> Result<CredentialCleanupReport, String> {
    let in_use = config.shares.values().any(|share| {
        share.protocol == macluster_core::storage_uri::StorageProtocol::Smb
            && share.server == key.server_id
            && share.smb_user.as_deref() == Some(key.account.as_str())
    });
    if in_use {
        return Ok(CredentialCleanupReport::default());
    }
    Ok(CredentialCleanupReport {
        removed_master: master.delete(key)?,
        ..CredentialCleanupReport::default()
    })
}

pub(crate) fn queue_global_master_cleanup(key: &SmbCredentialKey) -> Result<(), String> {
    let path = GlobalSmbCredentialCleanup::default_path().map_err(|error| error.to_string())?;
    let mut state = GlobalSmbCredentialCleanup::load(&path).map_err(|error| error.to_string())?;
    state.remember_master(key.clone());
    state.save(&path).map_err(|error| error.to_string())
}

pub(crate) fn queue_global_node_cleanup(
    entry: macluster_core::nfs_reconcile::DeferredSmbCredentialCleanup,
) -> Result<(), String> {
    let path = GlobalSmbCredentialCleanup::default_path().map_err(|error| error.to_string())?;
    queue_global_node_cleanup_at(&path, entry)
}

fn queue_global_node_cleanup_at(
    path: &std::path::Path,
    entry: macluster_core::nfs_reconcile::DeferredSmbCredentialCleanup,
) -> Result<(), String> {
    let mut state = GlobalSmbCredentialCleanup::load(path).map_err(|error| error.to_string())?;
    state.remember_node(entry);
    state.save(path).map_err(|error| error.to_string())
}

pub(crate) fn retry_global_smb_credential_cleanup() -> Result<CredentialCleanupReport, String> {
    let path = GlobalSmbCredentialCleanup::default_path().map_err(|error| error.to_string())?;
    let mut state = GlobalSmbCredentialCleanup::load(&path).map_err(|error| error.to_string())?;
    if state.nodes.is_empty() && state.masters.is_empty() {
        return Ok(CredentialCleanupReport::default());
    }
    let master = CredentialHelperClient::system();
    let mut report = CredentialCleanupReport::default();
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let master_keys = state.masters.keys().cloned().collect::<Vec<_>>();
    for service in master_keys {
        let Some(key) = state.masters.get(&service).cloned() else {
            continue;
        };
        match master.delete(&key) {
            Ok(_) => {
                state.masters.remove(&service);
                report.removed_master = true;
            }
            Err(error) => report.deferred.push((service, error.to_string())),
        }
    }
    let node_ids = state.nodes.keys().cloned().collect::<Vec<_>>();
    for node_id in node_ids {
        let Some(entry) = state.nodes.get(&node_id).cloned() else {
            continue;
        };
        if entry.next_retry_unix_ms > now_unix_ms {
            continue;
        }
        let mut entry = entry;
        if entry.node.transport == Transport::Ssh
            && !crate::node_admin::node_ssh_endpoint_reachable(&entry.node)
        {
            let error = "node remains unreachable";
            record_node_cleanup_failure(&mut entry, error, now_unix_ms);
            report.deferred.push((node_id.clone(), error.into()));
            state.nodes.insert(node_id, entry);
            continue;
        }
        let mut failed = false;
        if entry.wait_for_unmount {
            for share in &entry.shares {
                if let Err(error) =
                    crate::node_admin::unmount_smb_share_for_cleanup(&entry.node, share)
                {
                    record_node_cleanup_failure(&mut entry, &error, now_unix_ms);
                    report.deferred.push((node_id.clone(), error));
                    failed = true;
                    break;
                }
            }
        }
        for endpoint in entry.endpoints.clone() {
            if failed {
                break;
            }
            let result = if entry.node.transport == Transport::Local {
                PtySecurityRunner
                    .delete(&endpoint)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            } else {
                crate::node_admin::delete_smb_credential_on_node(&entry.node, &endpoint)
            };
            if let Err(error) = result {
                failed = true;
                record_node_cleanup_failure(&mut entry, &error, now_unix_ms);
                report.deferred.push((node_id.clone(), error));
            } else if entry.node.transport == Transport::Local
                && let Ok(state_dir) = default_state_dir()
            {
                let _ = remove_endpoint(&state_dir, &endpoint);
            }
        }
        if !failed {
            state.nodes.remove(&node_id);
            if let Ok(id) = NodeId::new(node_id.clone()) {
                report.removed_nodes.push(id);
            }
        } else {
            state.nodes.insert(node_id, entry);
        }
    }
    state.save(&path).map_err(|error| error.to_string())?;
    Ok(report)
}

fn record_node_cleanup_failure(
    entry: &mut macluster_core::nfs_reconcile::DeferredSmbCredentialCleanup,
    error: &str,
    now_unix_ms: u64,
) {
    entry.attempts = entry.attempts.saturating_add(1);
    entry.last_error_kind = Some(classify_smb_cleanup_failure(error));
    entry.last_error_summary = Some(bounded_smb_cleanup_error(error));
    entry.next_retry_unix_ms = now_unix_ms.saturating_add(
        smb_cleanup_retry_delay(entry.attempts)
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX),
    );
}

fn classify_smb_cleanup_failure(error: &str) -> SmbCleanupFailureKind {
    let error = error.to_ascii_lowercase();
    if error.contains("busy") {
        SmbCleanupFailureKind::Busy
    } else if [
        "unreachable",
        "offline",
        "host is down",
        "no route to host",
        "connection refused",
    ]
    .iter()
    .any(|needle| error.contains(needle))
    {
        SmbCleanupFailureKind::Offline
    } else if ["authentication", "password", "permission denied (publickey"]
        .iter()
        .any(|needle| error.contains(needle))
    {
        SmbCleanupFailureKind::Authentication
    } else if [
        "permission denied",
        "operation not permitted",
        "not permitted",
    ]
    .iter()
    .any(|needle| error.contains(needle))
    {
        SmbCleanupFailureKind::Permission
    } else if [
        "timed out",
        "timeout",
        "unresponsive",
        "interrupted system call",
    ]
    .iter()
    .any(|needle| error.contains(needle))
    {
        SmbCleanupFailureKind::Unresponsive
    } else {
        SmbCleanupFailureKind::Unknown
    }
}

fn bounded_smb_cleanup_error(error: &str) -> String {
    const LIMIT: usize = 512;
    let mut summary = String::new();
    for character in error.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if summary.len() + character.len_utf8() > LIMIT {
            break;
        }
        summary.push(character);
    }
    summary
}

pub(crate) fn run_cleanup_command(args: &[String]) -> AppResult<()> {
    if args != ["retry"] {
        return Err((2, "internal smb-cleanup only supports retry".into()));
    }
    let report = retry_global_smb_credential_cleanup().map_err(|error| (1, error))?;
    println!(
        "{}",
        serde_json::json!({
            "removed_master": report.removed_master,
            "removed_nodes": report.removed_nodes,
            "deferred": report.deferred,
        })
    );
    Ok(())
}

#[cfg(test)]
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
            let state_dir =
                default_state_dir().map_err(|(_, error)| DistributionError::Local(error))?;
            CredentialHelperClient::system()
                .provision_login_keychain(
                    &provision.key,
                    provision.credential.generation,
                    &provision.credential.password,
                )
                .map_err(|error| DistributionError::Local(error.to_string()))?;
            record_node_generation(
                &state_dir,
                provision.key.cluster_uuid,
                &endpoint,
                provision.credential.generation,
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
    #[cfg(test)]
    Cleanup(String),
    #[cfg(test)]
    #[error("SMB server rejected the supplied credentials")]
    Rejected,
    #[error("SMB credentials were rejected after {attempts} attempt(s): {detail}")]
    InvalidCredentials { attempts: u8, detail: String },
    #[error("{0}")]
    ShareNotFound(String),
    #[error("{0}")]
    MountConflict(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SmbAuthFailureKind {
    Authentication,
    ShareNotFound,
    MountConflict,
    Other,
}

impl SmbAuthError {
    fn failure_kind(&self) -> SmbAuthFailureKind {
        let detail = match self {
            #[cfg(test)]
            Self::Rejected => return SmbAuthFailureKind::Authentication,
            Self::MountConflict(_) => return SmbAuthFailureKind::MountConflict,
            Self::InvalidCredentials { .. } => {
                return SmbAuthFailureKind::Authentication;
            }
            Self::ShareNotFound(_) => return SmbAuthFailureKind::ShareNotFound,
            Self::Timeout => return SmbAuthFailureKind::Other,
            #[cfg(test)]
            Self::Cleanup(_) => return SmbAuthFailureKind::Other,
            Self::Pty(NodeKeychainError::SecurityFailed { detail, .. }) => {
                detail.as_deref().unwrap_or_default()
            }
            Self::Pty(_) => return SmbAuthFailureKind::Other,
        };
        let detail = detail.to_ascii_lowercase();
        if detail.contains("file exists") {
            SmbAuthFailureKind::MountConflict
        } else if [
            "no such file or directory",
            "bad network name",
            "tree connect failed",
            "share not found",
            "network name not found",
            "status_not_found",
            "path not found",
        ]
        .iter()
        .any(|needle| detail.contains(needle))
        {
            SmbAuthFailureKind::ShareNotFound
        } else if [
            "authentication",
            "logon failure",
            "invalid credentials",
            "permission denied",
            "access denied",
            "status_logon_failure",
            "status_access_denied",
            "session setup failed",
            "not authorized",
            "password",
        ]
        .iter()
        .any(|needle| detail.contains(needle))
        {
            SmbAuthFailureKind::Authentication
        } else {
            SmbAuthFailureKind::Other
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum DistributionError {
    #[error("local SMB credential helper update failed: {0}")]
    Local(String),
    #[error("node transport failed: {0}")]
    Transport(String),
}

trait NodeKeychainCommandRunner: Send + Sync {
    #[cfg(test)]
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
    #[cfg(test)]
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
    ];
    if action != "delete" {
        args.extend(["-r".into(), "smb ".into(), "-t".into(), "dflt".into()]);
    }
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

#[cfg(test)]
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
            action: pty_action_name(program, args),
            code: Some(status.exit_code() as i32),
            detail: Some(redact_security_output(&output, password.as_secret())),
        })
    }
}

fn pty_action_name(program: &Path, args: &[String]) -> String {
    args.first()
        .filter(|argument| !argument.starts_with('-'))
        .cloned()
        .or_else(|| {
            program
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| program.display().to_string())
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
    #[cfg(test)]
    #[error("SMB credential endpoint is invalid: {0}")]
    InvalidEndpoint(macluster_protocol::smb_credential::SmbCredentialValidationError),
    #[cfg(test)]
    #[error("SMB credential generation must be greater than zero")]
    InvalidGeneration,
    #[cfg(test)]
    #[error("SMB password exceeds the {maximum}-byte limit")]
    FrameTooLarge { maximum: usize },
    #[cfg(test)]
    #[error("SMB password is invalid: {0}")]
    InvalidSecret(macluster_protocol::smb_credential::SmbCredentialValidationError),
    #[error("SMB credential helper I/O failed: {0}")]
    Io(String),
    #[error("SMB credential helper pseudo-terminal failed: {0}")]
    Pty(String),
    #[error("security {action} failed with status {code:?}{}", detail.as_deref().map(|value| format!(": {value}")).unwrap_or_default())]
    SecurityFailed {
        action: String,
        code: Option<i32>,
        detail: Option<String>,
    },
    #[cfg(test)]
    #[error("SMB credential helper state failed: {0}")]
    State(String),
    #[error("SMB credential helper operation timed out after {0:?}")]
    Timeout(Duration),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        io::Cursor,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use macluster_core::{
        config::{ClusterConfig, NodeConfig, Transport},
        smb_credentials_state::NodeKeychainState,
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
        GlobalSmbCredentialCleanup, MasterCredentialStore, NodeKeychainCommandRunner,
        NodeKeychainError, PasswordPrompt, ProvisionReport, ProvisionState, SmbAuthError,
        SmbAuthFailureKind, SmbAuthenticator, cleanup_smb_credential_if_unused_with,
        ensure_smb_mount_credential_with, parse_smbutil_shares, provision_before_commit_with,
        pty_action_name, queue_global_node_cleanup_at, record_node_cleanup_failure,
        rollback_smb_credential_plan, security_command, smb_validation_arguments,
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

    struct RetryAuthenticator {
        failures_left: AtomicUsize,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl SmbAuthenticator for RetryAuthenticator {
        fn validate(
            &self,
            _uri: &StorageUri,
            _account: &str,
            _password: &SecretString,
        ) -> Result<(), SmbAuthError> {
            self.events.lock().unwrap().push("auth");
            let remaining = self.failures_left.load(Ordering::SeqCst);
            if remaining > 0 {
                self.failures_left.store(remaining - 1, Ordering::SeqCst);
                Err(SmbAuthError::Rejected)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct FakeMaster {
        credential: Mutex<Option<StoredSmbCredential>>,
        get_error: Mutex<Option<String>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MasterCredentialStore for FakeMaster {
        fn get(&self, _key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
            if let Some(error) = self.get_error.lock().unwrap().clone() {
                return Err(error);
            }
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
        let delete = security_command(&endpoint(), "delete");
        assert!(!delete.args.iter().any(|arg| arg == "-w"));
        assert!(
            !delete.args.iter().any(|arg| arg == "-r" || arg == "-t"),
            "macOS delete-internet-password does not match -r/-t filters reliably"
        );
        assert!(
            delete
                .args
                .iter()
                .any(|arg| arg == "--server" || delete.args.windows(2).any(|pair| pair[0] == "-s"))
        );
        assert!(
            delete.args.windows(2).any(|pair| pair[0] == "--account")
                || delete.args.windows(2).any(|pair| pair[0] == "-a")
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
    fn smbutil_share_parser_distinguishes_existing_and_missing_shares() {
        let shares = parse_smbutil_shares(
            "Share                                           Type    Comments\n\
             -------------------------------\n\
             external-disk                                           Disk    external-disk share directory\n\
             cluster-user                                            Disk    cluster-user share directory\n\
             Shared Data                                     Disk    share with a space\n\
             IPC$                                            Pipe    IPC Service\n\
             \n\
             4 shares listed\n",
        );
        assert_eq!(shares, ["external-disk", "cluster-user", "Shared Data"]);
    }

    #[test]
    fn smb_credential_validation_forces_a_fresh_authenticated_session() {
        assert_eq!(
            smb_validation_arguments("//smb-user@192.0.2.20/Partition_2"),
            ["view", "-f", "//smb-user@192.0.2.20/Partition_2"]
        );
    }

    #[test]
    fn smb_mount_errors_are_classified_before_retrying_passwords() {
        let missing = SmbAuthError::Pty(NodeKeychainError::SecurityFailed {
            action: "mount_smbfs".into(),
            code: Some(64),
            detail: Some(
                "mount_smbfs: mount error: //user@host/data: No such file or directory".into(),
            ),
        });
        assert_eq!(missing.failure_kind(), SmbAuthFailureKind::ShareNotFound);

        let rejected = SmbAuthError::Pty(NodeKeychainError::SecurityFailed {
            action: "mount_smbfs".into(),
            code: Some(13),
            detail: Some("Authentication error".into()),
        });
        assert_eq!(rejected.failure_kind(), SmbAuthFailureKind::Authentication);

        let conflict = SmbAuthError::Pty(NodeKeychainError::SecurityFailed {
            action: "mount_smbfs".into(),
            code: Some(64),
            detail: Some("mount_smbfs: mount error: //user@host/share: File exists".into()),
        });
        assert_eq!(conflict.failure_kind(), SmbAuthFailureKind::MountConflict);
    }

    #[test]
    fn wrong_password_is_prompted_three_times_before_failing() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let nodes = workflow_nodes();
        let prompt_count = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let error = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            false,
            &nodes,
            &FakePrompt {
                count: Arc::clone(&prompt_count),
                result: Ok(SecretString::new("wrong-secret")),
            },
            &RetryAuthenticator {
                failures_left: AtomicUsize::new(3),
                events: Arc::clone(&events),
            },
            &FakeMaster::default(),
            &workflow_distributor(),
        )
        .unwrap_err();

        assert!(matches!(error, CredentialWorkflowError::Authentication(_)));
        assert_eq!(prompt_count.load(Ordering::SeqCst), 3);
        assert_eq!(events.lock().unwrap().len(), 3);
    }

    #[test]
    fn password_retry_succeeds_before_the_third_attempt() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let nodes = workflow_nodes();
        let prompt_count = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let plan = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            false,
            &nodes,
            &FakePrompt {
                count: Arc::clone(&prompt_count),
                result: Ok(SecretString::new("correct-secret")),
            },
            &RetryAuthenticator {
                failures_left: AtomicUsize::new(2),
                events: Arc::clone(&events),
            },
            &FakeMaster::default(),
            &workflow_distributor(),
        )
        .unwrap();

        assert_eq!(prompt_count.load(Ordering::SeqCst), 3);
        assert_eq!(events.lock().unwrap().len(), 3);
        assert_eq!(plan.credential.generation, 1);
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
        assert_eq!(auth_events.lock().unwrap().len(), 3);
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
            get_error: Mutex::new(None),
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
    fn credential_rotation_prompts_without_reading_an_unreadable_master() {
        let config = workflow_config();
        let uri = StorageUri::parse("smb://nas-01/data").unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let master = FakeMaster {
            credential: Mutex::new(None),
            get_error: Mutex::new(Some("Keychain authentication failed".into())),
            events: Arc::clone(&events),
        };
        let prompt_count = Arc::new(AtomicUsize::new(0));

        let plan = ensure_smb_mount_credential_with(
            &config,
            &uri,
            "smb-user",
            true,
            &workflow_nodes(),
            &FakePrompt {
                count: Arc::clone(&prompt_count),
                result: Ok(SecretString::new("replacement-secret")),
            },
            &FakeAuthenticator {
                succeed: true,
                events: Arc::clone(&events),
            },
            &master,
            &workflow_distributor(),
        )
        .unwrap();

        assert_eq!(prompt_count.load(Ordering::SeqCst), 1);
        assert_eq!(plan.credential.generation, 1);
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
    fn smb_credential_cleanup_removes_master_only_after_last_share() {
        let master = FakeMaster::default();
        let key = SmbCredentialKey {
            cluster_uuid: Id128::parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            server_id: NodeId::new("nas-01").unwrap(),
            server_host: "192.0.2.20".into(),
            account: "smb-user".into(),
        };
        *master.credential.lock().unwrap() = Some(StoredSmbCredential {
            generation: 1,
            password: SecretString::new("test-secret"),
        });
        let mut config = workflow_config();
        config.shares.insert(
            "one".into(),
            macluster_core::config::ShareConfig {
                protocol: macluster_core::storage_uri::StorageProtocol::Smb,
                server: key.server_id.clone(),
                source_root: "/one".into(),
                mount_root: "/Users/Shared/one".into(),
                share_uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                smb_user: Some(key.account.clone()),
                allow_existing_contents: false,
            },
        );
        config.shares.insert(
            "two".into(),
            macluster_core::config::ShareConfig {
                protocol: macluster_core::storage_uri::StorageProtocol::Smb,
                server: key.server_id.clone(),
                source_root: "/two".into(),
                mount_root: "/Users/Shared/two".into(),
                share_uuid: "cccccccc-cccc-4ccc-8ccc-cccccccccccc".into(),
                smb_user: Some(key.account.clone()),
                allow_existing_contents: false,
            },
        );

        let report = cleanup_smb_credential_if_unused_with(&config, &key, &master).unwrap();
        assert!(!report.removed_master);
        assert!(master.credential.lock().unwrap().is_some());

        config.shares.remove("one");
        let report = cleanup_smb_credential_if_unused_with(&config, &key, &master).unwrap();
        assert!(!report.removed_master);
        assert!(master.credential.lock().unwrap().is_some());

        config.shares.remove("two");
        let report = cleanup_smb_credential_if_unused_with(&config, &key, &master).unwrap();
        assert!(report.removed_master);
        assert!(master.credential.lock().unwrap().is_none());
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
    fn node_cleanup_queue_persists_a_mount_retry_without_credentials() {
        let root = std::env::temp_dir().join(format!("macluster-smb-queue-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("smb-cleanup.json");
        let node = workflow_nodes()[0].1.clone();
        let share = macluster_core::config::ShareConfig {
            protocol: macluster_core::storage_uri::StorageProtocol::Smb,
            server: NodeId::new("nas-01").unwrap(),
            source_root: "/data".into(),
            mount_root: "/Users/Shared/data".into(),
            share_uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            smb_user: Some("smb-user".into()),
            allow_existing_contents: false,
        };
        let entry = macluster_core::nfs_reconcile::DeferredSmbCredentialCleanup {
            node_id: "worker-a".into(),
            machine_uuid: node.machine_uuid.clone(),
            node,
            shares: vec![share.clone()],
            endpoints: Vec::new(),
            wait_for_unmount: true,
            attempts: 0,
            next_retry_unix_ms: 0,
            last_error_kind: None,
            last_error_summary: None,
        };

        queue_global_node_cleanup_at(&path, entry.clone()).unwrap();

        let pending = GlobalSmbCredentialCleanup::load(&path).unwrap();
        assert_eq!(pending.nodes["worker-a"], entry);
        assert!(pending.masters.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cleanup_failure_records_kind_attempts_and_backoff() {
        let node = workflow_nodes()[0].1.clone();
        let mut entry = macluster_core::nfs_reconcile::DeferredSmbCredentialCleanup {
            node_id: "worker-a".into(),
            machine_uuid: node.machine_uuid.clone(),
            node,
            shares: Vec::new(),
            endpoints: Vec::new(),
            wait_for_unmount: true,
            attempts: 0,
            next_retry_unix_ms: 0,
            last_error_kind: None,
            last_error_summary: None,
        };

        record_node_cleanup_failure(
            &mut entry,
            "unmount SMB share /x: operation remained busy after 10 seconds",
            10_000,
        );

        assert_eq!(entry.attempts, 1);
        assert_eq!(
            entry.last_error_kind,
            Some(macluster_core::nfs_reconcile::SmbCleanupFailureKind::Busy)
        );
        assert_eq!(entry.next_retry_unix_ms, 25_000);
        assert_eq!(
            entry.last_error_summary.as_deref(),
            Some("unmount SMB share /x: operation remained busy after 10 seconds")
        );
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
    fn new_enrollment_provisions_credentials_before_committing_smb_config() {
        struct Reader(StoredSmbCredential);
        impl macluster_controller::smb_credential::MasterCredentialReader for Reader {
            fn get(&self, _key: &SmbCredentialKey) -> Result<Option<StoredSmbCredential>, String> {
                Ok(Some(self.0.clone()))
            }
        }
        struct Distributor {
            events: Arc<Mutex<Vec<&'static str>>>,
        }
        impl CredentialDistributor for Distributor {
            fn ensure_node(
                &self,
                _node_id: &NodeId,
                _node: &NodeConfig,
                _provision: &SmbCredentialProvision,
            ) -> Result<ProvisionState, DistributionError> {
                self.events.lock().unwrap().push("store");
                Ok(ProvisionState::Provisioned)
            }

            fn delete_node(
                &self,
                _node_id: &NodeId,
                _node: &NodeConfig,
                _endpoint: &SmbKeychainEndpoint,
            ) -> Result<(), DistributionError> {
                Ok(())
            }
        }

        let mut config = workflow_config();
        config.shares.insert(
            "data".into(),
            macluster_core::config::ShareConfig {
                protocol: macluster_core::storage_uri::StorageProtocol::Smb,
                server: NodeId::new("nas-01").unwrap(),
                source_root: "/data".into(),
                mount_root: "/Users/Shared/data".into(),
                share_uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                smb_user: Some("smb-user".into()),
                allow_existing_contents: false,
            },
        );
        let reader = Reader(StoredSmbCredential {
            generation: 2,
            password: SecretString::new("test-secret"),
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let distributor = Distributor {
            events: Arc::clone(&events),
        };
        let (_warnings, committed) = provision_before_commit_with(
            &config,
            &NodeId::new("worker-a").unwrap(),
            &workflow_nodes()[0].1,
            &reader,
            &distributor,
            || {
                events.lock().unwrap().push("commit");
                true
            },
        );

        assert!(committed);
        assert_eq!(events.lock().unwrap().as_slice(), ["store", "commit"]);
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

    #[test]
    fn password_pty_error_uses_program_name_when_first_argument_is_a_flag() {
        assert_eq!(
            pty_action_name(
                &PathBuf::from("/sbin/mount_smbfs"),
                &["-s".into(), "//user@host/share".into()]
            ),
            "mount_smbfs"
        );
        assert_eq!(
            pty_action_name(
                &PathBuf::from("/usr/bin/security"),
                &["add-internet-password".into(), "-a".into()]
            ),
            "add-internet-password"
        );
    }
}
