use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use macluster_controller::smb_credential::CredentialHelperClient;
use macluster_protocol::{
    identifiers::{Id128, NodeId},
    smb_credential::{
        MAX_SMB_CREDENTIAL_BYTES, SecretString, SmbCredentialKey, SmbKeychainEndpoint,
        StoredSmbCredential,
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

    let mut state = NodeKeychainState::load(state_dir)
        .map_err(|error| NodeKeychainError::State(error.to_string()))?;
    state.entries.insert(
        entry_key(endpoint),
        NodeCredentialEntry {
            server: endpoint.server.clone(),
            account: endpoint.account.clone(),
            generation,
            cluster_uuid,
        },
    );
    state
        .save(state_dir)
        .map_err(|error| NodeKeychainError::State(error.to_string()))
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
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize::default())
        .map_err(|error| NodeKeychainError::Pty(error.to_string()))?;
    let mut command = CommandBuilder::new(&spec.program);
    command.args(&spec.args);
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
            } else if prompt.contains("password data for new item") || prompt.contains("password:")
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
        if started.elapsed() >= PTY_TIMEOUT {
            let _ = child.kill();
            return Err(NodeKeychainError::Timeout(PTY_TIMEOUT));
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(writer);
    let _ = reader_thread.join();
    if status.success() {
        Ok(())
    } else {
        Err(NodeKeychainError::SecurityFailed {
            action: spec.args.first().cloned().unwrap_or_default(),
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
enum NodeKeychainError {
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
        io::Cursor,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use macluster_protocol::{
        identifiers::Id128,
        smb_credential::{MAX_SMB_CREDENTIAL_BYTES, SmbKeychainEndpoint},
    };

    use super::{
        NodeKeychainCommandRunner, NodeKeychainError, NodeKeychainState, security_command,
        store_from_reader,
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
