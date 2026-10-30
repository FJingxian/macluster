use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Write},
    net::Ipv4Addr,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

use macluster_core::{
    config::{ClusterConfig, NodeConfig},
    maintenance::MaintenanceLock,
};
use macluster_protocol::{
    framing::sha256_hex,
    identifiers::{Id128, NodeId},
};
use serde::{Deserialize, Serialize};

use crate::arguments::tokenize_shell_words;
use crate::node_admin::{self, AgentStagePurpose};

pub(crate) mod reset;

type AppResult<T> = Result<T, (i32, String)>;

const LOGIN_NODE_ID: &str = "login-01";
const STORAGE_NODE_ID: &str = "storage-01";
const DEFAULT_NAME: &str = "macluster";
const DEFAULT_QUEUE: &str = "default";
const DEFAULT_SHARED_ROOT: &str = "/Users/Shared/macluster";
const LOCAL_INIT_JOURNAL_VERSION: u32 = 1;
const REMOTE_INIT_JOURNAL_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct InitOptions {
    help: bool,
    #[serde(skip)]
    help_long: bool,
    #[serde(skip)]
    force: bool,
    name: Option<String>,
    queue: Option<String>,
    shared_root: Option<PathBuf>,
    #[serde(default)]
    software_shares: Vec<SoftwareRoot>,
    primary_nfs: Option<RemoteNfs>,
    host: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SoftwareRoot {
    id: String,
    path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct RemoteNfs {
    user: String,
    host: Ipv4Addr,
    port: u16,
    source_root: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InitContext {
    login_host: Ipv4Addr,
    login_uuid: String,
    login_uid: u32,
    remote_binary: String,
    share_uuid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LocalInitJournal {
    version: u32,
    config_path: String,
    state_dir: String,
    config_source: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RemoteInitPhase {
    Prepared,
    AgentsStaged,
    NfsReady,
    ConfigCommitted,
    ConfigSynced,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RemoteInitJournal {
    version: u32,
    config_path: String,
    state_dir: String,
    binary_sha256: String,
    config_source: String,
    prepared_config_source: Option<String>,
    primary_nfs: RemoteNfs,
    phase: RemoteInitPhase,
}

pub fn run(config_path: PathBuf, state_dir: PathBuf, args: &[String]) -> AppResult<()> {
    let mut options = parse_options(args)?;
    if options.help {
        print_help(options.help_long);
        return Ok(());
    }
    let config_path = config_path.canonicalize().unwrap_or(config_path);
    preflight_config_destination(&config_path)?;
    let init_journal = local_init_journal_path(&config_path);
    let remote_journal = remote_init_journal_path(&config_path);
    preflight_local_init_journal(&init_journal)?;
    preflight_remote_init_journal(&remote_journal)?;
    let reset_journal_exists = reset::journal_path(&config_path).exists();
    validate_recovery_journal_conflicts(
        init_journal.exists(),
        remote_journal.exists(),
        reset_journal_exists,
    )?;
    if init_journal.exists() {
        resume_local_init(&config_path, &state_dir)?;
        setup_login_power_after_init(&config_path);
        return Ok(());
    }
    if remote_journal.exists() {
        resume_remote_init(&config_path, &state_dir)?;
        return Ok(());
    }
    if let Some(shared_root) = options.shared_root.as_deref() {
        validate_path_relationships(&config_path, &state_dir, shared_root)?;
    }
    let reset_completed = if config_path.exists() || reset::journal_path(&config_path).exists() {
        let Some(next_options) = reset::run(config_path.clone(), state_dir.clone(), options)?
        else {
            // A legacy reset journal may have already installed its saved target.
            return Ok(());
        };
        options = next_options;
        options.force = false;
        true
    } else if options.force {
        return Err((2, "--force requires an existing cluster or an interrupted reset; run `macluster init` for first-time setup".into()));
    } else {
        false
    };
    reset::ensure_no_reset_in_progress(&config_path, &state_dir)?;
    if state_dir_has_entries(&state_dir)? {
        if reset_completed {
            if let Some(archive) = archive_unbound_controller_state(&state_dir)? {
                println!(
                    "Preserved the pre-existing unbound controller state at {}.",
                    archive.display()
                );
            }
        } else {
            return Err((
                1,
                format!(
                    "controller state directory {} is not empty but no active config exists; restore its matching archived config before rerunning `macluster init`",
                    state_dir.display()
                ),
            ));
        }
    }

    let _maintenance = MaintenanceLock::exclusive_for_creation(&config_path)
        .map_err(|error| (1, format!("cannot lock cluster initialization: {error}")))?;
    if config_path.exists() {
        return Err((
            1,
            format!(
                "cluster config {} was created by another initializer; refusing to overwrite it",
                config_path.display()
            ),
        ));
    }
    preflight_config_destination(&config_path)?;

    options.name = Some(prompt_value(
        "Cluster name",
        options.name.as_deref(),
        DEFAULT_NAME,
    )?);
    options.queue = Some(prompt_value(
        "Default queue",
        options.queue.as_deref(),
        DEFAULT_QUEUE,
    )?);
    options.shared_root = Some(PathBuf::from(prompt_value(
        "Shared root",
        options.shared_root.as_deref().and_then(Path::to_str),
        DEFAULT_SHARED_ROOT,
    )?));
    let name = options.name.as_deref().expect("name was prompted");
    let queue = options.queue.as_deref().expect("queue was prompted");
    let shared_root = options
        .shared_root
        .as_deref()
        .expect("shared root was prompted");
    validate_name(name)?;
    validate_queue(queue)?;
    validate_absolute_path(shared_root, "shared root")?;
    validate_path_relationships(&config_path, &state_dir, shared_root)?;
    options.software_shares = prompt_software_shares(shared_root)?;
    for software_share in &options.software_shares {
        validate_path_relationships(&config_path, &state_dir, &software_share.path)?;
    }

    let remote_host = options.primary_nfs.as_ref().map(|primary| primary.host);
    let login_host = choose_login_host(options.host, remote_host)?;
    let local_uuid = node_admin::local_platform_uuid()?;
    let login_uid = unsafe { libc::geteuid() };
    if login_uid == 0 {
        return Err((
            1,
            "initialize the cluster as the normal login account, not root".into(),
        ));
    }
    let executable = env::current_exe()
        .map_err(|error| (1, error.to_string()))?
        .canonicalize()
        .map_err(|error| (1, error.to_string()))?;
    let remote_binary = executable
        .to_str()
        .ok_or_else(|| (1, "current macluster binary path is not UTF-8".into()))?
        .to_owned();
    if !safe_toml_path(&remote_binary) {
        return Err((
            1,
            "current macluster binary path contains characters that cannot be stored safely in TOML".into(),
        ));
    }
    let context = InitContext {
        login_host,
        login_uuid: local_uuid,
        login_uid,
        remote_binary,
        share_uuid: Id128::random().to_string(),
    };
    let config_source = render_config(&options, &context)?;
    let config = ClusterConfig::parse(&config_source).map_err(|error| (2, error.to_string()))?;

    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        println!(
            "\nNew cluster topology:\n  login: {LOGIN_NODE_ID} at {login_host}\n  primary NFS: {}\n  shared root: {}\n  default queue: {queue}",
            if let Some(primary) = options.primary_nfs.as_ref() {
                format!(
                    "{STORAGE_NODE_ID} at {}:{}",
                    primary.host,
                    primary.source_root.display()
                )
            } else {
                format!("local {LOGIN_NODE_ID}:{}", config.shared_root.display())
            },
            config.shared_root.display()
        );
        for (id, share) in &config.shares {
            println!(
                "  software share ({id}): {} -> {} (exported by the login node during node enrollment)",
                share.source_root.display(),
                share.mount_root.display()
            );
        }
        let response = prompt_value("Create this cluster? (Y/N)", None, "N")?;
        if !response.eq_ignore_ascii_case("y") && !response.eq_ignore_ascii_case("yes") {
            return Err((1, "cluster initialization cancelled".into()));
        }
    } else {
        return Err((
            2,
            "cluster initialization requires terminal confirmation; run `macluster init` from an interactive Terminal".into(),
        ));
    }

    if let Some(primary) = options.primary_nfs.as_ref() {
        let executable = env::current_exe().map_err(|error| (1, error.to_string()))?;
        let binary_sha256 = sha256_hex(
            &fs::read(&executable)
                .map_err(|error| (1, format!("cannot read current binary: {error}")))?,
        )
        .map_err(|error| (1, error.to_string()))?;
        let journal = RemoteInitJournal {
            version: REMOTE_INIT_JOURNAL_VERSION,
            config_path: absolute_path(&config_path)
                .map_err(|error| (1, format!("cannot resolve config path: {error}")))?
                .display()
                .to_string(),
            state_dir: absolute_path(&state_dir)
                .map_err(|error| (1, format!("cannot resolve controller state path: {error}")))?
                .display()
                .to_string(),
            binary_sha256,
            config_source,
            prepared_config_source: None,
            primary_nfs: primary.clone(),
            phase: RemoteInitPhase::Prepared,
        };
        write_remote_init_journal(&config_path, &journal, true)?;
        finish_remote_init(&config_path, &state_dir, journal)?;
        println!("Cluster '{}' initialized.", config.name);
        return Ok(());
    }

    let journal = LocalInitJournal {
        version: LOCAL_INIT_JOURNAL_VERSION,
        config_path: config_path.display().to_string(),
        state_dir: absolute_path(&state_dir)
            .map_err(|error| (1, format!("cannot resolve controller state path: {error}")))?
            .display()
            .to_string(),
        config_source: config_source.clone(),
    };
    write_local_init_journal(&config_path, &journal)?;
    finish_local_init(&config_path, &state_dir, &journal)?;
    setup_login_power_after_init(&config_path);
    println!("Cluster '{}' initialized.", config.name);
    Ok(())
}

fn setup_login_power_after_init(config_path: &Path) {
    if std::env::var_os("MACLUSTER_DISABLE_SERVICE_AUTOSTART").is_some() {
        return;
    }
    let result = fs::read_to_string(config_path)
        .map_err(|error| error.to_string())
        .and_then(|source| ClusterConfig::parse(&source).map_err(|error| error.to_string()))
        .and_then(|config| node_admin::ensure_local_power_sampler(&config));
    if let Err(error) = result {
        eprintln!(
            "Power sampler setup is incomplete: {error}. Open mtop in Terminal to retry authorization."
        );
    }
}

fn local_init_journal_path(config_path: &Path) -> PathBuf {
    let name = config_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    config_path.with_file_name(format!("{name}.macluster-init.json"))
}

fn remote_init_journal_path(config_path: &Path) -> PathBuf {
    let name = config_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    config_path.with_file_name(format!("{name}.macluster-remote-init.json"))
}

fn validate_recovery_journal_conflicts(
    local_init_exists: bool,
    remote_init_exists: bool,
    reset_exists: bool,
) -> AppResult<()> {
    if local_init_exists && remote_init_exists {
        return Err((
            1,
            "both local and remote initialization recovery records exist; keep the controller stopped and inspect both records".into(),
        ));
    }
    if reset_exists && (local_init_exists || remote_init_exists) {
        return Err((
            1,
            "initialization and reset recovery records both exist; keep the controller stopped and inspect both records".into(),
        ));
    }
    Ok(())
}

fn remote_init_requires_nfs_setup(phase: RemoteInitPhase) -> bool {
    matches!(
        phase,
        RemoteInitPhase::Prepared | RemoteInitPhase::AgentsStaged
    )
}

fn preflight_remote_init_journal(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err((
            1,
            format!(
                "remote initialization recovery record {} is not a regular file; inspect it before continuing",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err((
            1,
            format!("cannot inspect remote initialization recovery record: {error}"),
        )),
    }
}

fn write_remote_init_journal(
    config_path: &Path,
    journal: &RemoteInitJournal,
    create_only: bool,
) -> AppResult<()> {
    let path = remote_init_journal_path(config_path);
    let parent = path.parent().expect("remote init journal has a parent");
    fs::create_dir_all(parent).map_err(|error| (1, error.to_string()))?;
    preflight_remote_init_journal(&path)?;
    if create_only && path.exists() {
        return Err((
            1,
            format!(
                "remote initialization recovery record {} already exists; resume it with `macluster init`",
                path.display()
            ),
        ));
    }
    if !create_only && !path.exists() {
        return Err((
            1,
            format!(
                "remote initialization recovery record {} disappeared during setup; inspect the config and remote NFS state before continuing",
                path.display()
            ),
        ));
    }
    let bytes = serde_json::to_vec(journal).map_err(|error| (1, error.to_string()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Id128::random()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if create_only {
            fs::hard_link(&temp, &path)?;
            fs::remove_file(&temp)?;
        } else {
            fs::rename(&temp, &path)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|error| {
        (
            1,
            format!(
                "cannot save remote initialization recovery record {}: {error}",
                path.display()
            ),
        )
    })
}

fn resume_remote_init(config_path: &Path, state_dir: &Path) -> AppResult<()> {
    let journal_path = remote_init_journal_path(config_path);
    let bytes = fs::read(&journal_path).map_err(|error| {
        (
            1,
            format!("cannot read remote initialization recovery record: {error}"),
        )
    })?;
    let journal: RemoteInitJournal = serde_json::from_slice(&bytes).map_err(|error| {
        (
            1,
            format!(
                "remote initialization recovery record {} is invalid: {error}",
                journal_path.display()
            ),
        )
    })?;
    let _maintenance = MaintenanceLock::exclusive_for_creation(config_path).map_err(|error| {
        (
            1,
            format!("cannot lock remote initialization recovery: {error}"),
        )
    })?;
    let cluster_name = ClusterConfig::parse(&journal.config_source)
        .map_err(|error| {
            (
                1,
                format!("saved remote initialization config is invalid: {error}"),
            )
        })?
        .name;
    finish_remote_init(config_path, state_dir, journal)?;
    println!("Resumed interrupted remote initialization for cluster '{cluster_name}'.");
    Ok(())
}

fn finish_remote_init(
    config_path: &Path,
    state_dir: &Path,
    mut journal: RemoteInitJournal,
) -> AppResult<()> {
    if journal.version != REMOTE_INIT_JOURNAL_VERSION {
        return Err((
            1,
            format!(
                "unsupported remote initialization recovery version {}",
                journal.version
            ),
        ));
    }
    let expected_config = absolute_path(config_path)
        .map_err(|error| (1, format!("cannot resolve config path: {error}")))?;
    let expected_state = absolute_path(state_dir)
        .map_err(|error| (1, format!("cannot resolve controller state path: {error}")))?;
    if journal.config_path != expected_config.to_string_lossy()
        || journal.state_dir != expected_state.to_string_lossy()
    {
        return Err((
            1,
            "remote initialization recovery record belongs to a different config or state directory".into(),
        ));
    }
    let executable = env::current_exe().map_err(|error| (1, error.to_string()))?;
    let binary_digest = sha256_hex(
        &fs::read(&executable)
            .map_err(|error| (1, format!("cannot read current binary: {error}")))?,
    )
    .map_err(|error| (1, error.to_string()))?;
    if binary_digest != journal.binary_sha256 {
        return Err((
            1,
            "current macluster binary differs from the one recorded by interrupted initialization; rerun with the original binary so the saved cluster identity stays stable".into(),
        ));
    }

    let base_config = ClusterConfig::parse(&journal.config_source).map_err(|error| {
        (
            1,
            format!("saved remote initialization config is invalid: {error}"),
        )
    })?;
    validate_remote_init_topology(&base_config, &journal.primary_nfs)?;
    validate_path_relationships(&expected_config, &expected_state, &base_config.shared_root)?;

    let existing_config = remote_init_config_matches(&expected_config, &journal)?;
    if !existing_config {
        if let Some(archive) = archive_unbound_controller_state(&expected_state)? {
            println!(
                "Preserved the pre-existing unbound controller state at {}.",
                archive.display()
            );
        }
    }
    if journal.prepared_config_source.is_none() {
        if existing_config {
            return Err((
                1,
                "cluster config exists but the remote initialization journal has no prepared candidate; inspect both before continuing".into(),
            ));
        }
        let (prepared_source, _) = node_admin::stage_current_agents(
            &base_config,
            &journal.config_source,
            &base_config.share_uuid,
            AgentStagePurpose::Share,
        )
        .map_err(|(_, error)| (1, error))?;
        journal.prepared_config_source = Some(prepared_source);
        journal.phase = RemoteInitPhase::AgentsStaged;
        write_remote_init_journal(&expected_config, &journal, false)?;
    }
    let prepared_source = journal
        .prepared_config_source
        .as_deref()
        .expect("remote init candidate was prepared");
    let config = ClusterConfig::parse(prepared_source).map_err(|error| {
        (
            1,
            format!("prepared remote initialization config is invalid: {error}"),
        )
    })?;
    validate_remote_init_topology(&config, &journal.primary_nfs)?;
    let existing_config = remote_init_config_matches(&expected_config, &journal)?;

    if remote_init_requires_nfs_setup(journal.phase) {
        configure_remote_primary(&config, &journal.primary_nfs, &config.share_uuid)?;
        journal.phase = RemoteInitPhase::NfsReady;
        write_remote_init_journal(&expected_config, &journal, false)?;
    }

    if !existing_config {
        if let Some(archive) = archive_unbound_controller_state(&expected_state)? {
            println!(
                "Preserved the pre-existing unbound controller state at {}.",
                archive.display()
            );
        }
        atomic_create_config(&expected_config, prepared_source.as_bytes())?;
    }
    journal.phase = RemoteInitPhase::ConfigCommitted;
    write_remote_init_journal(&expected_config, &journal, false)?;
    MaintenanceLock::bind_state_dir(&expected_config, &expected_state).map_err(|error| {
        (
            1,
            format!("cluster config was written, but state binding failed: {error}"),
        )
    })?;
    fs::create_dir_all(&expected_state).map_err(|error| (1, error.to_string()))?;
    node_admin::sync_remote_configs(
        &config,
        prepared_source,
        &expected_state,
        &config.share_uuid,
        None,
    )
    .map_err(|error| {
        (
            1,
            format!(
                "cluster config is committed, but remote storage config sync failed: {error}. Rerun `macluster init` to resume; keep the controller stopped until it completes."
            ),
        )
    })?;
    journal.phase = RemoteInitPhase::ConfigSynced;
    write_remote_init_journal(&expected_config, &journal, false)?;
    remove_remote_init_journal(&expected_config)?;
    Ok(())
}

fn validate_remote_init_topology(config: &ClusterConfig, primary: &RemoteNfs) -> AppResult<()> {
    let login_id = config.login_node.as_ref().ok_or_else(|| {
        (
            1,
            "saved remote initialization config has no login node".into(),
        )
    })?;
    if login_id.as_str() == config.storage_server.as_str()
        || config.nodes[login_id.as_str()].transport != macluster_core::config::Transport::Local
        || config.nodes[config.storage_server.as_str()].transport
            != macluster_core::config::Transport::Ssh
    {
        return Err((
            1,
            "remote initialization recovery record does not describe a local login and remote NFS server".into(),
        ));
    }
    let storage = &config.nodes[config.storage_server.as_str()];
    let storage_host = storage.host.parse::<Ipv4Addr>().map_err(|_| {
        (
            1,
            "saved remote NFS host is not a valid IPv4 address".into(),
        )
    })?;
    if storage_host != primary.host
        || storage.ssh_user.as_deref() != Some(primary.user.as_str())
        || storage.ssh_port.unwrap_or(22) != primary.port
        || config.primary_source_root() != primary.source_root
    {
        return Err((
            1,
            "saved remote NFS endpoint does not match the prepared cluster config".into(),
        ));
    }
    Ok(())
}

fn remote_init_config_matches(path: &Path, journal: &RemoteInitJournal) -> AppResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let expected = journal.prepared_config_source.as_deref().ok_or_else(|| {
                (
                    1,
                    "cluster config exists before the remote initialization candidate was saved; inspect both before continuing".into(),
                )
            })?;
            let existing = fs::read(path).map_err(|error| (1, error.to_string()))?;
            if existing != expected.as_bytes() {
                return Err((
                    1,
                    "cluster config exists but does not match the saved remote initialization candidate; inspect both before continuing".into(),
                ));
            }
            Ok(true)
        }
        Ok(_) => Err((
            1,
            format!(
                "config destination {} is not a regular file",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err((1, format!("cannot inspect config destination: {error}"))),
    }
}

fn remove_remote_init_journal(config_path: &Path) -> AppResult<()> {
    let path = remote_init_journal_path(config_path);
    fs::remove_file(&path).map_err(|error| {
        (
            1,
            format!(
                "remote initialization completed, but recovery record {} could not be removed: {error}",
                path.display()
            ),
        )
    })?;
    File::open(path.parent().expect("remote init journal has a parent"))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            (
                1,
                format!("cannot flush remote initialization cleanup: {error}"),
            )
        })?;
    Ok(())
}

fn preflight_config_destination(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err((
            1,
            format!(
                "config destination {} must be a regular file, not a directory or symbolic link",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err((1, format!("cannot inspect config destination: {error}"))),
    }
}

fn preflight_local_init_journal(path: &Path) -> AppResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err((
            1,
            format!(
                "initialization recovery record {} is not a regular file; inspect it before continuing",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err((
            1,
            format!("cannot inspect initialization recovery record: {error}"),
        )),
    }
}

fn write_local_init_journal(config_path: &Path, journal: &LocalInitJournal) -> AppResult<()> {
    let path = local_init_journal_path(config_path);
    let parent = path.parent().expect("init journal has a parent");
    let bytes = serde_json::to_vec(journal).map_err(|error| (1, error.to_string()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Id128::random()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::hard_link(&temp, &path)?;
        fs::remove_file(&temp)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|error| {
        (
            1,
            format!(
                "cannot save initialization recovery record {}: {error}",
                path.display()
            ),
        )
    })
}

fn resume_local_init(config_path: &Path, state_dir: &Path) -> AppResult<()> {
    let journal_path = local_init_journal_path(config_path);
    let bytes = fs::read(&journal_path).map_err(|error| {
        (
            1,
            format!("cannot read initialization recovery record: {error}"),
        )
    })?;
    let journal: LocalInitJournal = serde_json::from_slice(&bytes).map_err(|error| {
        (
            1,
            format!(
                "initialization recovery record {} is invalid: {error}",
                journal_path.display()
            ),
        )
    })?;
    let _maintenance = MaintenanceLock::exclusive_for_creation(config_path)
        .map_err(|error| (1, format!("cannot lock initialization recovery: {error}")))?;
    finish_local_init(config_path, state_dir, &journal)?;
    println!("Resumed interrupted local initialization.");
    Ok(())
}

fn finish_local_init(
    config_path: &Path,
    state_dir: &Path,
    journal: &LocalInitJournal,
) -> AppResult<()> {
    if journal.version != LOCAL_INIT_JOURNAL_VERSION {
        return Err((
            1,
            format!(
                "unsupported local initialization recovery version {}",
                journal.version
            ),
        ));
    }
    let expected_config = absolute_path(config_path)
        .map_err(|error| (1, format!("cannot resolve config path: {error}")))?;
    let expected_state = absolute_path(state_dir)
        .map_err(|error| (1, format!("cannot resolve controller state path: {error}")))?;
    if journal.config_path != expected_config.to_string_lossy()
        || journal.state_dir != expected_state.to_string_lossy()
    {
        return Err((
            1,
            "initialization recovery record belongs to a different config or state directory"
                .into(),
        ));
    }
    let config = ClusterConfig::parse(&journal.config_source).map_err(|error| {
        (
            1,
            format!("saved initialization config is invalid: {error}"),
        )
    })?;
    let login = config
        .login_node
        .as_ref()
        .expect("validated config has login node");
    if login != &config.storage_server
        || config.nodes[login.as_str()].transport != macluster_core::config::Transport::Local
        || config.primary_source_root() != config.shared_root
    {
        return Err((
            1,
            "initialization recovery record does not describe local primary storage".into(),
        ));
    }
    validate_path_relationships(&expected_config, &expected_state, &config.shared_root)?;

    let existing_config = match fs::symlink_metadata(&expected_config) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            let existing = fs::read(&expected_config)
                .map_err(|error| (1, format!("cannot read existing config: {error}")))?;
            if existing != journal.config_source.as_bytes() {
                return Err((
                    1,
                    "config exists but does not match the saved initialization record; inspect both before continuing".into(),
                ));
            }
            true
        }
        Ok(_) => {
            return Err((
                1,
                format!(
                    "config destination {} is not a regular file",
                    expected_config.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err((1, format!("cannot inspect config destination: {error}"))),
    };
    if !existing_config {
        if let Some(archive) = archive_unbound_controller_state(&expected_state)? {
            println!(
                "Preserved the pre-existing unbound controller state at {}.",
                archive.display()
            );
        }
    }

    prepare_local_primary_inner(&config.shared_root, &config.share_uuid, true)?;
    if !existing_config {
        atomic_create_config(&expected_config, journal.config_source.as_bytes())?;
    }
    MaintenanceLock::bind_state_dir(&expected_config, &expected_state).map_err(|error| {
        (
            1,
            format!("cluster config was written, but state binding failed: {error}"),
        )
    })?;

    let journal_path = local_init_journal_path(&expected_config);
    fs::remove_file(&journal_path).map_err(|error| {
        (
            1,
            format!(
                "local initialization completed, but recovery record {} could not be removed: {error}",
                journal_path.display()
            ),
        )
    })?;
    File::open(journal_path.parent().expect("init journal has a parent"))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| (1, format!("cannot flush initialization cleanup: {error}")))?;
    Ok(())
}

fn parse_options(args: &[String]) -> AppResult<InitOptions> {
    let mut options = InitOptions::default();
    let mut index = 0;
    while index < args.len() {
        let (key, inline) = args[index]
            .split_once('=')
            .map_or((args[index].as_str(), None), |(key, value)| {
                (key, Some(value))
            });
        match key {
            "-h" => options.help = true,
            "--help" => {
                options.help = true;
                options.help_long = true;
            }
            "--force" if inline.is_none() => options.force = true,
            "--name" | "--queue" | "--shared-root" | "--primary-nfs" | "--host" => {
                let value = if let Some(value) = inline {
                    value.to_owned()
                } else {
                    index += 1;
                    args.get(index)
                        .ok_or_else(|| (2, format!("missing value for {key}")))?
                        .clone()
                };
                if value.is_empty() {
                    return Err((2, format!("{key} cannot be empty")));
                }
                match key {
                    "--name" => {
                        validate_name(&value)?;
                        options.name = Some(value);
                    }
                    "--queue" => {
                        validate_queue(&value)?;
                        options.queue = Some(value);
                    }
                    "--shared-root" => {
                        validate_absolute_path(Path::new(&value), "shared root")?;
                        options.shared_root = Some(PathBuf::from(value));
                    }
                    "--primary-nfs" => options.primary_nfs = Some(parse_remote_nfs(&value)?),
                    "--host" => {
                        let host = value
                            .parse::<Ipv4Addr>()
                            .map_err(|_| (2, "--host must be an IPv4 address".into()))?;
                        if !valid_unicast(host) {
                            return Err((2, "--host must be a usable unicast IPv4 address".into()));
                        }
                        options.host = Some(host);
                    }
                    _ => unreachable!(),
                }
            }
            _ => return Err((2, format!("unknown init option '{key}'"))),
        }
        index += 1;
    }
    if options.help {
        return Ok(options);
    }
    Ok(options)
}

fn parse_remote_nfs(value: &str) -> AppResult<RemoteNfs> {
    let (user, address) = value.split_once('@').ok_or_else(|| {
        (
            2,
            "--primary-nfs must be USER@IPv4[:PORT]:SOURCE_PATH".into(),
        )
    })?;
    if user.is_empty()
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err((
            2,
            "--primary-nfs SSH user contains unsupported characters".into(),
        ));
    }
    let mut parts = address.splitn(3, ':');
    let host = parts
        .next()
        .unwrap_or_default()
        .parse::<Ipv4Addr>()
        .map_err(|_| (2, "--primary-nfs host must be an IPv4 address".into()))?;
    if !valid_unicast(host) {
        return Err((
            2,
            "--primary-nfs host must be a usable unicast IPv4 address".into(),
        ));
    }
    let second = parts.next().unwrap_or_default();
    let third = parts.next();
    let (port, source) = if second.bytes().all(|byte| byte.is_ascii_digit()) && !second.is_empty() {
        let port = second
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| (2, "--primary-nfs SSH port must be in 1..=65535".into()))?;
        (port, third)
    } else if third.is_none() {
        (22, Some(second))
    } else {
        return Err((2, "--primary-nfs port must come before SOURCE_PATH".into()));
    };
    let source = source.ok_or_else(|| {
        (
            2,
            "--primary-nfs requires a source path: USER@IPv4[:PORT]:SOURCE_PATH".into(),
        )
    })?;
    let source_root = PathBuf::from(source);
    validate_absolute_path(&source_root, "primary NFS source")?;
    Ok(RemoteNfs {
        user: user.to_owned(),
        host,
        port,
        source_root,
    })
}

fn render_config(options: &InitOptions, context: &InitContext) -> AppResult<String> {
    let name = options.name.as_deref().unwrap_or(DEFAULT_NAME);
    let queue = options.queue.as_deref().unwrap_or(DEFAULT_QUEUE);
    let shared_root = options
        .shared_root
        .as_deref()
        .unwrap_or_else(|| Path::new(DEFAULT_SHARED_ROOT));
    validate_name(name)?;
    validate_queue(queue)?;
    validate_absolute_path(shared_root, "shared root")?;

    let remote = options.primary_nfs.as_ref();
    let storage_id = if remote.is_some() {
        STORAGE_NODE_ID
    } else {
        LOGIN_NODE_ID
    };
    let mut source = format!(
        "[cluster]\nname = {}\ndefault_queue = {}\nlogin_node = {}\nshared_root = {}\nshare_uuid = {}\nstorage_server = {}\nprotocol_version = 1\n",
        toml_string(name),
        toml_string(queue),
        toml_string(LOGIN_NODE_ID),
        toml_string(&shared_root.to_string_lossy()),
        toml_string(&context.share_uuid),
        toml_string(storage_id),
    );
    if let Some(remote) = remote {
        if remote.source_root != shared_root {
            source.push_str(&format!(
                "storage_source_root = {}\n",
                toml_string(&remote.source_root.to_string_lossy())
            ));
        }
    }
    let mut software_paths = Vec::new();
    for software_share in &options.software_shares {
        let id = NodeId::new(software_share.id.clone()).map_err(|_| {
            (
                2,
                format!("invalid software share ID '{} '", software_share.id),
            )
        })?;
        let software_root = &software_share.path;
        validate_absolute_path(software_root, "software root")?;
        if software_root.starts_with(shared_root) {
            // The primary export already exposes this path to every node.
            continue;
        }
        if shared_root.starts_with(software_root) {
            return Err((
                2,
                format!(
                    "software root {} overlaps the primary shared root {}; choose a path outside the primary root or skip software sharing",
                    software_root.display(),
                    shared_root.display()
                ),
            ));
        }
        if software_paths.iter().any(|existing: &PathBuf| {
            existing.starts_with(software_root) || software_root.starts_with(existing)
        }) {
            return Err((
                2,
                format!(
                    "software root {} overlaps another selected software share; select only the parent root",
                    software_root.display()
                ),
            ));
        }
        software_paths.push(software_root.clone());
        source.push_str(&format!(
            "\n[shares.{}]\nserver = {}\nsource_root = {}\nmount_root = {}\nshare_uuid = {}\n",
            id,
            toml_string(LOGIN_NODE_ID),
            toml_string(&software_root.to_string_lossy()),
            toml_string(&software_root.to_string_lossy()),
            toml_string(&Id128::random().to_string()),
        ));
    }
    source.push_str(&format!(
        "\n[queues.{queue}]\nnodes = []\nscheduler = \"fifo\"\n\n[nodes.{LOGIN_NODE_ID}]\nhost = {}\ntransport = \"local\"\nremote_binary = {}\nmachine_uuid = {}\nexecution_uid = {}\n",
        toml_string(&context.login_host.to_string()),
        toml_string(&context.remote_binary),
        toml_string(&context.login_uuid),
        context.login_uid,
    ));
    if let Some(remote) = remote {
        source.push_str(&format!(
            "\n[nodes.{STORAGE_NODE_ID}]\nhost = {}\ntransport = \"ssh\"\nremote_binary = \"/usr/local/bin/macluster\"\nssh_user = {}\nssh_port = {}\n",
            toml_string(&remote.host.to_string()),
            toml_string(&remote.user),
            remote.port,
        ));
    }
    ClusterConfig::parse(&source).map_err(|error| (2, error.to_string()))?;
    Ok(source)
}

fn prompt_software_shares(shared_root: &Path) -> AppResult<Vec<SoftwareRoot>> {
    let mut candidates = detect_software_roots();
    candidates.sort_by_key(|(_, _, path)| path.components().count());
    let mut unique = Vec::<(String, String, PathBuf)>::new();
    for candidate in candidates {
        if unique
            .iter()
            .any(|(_, _, root)| candidate.2.starts_with(root))
        {
            continue;
        }
        unique.push(candidate);
    }

    let had_candidates = !unique.is_empty();
    let mut selected = Vec::<SoftwareRoot>::new();
    for (id, label, path) in unique {
        if path.starts_with(shared_root) {
            eprintln!(
                "{label} {} is already covered by the primary shared root.",
                path.display()
            );
            continue;
        }
        if shared_root.starts_with(&path) {
            eprintln!(
                "{label} {} overlaps the primary shared root {}; skipping this separate share.",
                path.display(),
                shared_root.display()
            );
            continue;
        }
        eprintln!("Detected {label}: {}", path.display());
        let response = prompt_value(
            &format!("Register this {label} as a named NFS share? (Y/N)"),
            None,
            "N",
        )?;
        if response.eq_ignore_ascii_case("y") || response.eq_ignore_ascii_case("yes") {
            selected.push(SoftwareRoot { id, path });
        }
    }

    loop {
        let prompt = if had_candidates {
            "Add another software/toolchain root? (Y/N)"
        } else {
            "Register a software/toolchain root? (Y/N)"
        };
        let response = prompt_value(prompt, None, "N")?;
        if !response.eq_ignore_ascii_case("y") && !response.eq_ignore_ascii_case("yes") {
            break;
        }

        let default_id = if selected.is_empty() {
            "software".to_owned()
        } else {
            format!("toolchain-{}", selected.len())
        };
        let id = prompt_value("Share ID", None, &default_id)?;
        NodeId::new(id.clone()).map_err(|_| {
            (
                2,
                format!("invalid software share ID '{id}'; use letters, digits, '_' or '-'"),
            )
        })?;
        if selected.iter().any(|share| share.id == id) {
            return Err((
                2,
                format!("software share ID '{id}' is selected more than once"),
            ));
        }
        let value = prompt_value("Software/toolchain root (absolute path)", None, "")?;
        if value.trim().is_empty() {
            break;
        }
        let path = validate_software_root(Path::new(value.trim()))?;
        if path.starts_with(shared_root) {
            eprintln!(
                "Software path {} is already covered by the primary shared root.",
                path.display()
            );
            continue;
        }
        if shared_root.starts_with(&path) {
            return Err((
                2,
                format!(
                    "software root {} overlaps the primary shared root {}; choose a path outside the primary root",
                    path.display(),
                    shared_root.display()
                ),
            ));
        }
        if selected
            .iter()
            .any(|existing| existing.path.starts_with(&path) || path.starts_with(&existing.path))
        {
            return Err((
                2,
                format!(
                    "software root {} overlaps another selected software share; select only the parent root",
                    path.display()
                ),
            ));
        }
        selected.push(SoftwareRoot { id, path });
    }
    Ok(selected)
}

fn detect_software_roots() -> Vec<(String, String, PathBuf)> {
    let mut roots = Vec::new();
    for (key, id, label) in [
        ("MAMBA_ROOT_PREFIX", "mamba", "Mamba root"),
        ("HOMEBREW_PREFIX", "homebrew", "Homebrew root"),
        ("CONDA_PREFIX", "conda", "active Conda environment"),
        ("VIRTUAL_ENV", "venv", "active virtualenv"),
        ("CARGO_HOME", "cargo", "Cargo home"),
        ("RUSTUP_HOME", "rustup", "Rustup toolchain home"),
        ("JAVA_HOME", "java", "Java toolchain"),
        ("VCPKG_ROOT", "vcpkg", "vcpkg toolchain"),
        ("OPENSSL_DIR", "openssl", "OpenSSL toolchain"),
        ("CUDA_HOME", "cuda", "CUDA toolchain"),
        ("LLVM_ROOT", "llvm", "LLVM toolchain"),
    ] {
        append_software_candidate_from_env(&mut roots, key, id, label);
    }

    // Toolchain roots often use project-specific environment variable names.
    // Offer values whose names clearly identify an install prefix, while
    // excluding node-local/cache variables such as HOME and XDG_*_HOME.
    for (key, value) in env::vars_os() {
        let Some(key) = key.to_str() else { continue };
        if key.starts_with("MCLUSTER_")
            || key == "HOME"
            || key.starts_with("XDG_")
            || !(key.ends_with("_ROOT") || key.ends_with("_PREFIX") || key.ends_with("_TOOLCHAIN"))
        {
            continue;
        }
        let Some(value) = value.to_str() else {
            continue;
        };
        let id = normalized_share_id(key);
        append_software_candidate_from_env_value(
            &mut roots,
            key,
            &id,
            &format!("{} root", key.replace('_', " ").to_ascii_lowercase()),
            value,
        );
    }

    if let Some(prefixes) = env::var_os("CMAKE_PREFIX_PATH") {
        for (index, prefix) in prefixes.to_string_lossy().split(':').enumerate() {
            if prefix.is_empty() {
                continue;
            }
            append_software_candidate_from_env_value(
                &mut roots,
                "CMAKE_PREFIX_PATH",
                &format!("cmake-{}", index + 1),
                &format!("CMake prefix {}", index + 1),
                prefix,
            );
        }
    }

    for key in ["CC", "CXX", "FC", "CMAKE_C_COMPILER", "CMAKE_CXX_COMPILER"] {
        if let Some(value) = env::var_os(key).filter(|value| !value.is_empty()) {
            if let Some(path) = compiler_toolchain_root(&PathBuf::from(value)) {
                let id = format!("{}-toolchain", key.to_ascii_lowercase().replace('_', "-"));
                roots.push((id, format!("{key} toolchain"), path));
            }
        }
    }

    if !roots.iter().any(|(id, _, _)| id == "homebrew")
        && let Ok(output) = Command::new("brew").arg("--prefix").output()
        && output.status.success()
        && let Ok(value) = String::from_utf8(output.stdout)
    {
        match validate_software_root(Path::new(value.trim())) {
            Ok(path) => roots.push(("homebrew".into(), "Homebrew root".into(), path)),
            Err((_, error)) => eprintln!("Ignoring unusable `brew --prefix`: {error}"),
        }
    }
    roots
}

fn append_software_candidate_from_env(
    roots: &mut Vec<(String, String, PathBuf)>,
    key: &str,
    id: &str,
    label: &str,
) {
    if let Some(value) = env::var_os(key).filter(|value| !value.is_empty()) {
        append_software_candidate_from_env_value(
            roots,
            key,
            id,
            label,
            &PathBuf::from(value).to_string_lossy(),
        );
    }
}

fn append_software_candidate_from_env_value(
    roots: &mut Vec<(String, String, PathBuf)>,
    key: &str,
    id: &str,
    label: &str,
    value: &str,
) {
    if !Path::new(value.trim()).is_absolute() {
        return;
    }
    match validate_software_root(Path::new(value.trim())) {
        Ok(path) => roots.push((id.to_owned(), label.to_owned(), path)),
        Err((_, error)) => eprintln!("Ignoring unusable {key}: {error}"),
    }
}

fn normalized_share_id(value: &str) -> String {
    let mut id = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(48)
        .collect::<String>();
    while id.starts_with('-') {
        id.remove(0);
    }
    while id.ends_with('-') {
        id.pop();
    }
    if id.is_empty() || !id.as_bytes()[0].is_ascii_alphanumeric() {
        "toolchain".into()
    } else {
        id
    }
}

fn compiler_toolchain_root(command: &Path) -> Option<PathBuf> {
    let command_text = command.to_str()?;
    let words = tokenize_shell_words(command_text).ok()?;
    let executable = words.iter().find(|word| !word.starts_with('-'))?;
    let command_path = Path::new(executable);
    let resolved = if command_path.is_absolute() {
        command_path.to_path_buf()
    } else if executable.contains('/') {
        env::current_dir().ok()?.join(command_path)
    } else {
        env::split_paths(&env::var_os("PATH")?)
            .map(|directory| directory.join(command_path))
            .find(|path| path.is_file())?
    };
    let resolved = resolved.canonicalize().ok()?;
    if !resolved.is_file() || is_portable_system_toolchain_path(&resolved) {
        return None;
    }
    let bin = resolved.parent()?;
    if bin.file_name().is_none_or(|name| name != "bin") {
        return None;
    }
    let root = bin.parent()?;
    validate_software_root(root).ok()
}

fn is_portable_system_toolchain_path(path: &Path) -> bool {
    [
        "/usr/bin",
        "/usr/sbin",
        "/usr/include",
        "/usr/lib",
        "/usr/libexec",
        "/bin",
        "/sbin",
        "/System",
        "/Library/Developer/CommandLineTools",
        "/Applications/Xcode.app/Contents/Developer",
    ]
    .iter()
    .any(|root| path.starts_with(root))
}

fn validate_software_root(path: &Path) -> AppResult<PathBuf> {
    validate_absolute_path(path, "software root")?;
    if path == Path::new("/") {
        return Err((
            2,
            "the filesystem root cannot be registered as a software share".into(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        (
            2,
            format!("software root {} is unavailable: {error}", path.display()),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err((
            2,
            format!(
                "software root {} must be a real directory, not a symbolic link",
                path.display()
            ),
        ));
    }
    let canonical = path.canonicalize().map_err(|error| {
        (
            2,
            format!("cannot resolve software root {}: {error}", path.display()),
        )
    })?;
    validate_absolute_path(&canonical, "software root")?;
    Ok(canonical)
}

pub(crate) fn prepare_local_primary_for_reset(root: &Path, share_uuid: &str) -> AppResult<()> {
    prepare_local_primary_inner(root, share_uuid, true)
}

fn prepare_local_primary_inner(
    root: &Path,
    share_uuid: &str,
    reuse_matching_marker: bool,
) -> AppResult<()> {
    create_real_directory_path(root)?;
    let marker = root.join(".macluster-share-id");
    let marker_exists = match fs::symlink_metadata(&marker) {
        Ok(metadata)
            if reuse_matching_marker
                && metadata.is_file()
                && !metadata.file_type().is_symlink() =>
        {
            let contents = fs::read_to_string(&marker).map_err(|error| (1, error.to_string()))?;
            if contents.trim() != share_uuid {
                return Err((
                    1,
                    format!(
                        "primary storage marker {} belongs to a different share",
                        marker.display()
                    ),
                ));
            }
            true
        }
        Ok(_) => {
            return Err((
                1,
                format!(
                    "primary storage marker {} already exists; run `macluster init` with its matching cluster config to verify and reset the managed share",
                    marker.display()
                ),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err((1, error.to_string())),
    };
    if !marker_exists {
        let temporary = root.join(format!(
            ".macluster-share-id.{}.{}.tmp",
            share_uuid,
            Id128::random()
        ));
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            writeln!(file, "{share_uuid}")?;
            file.sync_all()?;
            fs::hard_link(&temporary, &marker)?;
            fs::remove_file(&temporary)?;
            File::open(root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|error| (1, format!("cannot create primary share marker: {error}")))?;
    }
    if !macluster_controller::verify_primary_share_direct(root, root, share_uuid, "127.0.0.1", true)
    {
        return Err((
            1,
            format!(
                "local shared root {} failed its filesystem and marker check",
                root.display()
            ),
        ));
    }
    Ok(())
}

fn configure_remote_primary(
    config: &ClusterConfig,
    primary: &RemoteNfs,
    operation_id: &str,
) -> AppResult<()> {
    let original_storage = config
        .nodes
        .get(STORAGE_NODE_ID)
        .expect("remote storage node is in prepared config")
        .clone();
    let facts = node_admin::read_remote_facts(&original_storage).map_err(|(_, error)| {
        (
            1,
            format!("SSH preflight failed for {}: {error}", primary.host),
        )
    })?;
    if facts.os != "Darwin" {
        return Err((2, format!("primary NFS host {} is not macOS", primary.host)));
    }
    if facts.uid != unsafe { libc::geteuid() } || facts.gid != unsafe { libc::getegid() } {
        return Err((
            2,
            format!(
                "login account UID/GID is {}/{}, but storage SSH account UID/GID is {}/{}; NFS files would not have consistent ownership",
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                facts.uid,
                facts.gid
            ),
        ));
    }
    let login_node = config.nodes.get(LOGIN_NODE_ID).expect("login node exists");
    let login_host = login_node.host.clone();
    let source_root = config.primary_source_root().to_path_buf();
    node_admin::preflight_primary_mount(
        login_node,
        &original_storage,
        &source_root,
        &config.shared_root,
        &config.share_uuid,
    )
    .map_err(|error| (1, error))?;
    let storage = &original_storage;
    node_admin::prepare_share_source(storage, &source_root, &config.share_uuid)
        .map_err(|(_, error)| (1, error))?;
    node_admin::verify_storage_root(
        storage,
        &source_root,
        &config.share_uuid,
        facts.uid,
        facts.gid,
    )?;
    let storage_power_setup =
        match node_admin::prepare_power_helper(storage, facts.uid, &facts.arch, operation_id) {
            Ok(setup) => setup,
            Err(error) => {
                eprintln!("Power sampler setup for {STORAGE_NODE_ID} was skipped: {error}");
                None
            }
        };
    let export_request = node_admin::NfsExportRequest {
        root: source_root.to_string_lossy().into_owned(),
        client_ip: login_host,
        share_uuid: config.share_uuid.clone(),
        node_id: LOGIN_NODE_ID.into(),
    };
    let (managed, export_result) = node_admin::ensure_nfs_exports_with_setup(
        storage,
        &[export_request],
        operation_id,
        storage_power_setup
            .as_ref()
            .map(|setup| setup.script.as_str()),
    );
    if let Some(setup) = &storage_power_setup {
        node_admin::cleanup_power_helper_stage(storage, setup);
    }
    export_result.map_err(|error| (1, error))?;
    let login_uid = unsafe { libc::geteuid() };
    let login_power_setup = match node_admin::prepare_power_helper(
        login_node,
        login_uid,
        std::env::consts::ARCH,
        operation_id,
    ) {
        Ok(setup) => setup,
        Err(error) => {
            eprintln!("Power sampler setup for {LOGIN_NODE_ID} was skipped: {error}");
            None
        }
    };
    node_admin::mount_candidate_with_power(
        login_node,
        storage,
        &source_root,
        &config.shared_root,
        &config.share_uuid,
        login_power_setup,
    )
    .map_err(|error| (1, error))?;
    if !macluster_controller::verify_primary_share_direct(
        &config.shared_root,
        &source_root,
        &config.share_uuid,
        &primary.host.to_string(),
        false,
    ) {
        return Err((
            1,
            "login Mac could not verify the configured primary NFS mount".into(),
        ));
    }
    verify_nfs_roundtrip(storage, &source_root, &config.shared_root, operation_id)?;
    if managed.iter().any(|managed| *managed) {
        eprintln!(
            "Created the managed primary NFS export on {}.",
            primary.host
        );
    }
    Ok(())
}

pub(super) fn prepare_remote_primary_for_reset(
    config_source: &mut String,
    config: &mut ClusterConfig,
    primary: &RemoteNfs,
    operation_id: &str,
) -> AppResult<()> {
    let (staged_source, staged_config) = node_admin::stage_current_agents(
        config,
        config_source,
        operation_id,
        AgentStagePurpose::Share,
    )
    .map_err(|(_, error)| (1, error))?;
    *config_source = staged_source;
    *config = staged_config;
    configure_remote_primary(config, primary, operation_id)
}

fn verify_nfs_roundtrip(
    storage: &NodeConfig,
    source_root: &Path,
    mount_root: &Path,
    operation_id: &str,
) -> AppResult<()> {
    let name = format!(".macluster-init-probe-{operation_id}");
    let local = mount_root.join(&name);
    let remote = source_root.join(&name);
    let payload = format!("macluster-init:{operation_id}\n");
    let result = (|| {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&local)
        {
            Ok(mut file) => {
                file.write_all(payload.as_bytes())
                    .and_then(|()| file.sync_all())
                    .map_err(|error| {
                        (1, format!("cannot flush NFS verification probe: {error}"))
                    })?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if fs::read(&local).map_err(|error| (1, error.to_string()))? != payload.as_bytes() {
                    return Err((
                        1,
                        "NFS verification probe path contains unexpected data".into(),
                    ));
                }
            }
            Err(error) => return Err((1, format!("cannot write NFS verification probe: {error}"))),
        }
        let command = format!(
            "/bin/cat {}",
            node_admin::shell_quote(&remote.to_string_lossy())
        );
        let output = node_admin::ssh_output(storage, &command, None)?;
        if !output.status.success() || output.stdout != payload.as_bytes() {
            return Err((
                1,
                "NFS source did not observe the login node's verification write".into(),
            ));
        }
        Ok(())
    })();
    let _ = fs::remove_file(local);
    result
}

fn choose_login_host(
    explicit: Option<Ipv4Addr>,
    remote_host: Option<Ipv4Addr>,
) -> AppResult<Ipv4Addr> {
    let addresses = node_admin::local_ipv4_addresses()?;
    if let Some(host) = explicit {
        if addresses.contains(&host) {
            return Ok(host);
        }
        return Err((
            2,
            format!("--host {host} is not assigned to an active local interface"),
        ));
    }
    if let Some(remote_host) = remote_host
        && let Some(address) = route_local_ipv4(remote_host, &addresses)
    {
        return Ok(address);
    }
    match addresses.as_slice() {
        [address] => Ok(*address),
        [] => Err((
            1,
            "no active non-loopback IPv4 address was found; pass --host IPv4".into(),
        )),
        _ if io::stdin().is_terminal() && io::stdout().is_terminal() => {
            eprintln!("Select the IPv4 address used by cluster nodes:");
            for (index, address) in addresses.iter().enumerate() {
                eprintln!("  {}. {address}", index + 1);
            }
            let choice = prompt_value("Interface number", None, "1")?;
            let index = choice
                .parse::<usize>()
                .ok()
                .filter(|index| (1..=addresses.len()).contains(index))
                .ok_or_else(|| (2, "interface choice is out of range".into()))?;
            Ok(addresses[index - 1])
        }
        _ => Err((
            2,
            format!(
                "multiple local IPv4 addresses are active ({}); pass --host IPv4 to select the cluster interface",
                addresses
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

fn route_local_ipv4(remote: Ipv4Addr, addresses: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", &remote.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let route_text = String::from_utf8_lossy(&output.stdout);
    let interface = route_text
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))?;
    let output = Command::new("/sbin/ifconfig")
        .arg(interface)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("inet "))
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|value| value.parse::<Ipv4Addr>().ok())
        .find(|address| addresses.contains(address))
}

fn prompt_value(label: &str, supplied: Option<&str>, default: &str) -> AppResult<String> {
    if let Some(value) = supplied {
        return Ok(value.to_owned());
    }
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(default.to_owned());
    }
    if default.is_empty() {
        eprint!("{label}: ");
    } else {
        eprint!("{label} [{default}]: ");
    }
    io::stderr()
        .flush()
        .map_err(|error| (1, error.to_string()))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| (1, error.to_string()))?;
    let value = input.trim();
    if value.is_empty() {
        Ok(default.to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn print_help(full: bool) {
    println!("{}", init_help(full));
}

fn init_help(full: bool) -> &'static str {
    if !full {
        return "Usage: macluster init [--name NAME] [--queue QUEUE] [--shared-root PATH] [--host IPv4] [--primary-nfs USER@IPv4[:PORT]:SOURCE_PATH]\n\nFirst run sets this Mac as login/storage and creates an empty compute queue. Add compute Macs with `mnode -a USER@IPv4[:PORT]`. An existing config starts the reset confirmation flow. Use --help for share setup and reset details.";
    }

    "Usage: macluster init [--force] [--name NAME] [--queue QUEUE] [--shared-root PATH] [--host IPv4] [--primary-nfs USER@IPv4[:PORT]:SOURCE_PATH]\n\nFirst setup\n  The login Mac is the control and default storage node; the compute queue starts empty. Init offers detected Mamba/Conda, virtualenv, and Homebrew roots as named NFS software shares, then lets you add custom software or compiler toolchain roots. Each share mounts at its original absolute path on every node. Add compute Macs with `mnode -a USER@IPv4[:PORT]`.\n\nStorage\n  --primary-nfs selects a remote macOS NFS source. That storage node stays outside compute queues.\n\nReset\n  With an existing cluster, init asks whether to reset (Y/N, default N), removes verified managed NFS resources, archives old state, then continues with new cluster setup. Shared data files are preserved. --force abandons pending snapshot/log synchronization for terminal jobs, so unsynchronized output may be unavailable. Active jobs still block reset. --force requires an existing cluster or interrupted reset. Rerun `macluster init` to resume cleanup after it has started."
}

fn validate_name(name: &str) -> AppResult<()> {
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err((
            2,
            "cluster name must contain 1 to 128 printable characters".into(),
        ));
    }
    Ok(())
}

fn validate_queue(queue: &str) -> AppResult<()> {
    macluster_protocol::identifiers::QueueName::new(queue.to_owned())
        .map(|_| ())
        .map_err(|_| (2, "queue name must use letters, digits, '_' or '-'".into()))
}

fn validate_absolute_path(path: &Path, label: &str) -> AppResult<()> {
    let text = path
        .to_str()
        .ok_or_else(|| (2, format!("{label} path must be UTF-8")))?;
    let valid = text.starts_with('/')
        && text != "/"
        && !text.ends_with('/')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir));
    if valid {
        Ok(())
    } else {
        Err((
            2,
            format!("{label} must be a normalized absolute path without spaces or '..'"),
        ))
    }
}

fn validate_path_relationships(config: &Path, state: &Path, shared_root: &Path) -> AppResult<()> {
    let config = absolute_path(config).map_err(|error| (2, error.to_string()))?;
    let state = absolute_path(state).map_err(|error| (2, error.to_string()))?;
    if state.starts_with(shared_root) || shared_root.starts_with(&state) {
        return Err((
            2,
            "controller state directory and shared root must not overlap".into(),
        ));
    }
    if config.starts_with(shared_root) {
        return Err((
            2,
            "cluster config must be stored outside the shared root".into(),
        ));
    }
    Ok(())
}

fn safe_toml_path(value: &str) -> bool {
    value.starts_with('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && !Path::new(value)
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn valid_unicast(address: Ipv4Addr) -> bool {
    !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
        && address != Ipv4Addr::BROADCAST
}

fn toml_string(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            character => result.push(character),
        }
    }
    result.push('"');
    result
}

fn state_dir_has_entries(path: &Path) -> AppResult<bool> {
    match fs::read_dir(path) {
        Ok(mut entries) => Ok(entries
            .next()
            .transpose()
            .map_err(|error| (1, error.to_string()))?
            .is_some()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err((1, error.to_string())),
    }
}

/// A confirmed local init may race with a stale client recreating the old
/// controller directory after reset archived it. Keep that directory intact,
/// but move it out of the way before binding this new cluster to a fresh state
/// directory. This only runs while resuming/finishing a saved init journal, so
/// the user has already confirmed creation of the new cluster.
fn archive_unbound_controller_state(state_dir: &Path) -> AppResult<Option<PathBuf>> {
    if !state_dir_has_entries(state_dir)? {
        return Ok(None);
    }

    let metadata = fs::symlink_metadata(state_dir).map_err(|error| {
        (
            1,
            format!(
                "cannot inspect pre-existing controller state {}: {error}",
                state_dir.display()
            ),
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err((
            1,
            format!(
                "pre-existing controller state path {} is not a real directory; inspect it before continuing",
                state_dir.display()
            ),
        ));
    }

    let parent = state_dir.parent().ok_or_else(|| {
        (
            1,
            format!(
                "controller state directory {} has no parent for safe archival",
                state_dir.display()
            ),
        )
    })?;
    let archive_root = parent.join("macluster-archive");
    fs::create_dir_all(&archive_root).map_err(|error| {
        (
            1,
            format!(
                "cannot create controller state archive {}: {error}",
                archive_root.display()
            ),
        )
    })?;
    let archive_metadata = fs::symlink_metadata(&archive_root).map_err(|error| {
        (
            1,
            format!(
                "cannot inspect controller state archive {}: {error}",
                archive_root.display()
            ),
        )
    })?;
    if !archive_metadata.is_dir() || archive_metadata.file_type().is_symlink() {
        return Err((
            1,
            format!(
                "controller state archive path {} is not a real directory",
                archive_root.display()
            ),
        ));
    }

    let recovery_dir = archive_root.join(format!("local-init-recovery-{}", Id128::random()));
    fs::create_dir(&recovery_dir).map_err(|error| {
        (
            1,
            format!(
                "cannot reserve controller state recovery archive {}: {error}",
                recovery_dir.display()
            ),
        )
    })?;
    let archived_state = recovery_dir.join("controller");
    if let Err(error) = fs::rename(state_dir, &archived_state) {
        let _ = fs::remove_dir(&recovery_dir);
        return Err((
            1,
            format!(
                "cannot preserve pre-existing controller state {} at {}: {error}",
                state_dir.display(),
                archived_state.display()
            ),
        ));
    }

    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .and_then(|()| File::open(&archive_root)?.sync_all())
        .and_then(|()| File::open(&recovery_dir)?.sync_all())
        .map_err(|error| {
            (
                1,
                format!(
                    "controller state was preserved at {}, but the archive could not be flushed: {error}",
                    archived_state.display()
                ),
            )
        })?;

    Ok(Some(archived_state))
}

fn create_real_directory_path(path: &Path) -> AppResult<()> {
    validate_absolute_path(path, "shared root")?;
    let mut current = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err((
                    1,
                    format!(
                        "path component {} is not a real directory",
                        current.display()
                    ),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    (
                        1,
                        format!(
                            "cannot create shared root component {}: {error}",
                            current.display()
                        ),
                    )
                })?;
            }
            Err(error) => return Err((1, error.to_string())),
        }
    }
    Ok(())
}

fn atomic_create_config(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let absolute = absolute_path(path).map_err(|error| (1, error.to_string()))?;
    let parent = absolute.parent().expect("absolute config path has parent");
    fs::create_dir_all(parent).map_err(|error| (1, error.to_string()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        absolute.file_name().unwrap_or_default().to_string_lossy(),
        Id128::random()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temp, &absolute)?;
        fs::remove_file(&temp)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            (1, format!("config {} already exists", absolute.display()))
        } else {
            (
                1,
                format!(
                    "cannot commit cluster config {}: {error}",
                    absolute.display()
                ),
            )
        }
    })
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        let parent = path.parent().unwrap_or_else(|| Path::new("/"));
        let canonical_parent = fs::canonicalize(parent).or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                fs::create_dir_all(parent)?;
                fs::canonicalize(parent)
            } else {
                Err(error)
            }
        })?;
        Ok(canonical_parent.join(path.file_name().unwrap_or_default()))
    } else {
        let cwd = env::current_dir()?;
        absolute_path(&cwd.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Id128, InitContext, InitOptions, LOGIN_NODE_ID, LocalInitJournal, RemoteInitJournal,
        RemoteInitPhase, SoftwareRoot, compiler_toolchain_root, local_init_journal_path,
        parse_options, prepare_local_primary_inner, remote_init_config_matches,
        remote_init_journal_path, remote_init_requires_nfs_setup, render_config, resume_local_init,
        validate_recovery_journal_conflicts, validate_remote_init_topology,
        write_local_init_journal, write_remote_init_journal,
    };
    use macluster_core::config::{ClusterConfig, Transport};
    use std::{
        fs,
        net::Ipv4Addr,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn context() -> InitContext {
        InitContext {
            login_host: Ipv4Addr::new(192, 168, 2, 2),
            login_uuid: "01234567-89ab-cdef-0123-456789abcdef".into(),
            login_uid: 501,
            remote_binary: "/Users/test/bin/macluster".into(),
            share_uuid: "00000000-0000-4000-8000-000000000001".into(),
        }
    }

    #[test]
    fn default_topology_keeps_login_as_storage_but_outside_compute_queue() {
        let options = parse_options(&[
            "--name".into(),
            "test-cluster".into(),
            "--queue".into(),
            "mini01".into(),
            "--shared-root".into(),
            "/Users/Shared/macluster".into(),
        ])
        .expect("parse default topology options");
        let source = render_config(&options, &context()).expect("render default topology");
        let config = ClusterConfig::parse(&source).expect("parse generated config");

        assert_eq!(
            config.login_node.as_ref().map(|node| node.as_str()),
            Some("login-01")
        );
        assert_eq!(config.storage_server.as_str(), "login-01");
        assert_eq!(config.primary_source_root(), config.shared_root);
        assert!(config.queues["mini01"].nodes.is_empty());
        assert_eq!(config.nodes["login-01"].transport, Transport::Local);
    }

    #[test]
    fn init_offers_detected_mamba_root_as_named_share() {
        let mut options = parse_options(&[]).expect("parse default init options");
        options.software_shares = vec![SoftwareRoot {
            id: "mamba".into(),
            path: PathBuf::from("/Users/test/mamba"),
        }];

        let source = render_config(&options, &context()).expect("render Mamba software share");
        let config = ClusterConfig::parse(&source).expect("parse generated config");
        let share = config.shares.get("mamba").expect("named Mamba share");

        assert_eq!(share.server.as_str(), LOGIN_NODE_ID);
        assert_eq!(share.source_root, PathBuf::from("/Users/test/mamba"));
        assert_eq!(share.mount_root, PathBuf::from("/Users/test/mamba"));
    }

    #[test]
    fn init_skips_mamba_root_already_covered_by_primary_share() {
        let mut options = parse_options(&[]).expect("parse default init options");
        let shared_root = PathBuf::from("/Users/Shared/macluster");
        options.shared_root = Some(shared_root.clone());
        options.software_shares = vec![SoftwareRoot {
            id: "mamba".into(),
            path: shared_root.join("software/mamba"),
        }];

        let source = render_config(&options, &context()).expect("render primary-covered root");
        let config = ClusterConfig::parse(&source).expect("parse generated config");

        assert!(config.shares.is_empty());
    }

    #[test]
    fn init_renders_multiple_generic_toolchain_shares() {
        let mut options = parse_options(&[]).expect("parse default init options");
        options.software_shares = vec![
            SoftwareRoot {
                id: "homebrew".into(),
                path: PathBuf::from("/opt/homebrew"),
            },
            SoftwareRoot {
                id: "llvm".into(),
                path: PathBuf::from("/opt/llvm"),
            },
        ];

        let source = render_config(&options, &context()).expect("render toolchain shares");
        let config = ClusterConfig::parse(&source).expect("parse generated config");

        assert_eq!(config.shares.len(), 2);
        for (id, path) in [("homebrew", "/opt/homebrew"), ("llvm", "/opt/llvm")] {
            let share = config.shares.get(id).expect("named toolchain share");
            assert_eq!(share.server.as_str(), LOGIN_NODE_ID);
            assert_eq!(share.source_root, PathBuf::from(path));
            assert_eq!(share.mount_root, PathBuf::from(path));
        }
    }

    #[test]
    fn init_detects_custom_compiler_prefix_for_optional_sharing() {
        let root = std::env::temp_dir().join(format!(
            "macluster-init-compiler-prefix-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let compiler = root.join("llvm/bin/clang");
        fs::create_dir_all(compiler.parent().unwrap()).unwrap();
        fs::write(&compiler, "compiler placeholder").unwrap();

        assert_eq!(
            compiler_toolchain_root(&compiler),
            Some(root.join("llvm").canonicalize().unwrap())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn init_resume_preserves_software_share() {
        let root = std::env::temp_dir().join(format!(
            "macluster-init-software-resume-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let config_path = root.join("config.toml");
        let state = root.join("controller");
        let shared_root = root.join("shared");
        let software_root = root.join("software");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&software_root).unwrap();
        fs::create_dir_all(&shared_root).unwrap();
        fs::write(software_root.join("keep.txt"), "software environment").unwrap();
        let options = InitOptions {
            name: Some("resume-software".into()),
            queue: Some("compute".into()),
            shared_root: Some(shared_root.clone()),
            software_shares: vec![SoftwareRoot {
                id: "mamba".into(),
                path: software_root.clone(),
            }],
            ..InitOptions::default()
        };
        // Keep the test's render input normalized and independent of the cwd.
        let options = InitOptions {
            shared_root: Some(shared_root.canonicalize().unwrap()),
            software_shares: vec![SoftwareRoot {
                id: "mamba".into(),
                path: software_root.canonicalize().unwrap(),
            }],
            ..options
        };
        let config_source = render_config(&options, &context()).unwrap();
        let journal = LocalInitJournal {
            version: super::LOCAL_INIT_JOURNAL_VERSION,
            config_path: super::absolute_path(&config_path)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            state_dir: super::absolute_path(&state)
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            config_source,
        };
        super::write_local_init_journal(&config_path, &journal).unwrap();

        resume_local_init(&config_path, &state).unwrap();

        let config = ClusterConfig::parse(&fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(
            config.shares["mamba"].source_root,
            software_root.canonicalize().unwrap()
        );
        assert_eq!(
            fs::read_to_string(software_root.join("keep.txt")).unwrap(),
            "software environment"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn external_primary_storage_is_registered_but_not_queued() {
        let options = parse_options(&[
            "--name".into(),
            "test-cluster".into(),
            "--queue".into(),
            "mini01".into(),
            "--shared-root".into(),
            "/Users/Shared/macluster".into(),
            "--primary-nfs".into(),
            "operator@192.168.2.1:22:/Volumes/Storage/macluster".into(),
        ])
        .expect("parse remote primary options");
        let source = render_config(&options, &context()).expect("render remote topology");
        let config = ClusterConfig::parse(&source).expect("parse generated config");

        assert_eq!(
            config.login_node.as_ref().map(|node| node.as_str()),
            Some("login-01")
        );
        assert_eq!(config.storage_server.as_str(), "storage-01");
        assert_eq!(
            config.primary_source_root(),
            PathBuf::from("/Volumes/Storage/macluster")
        );
        assert_eq!(config.shared_root, PathBuf::from("/Users/Shared/macluster"));
        assert_eq!(config.nodes["login-01"].transport, Transport::Local);
        assert_eq!(config.nodes["storage-01"].transport, Transport::Ssh);
        assert!(config.queues["mini01"].nodes.is_empty());
    }

    #[test]
    fn invalid_endpoint_paths_and_queue_names_are_rejected() {
        for args in [
            vec!["--primary-nfs".into(), "user@not-an-ip:/data".into()],
            vec!["--shared-root".into(), "relative/path".into()],
            vec!["--queue".into(), "bad/name".into()],
        ] {
            assert!(
                parse_options(&args).is_err(),
                "accepted invalid args: {args:?}"
            );
        }
    }

    #[test]
    fn removed_reset_flag_is_rejected() {
        let error = parse_options(&["--reset".into()]).expect_err("reset is now part of init");
        assert!(error.1.contains("unknown init option"));
    }

    #[test]
    fn force_can_be_combined_with_new_topology_options() {
        let options = parse_options(&[
            "--force".into(),
            "--name".into(),
            "fresh-cluster".into(),
            "--queue".into(),
            "fresh-queue".into(),
        ])
        .expect("init selects reset from the existing cluster, not an extra flag");
        assert!(options.force);
        assert_eq!(options.name.as_deref(), Some("fresh-cluster"));
        assert_eq!(options.queue.as_deref(), Some("fresh-queue"));
    }

    #[test]
    fn local_init_recovery_completes_after_marker_creation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "macluster-local-init-recovery-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let shared = root.join("shared");
        let state = root.join("controller");
        let config_path = root.join("config.toml");
        let options = parse_options(&[
            "--name".into(),
            "recovery-test".into(),
            "--queue".into(),
            "q".into(),
            "--shared-root".into(),
            shared.display().to_string(),
        ])
        .unwrap();
        let source = render_config(&options, &context()).unwrap();
        let parsed = ClusterConfig::parse(&source).unwrap();
        let journal = LocalInitJournal {
            version: super::LOCAL_INIT_JOURNAL_VERSION,
            config_path: config_path.display().to_string(),
            state_dir: state.display().to_string(),
            config_source: source.clone(),
        };

        write_local_init_journal(&config_path, &journal).unwrap();
        prepare_local_primary_inner(&shared, &parsed.share_uuid, true).unwrap();
        let marker_before = fs::read(shared.join(".macluster-share-id")).unwrap();

        resume_local_init(&config_path, &state).unwrap();

        assert_eq!(fs::read(&config_path).unwrap(), source.as_bytes());
        assert_eq!(
            fs::read(shared.join(".macluster-share-id")).unwrap(),
            marker_before
        );
        assert!(!local_init_journal_path(&config_path).exists());
        assert!(
            config_path
                .with_file_name("config.toml.macluster.state-dir")
                .exists()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn primary_nfs_endpoint_defaults_to_port_22_and_requires_source_path() {
        let options = parse_options(&[
            "--primary-nfs".into(),
            "user@192.168.2.1:/Volumes/Data".into(),
        ])
        .expect("parse endpoint without port");
        let primary = options.primary_nfs.expect("remote NFS configuration");
        assert_eq!(primary.port, 22);
        assert_eq!(primary.source_root, PathBuf::from("/Volumes/Data"));
        assert!(parse_options(&["--primary-nfs".into(), "user@192.168.2.1:22".into()]).is_err());
    }

    #[test]
    fn remote_init_journal_keeps_the_same_uuid_when_resumed_after_agent_staging() {
        let root = std::env::temp_dir().join(format!(
            "macluster-remote-init-recovery-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let config_path = root.join("config.toml");
        let state_dir = root.join("controller");
        let options = parse_options(&[
            "--name".into(),
            "remote-recovery".into(),
            "--queue".into(),
            "q".into(),
            "--shared-root".into(),
            root.join("shared").display().to_string(),
            "--primary-nfs".into(),
            "user@192.168.2.1:/Volumes/Data".into(),
        ])
        .unwrap();
        let source = render_config(&options, &context()).unwrap();
        let config = ClusterConfig::parse(&source).unwrap();
        let primary = options.primary_nfs.unwrap();
        validate_remote_init_topology(&config, &primary).unwrap();
        let journal = RemoteInitJournal {
            version: super::REMOTE_INIT_JOURNAL_VERSION,
            config_path: config_path.display().to_string(),
            state_dir: state_dir.display().to_string(),
            binary_sha256: "a".repeat(64),
            config_source: source.clone(),
            prepared_config_source: None,
            primary_nfs: primary,
            phase: RemoteInitPhase::Prepared,
        };

        write_remote_init_journal(&config_path, &journal, true).unwrap();
        let first: RemoteInitJournal =
            serde_json::from_slice(&fs::read(remote_init_journal_path(&config_path)).unwrap())
                .unwrap();
        let saved_uuid = ClusterConfig::parse(&first.config_source)
            .unwrap()
            .share_uuid;
        let mut staged = first;
        staged.prepared_config_source = Some(source.clone());
        staged.phase = RemoteInitPhase::AgentsStaged;
        write_remote_init_journal(&config_path, &staged, false).unwrap();
        let resumed: RemoteInitJournal =
            serde_json::from_slice(&fs::read(remote_init_journal_path(&config_path)).unwrap())
                .unwrap();

        assert_eq!(
            ClusterConfig::parse(&resumed.config_source)
                .unwrap()
                .share_uuid,
            saved_uuid
        );
        assert_eq!(resumed.phase, RemoteInitPhase::AgentsStaged);
        assert!(!remote_init_config_matches(&config_path, &resumed).unwrap());

        fs::write(&config_path, source.as_bytes()).unwrap();
        assert!(remote_init_config_matches(&config_path, &resumed).unwrap());
        fs::write(&config_path, b"[cluster]\nname = 'other'\n").unwrap();
        assert!(remote_init_config_matches(&config_path, &resumed).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn initialization_and_reset_recovery_journals_cannot_be_mixed() {
        assert!(validate_recovery_journal_conflicts(false, false, false).is_ok());
        assert!(validate_recovery_journal_conflicts(true, false, false).is_ok());
        assert!(validate_recovery_journal_conflicts(false, true, false).is_ok());
        assert!(validate_recovery_journal_conflicts(true, true, false).is_err());
        assert!(validate_recovery_journal_conflicts(true, false, true).is_err());
        assert!(validate_recovery_journal_conflicts(false, true, true).is_err());
    }

    #[test]
    fn remote_init_phase_checkpoints_skip_nfs_after_verified_setup() {
        assert!(remote_init_requires_nfs_setup(RemoteInitPhase::Prepared));
        assert!(remote_init_requires_nfs_setup(
            RemoteInitPhase::AgentsStaged
        ));
        assert!(!remote_init_requires_nfs_setup(RemoteInitPhase::NfsReady));
        assert!(!remote_init_requires_nfs_setup(
            RemoteInitPhase::ConfigCommitted
        ));
        assert!(!remote_init_requires_nfs_setup(
            RemoteInitPhase::ConfigSynced
        ));
    }
}
