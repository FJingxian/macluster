use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    env,
    ffi::{CStr, CString, OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, BufRead, IsTerminal, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Component, Path, PathBuf},
    process, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use macluster_core::{
    config::{ClusterConfig, Transport},
    maintenance::MaintenanceLock,
    service::{ServiceBinding, ServiceIntent, ServiceIntentStore},
    storage::{ReadOnlyJobStore, Storage, SubmitError},
};
use macluster_protocol::{
    control::{
        AgentCompatibilityRecord, AgentCompatibilityState, AgentCompatibilityUpdate,
        ControlCommand, ControlPayload, ControllerHello, ControllerLifecycle,
        MAX_CONTROL_COMPATIBILITY_NODES, MAX_CONTROL_SNAPSHOT_CHUNK_BYTES,
    },
    framing::{MAX_SNAPSHOT_BYTES, sha256_hex},
    identifiers::{Id128, NodeId, QueueName, RequestId, StartToken},
    types::{
        ACTIVE_ENV_PREFIX_ENV, EXPLICIT_TASK_PATH_ENV, INTERACTIVE_PTY_FEATURE, JobMode, JobRecord,
        JobSpec, JobState, METRICS_FAN_SPEED_FEATURE, MetricSnapshot, PROTOCOL_VERSION,
        SnapshotRef, VERBOSE_TASK_LOG_ENV, VERBOSE_TASK_LOG_ROOT_ENV,
    },
};
use serde::{Deserialize, Serialize};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::arguments::{
    CliError, SubmitOptions, merge_submit_options, parse_script_declarations, parse_submit_args,
    quote_argv, tokenize_shell_words,
};

type AppResult<T> = Result<T, (i32, String)>;

#[derive(Default)]
struct GlobalOptions {
    config: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
struct CachedSubmission {
    spec: JobSpec,
}

pub fn run(program: &str, input: &[String]) -> AppResult<()> {
    let invoked_name = Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("macluster");
    let mut args = input.to_vec();
    let mut command = alias_to_command(invoked_name).map(str::to_owned);
    if command.is_none() {
        if matches!(invoked_name, "update" | "mupdate") {
            return Err((
                2,
                format!("unknown command alias '{invoked_name}'; try `macluster --help`"),
            ));
        }
        let Some(command_index) = find_command_index(&args)? else {
            print_help();
            return Ok(());
        };
        let command_arg = &args[command_index];
        if command_arg == "--help" || command_arg == "-h" {
            print_help();
            return Ok(());
        }
        if command_arg == "--version" || command_arg == "-V" {
            println!(
                "macluster {} (protocol {})",
                env!("CARGO_PKG_VERSION"),
                PROTOCOL_VERSION
            );
            return Ok(());
        }
        command = alias_to_command(command_arg).map(str::to_owned);
        if command.is_some() {
            args.remove(command_index);
        } else {
            return Err((
                2,
                format!("unknown command '{command_arg}'; try `macluster --help`"),
            ));
        }
    }
    let command = command.expect("argv0 alias or parsed subcommand is present");

    let (global, args) = take_global_options(args, command == "submit")?;
    if command == "submit"
        && parse_submit_args(&args).is_ok_and(|options| options.interactive)
        && (!io::stdin().is_terminal() || !io::stdout().is_terminal())
    {
        return Err((2, "msub -Is requires terminal stdin and stdout".into()));
    }
    let mut address_migration_deferred = false;
    let local_read_query = is_read_only_query(&command, &args);
    let refresh_node_addresses = !local_read_query
        && is_macluster_executable()
        && should_refresh_node_addresses(&command, &args);
    let controller_owns_address_discovery = if refresh_node_addresses {
        let state_dir = state_root(global.state_dir.as_deref())?;
        !crate::node_admin::address_migration_pending(&state_dir)
            && controller_is_running(&global, &state_dir)
    } else {
        false
    };
    if refresh_node_addresses && !controller_owns_address_discovery {
        let config_path = resolved_config_path(global.config.as_deref());
        let state_dir = state_root(global.state_dir.as_deref())?;
        let can_defer = can_defer_agent_update_for_work(&command, &args);
        // Recovery/status commands remain usable when a migration journal is
        // unreadable. Existing valid journals are resumed below when the
        // cluster is idle; active work keeps the old endpoints available for
        // inspection until the controller can safely migrate them.
        let preparation = if can_defer && crate::node_admin::address_migration_pending(&state_dir) {
            Ok(true)
        } else {
            crate::node_admin::prepare_node_address_migration(&config_path, &state_dir)
        };
        let pending = match preparation {
            Ok(pending) => pending,
            Err((_, error)) if can_defer => {
                eprintln!(
                    "Node address discovery needs attention: {error}. Continuing with `{command}`; automatic Agent updates are deferred."
                );
                address_migration_deferred = true;
                false
            }
            Err(error) => return Err(error),
        };
        if pending {
            if can_defer {
                match crate::node_admin::address_migration_has_active_jobs(&state_dir) {
                    Ok(active_jobs) => {
                        address_migration_deferred =
                            should_defer_address_migration(can_defer, active_jobs);
                        if address_migration_deferred {
                            eprintln!(
                                "Node address/NFS migration is pending while jobs are active. Continuing with `{command}` using the current configuration; it will retry automatically when the cluster is idle."
                            );
                        }
                    }
                    Err((_, error)) => {
                        address_migration_deferred = true;
                        eprintln!(
                            "Cannot verify whether jobs are active: {error}. Continuing with `{command}` using the current configuration; migration progress is preserved."
                        );
                    }
                }
            }
        }
        if address_migration_deferred && command == "submit" {
            return Err((1, "New node addresses were verified; submissions are paused until active tasks finish and the controller completes address/NFS migration. Existing tasks and output are preserved.".into()));
        }
        let stopped = if pending && !address_migration_deferred {
            match crate::node_admin::refresh_node_addresses(&config_path, &state_dir, false) {
                Ok(stopped) => stopped,
                Err((_, error)) if can_defer => {
                    address_migration_deferred = true;
                    eprintln!(
                        "Node address/NFS migration could not finish yet: {error}. Continuing with `{command}`; migration progress is preserved."
                    );
                    false
                }
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        if stopped && command == "submit" {
            return Err((1, "Node addresses and NFS mappings were updated. Restart `macluster controller run`, then resubmit the command.".into()));
        }
        if stopped && command != "controller" {
            eprintln!(
                "Node address migration stopped the controller; run `macluster controller run` to resume scheduling."
            );
        }
    }
    let defer_mtop_preflight = command == "top" && top_will_use_tui(&args);
    if should_preflight_agent_update(&command, &args)
        && !address_migration_deferred
        && is_macluster_executable()
        && !defer_mtop_preflight
    {
        preflight_agent_update(&command, &args, &global)?;
    }

    match command.as_str() {
        "submit" => submit(global, &args),
        "job" => job(global, &args),
        "queue" => queue(global, &args),
        "kill" => kill(global, &args),
        "top" => top(global, &args, address_migration_deferred),
        "controller" => controller(global, &args, false),
        "init" => {
            let config_path = resolved_config_path(global.config.as_deref());
            let state_dir = state_root(global.state_dir.as_deref())?;
            let initialized = crate::init::run(config_path.clone(), state_dir.clone(), &args)?;
            let help = args
                .iter()
                .any(|arg| matches!(arg.as_str(), "--help" | "-h"));
            let disabled_for_test = env::var_os("MACLUSTER_DISABLE_SERVICE_AUTOSTART").is_some();
            if !help && !disabled_for_test && is_macluster_executable() && config_path.is_file() {
                match controller_service_manager(&global, &state_dir).and_then(|manager| {
                    manager.start(Duration::from_secs(5)).map_err(service_error)
                }) {
                    Ok(hello) => println!(
                        "Controller service ready ({:?}, epoch {}).",
                        hello.lifecycle, hello.controller_epoch.epoch
                    ),
                    Err((_, error)) => eprintln!(
                        "Cluster initialization completed, but the controller did not start: {error}. Start it with `macluster controller start`."
                    ),
                }
            }
            Ok(initialized)
        }
        "node" => node_admin(global, &args),
        "fans" => fans(global, &args),
        "internal" => internal(global, &args),
        "agent" => Err((1, format!("`{command}` is not implemented yet"))),
        _ => unreachable!(),
    }
}

// The controller runs the address watcher continuously. When it is healthy,
// avoid making every CLI invocation repeat the same per-node SSH and subnet
// discovery work; a durable proposal/migration still takes the normal recovery
// path above.
fn controller_is_running(global: &GlobalOptions, state_dir: &Path) -> bool {
    let config_path = resolved_config_path(global.config.as_deref());
    let Ok(binding) = ServiceBinding::load(&config_path, state_dir) else {
        return false;
    };
    crate::control_client::ControlClient::connect(&binding, Duration::from_millis(200)).is_ok()
}

fn should_preflight_agent_update(command: &str, args: &[String]) -> bool {
    // Init owns reset/recovery and stages any artifacts needed by a new cluster.
    // Updating the old cluster first can block the very operation repairing it.
    if command == "init" {
        return false;
    }
    if command == "controller"
        && args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "start" | "stop" | "restart" | "status"))
    {
        return false;
    }
    // Removing a moved or unreachable node must not first update that node
    // through the stale endpoint. Removal performs its own identity and idle checks.
    if command == "node"
        && args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "-rm" | "--remove"))
    {
        return false;
    }
    let help_requested = if command == "submit" {
        submit_help_requested(args)
    } else {
        args.iter()
            .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    };
    !matches!(command, "internal" | "agent") && !help_requested
}

fn should_refresh_node_addresses(command: &str, args: &[String]) -> bool {
    if matches!(command, "internal" | "agent" | "init") {
        return false;
    }
    if command == "fans"
        && args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--status" | "-l"))
    {
        return false;
    }
    if command == "controller"
        && args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "start" | "stop" | "restart" | "status"))
    {
        return false;
    }
    if command == "node"
        && args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "-rm" | "--remove"))
    {
        return false;
    }
    if command == "submit" {
        !submit_help_requested(args)
    } else {
        !args
            .iter()
            .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    }
}

fn top_will_use_tui(args: &[String]) -> bool {
    let once = args.iter().any(|argument| argument == "--once");
    let json = args.iter().any(|argument| argument == "--json");
    let term_is_dumb = env::var("TERM").is_ok_and(|value| value == "dumb");
    crate::mtop::should_use_tui(
        once,
        json,
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        term_is_dumb,
    )
}

fn should_defer_agent_update_for_node_recovery(command: &str, recovery_pending: bool) -> bool {
    matches!(command, "node" | "init") && recovery_pending
}

fn should_block_agent_update_for_pending_node_recovery(
    command: &str,
    recovery_pending: bool,
    update_required: bool,
) -> bool {
    recovery_pending
        && update_required
        && !should_defer_agent_update_for_node_recovery(command, recovery_pending)
}

// Read-only inspection and cancellation must remain usable from scripts even
// when a new build needs privileged installation. Submissions still fail closed.
fn defer_update_without_terminal(
    command: &str,
    args: &[String],
    interactive: bool,
    requires_privileged_authorization: bool,
) -> AppResult<bool> {
    if interactive || !requires_privileged_authorization {
        return Ok(false);
    }
    if can_defer_agent_update_for_work(command, args) {
        return Ok(true);
    }
    Err((
        1,
        format!(
            "Agent update is required before `{command}`, but administrator authorization needs an interactive Terminal. Rerun the same command from Terminal to resume; any interrupted maintenance is preserved."
        ),
    ))
}

fn can_defer_agent_update_for_work(command: &str, args: &[String]) -> bool {
    matches!(command, "job" | "queue" | "kill" | "top")
        || command == "fans"
            && args
                .iter()
                .any(|arg| matches!(arg.as_str(), "--status" | "-l"))
        || command == "node"
            && args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "-l" | "--list"))
}

fn should_defer_address_migration(can_defer: bool, active_jobs: bool) -> bool {
    can_defer && active_jobs
}

fn is_macluster_executable() -> bool {
    env::current_exe()
        .ok()
        .is_some_and(|path| is_macluster_binary_path(&path))
}

fn is_macluster_binary_path(path: &Path) -> bool {
    path.canonicalize()
        .ok()
        .and_then(|path| path.file_stem().map(|name| name == "macluster"))
        .unwrap_or(false)
}

fn preflight_agent_update(command: &str, args: &[String], global: &GlobalOptions) -> AppResult<()> {
    preflight_agent_update_with_compatibility(command, args, global, None)
}

fn preflight_agent_update_with_compatibility(
    command: &str,
    args: &[String],
    global: &GlobalOptions,
    checked_compatibility: Option<crate::node_admin::AgentBuildCompatibility>,
) -> AppResult<()> {
    let config_path = resolved_config_path(global.config.as_deref());
    let config_exists = match fs::symlink_metadata(&config_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err((
                1,
                format!(
                    "cannot inspect cluster config {}: {error}",
                    config_path.display()
                ),
            ));
        }
    };
    let config = match load_config(global.config.as_deref()) {
        Ok(config) => config,
        Err(_) if command == "init" || !config_exists => {
            // A missing config is a valid bootstrap case. `init` also needs
            // to remain available to repair or reset an invalid old config.
            return Ok(());
        }
        Err(error) => {
            return Err((
                2,
                format!("cannot check Agent builds because the cluster config is invalid: {error}"),
            ));
        }
    };
    if is_read_only_query(command, args)
        && !checked_compatibility
            .as_ref()
            .is_some_and(|compatibility| compatibility.requires_update())
        && !crate::node_admin::configured_agent_build_mismatch_local(&config)?
    {
        return Ok(());
    }
    let state_dir = state_root(global.state_dir.as_deref())?;
    let node_recovery_pending =
        crate::node_admin::node_admin_recovery_pending(&config_path, &state_dir).map_err(
            |error| {
                (
                    1,
                    format!("cannot inspect node administration recovery state: {error}"),
                )
            },
        )?;
    if should_defer_agent_update_for_node_recovery(command, node_recovery_pending) {
        return Ok(());
    }
    let mut local_validation = None;
    let (compatibility, compatibility_age_ms, publish_compatibility) = match checked_compatibility {
        Some(_) if command == "top" => {
            let (compatibility, age_ms) =
                crate::node_admin::configured_agent_build_compatibility_cached_with_age(
                    &config,
                    &state_dir.join("mtop-cache"),
                )
                .map_err(|(code, error)| {
                    (
                        code,
                        format!("cannot revalidate configured Agent builds: {error}"),
                    )
                })?;
            local_validation = Some(compatibility.clone());
            (compatibility, age_ms, true)
        }
        Some(compatibility) => (compatibility, 0, true),
        None => {
            if let Some(compatibility) =
                query_controller_agent_compatibility(&config_path, &state_dir, &config)
            {
                (compatibility, 0, false)
            } else {
                let (compatibility, age_ms) =
                    crate::node_admin::configured_agent_build_compatibility_cached_with_age(
                        &config,
                        &state_dir.join("mtop-cache"),
                    )
                    .map_err(|(code, error)| {
                        (
                            code,
                            format!("cannot check configured Agent builds: {error}"),
                        )
                    })?;
                local_validation = Some(compatibility.clone());
                (compatibility, age_ms, true)
            }
        }
    };
    if publish_compatibility {
        publish_controller_agent_compatibility(
            &config_path,
            &state_dir,
            &config,
            &compatibility,
            compatibility_age_ms,
        );
    }
    // The controller's build cache cannot see a stale/partial executable at a
    // managed path whose directory hash is current. Reuse the short-lived
    // local validation cache to also verify runtime capabilities before a job
    // can be admitted to a queue that no worker can service.
    let local_validation = match local_validation {
        Some(validation) => validation,
        None => {
            crate::node_admin::configured_agent_build_compatibility_cached_with_age(
                &config,
                &state_dir.join("mtop-cache"),
            )
            .map_err(|(code, error)| {
                (
                    code,
                    format!("cannot validate configured Agent capabilities: {error}"),
                )
            })?
            .0
        }
    };
    let recovery_pending =
        crate::node_admin::agent_update_recovery_pending(&config_path, &state_dir).map_err(
            |error| {
                (
                    1,
                    format!("cannot inspect Agent update recovery state: {error}"),
                )
            },
        )?;
    let helper_refresh_pending =
        crate::node_admin::agent_helper_refresh_pending(&state_dir).map_err(|error| (1, error))?;
    let agent_mismatch = compatibility.requires_update() || local_validation.requires_update();
    let update_required = recovery_pending || agent_mismatch || helper_refresh_pending;
    if !local_validation.missing_required_features.is_empty() {
        eprintln!(
            "Agent capability mismatch detected on {}; updating the cluster before `{command}`.",
            local_validation.missing_required_features.join(", ")
        );
    }
    if update_required
        && can_defer_agent_update_for_work(command, args)
        && crate::node_admin::agent_update_blocked_by_work(&state_dir).map_err(|error| {
            (
                1,
                format!("cannot determine whether Agent update is safe: {error}"),
            )
        })?
    {
        eprintln!(
            "Agent update is deferred while active tasks or output synchronization remain; continuing with `{}`. Retry after the work drains to resume the automatic update.",
            command
        );
        return Ok(());
    }
    if update_required
        && defer_update_without_terminal(
            command,
            args,
            io::stdin().is_terminal(),
            helper_refresh_pending && !agent_mismatch && !recovery_pending,
        )?
    {
        eprintln!(
            "Agent update needs an interactive Terminal; continuing with `{command}` without updating."
        );
        return Ok(());
    }
    if should_block_agent_update_for_pending_node_recovery(
        command,
        node_recovery_pending,
        update_required,
    ) {
        return Err((
            1,
            "Agent update is blocked by an unfinished node administration operation; finish or resolve it with `mnode`, then retry the requested command.".into(),
        ));
    }
    let update_result = maybe_run_agent_update(update_required, || {
        crate::node_admin::update_all_agents_for_preflight(&config_path, &state_dir)
    })?;
    if update_result.is_some() {
        crate::node_admin::invalidate_agent_validation_cache(&state_dir.join("mtop-cache"));
        publish_unknown_controller_agent_compatibility(&config_path, &state_dir, &config);
    }
    if update_result.is_some_and(|controller_was_running| {
        controller_should_resume_after_agent_update(command, args, controller_was_running)
    }) {
        controller_service_manager(global, &state_dir)?
            .ensure_running(Duration::from_secs(5))
            .map_err(|error| {
                (
                    1,
                    format!(
                        "Agent update completed, but the controller could not be restarted automatically: {error}. Run `macluster controller start`, then retry the requested command."
                    ),
                )
            })?;
        eprintln!("Controller restarted after Agent update.");
    }
    Ok(())
}

fn query_controller_agent_compatibility(
    config_path: &Path,
    state_dir: &Path,
    config: &ClusterConfig,
) -> Option<crate::node_admin::AgentBuildCompatibility> {
    if config.nodes.len() > MAX_CONTROL_COMPATIBILITY_NODES {
        return None;
    }
    let binding = ServiceBinding::load(config_path, state_dir).ok()?;
    let mut client =
        crate::control_client::ControlClient::connect(&binding, Duration::from_millis(200)).ok()?;
    if !client
        .hello()
        .capabilities
        .iter()
        .any(|capability| capability == "agent.compatibility.v1")
    {
        return None;
    }
    let node_ids = config
        .nodes
        .keys()
        .map(|id| id.parse::<NodeId>().ok())
        .collect::<Option<Vec<_>>>()?;
    let payload = client
        .request(ControlCommand::QueryAgentCompatibility {
            node_ids: node_ids.clone(),
        })
        .ok()?;
    let ControlPayload::AgentCompatibility(records) = payload else {
        return None;
    };
    if records.len() != node_ids.len() {
        return None;
    }
    let mut compatibility = crate::node_admin::AgentBuildCompatibility::default();
    let mut expected = node_ids
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    for AgentCompatibilityRecord {
        node_id,
        state,
        age_ms,
    } in records
    {
        if !expected.remove(&node_id) {
            return None;
        }
        if !matches!(state, AgentCompatibilityState::Stale)
            && (age_ms.is_none() || age_ms.is_some_and(|age| age >= 60_000))
        {
            // An unpopulated service cache is not an observation. Fall back to
            // the bounded local compatibility check on first use.
            return None;
        }
        match state {
            AgentCompatibilityState::Current => compatibility.current.push(node_id.to_string()),
            AgentCompatibilityState::Mismatch => compatibility.stale.push(node_id.to_string()),
            AgentCompatibilityState::Unknown => compatibility.unknown.push(node_id.to_string()),
            AgentCompatibilityState::Stale => return None,
        }
    }
    if !expected.is_empty() {
        return None;
    }
    Some(compatibility)
}

fn publish_controller_agent_compatibility(
    config_path: &Path,
    state_dir: &Path,
    config: &ClusterConfig,
    compatibility: &crate::node_admin::AgentBuildCompatibility,
    age_ms: u64,
) {
    if config.nodes.len() > MAX_CONTROL_COMPATIBILITY_NODES {
        return;
    }
    let Some(mut client) = agent_compatibility_control_client(config_path, state_dir) else {
        return;
    };
    let entries = config
        .nodes
        .keys()
        .filter_map(|id| {
            let node_id = id.parse::<NodeId>().ok()?;
            let state = if compatibility.current.iter().any(|value| value == id) {
                AgentCompatibilityState::Current
            } else if compatibility.stale.iter().any(|value| value == id) {
                AgentCompatibilityState::Mismatch
            } else {
                AgentCompatibilityState::Unknown
            };
            Some(AgentCompatibilityUpdate {
                node_id,
                state,
                boot_id: None,
                age_ms,
            })
        })
        .collect();
    let _ = client.request(ControlCommand::PublishAgentCompatibility { entries });
}

fn publish_unknown_controller_agent_compatibility(
    config_path: &Path,
    state_dir: &Path,
    config: &ClusterConfig,
) {
    if config.nodes.len() > MAX_CONTROL_COMPATIBILITY_NODES {
        return;
    }
    let Some(mut client) = agent_compatibility_control_client(config_path, state_dir) else {
        return;
    };
    let entries = config
        .nodes
        .keys()
        .filter_map(|id| {
            Some(AgentCompatibilityUpdate {
                node_id: id.parse::<NodeId>().ok()?,
                state: AgentCompatibilityState::Unknown,
                boot_id: None,
                age_ms: 0,
            })
        })
        .collect();
    let _ = client.request(ControlCommand::PublishAgentCompatibility { entries });
}

fn agent_compatibility_control_client(
    config_path: &Path,
    state_dir: &Path,
) -> Option<crate::control_client::ControlClient> {
    let binding = ServiceBinding::load(config_path, state_dir).ok()?;
    let client =
        crate::control_client::ControlClient::connect(&binding, Duration::from_millis(200)).ok()?;
    client
        .hello()
        .capabilities
        .iter()
        .any(|capability| capability == "agent.compatibility.v1")
        .then_some(client)
}

fn find_command_index(args: &[String]) -> AppResult<Option<usize>> {
    let mut index = 0;
    while index < args.len() {
        let (key, inline) = args[index]
            .split_once('=')
            .map_or((args[index].as_str(), None), |(key, value)| {
                (key, Some(value))
            });
        if key == "--config" || key == "--state-dir" {
            if inline.is_none() {
                if index + 1 >= args.len() {
                    return Err((2, format!("missing value for {key}")));
                }
                index += 2;
            } else {
                index += 1;
            }
        } else {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn alias_to_command(name: &str) -> Option<&'static str> {
    Some(match name {
        "submit" | "msub" => "submit",
        "job" | "mjob" => "job",
        "queue" | "mqueue" => "queue",
        "kill" | "mkill" => "kill",
        "top" | "mtop" => "top",
        "controller" => "controller",
        "init" => "init",
        "agent" => "agent",
        "internal" => "internal",
        "node" | "mnode" => "node",
        "fans" | "mfans" => "fans",
        _ => return None,
    })
}

fn take_global_options(
    args: Vec<String>,
    stop_at_submit_command: bool,
) -> AppResult<(GlobalOptions, Vec<String>)> {
    let mut options = GlobalOptions::default();
    let mut remaining = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if stop_at_submit_command && is_submit_command_boundary(argument) {
            remaining.extend(args[index..].iter().cloned());
            break;
        }
        let (key, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(key, value)| (key, Some(value)));
        if key == "--config" || key == "--state-dir" {
            let value = if let Some(value) = inline {
                value.to_owned()
            } else {
                index += 1;
                args.get(index)
                    .cloned()
                    .ok_or_else(|| (2, format!("missing value for {key}")))?
            };
            if value.is_empty() {
                return Err((2, format!("empty value for {key}")));
            }
            if key == "--config" {
                options.config = Some(PathBuf::from(value));
            } else {
                options.state_dir = Some(PathBuf::from(value));
            }
        } else {
            remaining.push(argument.clone());
            if stop_at_submit_command
                && inline.is_none()
                && submit_option_takes_value(key)
                && index + 1 < args.len()
            {
                remaining.push(args[index + 1].clone());
                index += 2;
                continue;
            }
        }
        index += 1;
    }
    Ok((options, remaining))
}

fn submit_option_takes_value(key: &str) -> bool {
    matches!(
        key,
        "-q" | "--queue"
            | "--node"
            | "-J"
            | "--name"
            | "-t"
            | "--time"
            | "--cwd"
            | "-o"
            | "--output"
            | "-e"
            | "--error"
            | "--env"
            | "--request-id"
    )
}

fn is_submit_command_boundary(argument: &str) -> bool {
    argument == "--" || argument == "--wrap" || argument.is_empty() || !argument.starts_with('-')
}

fn submit(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    if submit_help_requested(args) {
        print_submit_help();
        return Ok(());
    }
    let config_file = resolved_config_path(global.config.as_deref());
    let state_root = state_root(global.state_dir.as_deref())?;
    crate::init::reset::ensure_no_reset_in_progress(&config_file, &state_root)?;
    crate::node_admin::ensure_no_node_maintenance_in_progress(&config_file, &state_root)
        .map_err(|error| (1, error))?;
    let _maintenance = MaintenanceLock::try_shared(&config_file).map_err(|error| {
        (
            1,
            format!("cannot use cluster config while node maintenance is active: {error}"),
        )
    })?;
    crate::init::reset::ensure_no_reset_in_progress(&config_file, &state_root)?;
    crate::node_admin::ensure_no_node_maintenance_in_progress(&config_file, &state_root)
        .map_err(|error| (1, error))?;
    let cli_options = parse_submit_args(args).map_err(cli_error)?;
    if cli_options.interactive && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        return Err((2, "msub -Is requires terminal stdin and stdout".into()));
    }
    let cli_options = promote_inline_command(cli_options);
    MaintenanceLock::bind_state_dir(&config_file, &state_root).map_err(|error| {
        (
            1,
            format!("cluster config/state directory binding failed: {error}"),
        )
    })?;
    let storage = Storage::open(&state_root).map_err(operation_error)?;

    let requested_id = cli_options.request_id;
    let (request_id, mut spec, script, config, loaded_from_cache) = if let Some(request_id) =
        requested_id
    {
        if let Some((cached_spec, cached_script)) = load_submission_cache(&state_root, request_id)?
        {
            let config = load_config(global.config.as_deref()).ok();
            (request_id, cached_spec, cached_script, config, true)
        } else {
            let config = load_config(global.config.as_deref()).map_err(config_error)?;
            let (spec, script) = build_submission(&config, &cli_options)?;
            (request_id, spec, script, Some(config), false)
        }
    } else {
        let config = load_config(global.config.as_deref()).map_err(config_error)?;
        let (spec, script) = build_submission(&config, &cli_options)?;
        let request_id = RequestId(Id128::random());
        (request_id, spec, script, Some(config), false)
    };

    if script.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err((2, "script exceeds the 8 MiB limit".into()));
    }
    if let Some(expected) = spec.snapshot.as_ref() {
        if loaded_from_cache && snapshot_reference(&script)? != *expected {
            return Err((
                1,
                "cached script does not match the cached submission".into(),
            ));
        }
    } else if loaded_from_cache && !script.is_empty() {
        return Err((
            1,
            "cached interactive shell unexpectedly contains a script".into(),
        ));
    } else if !script.is_empty() {
        spec.snapshot = Some(snapshot_reference(&script)?);
    }
    if !loaded_from_cache {
        save_submission_cache(&state_root, request_id, &spec, &script)?;
    }
    if spec.mode == JobMode::Interactive
        && (!io::stdin().is_terminal() || !io::stdout().is_terminal())
    {
        return Err((
            2,
            "interactive submission requires terminal stdin and stdout".into(),
        ));
    }
    if spec.mode == JobMode::Interactive && config.is_none() {
        return Err((
            1,
            "cannot load cluster config for interactive attachment".into(),
        ));
    }
    let terminal_guard = if spec.mode == JobMode::Interactive {
        Some(crate::terminal::RawModeGuard::enter().map_err(|error| {
            (
                2,
                format!("could not enter interactive terminal mode: {error}"),
            )
        })?)
    } else {
        None
    };
    crate::init::reset::ensure_no_reset_in_progress(&config_file, &state_root)?;
    crate::node_admin::ensure_no_node_maintenance_in_progress(&config_file, &state_root)
        .map_err(|error| (1, error))?;
    let mut online = online_controller(&config_file, &state_root, spec.mode == JobMode::Batch)?;
    let record = if let Some(controller) = &mut online {
        submit_online(controller, request_id, spec, &script)?
    } else {
        if let Some(expected) = spec.snapshot.as_ref() {
            let staged = storage.stage_snapshot(&script).map_err(operation_error)?;
            if &staged != expected {
                return Err((1, "script snapshot changed before local admission".into()));
            }
        }
        storage
            .submit_once(request_id, spec)
            .map_err(operation_error)?
    };
    wake_controller_best_effort(&state_root);
    if !record.snapshot_sync_pending {
        if record.spec.mode == JobMode::Interactive {
            write_interactive_status(&format!(
                "Submitted job {} ({})\r\n",
                record.id, record.spec.name
            ))?;
        } else {
            println!("Submitted job {} ({})", record.id, record.spec.name);
        }
    } else {
        if record.spec.mode == JobMode::Interactive {
            write_interactive_status(&format!(
                "Submitted job {} ({}) — shared snapshot pending\r\n",
                record.id, record.spec.name
            ))?;
        } else {
            println!(
                "Submitted job {} ({}) — shared snapshot pending",
                record.id, record.spec.name
            );
        }
    }
    if record.spec.mode == JobMode::Interactive {
        write_interactive_status(&format!("Request ID: {request_id}\r\n"))?;
    } else {
        println!("Request ID: {request_id}");
    }
    if record.spec.mode == JobMode::Interactive {
        let config = config.expect("interactive config was validated before submission");
        return run_interactive_submission(
            &storage,
            record,
            &config,
            &config_file,
            terminal_guard.expect("interactive mode entered raw terminal mode"),
        );
    }
    Ok(())
}

fn snapshot_reference(script: &[u8]) -> AppResult<SnapshotRef> {
    Ok(SnapshotRef {
        sha256: sha256_hex(script).map_err(|error| (1, error.to_string()))?,
        size_bytes: script.len() as u64,
    })
}

fn submit_online(
    controller: &mut OnlineController,
    request_id: RequestId,
    spec: JobSpec,
    script: &[u8],
) -> AppResult<JobRecord> {
    if let Some(expected) = spec.snapshot.as_ref() {
        if snapshot_reference(script)? != *expected {
            return Err((
                1,
                "script snapshot digest does not match the submission".into(),
            ));
        }
        let upload_id = Id128::random();
        let begin = controller
            .client
            .request(ControlCommand::BeginSnapshot {
                upload_id,
                size_bytes: expected.size_bytes,
                sha256: expected.sha256.clone(),
            })
            .map_err(|error| (1, error.to_string()))?;
        if !matches!(begin, ControlPayload::SnapshotProgress { offset: 0 }) {
            return Err((
                1,
                "controller returned an invalid script upload response".into(),
            ));
        }
        let mut offset = 0_u64;
        for bytes in script.chunks(MAX_CONTROL_SNAPSHOT_CHUNK_BYTES) {
            let payload = controller
                .client
                .request(ControlCommand::PutSnapshotChunk {
                    upload_id,
                    offset,
                    bytes: bytes.to_vec(),
                })
                .map_err(|error| (1, error.to_string()))?;
            offset = offset.saturating_add(bytes.len() as u64);
            if payload != (ControlPayload::SnapshotProgress { offset }) {
                return Err((
                    1,
                    "controller returned an invalid script chunk offset".into(),
                ));
            }
        }
        match controller
            .client
            .request(ControlCommand::FinishSnapshot { upload_id })
            .map_err(|error| (1, error.to_string()))?
        {
            ControlPayload::SnapshotFinished(staged) if staged == *expected => {}
            ControlPayload::SnapshotFinished(_) => {
                return Err((1, "controller staged a different script snapshot".into()));
            }
            _ => return Err((1, "controller returned an invalid script completion".into())),
        }
    }

    match controller.client.request(ControlCommand::Submit {
        request_id,
        spec: spec.clone(),
    }) {
        Ok(ControlPayload::Submission(record)) => Ok(record),
        Ok(_) => Err((
            1,
            "controller returned an invalid submission response".into(),
        )),
        Err(crate::control_client::ControlClientError::Remote { code, message }) => Err((
            1,
            format!("controller rejected submission ({code:?}): {message}"),
        )),
        Err(first_error) => {
            // The controller may have committed the request before the reply was lost.
            // Resolve the durable request ID before considering any retry or fallback.
            let mut retry_client = crate::control_client::ControlClient::connect(
                &controller.binding,
                Duration::from_secs(5),
            )
            .map_err(|_error| {
                (
                    1,
                    format!(
                        "submission result is unknown after {first_error}; query `mjob --request-id {request_id}` after the controller reconnects"
                    ),
                )
            })?;
            match retry_client
                .request(ControlCommand::LookupRequest { request_id })
                .map_err(|error| {
                    (
                        1,
                        format!(
                            "submission result is unknown after {first_error}; request lookup failed: {error}; retry with `msub --request-id {request_id}`"
                        ),
                    )
                })? {
                ControlPayload::Lookup(Some(record)) => {
                    controller.client = retry_client;
                    Ok(record)
                }
                ControlPayload::Lookup(None) => match retry_client.request(ControlCommand::Submit {
                    request_id,
                    spec,
                }) {
                    Ok(ControlPayload::Submission(record)) => {
                        controller.client = retry_client;
                        Ok(record)
                    }
                    Ok(_) => Err((1, "controller returned an invalid retry response".into())),
                    Err(error) => Err((
                        1,
                        format!(
                            "submission result is still unknown after retry: {error}; query `mjob --request-id {request_id}` before submitting again"
                        ),
                    )),
                },
                _ => Err((1, "controller returned an invalid request lookup".into())),
            }
        }
    }
}

fn submit_help_requested(args: &[String]) -> bool {
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" || argument == "--wrap" {
            return false;
        }
        if argument == "--help" || argument == "-h" {
            return true;
        }
        if is_submit_command_boundary(argument) {
            return false;
        }
        let (key, inline) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(key, value)| (key, Some(value)));
        if inline.is_none()
            && matches!(
                key,
                "-q" | "--queue"
                    | "--node"
                    | "-J"
                    | "--name"
                    | "-t"
                    | "--time"
                    | "--cwd"
                    | "-o"
                    | "--output"
                    | "-e"
                    | "--error"
                    | "--env"
                    | "--request-id"
                    | "--config"
                    | "--state-dir"
            )
        {
            index += 2;
        } else {
            index += 1;
        }
    }
    false
}

fn maybe_run_agent_update(
    update_required: bool,
    update: impl FnOnce() -> AppResult<bool>,
) -> AppResult<Option<bool>> {
    if !update_required {
        return Ok(None);
    }
    update().map(Some)
}

fn controller_should_resume_after_agent_update(
    command: &str,
    args: &[String],
    controller_was_running: bool,
) -> bool {
    controller_was_running
        && !(command == "controller" && args.first().is_some_and(|arg| arg == "run"))
}

fn run_interactive_submission(
    storage: &Storage,
    initial: JobRecord,
    config: &ClusterConfig,
    config_path: &Path,
    _terminal: crate::terminal::RawModeGuard,
) -> AppResult<()> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    write_interactive_status("Waiting for an interactive node; press Ctrl-C to cancel.\r\n")?;
    let mut job = initial;
    let mut shown_waiting_reason = None;

    loop {
        if job.state.is_terminal() {
            return interactive_job_result(&job);
        }
        if job.state != JobState::Cancelling
            && let (Some(node_id), Some(start_token)) =
                (job.node.as_ref(), job.start_token.as_ref())
        {
            let node = config.nodes.get(node_id.as_str()).ok_or_else(|| {
                (
                    1,
                    format!("allocated node '{node_id}' is missing from the active config"),
                )
            })?;
            write_interactive_status(&format!(
                "\r\nJob {} allocated on {}; attaching.\r\n",
                job.id, node_id
            ))?;
            let transport = macluster_controller::transport::ClusterTransport::new_with_namespace(
                config_path.to_path_buf(),
                config.share_uuid.clone(),
            );
            let attach_status =
                match transport.attach_interactive(node_id, node, job.id, *start_token) {
                    Ok(status) => status,
                    Err(error) => {
                        if storage.request_cancel(job.id, false).is_ok() {
                            wake_controller_best_effort(storage.root());
                        }
                        return Err((1, format!("interactive attach failed: {error}")));
                    }
                };
            if attach_status != 0 {
                let latest = storage
                    .get_job(job.id)
                    .map_err(operation_error)?
                    .ok_or_else(|| (1, format!("job {} disappeared", job.id)))?;
                if latest.state.is_terminal() {
                    return interactive_job_result(&latest);
                }
                if storage.request_cancel(job.id, false).is_ok() {
                    wake_controller_best_effort(storage.root());
                }
                return Err((
                    attach_status.clamp(1, 255),
                    format!("interactive attach process exited with status {attach_status}"),
                ));
            }
            return wait_for_interactive_completion(storage, job.id, config_path);
        }

        if let Some(reason) = job.waiting_reason.as_deref()
            && shown_waiting_reason.as_deref() != Some(reason)
        {
            write_interactive_status(&format!("Waiting: {reason}\r\n"))?;
            shown_waiting_reason = Some(reason.to_owned());
        }

        if event::poll(Duration::from_millis(100)).map_err(|error| {
            (
                1,
                format!("could not read interactive terminal input: {error}"),
            )
        })? && let Event::Key(key) = event::read().map_err(|error| {
            (
                1,
                format!("could not read interactive terminal input: {error}"),
            )
        })? && key.kind == KeyEventKind::Press
            && key.code == KeyCode::Char('c')
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            match storage.request_cancel(job.id, false) {
                Ok(_) => {
                    wake_controller_best_effort(storage.root());
                    return Err((130, "interactive job cancelled before attachment".into()));
                }
                Err(error) => {
                    let latest = storage
                        .get_job(job.id)
                        .map_err(operation_error)?
                        .ok_or_else(|| (1, format!("job {} disappeared", job.id)))?;
                    if latest.state.is_terminal() {
                        return interactive_job_result(&latest);
                    }
                    return Err(operation_error(error));
                }
            }
        }

        job = storage
            .get_job(job.id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("job {} disappeared", job.id)))?;
    }
}

fn wait_for_interactive_completion(
    storage: &Storage,
    job_id: u64,
    config_path: &Path,
) -> AppResult<()> {
    wait_for_interactive_completion_with(
        job_id,
        Duration::from_secs(30),
        Duration::from_secs(5),
        || {
            storage
                .get_job(job_id)
                .map_err(operation_error)?
                .ok_or_else(|| (1, format!("job {job_id} disappeared")))
        },
        || {
            // Reuse service lifecycle locking and binding checks; never resubmit
            // or change the execution identity while recovering reconciliation.
            let _controller = online_controller(config_path, storage.root(), false)?;
            macluster_controller::wake::notify_controller(storage.root())
                .map_err(|error| (1, error.to_string()))
        },
    )
}

fn wait_for_interactive_completion_with(
    job_id: u64,
    timeout: Duration,
    recovery_interval: Duration,
    mut read_job: impl FnMut() -> AppResult<JobRecord>,
    mut recover: impl FnMut() -> AppResult<()>,
) -> AppResult<()> {
    let deadline = Instant::now() + timeout;
    let mut next_recovery = Instant::now() + recovery_interval;
    let mut recovery_error = None;
    loop {
        let job = read_job()?;
        if job.state.is_terminal() {
            return interactive_job_result(&job);
        }
        let now = Instant::now();
        if now >= deadline {
            let detail = recovery_error
                .map(|error: String| format!(" Last recovery error: {error}."))
                .unwrap_or_default();
            return Err((
                1,
                format!(
                    "interactive terminal closed, but job {job_id} completion is not yet confirmed.{detail} The job is preserved; inspect `macluster mjob {job_id}` or run `macluster controller run` to reconcile. Do not resubmit until its state is confirmed."
                ),
            ));
        }
        if now >= next_recovery {
            recovery_error = recover().err().map(|(_, message)| message);
            next_recovery = Instant::now() + recovery_interval;
            continue;
        }
        thread::sleep(
            Duration::from_millis(100)
                .min(deadline.saturating_duration_since(now))
                .min(next_recovery.saturating_duration_since(now)),
        );
    }
}

fn interactive_job_result(job: &JobRecord) -> AppResult<()> {
    match job.state {
        JobState::Completed => Ok(()),
        JobState::Failed => {
            let code = job.exit_code.filter(|code| *code != 0).unwrap_or(1);
            Err((
                code.clamp(1, 255),
                format!("interactive job {} exited with status {code}", job.id),
            ))
        }
        JobState::Cancelled => Err((130, format!("interactive job {} was cancelled", job.id))),
        JobState::Timeout => Err((
            124,
            format!("interactive job {} reached its walltime", job.id),
        )),
        JobState::NodeLost => Err((1, format!("interactive job {} lost its node", job.id))),
        _ => Err((1, format!("interactive job {} is not finished", job.id))),
    }
}

fn write_interactive_status(line: &str) -> AppResult<()> {
    io::stdout()
        .lock()
        .write_all(line.as_bytes())
        .map_err(|error| (1, error.to_string()))
}

fn wake_controller_best_effort(state_dir: &Path) {
    if let Err(error) = macluster_controller::wake::notify_controller(state_dir) {
        eprintln!(
            "macluster: could not notify the controller ({error}); the job is saved and will be seen on the next reconcile pass"
        );
    }
}

fn build_submission(
    config: &ClusterConfig,
    options: &SubmitOptions,
) -> AppResult<(JobSpec, Vec<u8>)> {
    let script = if options.interactive && options.script.is_none() && options.wrap.is_none() {
        Vec::new()
    } else if let Some(wrap) = &options.wrap {
        if wrap.contains('\0') {
            return Err((2, "--wrap cannot contain NUL".into()));
        }
        format!("#!/bin/bash\n{wrap}\n").into_bytes()
    } else {
        let path = options.script.as_ref().ok_or_else(|| {
            (
                2,
                "missing script path; or provide a valid --request-id cache".into(),
            )
        })?;
        fs::read(path)
            .map_err(|error| (2, format!("cannot read script {}: {error}", path.display())))?
    };
    if script.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err((2, "script exceeds the 8 MiB limit".into()));
    }
    if script.is_empty()
        && (!options.interactive || options.script.is_some() || options.wrap.is_some())
    {
        return Err((2, "script is empty".into()));
    }

    let declarations = if options.wrap.is_none() && !script.is_empty() {
        let header = String::from_utf8_lossy(&script);
        parse_script_declarations(&header).map_err(cli_error)?
    } else {
        SubmitOptions::default()
    };
    let merged = merge_submit_options(declarations, options.clone());
    let queue = merged
        .queue
        .clone()
        .unwrap_or_else(|| config.default_queue.clone());
    let queue_config = config
        .queue_for_dispatch(queue.as_str())
        .ok_or_else(|| (2, format!("queue '{queue}' is not configured")))?;
    if let Some(node) = &merged.node {
        if config.is_login_node(node.as_str()) {
            return Err((
                2,
                format!("login node '{node}' cannot accept jobs; select a compute node"),
            ));
        }
        if !queue_config
            .nodes
            .iter()
            .any(|member| member == node.as_str())
        {
            return Err((
                2,
                format!("node '{node}' is not a member of queue '{queue}'"),
            ));
        }
    }

    let _path_resolver = SubmissionPathResolverGuard::enter(config);
    let shared_root = config.shared_root.canonicalize().map_err(|error| {
        (
            1,
            format!(
                "shared root {} is unavailable: {error}",
                config.shared_root.display()
            ),
        )
    })?;
    let submit_cwd = if let Some(cwd) = merged.cwd.clone() {
        cwd
    } else {
        let current_dir = env::current_dir().map_err(|error| (1, error.to_string()))?;
        let canonical_current = current_dir.canonicalize().map_err(|error| {
            (
                2,
                format!(
                    "cannot resolve working directory {}: {error}",
                    current_dir.display()
                ),
            )
        })?;
        if (options.wrap.is_some() || options.interactive)
            && shared_working_directory(config, &canonical_current).is_none()
        {
            config.shared_root.clone()
        } else {
            current_dir
        }
    };
    let cwd = submit_cwd.canonicalize().map_err(|error| {
        (
            2,
            format!(
                "cannot resolve working directory {}: {error}",
                submit_cwd.display()
            ),
        )
    })?;
    let submitter_cwd = cwd;
    let cwd = shared_working_directory(config, &submitter_cwd).ok_or_else(|| {
        (
            2,
            "working directory must be inside the primary or a configured named share".into(),
        )
    })?;

    let storage_namespace =
        Id128::parse(&config.share_uuid).map_err(|error| (2, error.to_string()))?;
    let output_root = shared_root.join("jobs").join(storage_namespace.to_string());
    let stdout_path = if let Some(path) = merged.stdout_path.as_deref() {
        validate_shared_output_path(path, &submitter_cwd, config)?
    } else {
        output_root
            .join("%j/stdout.log")
            .to_string_lossy()
            .into_owned()
    };
    let stderr_path = if let Some(path) = merged.stderr_path.as_deref() {
        validate_shared_output_path(path, &submitter_cwd, config)?
    } else {
        output_root
            .join("%j/stderr.log")
            .to_string_lossy()
            .into_owned()
    };
    if stdout_path == stderr_path {
        return Err((2, "stdout and stderr paths must be different".into()));
    }

    let inherited_env = inherited_task_environment();
    let validate_active_environment =
        should_validate_active_environment_for_command(&merged, &inherited_env, &submitter_cwd);
    let name = merged
        .name
        .or_else(|| {
            options
                .script
                .as_ref()
                .and_then(|path| path.file_stem())
                .and_then(OsStr::to_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| {
            if merged.interactive {
                "interactive".into()
            } else {
                "wrap".into()
            }
        });
    let mut task_env = prepare_task_environment_with_policy(
        config,
        inherited_env,
        merged.env,
        validate_active_environment,
    )?;
    if merged.verbose {
        task_env.insert(VERBOSE_TASK_LOG_ENV.into(), "1".into());
        task_env.insert(
            VERBOSE_TASK_LOG_ROOT_ENV.into(),
            config.shared_root.to_string_lossy().into_owned(),
        );
    }
    let spec = JobSpec {
        storage_namespace: Some(storage_namespace),
        queue,
        node: merged.node,
        name,
        cwd: cwd.to_string_lossy().into_owned(),
        stdout_path,
        stderr_path,
        walltime_secs: merged.walltime_secs,
        env: task_env,
        mode: if merged.interactive {
            JobMode::Interactive
        } else {
            JobMode::Batch
        },
        snapshot: None,
    };
    for output in [&spec.stdout_path, &spec.stderr_path] {
        if [&shared_root, &config.shared_root]
            .into_iter()
            .any(|root| spec.verbose_log_output_conflicts(root, Path::new(output)))
        {
            return Err((
                2,
                format!(
                    "output path {output} is reserved for verbose task logs; choose a different stdout/stderr path"
                ),
            ));
        }
    }
    Ok((spec, script))
}

fn promote_inline_command(mut options: SubmitOptions) -> SubmitOptions {
    let Some(script) = options.script.as_ref() else {
        return options;
    };
    if script.exists() {
        return options;
    }
    let command = script.to_string_lossy().into_owned();
    if command.is_empty() {
        return options;
    }
    let has_arguments = command.chars().any(char::is_whitespace);
    if !has_arguments
        && (command.contains('/') || command.starts_with('.') || command.starts_with('~'))
    {
        return options;
    }
    let command_exists = has_arguments || is_command_available(&command, &options.env);
    if command_exists {
        options.script = None;
        options.wrap = Some(command);
    }
    options
}

fn is_command_available(command: &str, overrides: &BTreeMap<String, String>) -> bool {
    const SHELL_BUILTINS: &[&str] = &[
        "alias", "cd", "echo", "eval", "export", "false", "printf", "pwd", "read", "set", "source",
        "test", "true", "type", "umask", "unalias", "unset", "wait",
    ];
    SHELL_BUILTINS.contains(&command)
        || overrides
            .get("PATH")
            .map(|path| OsString::from(path.as_str()))
            .or_else(|| env::var_os("PATH"))
            .is_some_and(|paths| {
                env::split_paths(&paths).any(|directory| directory.join(command).is_file())
            })
        || ["VIRTUAL_ENV", "CONDA_PREFIX"].into_iter().any(|key| {
            let prefix = overrides.get(key).cloned().or_else(|| env::var(key).ok());
            prefix.as_deref().is_some_and(|prefix| {
                !prefix.is_empty() && Path::new(prefix).join("bin").join(command).is_file()
            })
        })
}

fn inherited_task_environment() -> BTreeMap<String, String> {
    let cargo_build_context = env::var_os("CARGO_MANIFEST_DIR").is_some();
    const NODE_LOCAL_ENV: &[&str] = &[
        "HOME",
        "USER",
        "LOGNAME",
        "PWD",
        "OLDPWD",
        "TMPDIR",
        "TMP",
        "TEMP",
        "TERM_PROGRAM",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SHLVL",
        // Cargo exports this pointer while running build scripts and test
        // binaries. It identifies the parent Cargo process, not a cluster
        // tool that a task can safely reuse on another node.
        "CARGO",
        "CARGO_MANIFEST_DIR",
        "CARGO_MANIFEST_PATH",
        "CARGO_TARGET_TMPDIR",
        "CARGO_CRATE_NAME",
        "CARGO_PRIMARY_PACKAGE",
        "OUT_DIR",
        "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR",
        "_",
    ];

    env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            if NODE_LOCAL_ENV.contains(&key.as_str())
                || (cargo_build_context
                    && matches!(
                        key.as_str(),
                        "CARGO_HOME"
                            | "RUSTUP_HOME"
                            | "RUSTC"
                            | "DYLD_LIBRARY_PATH"
                            | "DYLD_FALLBACK_LIBRARY_PATH"
                    ))
                || key.starts_with("CARGO_PKG_")
                || key.starts_with("CARGO_BIN_EXE_")
                || key.starts_with("ZSH_")
                || key.starts_with("POWERLEVEL9K_")
                || key.starts_with("OH_MY_ZSH")
                || key.starts_with("STARSHIP_")
                || key.starts_with("MCLUSTER_")
            {
                return None;
            }
            Some((key, value.into_string().ok()?))
        })
        .collect()
}

#[cfg(test)]
fn prepare_task_environment(
    config: &ClusterConfig,
    task_env: BTreeMap<String, String>,
    overrides: BTreeMap<String, String>,
) -> AppResult<BTreeMap<String, String>> {
    prepare_task_environment_with_policy(config, task_env, overrides, true)
}

fn prepare_task_environment_with_policy(
    config: &ClusterConfig,
    mut task_env: BTreeMap<String, String>,
    overrides: BTreeMap<String, String>,
    should_validate_active_environment: bool,
) -> AppResult<BTreeMap<String, String>> {
    let explicit_path = overrides.contains_key("PATH");
    let explicit_env_keys = overrides.keys().cloned().collect::<Vec<_>>();
    let explicit_cache_paths = overrides
        .keys()
        .filter(|key| {
            matches!(
                key.as_str(),
                "CARGO_TARGET_DIR" | "CARGO_HOME" | "CCACHE_DIR" | "SCCACHE_DIR"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    task_env.extend(overrides);
    // Match cc-rs's source parser mode. Enabling shell parsing implicitly can
    // remove literal quotes from string macros that compiled on the login Mac.
    let cc_shell_escaped_flags = task_env
        .get("CC_SHELL_ESCAPED_FLAGS")
        .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "no"));
    if explicit_path {
        task_env.insert(EXPLICIT_TASK_PATH_ENV.into(), "1".into());
    }
    let selected_prefix = if should_validate_active_environment && !explicit_path {
        select_active_environment(&task_env)?
    } else {
        None
    };
    let selected_prefix = selected_prefix
        .as_deref()
        .map(|prefix| validate_active_environment(config, prefix))
        .transpose()?;

    let login_path = task_env.get("PATH").cloned().unwrap_or_default();
    for (key, value) in &mut task_env {
        if matches!(
            key.as_str(),
            "CARGO_TARGET_DIR" | "CARGO_HOME" | "CCACHE_DIR" | "SCCACHE_DIR"
        ) && !explicit_cache_paths.contains(key)
            && Path::new(value).is_absolute()
            && remap_shared_path(config, Path::new(value)).is_none()
        {
            eprintln!(
                "macluster: {key} points outside configured shares; using this compute node's private cache"
            );
            value.clear();
        }
        if is_optional_software_metadata_variable(key)
            && !explicit_env_keys.contains(key)
            && Path::new(value).is_absolute()
            && remap_shared_path(config, Path::new(value)).is_none()
        {
            value.clear();
        }
        *value = remap_task_environment_value(
            config,
            key,
            value,
            if explicit_path {
                None
            } else {
                selected_prefix.as_deref()
            },
            &login_path,
            cc_shell_escaped_flags,
        )?;
    }
    if !explicit_path && let Some(prefix) = selected_prefix.as_ref() {
        task_env.insert(
            ACTIVE_ENV_PREFIX_ENV.into(),
            prefix.to_string_lossy().into_owned(),
        );
    }
    if !task_env.contains_key("PATH")
        && let Some(path) = env::var_os("PATH")
    {
        task_env.insert("PATH".into(), path.to_string_lossy().into_owned());
    }
    if !explicit_path && let Some(prefix) = selected_prefix {
        let bin = prefix.join("bin").to_string_lossy().into_owned();
        let path = task_env.entry("PATH".into()).or_default();
        let remainder = path
            .split(':')
            .filter(|entry| !entry.is_empty() && *entry != bin)
            .collect::<Vec<_>>()
            .join(":");
        *path = if remainder.is_empty() {
            bin
        } else {
            format!("{bin}:{remainder}")
        };
    }
    Ok(task_env)
}

fn should_validate_active_environment_for_command(
    options: &SubmitOptions,
    inherited_environment: &BTreeMap<String, String>,
    working_directory: &Path,
) -> bool {
    if options.env.contains_key("PATH") {
        return false;
    }
    let Some(command) = options.wrap.as_deref() else {
        return true;
    };
    if command.chars().any(|character| {
        matches!(
            character,
            ';' | '|' | '&' | '>' | '<' | '\n' | '\r' | '$' | '`'
        )
    }) {
        return true;
    }
    let mut environment = inherited_environment.clone();
    environment.extend(options.env.clone());
    let Ok(Some(prefix)) = select_active_environment(&environment) else {
        return false;
    };
    let prefix = prefix.canonicalize().unwrap_or(prefix);
    let Ok(words) = tokenize_shell_words(command) else {
        return true;
    };
    let Some(executable) = words.first() else {
        return true;
    };
    let basename = Path::new(executable)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(executable);
    if matches!(basename, "sh" | "bash" | "zsh" | "env" | "command" | "exec") {
        return true;
    }
    let candidate = if Path::new(executable).is_absolute() {
        Some(PathBuf::from(executable))
    } else if executable.contains('/') {
        Some(working_directory.join(executable))
    } else {
        environment
            .get("PATH")
            .into_iter()
            .flat_map(|path| path.split(':'))
            .filter(|path| !path.is_empty())
            .map(|path| Path::new(path).join(executable))
            .find(|path| path.is_file())
            .or_else(|| {
                prefix
                    .join("bin")
                    .join(executable)
                    .is_file()
                    .then(|| prefix.join("bin").join(executable))
            })
    };
    let Some(candidate) = candidate else {
        return false;
    };
    let candidate_is_in_prefix = candidate.starts_with(&prefix)
        || candidate
            .canonicalize()
            .is_ok_and(|resolved| resolved.starts_with(&prefix));
    if !candidate_is_in_prefix {
        return false;
    }
    let python_named =
        basename.starts_with("python") || basename.starts_with("pip") || basename == "ipython";
    python_named || executable_has_python_shebang(&candidate)
}

fn executable_has_python_shebang(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    let mut reader = io::BufReader::new(file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .is_ok_and(|_| line.starts_with("#!") && line.to_ascii_lowercase().contains("python"))
}

fn is_optional_software_metadata_variable(key: &str) -> bool {
    matches!(
        key,
        "HOMEBREW_PREFIX"
            | "HOMEBREW_CELLAR"
            | "HOMEBREW_REPOSITORY"
            | "HOMEBREW_CACHE"
            | "HOMEBREW_LOGS"
            | "HOMEBREW_TEMP"
            | "MAMBA_ROOT_PREFIX"
            | "MAMBA_EXE"
            | "CONDA_EXE"
    )
}

fn select_active_environment(environment: &BTreeMap<String, String>) -> AppResult<Option<PathBuf>> {
    let candidates: Vec<_> = ["VIRTUAL_ENV", "CONDA_PREFIX"]
        .into_iter()
        .filter_map(|key| {
            let value = environment.get(key)?.trim();
            (!value.is_empty()).then(|| (key, PathBuf::from(value)))
        })
        .collect();
    if candidates.is_empty() {
        return Ok(None);
    }

    let canonical_bins: Vec<_> = candidates
        .iter()
        .map(|(_, prefix)| {
            prefix
                .canonicalize()
                .ok()
                .and_then(|prefix| prefix.join("bin").canonicalize().ok())
        })
        .collect();
    if let Some(path) = environment.get("PATH") {
        for entry in path.split(':').filter(|entry| !entry.is_empty()) {
            let Ok(entry) = Path::new(entry).canonicalize() else {
                continue;
            };
            if let Some((index, _)) = canonical_bins
                .iter()
                .enumerate()
                .find(|(_, bin)| bin.as_ref() == Some(&entry))
            {
                return Ok(Some(candidates[index].1.clone()));
            }
        }
    }
    Ok(candidates.first().map(|(_, prefix)| prefix.clone()))
}

fn validate_active_environment(config: &ClusterConfig, raw_prefix: &Path) -> AppResult<PathBuf> {
    if !raw_prefix.is_absolute() {
        return Err((
            2,
            format!(
                "active environment {} must use an absolute path",
                raw_prefix.display()
            ),
        ));
    }
    let prefix = raw_prefix.canonicalize().map_err(|error| {
        (
            2,
            format!(
                "active environment {} is unavailable: {error}; mount its software share before submitting",
                raw_prefix.display()
            ),
        )
    })?;
    let mut matched = None;
    for mapping in submission_path_mappings(config) {
        let Some(visible_root) = mapping.canonical_visible_root else {
            continue;
        };
        let Ok(relative) = prefix.strip_prefix(&visible_root) else {
            continue;
        };
        matched = Some((visible_root, mapping.target_root.join(relative)));
        break;
    }
    let Some((share_root, mount_prefix)) = matched else {
        return Err((
            2,
            format!(
                "active environment {} is outside every configured shared path; register it with `mnode -a local:PATH --share-id ID --mount-root PATH`",
                raw_prefix.display()
            ),
        ));
    };
    let mounted_prefix =
        canonicalize_with_missing_suffix(&mount_prefix).unwrap_or_else(|| mount_prefix.clone());
    if mounted_prefix != prefix {
        return Err((
            2,
            format!(
                "active environment {} maps to {}, but software environments must use the same absolute path on every node; register the share with --mount-root {}",
                raw_prefix.display(),
                mount_prefix.display(),
                raw_prefix.display()
            ),
        ));
    }

    let bin = prefix.join("bin").canonicalize().map_err(|error| {
        (
            2,
            format!(
                "active environment {} has no usable bin directory: {error}",
                raw_prefix.display()
            ),
        )
    })?;
    if !bin.starts_with(&share_root) {
        return Err((
            2,
            format!(
                "active environment {} has a bin directory that escapes its registered shared path",
                raw_prefix.display()
            ),
        ));
    }
    for interpreter_name in ["python", "python3"] {
        let interpreter = bin.join(interpreter_name);
        match fs::symlink_metadata(&interpreter) {
            Ok(_) => {
                let canonical = interpreter.canonicalize().map_err(|error| {
                    (
                        2,
                        format!(
                            "active environment {} has an unusable bin/{interpreter_name}: {error}",
                            raw_prefix.display()
                        ),
                    )
                })?;
                if !canonical.is_file() || !canonical.starts_with(&share_root) {
                    return Err((
                        2,
                        format!(
                            "active environment {} has a bin/{interpreter_name} that escapes or is not a file within its registered share",
                            raw_prefix.display()
                        ),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err((
                    2,
                    format!(
                        "cannot inspect active environment {} bin/{interpreter_name}: {error}",
                        raw_prefix.display()
                    ),
                ));
            }
        }
    }
    Ok(prefix)
}

fn shared_path_mappings(config: &ClusterConfig) -> Vec<(PathBuf, PathBuf)> {
    let primary_is_local = config
        .nodes
        .get(config.storage_server.as_str())
        .is_some_and(|node| node.transport == Transport::Local);
    let mut mappings = vec![(
        if primary_is_local {
            config.primary_source_root().to_path_buf()
        } else {
            config.shared_root.clone()
        },
        config.shared_root.clone(),
    )];
    mappings.extend(config.shares.values().map(|share| {
        let local_server = config
            .nodes
            .get(share.server.as_str())
            .is_some_and(|node| node.transport == Transport::Local);
        (
            if local_server {
                share.source_root.clone()
            } else {
                share.mount_root.clone()
            },
            share.mount_root.clone(),
        )
    }));
    mappings
}

#[derive(Clone)]
struct SharedPathMapping {
    visible_root: PathBuf,
    canonical_visible_root: Option<PathBuf>,
    canonical_error: Option<String>,
    target_root: PathBuf,
}

struct SubmissionPathResolver {
    mappings: Vec<SharedPathMapping>,
    mapped_paths: RefCell<HashMap<PathBuf, Option<PathBuf>>>,
    invocation_paths: RefCell<HashMap<PathBuf, Option<PathBuf>>>,
}

impl SubmissionPathResolver {
    fn new(config: &ClusterConfig) -> Self {
        let mappings = shared_path_mappings(config)
            .into_iter()
            .map(|(visible_root, target_root)| {
                let canonical = visible_root.canonicalize();
                SharedPathMapping {
                    canonical_visible_root: canonical.as_ref().ok().cloned(),
                    canonical_error: canonical.err().map(|error| error.to_string()),
                    visible_root,
                    target_root,
                }
            })
            .collect();
        Self {
            mappings,
            mapped_paths: RefCell::new(HashMap::new()),
            invocation_paths: RefCell::new(HashMap::new()),
        }
    }

    fn remap(&self, path: &Path) -> Option<PathBuf> {
        if let Some(cached) = self.mapped_paths.borrow().get(path) {
            return cached.clone();
        }
        let mapped = canonicalize_with_missing_suffix(path)
            .and_then(|resolved| self.remap_canonical(&resolved));
        self.mapped_paths
            .borrow_mut()
            .insert(path.to_path_buf(), mapped.clone());
        mapped
    }

    fn remap_canonical(&self, resolved_path: &Path) -> Option<PathBuf> {
        self.mappings.iter().find_map(|mapping| {
            let root = mapping.canonical_visible_root.as_ref()?;
            let relative = resolved_path.strip_prefix(root).ok()?;
            Some(if relative.as_os_str().is_empty() {
                mapping.target_root.clone()
            } else {
                mapping.target_root.join(relative)
            })
        })
    }

    fn remap_invocation(&self, path: &Path) -> Option<PathBuf> {
        if let Some(cached) = self.invocation_paths.borrow().get(path) {
            return cached.clone();
        }
        let mapped = canonicalize_parent_preserving_leaf(path)
            .and_then(|resolved| self.remap_canonical(&resolved));
        self.invocation_paths
            .borrow_mut()
            .insert(path.to_path_buf(), mapped.clone());
        mapped
    }

    fn mappings(&self) -> &[SharedPathMapping] {
        &self.mappings
    }
}

fn submission_path_mappings(config: &ClusterConfig) -> Vec<SharedPathMapping> {
    SUBMISSION_PATH_RESOLVER.with(|cell| {
        if let Some(resolver) = cell.borrow().as_ref() {
            resolver.mappings().to_vec()
        } else {
            SubmissionPathResolver::new(config).mappings
        }
    })
}

thread_local! {
    static SUBMISSION_PATH_RESOLVER: RefCell<Option<SubmissionPathResolver>> = const { RefCell::new(None) };
}

struct SubmissionPathResolverGuard {
    previous: Option<SubmissionPathResolver>,
}

impl SubmissionPathResolverGuard {
    fn enter(config: &ClusterConfig) -> Self {
        let resolver = SubmissionPathResolver::new(config);
        let previous = SUBMISSION_PATH_RESOLVER.with(|cell| cell.replace(Some(resolver)));
        Self { previous }
    }
}

impl Drop for SubmissionPathResolverGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        SUBMISSION_PATH_RESOLVER.with(|cell| {
            cell.replace(previous);
        });
    }
}

fn canonicalize_with_missing_suffix(path: &Path) -> Option<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().ok()?.join(path)
    };
    let mut cursor = absolute.as_path();
    let mut suffix = Vec::new();
    loop {
        if let Ok(mut resolved) = cursor.canonicalize() {
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return Some(resolved);
        }
        suffix.push(cursor.file_name()?.to_os_string());
        cursor = cursor.parent()?;
    }
}

fn remap_shared_path(config: &ClusterConfig, path: &Path) -> Option<PathBuf> {
    SUBMISSION_PATH_RESOLVER.with(|cell| {
        if let Some(resolver) = cell.borrow().as_ref() {
            resolver.remap(path)
        } else {
            SubmissionPathResolver::new(config).remap(path)
        }
    })
}

// Resolve parent-directory aliases while retaining the final filename. Compiler
// shims such as rustup's `rustc` are symlinks whose name is part of their
// invocation contract (`argv[0]`).
fn canonicalize_parent_preserving_leaf(path: &Path) -> Option<PathBuf> {
    let leaf = path.file_name()?;
    Some(path.parent()?.canonicalize().ok()?.join(leaf))
}

fn remap_shared_invocation_path(config: &ClusterConfig, path: &Path) -> Option<PathBuf> {
    SUBMISSION_PATH_RESOLVER.with(|cell| {
        if let Some(resolver) = cell.borrow().as_ref() {
            resolver.remap_invocation(path)
        } else {
            SubmissionPathResolver::new(config).remap_invocation(path)
        }
    })
}

const COMPILER_EXECUTABLE_VARIABLES: &[&str] = &[
    "CC",
    "CXX",
    "CPP",
    "AR",
    "AS",
    "LD",
    "RANLIB",
    "NM",
    "STRIP",
    "FC",
    "F77",
    "F90",
    "OBJC",
    "OBJCXX",
    "MAKE",
    "NINJA",
    "PKG_CONFIG",
    "CMAKE_C_COMPILER",
    "CMAKE_CXX_COMPILER",
    "CMAKE_OBJC_COMPILER",
    "CMAKE_OBJCXX_COMPILER",
    "CMAKE_Fortran_COMPILER",
    "CMAKE_C_COMPILER_LAUNCHER",
    "CMAKE_CXX_COMPILER_LAUNCHER",
    "CMAKE_C_COMPILER_AR",
    "CMAKE_CXX_COMPILER_AR",
    "CMAKE_C_COMPILER_RANLIB",
    "CMAKE_CXX_COMPILER_RANLIB",
    "CMAKE_LINKER",
    "CMAKE_AR",
    "CMAKE_RANLIB",
    "CMAKE_OBJCOPY",
    "CMAKE_OBJDUMP",
    "CMAKE_MAKE_PROGRAM",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC",
    "RUSTDOC",
    "CARGO",
    "CMAKE",
    "PROTOC",
    "PYTHON",
    "PYTHON3",
    "PYO3_PYTHON",
    "PYTHON_SYS_EXECUTABLE",
    "GO",
    "GCC",
    "GXX",
    "NVCC",
    "CUDACXX",
    "CUDAHOSTCXX",
];

const COMPILER_FLAG_VARIABLES: &[&str] = &[
    "CFLAGS",
    "CPPFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "FFLAGS",
    "FCFLAGS",
    "OBJCFLAGS",
    "OBJCXXFLAGS",
];

const COMPILER_PATH_LIST_VARIABLES: &[&str] = &[
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "LIBRARY_PATH",
    "COMPILER_PATH",
    "CMAKE_PREFIX_PATH",
    "CMAKE_MODULE_PATH",
    "CMAKE_FRAMEWORK_PATH",
    "CMAKE_INCLUDE_PATH",
    "CMAKE_LIBRARY_PATH",
    "CMAKE_PROGRAM_PATH",
    "PKG_CONFIG_PATH",
    "PKG_CONFIG_LIBDIR",
    "CONDA_ENVS_PATH",
];

const COMPILER_SINGLE_PATH_VARIABLES: &[&str] = &[
    "SDKROOT",
    "DEVELOPER_DIR",
    "GCC_EXEC_PREFIX",
    "CONDA_BUILD_SYSROOT",
    "CMAKE_TOOLCHAIN_FILE",
    "CMAKE_SYSROOT",
    "CMAKE_OSX_SYSROOT",
    "OPENSSL_DIR",
    "VCPKG_ROOT",
    "ZLIB_ROOT",
    "CUDA_HOME",
    "CUDA_PATH",
    "LIBCLANG_PATH",
    "PROTOC_INCLUDE",
];

fn remap_task_environment_value(
    config: &ClusterConfig,
    key: &str,
    value: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
    cc_shell_escaped_flags: bool,
) -> AppResult<String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    if key == "CC_SHELL_ESCAPED_FLAGS" {
        return Ok(value.to_owned());
    }
    if matches!(
        key,
        "DYLD_LIBRARY_PATH" | "DYLD_FALLBACK_LIBRARY_PATH" | "LD_LIBRARY_PATH"
    ) {
        return Ok(filter_runtime_library_path(config, value));
    }
    if is_build_executable_variable(key) {
        return remap_compiler_command(config, key, value, active_prefix, login_path);
    }
    if is_build_flag_variable(key) {
        if key == "CARGO_ENCODED_RUSTFLAGS" {
            return remap_encoded_rustflags(config, value, active_prefix, login_path);
        }
        return remap_compiler_flags(
            config,
            key,
            value,
            active_prefix,
            login_path,
            cc_shell_escaped_flags,
        );
    }
    if is_build_path_list_variable(key) {
        return remap_compiler_path_list(config, key, value);
    }
    if is_build_single_path_variable(key) {
        return remap_compiler_path(config, key, value);
    }
    Ok(remap_environment_paths(config, key, value))
}

fn filter_runtime_library_path(config: &ClusterConfig, value: &str) -> String {
    const SYSTEM_LIBRARY_PATHS: &[&str] = &[
        "/usr/lib",
        "/System/Library/Frameworks",
        "/System/Library/PrivateFrameworks",
    ];
    value
        .split(':')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            remap_shared_path(config, Path::new(entry))
                .map(|path| path.to_string_lossy().into_owned())
                .or_else(|| {
                    SYSTEM_LIBRARY_PATHS
                        .iter()
                        .any(|root| Path::new(entry).starts_with(root))
                        .then(|| entry.to_owned())
                })
        })
        .collect::<Vec<_>>()
        .join(":")
}

fn is_build_executable_variable(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if COMPILER_EXECUTABLE_VARIABLES
        .iter()
        .any(|known| upper == known.to_ascii_uppercase())
    {
        return true;
    }
    is_target_variant_variable(
        &upper,
        &[
            "CC", "CXX", "CPP", "AR", "AS", "LD", "RANLIB", "NM", "STRIP", "FC", "F77", "F90",
            "OBJC", "OBJCXX",
        ],
    ) || upper.starts_with("CARGO_TARGET_")
        && (upper.ends_with("_LINKER") || upper.ends_with("_RUNNER") || upper.ends_with("_AR"))
}

fn is_build_flag_variable(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    COMPILER_FLAG_VARIABLES
        .iter()
        .any(|known| upper == known.to_ascii_uppercase())
        || matches!(upper.as_str(), "RUSTFLAGS" | "CARGO_ENCODED_RUSTFLAGS")
        || upper == "BINDGEN_EXTRA_CLANG_ARGS"
        || is_target_variant_variable(&upper, COMPILER_FLAG_VARIABLES)
        || (upper.starts_with("CARGO_TARGET_") && upper.ends_with("_RUSTFLAGS"))
}

fn is_build_path_list_variable(key: &str) -> bool {
    COMPILER_PATH_LIST_VARIABLES
        .iter()
        .any(|known| key.eq_ignore_ascii_case(known))
        || key.eq_ignore_ascii_case("GOPATH")
}

fn is_build_single_path_variable(key: &str) -> bool {
    COMPILER_SINGLE_PATH_VARIABLES
        .iter()
        .any(|known| key.eq_ignore_ascii_case(known))
        || matches!(
            key,
            "CARGO_HOME"
                | "RUSTUP_HOME"
                | "CARGO_TARGET_DIR"
                | "CCACHE_DIR"
                | "SCCACHE_DIR"
                | "GOPATH"
                | "GOBIN"
                | "GOROOT"
        )
}

fn is_target_variant_variable(key: &str, bases: &[&str]) -> bool {
    bases.iter().any(|base| {
        key.strip_prefix(&format!("{base}_"))
            .is_some_and(is_target_triple_suffix)
            || ["HOST_", "TARGET_"]
                .iter()
                .any(|scope| key == format!("{scope}{base}"))
    })
}

fn is_target_triple_suffix(target: &str) -> bool {
    const TARGET_ARCHITECTURES: &[&str] = &[
        "AARCH64",
        "ARM64",
        "X86_64",
        "I386",
        "I486",
        "I586",
        "I686",
        "WASM32",
        "WASM64",
        "RISCV32",
        "RISCV64",
        "POWERPC",
        "POWERPC64",
        "PPC",
        "PPC64",
        "S390X",
        "SPARC64",
        "MIPS",
        "MIPSEL",
        "LOONGARCH64",
        "HEXAGON",
    ];
    let upper = target.to_ascii_uppercase();
    TARGET_ARCHITECTURES.iter().any(|architecture| {
        upper.strip_prefix(architecture).is_some_and(|remainder| {
            remainder.is_empty() || remainder.starts_with('_') || remainder.starts_with('-')
        })
    }) || upper.strip_prefix("ARMV").is_some_and(|remainder| {
        remainder
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
    })
}

fn remap_compiler_command(
    config: &ClusterConfig,
    key: &str,
    value: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
) -> AppResult<String> {
    let mut words = tokenize_shell_words(value).map_err(|_| {
        (
            2,
            format!("{key} must be a valid shell-style executable and argument list"),
        )
    })?;
    if words.is_empty() {
        return Ok(String::new());
    }
    let mut executable_positions = vec![0];
    let wrapper = Path::new(&words[0])
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    let command_arguments_start = if matches!(wrapper, "ccache" | "sccache" | "distcc") {
        if let Some(position) = words
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(position, word)| (!word.starts_with('-')).then_some(position))
        {
            executable_positions.push(position);
            position + 1
        } else {
            words.len()
        }
    } else {
        1
    };
    for position in executable_positions {
        words[position] =
            resolve_compiler_executable(config, key, &words[position], active_prefix, login_path)?;
    }
    if command_arguments_start < words.len() {
        let arguments = words.split_off(command_arguments_start);
        words.extend(remap_compiler_flag_words(
            config,
            key,
            arguments,
            active_prefix,
            login_path,
        )?);
    }
    // Toolchain variables such as CXX are parsed by consumers like cc-rs with
    // whitespace splitting. Shell-quoting each word here leaves literal quote
    // characters in the environment value, so cc-rs searches for a compiler
    // whose filename includes those quotes.
    Ok(words.join(" "))
}

fn resolve_compiler_executable(
    config: &ClusterConfig,
    variable: &str,
    command: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
) -> AppResult<String> {
    let command_path = Path::new(command);
    let resolved = if command_path.is_absolute() {
        Some(command_path.to_path_buf())
    } else if command.contains('/') {
        Some(
            env::current_dir()
                .map_err(|error| (1, error.to_string()))?
                .join(command),
        )
    } else {
        active_prefix
            .map(|prefix| prefix.join("bin").join(command))
            .filter(|path| path.is_file())
            .or_else(|| {
                login_path
                    .split(':')
                    .filter(|entry| !entry.is_empty())
                    .map(|entry| Path::new(entry).join(command))
                    .find(|path| path.is_file())
            })
    };
    let Some(resolved) = resolved else {
        return Err((
            2,
            format!(
                "configured tool {command:?} in {variable} is not available on the login PATH or active environment"
            ),
        ));
    };
    if !resolved.is_file() {
        return Err((
            2,
            format!(
                "configured tool path {} in {variable} does not name a file",
                resolved.display()
            ),
        ));
    }
    let invocation = canonicalize_parent_preserving_leaf(&resolved).ok_or_else(|| {
        (
            2,
            format!(
                "cannot resolve the parent directory for configured tool {} in {variable}",
                resolved.display()
            ),
        )
    })?;
    let resolved = resolved.canonicalize().map_err(|error| {
        (
            2,
            format!(
                "cannot resolve configured tool {} in {variable}: {error}",
                resolved.display()
            ),
        )
    })?;
    if let Some(mount_path) = remap_shared_invocation_path(config, &invocation) {
        let mount_path =
            canonicalize_parent_preserving_leaf(&mount_path).unwrap_or_else(|| mount_path.clone());
        if mount_path != invocation {
            return Err((
                2,
                format!(
                    "configured tool {} in {variable} maps to {}, but toolchain executables must use the same absolute path on every node; register its share with --mount-root {}",
                    invocation.display(),
                    mount_path.display(),
                    invocation.display()
                ),
            ));
        }
        if let Some(mapped_target) = remap_shared_path(config, &resolved) {
            let mapped_target = canonicalize_with_missing_suffix(&mapped_target)
                .unwrap_or_else(|| mapped_target.clone());
            if mapped_target != resolved {
                return Err((
                    2,
                    format!(
                        "configured tool {} in {variable} resolves to {}, which does not keep the same absolute path on every node; register the toolchain with a matching mount path",
                        invocation.display(),
                        resolved.display()
                    ),
                ));
            }
        } else if !is_portable_system_toolchain_path(&resolved) {
            return Err(unshared_build_path_error(variable, &resolved));
        }
        return Ok(invocation.to_string_lossy().into_owned());
    }
    if is_portable_system_toolchain_path(&invocation)
        && is_portable_system_toolchain_path(&resolved)
    {
        return Ok(invocation.to_string_lossy().into_owned());
    }
    Err(unshared_build_path_error(variable, &resolved))
}

fn remap_compiler_flags(
    config: &ClusterConfig,
    key: &str,
    value: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
    cc_shell_escaped_flags: bool,
) -> AppResult<String> {
    let rustflags =
        key == "RUSTFLAGS" || (key.starts_with("CARGO_TARGET_") && key.ends_with("_RUSTFLAGS"));
    // Cargo splits these variables on whitespace and does not remove shell
    // quotes. In particular, --cfg name="value" must keep its double quotes.
    let words = if rustflags {
        value.split_whitespace().map(str::to_owned).collect()
    } else if is_cc_rs_flags_variable(key) && !cc_shell_escaped_flags {
        value.split_ascii_whitespace().map(str::to_owned).collect()
    } else {
        tokenize_shell_words(value).map_err(|_| {
            (
                2,
                format!("{key} contains invalid shell-style compiler flags"),
            )
        })?
    };
    let words = remap_compiler_flag_words(config, key, words, active_prefix, login_path)?;
    if rustflags {
        if words
            .iter()
            .any(|word| word.chars().any(char::is_whitespace))
        {
            return Err((
                2,
                format!(
                    "{key} maps to an argument containing whitespace; use CARGO_ENCODED_RUSTFLAGS to preserve argument boundaries"
                ),
            ));
        }
        return Ok(words.join(" "));
    }
    if is_cc_rs_flags_variable(key) {
        if cc_shell_escaped_flags {
            return Ok(quote_argv(&words));
        }
        if words
            .iter()
            .any(|word| word.chars().any(char::is_whitespace))
        {
            return Err((
                2,
                format!(
                    "{key} contains a flag with spaces but CC_SHELL_ESCAPED_FLAGS is disabled; enable it to preserve the flag argument"
                ),
            ));
        }
        return Ok(words.join(" "));
    }
    Ok(quote_argv(&words))
}

fn is_cc_rs_flags_variable(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    ["CFLAGS", "CXXFLAGS"].iter().any(|base| {
        upper == *base
            || is_target_variant_variable(&upper, &[*base])
            || upper == format!("HOST_{base}")
            || upper == format!("TARGET_{base}")
    })
}

fn remap_compiler_flag_words(
    config: &ClusterConfig,
    key: &str,
    mut words: Vec<String>,
    active_prefix: Option<&Path>,
    login_path: &str,
) -> AppResult<Vec<String>> {
    const SEPARATE_PATH_FLAGS: &[&str] = &[
        "-isysroot",
        "--sysroot",
        "-isystem",
        "-iquote",
        "-idirafter",
        "-iframework",
        "-include",
        "-imacros",
        "-I",
        "-L",
        "-F",
        "-B",
        "--extern",
        "-resource-dir",
        "--gcc-toolchain",
    ];
    const JOINED_PATH_FLAGS: &[&str] = &[
        "--sysroot=",
        "-isysroot",
        "-isystem",
        "-iquote",
        "-idirafter",
        "-iframework",
        "-I",
        "-L",
        "-F",
        "-B",
        "-resource-dir=",
        "--gcc-toolchain=",
        "--extern=",
        "-fuse-ld=",
    ];
    let mut expect_path: Option<String> = None;
    let mut expect_codegen = false;
    for word in &mut words {
        if let Some(flag) = expect_path.as_deref() {
            *word = if flag == "--extern" {
                remap_rust_extern(config, key, word)?
            } else {
                remap_compiler_flag_path(config, key, word)?
            };
            expect_path = None;
            continue;
        }
        if expect_codegen {
            *word = remap_rust_codegen_option(config, key, word, active_prefix, login_path)?;
            expect_codegen = false;
            continue;
        }
        if word == "-C" {
            expect_codegen = true;
            continue;
        }
        if SEPARATE_PATH_FLAGS.contains(&word.as_str()) {
            expect_path = Some(word.clone());
            continue;
        }
        if let Some((flag, path)) = JOINED_PATH_FLAGS.iter().find_map(|flag| {
            word.strip_prefix(flag)
                .map(|path| (*flag, path))
                .filter(|(_, path)| !path.is_empty())
        }) {
            let mapped = if flag == "--extern=" {
                remap_rust_extern(config, key, path)?
            } else {
                remap_compiler_flag_path(config, key, path)?
            };
            *word = format!("{flag}{mapped}");
            continue;
        }
        *word = remap_single_compiler_flag(config, key, word, active_prefix, login_path)?;
    }
    if let Some(flag) = expect_path {
        return Err((2, format!("{key} ends with {flag}, which requires a path")));
    }
    if expect_codegen {
        return Err((2, format!("{key} ends with -C, which requires an option")));
    }
    Ok(words)
}

fn remap_encoded_rustflags(
    config: &ClusterConfig,
    value: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
) -> AppResult<String> {
    let words = value.split('\u{1f}').map(str::to_owned).collect::<Vec<_>>();
    remap_compiler_flag_words(
        config,
        "CARGO_ENCODED_RUSTFLAGS",
        words,
        active_prefix,
        login_path,
    )
    .map(|arguments| arguments.join("\u{1f}"))
}

fn remap_single_compiler_flag(
    config: &ClusterConfig,
    key: &str,
    argument: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
) -> AppResult<String> {
    if let Some(codegen) = argument.strip_prefix("-C") {
        if !codegen.is_empty() {
            return Ok(format!(
                "-C{}",
                remap_rust_codegen_option(config, key, codegen, active_prefix, login_path)?
            ));
        }
    }
    if let Some(codegen) = argument.strip_prefix("-C=") {
        return Ok(format!(
            "-C={}",
            remap_rust_codegen_option(config, key, codegen, active_prefix, login_path)?
        ));
    }
    if argument.starts_with("-Wl,") {
        let mut linker_args = argument[4..]
            .split(',')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        remap_linker_arguments(config, key, &mut linker_args)?;
        return Ok(format!("-Wl,{}", linker_args.join(",")));
    }
    const JOINED_PATH_FLAGS: &[&str] = &[
        "--sysroot=",
        "--gcc-toolchain=",
        "-resource-dir=",
        "--extern=",
        "-isysroot",
        "-isystem",
        "-iquote",
        "-idirafter",
        "-iframework",
        "-I",
        "-L",
        "-F",
        "-B",
        "-fuse-ld=",
    ];
    if let Some((flag, path)) = JOINED_PATH_FLAGS.iter().find_map(|flag| {
        argument
            .strip_prefix(flag)
            .map(|path| (*flag, path))
            .filter(|(_, path)| !path.is_empty())
    }) {
        let path = if flag == "--extern=" {
            remap_rust_extern(config, key, path)?
        } else {
            remap_compiler_flag_path(config, key, path)?
        };
        return Ok(format!("{flag}{path}"));
    }
    if Path::new(argument).is_absolute() {
        return remap_compiler_path(config, key, argument);
    }
    Ok(argument.to_owned())
}

fn remap_rust_codegen_option(
    config: &ClusterConfig,
    key: &str,
    option: &str,
    active_prefix: Option<&Path>,
    login_path: &str,
) -> AppResult<String> {
    let Some((name, value)) = option.split_once('=') else {
        return Ok(option.to_owned());
    };
    if name == "link-arg" {
        return Ok(format!(
            "{name}={}",
            remap_single_compiler_flag(config, key, value, active_prefix, login_path)?
        ));
    }
    if name == "linker" {
        return Ok(format!(
            "{name}={}",
            resolve_compiler_executable(config, key, value, active_prefix, login_path)?
        ));
    }
    Ok(option.to_owned())
}

fn remap_rust_extern(config: &ClusterConfig, key: &str, value: &str) -> AppResult<String> {
    let Some((crate_name, path)) = value.split_once('=') else {
        return Ok(value.to_owned());
    };
    Ok(format!(
        "{crate_name}={}",
        remap_compiler_path(config, key, path)?
    ))
}

fn remap_compiler_flag_path(config: &ClusterConfig, key: &str, value: &str) -> AppResult<String> {
    if let Some((kind, path)) = value.split_once('=')
        && matches!(
            kind,
            "all" | "crate" | "dependency" | "framework" | "native"
        )
    {
        return Ok(format!(
            "{kind}={}",
            remap_compiler_path(config, key, path)?
        ));
    }
    if let Some(path) = value.strip_prefix('@') {
        return Ok(format!("@{}", remap_compiler_path(config, key, path)?));
    }
    remap_compiler_path(config, key, value)
}

fn remap_linker_arguments(
    config: &ClusterConfig,
    key: &str,
    arguments: &mut [String],
) -> AppResult<()> {
    let mut expect_path = false;
    for argument in arguments {
        if expect_path {
            *argument = remap_compiler_path(config, key, argument)?;
            expect_path = false;
            continue;
        }
        if matches!(
            argument.as_str(),
            "-rpath" | "-rpath-link" | "-L" | "-F" | "--sysroot"
        ) {
            expect_path = true;
        } else if let Some((flag, path)) = ["-rpath=", "-rpath-link=", "--sysroot="]
            .iter()
            .find_map(|flag| argument.strip_prefix(flag).map(|path| (*flag, path)))
        {
            *argument = format!("{flag}{}", remap_compiler_path(config, key, path)?);
        } else if Path::new(argument.as_str()).is_absolute() {
            *argument = remap_compiler_path(config, key, argument)?;
        }
    }
    if expect_path {
        return Err((
            2,
            format!("{key} ends with a linker option that requires a path"),
        ));
    }
    Ok(())
}

fn remap_compiler_path_list(config: &ClusterConfig, key: &str, value: &str) -> AppResult<String> {
    value
        .split(':')
        .map(|entry| {
            if entry.is_empty() || !Path::new(entry).is_absolute() {
                Ok(entry.to_owned())
            } else {
                remap_compiler_path(config, key, entry)
            }
        })
        .collect::<AppResult<Vec<_>>>()
        .map(|entries| entries.join(":"))
}

fn remap_compiler_path(config: &ClusterConfig, key: &str, value: &str) -> AppResult<String> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Ok(value.to_owned());
    }
    if let Some(mapped) = remap_shared_path(config, path) {
        return Ok(mapped.to_string_lossy().into_owned());
    }
    if is_portable_system_toolchain_path(path) {
        return Ok(value.to_owned());
    }
    Err(unshared_build_path_error(key, path))
}

fn is_portable_system_toolchain_path(path: &Path) -> bool {
    const SYSTEM_TOOLCHAIN_ROOTS: &[&str] = &[
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
    ];
    SYSTEM_TOOLCHAIN_ROOTS
        .iter()
        .any(|root| path.starts_with(root))
}

fn unshared_build_path_error(variable: &str, path: &Path) -> (i32, String) {
    (
        2,
        format!(
            "build environment variable {variable} references unshared path {}; register its software/toolchain root with `mnode -a local:PATH --share-id ID --mount-root PATH`",
            path.display()
        ),
    )
}

fn remap_environment_paths(config: &ClusterConfig, key: &str, value: &str) -> String {
    const PORTABLE_SYSTEM_PATH_ENTRIES: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
    const PATH_LIST_VARIABLES: &[&str] = &[
        "PATH",
        "PYTHONPATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
        "CMAKE_PREFIX_PATH",
        "CONDA_ENVS_PATH",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "CPATH",
        "C_INCLUDE_PATH",
        "CPLUS_INCLUDE_PATH",
        "LIBRARY_PATH",
        "MANPATH",
        "R_LIBS",
        "R_LIBS_USER",
        "R_LIBS_SITE",
    ];
    const SINGLE_PATH_VARIABLES: &[&str] = &[
        "CONDA_PREFIX",
        "CONDA_EXE",
        "CONDA_PYTHON_EXE",
        "HOMEBREW_PREFIX",
        "HOMEBREW_CELLAR",
        "HOMEBREW_REPOSITORY",
        "HOMEBREW_CACHE",
        "HOMEBREW_LOGS",
        "HOMEBREW_TEMP",
        "MAMBA_ROOT_PREFIX",
        "MAMBA_EXE",
        "VIRTUAL_ENV",
        "PYTHONHOME",
        "JAVA_HOME",
        "R_HOME",
        "SDKROOT",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "CARGO_TARGET_DIR",
        "CCACHE_DIR",
        "SCCACHE_DIR",
    ];

    if value.is_empty() {
        return String::new();
    }

    if key == "PATH" {
        return value
            .split(':')
            .filter_map(|entry| {
                if entry.is_empty() {
                    return None;
                }
                remap_shared_path(config, Path::new(entry))
                    .map(|path| path.to_string_lossy().into_owned())
                    .or_else(|| {
                        PORTABLE_SYSTEM_PATH_ENTRIES
                            .contains(&entry)
                            .then(|| entry.to_owned())
                    })
            })
            .collect::<Vec<_>>()
            .join(":");
    }
    if PATH_LIST_VARIABLES.contains(&key) {
        return value
            .split(':')
            .map(|entry| {
                if entry.is_empty() {
                    return String::new();
                }
                remap_shared_path(config, Path::new(entry)).map_or_else(
                    || entry.to_owned(),
                    |path| path.to_string_lossy().into_owned(),
                )
            })
            .collect::<Vec<_>>()
            .join(":");
    }
    if SINGLE_PATH_VARIABLES.contains(&key) {
        if matches!(key, "CARGO_HOME" | "RUSTUP_HOME" | "CARGO_TARGET_DIR")
            && !Path::new(value).is_absolute()
        {
            return value.to_owned();
        }
        return remap_shared_path(config, Path::new(value)).map_or_else(
            || value.to_owned(),
            |path| path.to_string_lossy().into_owned(),
        );
    }
    value.to_owned()
}

// Store the path visible on compute nodes, even when the login Mac uses a
// server-side source path or a symlink for the same share.
fn shared_working_directory(config: &ClusterConfig, cwd: &Path) -> Option<PathBuf> {
    remap_shared_path(config, cwd)
}

fn validate_shared_output_path(
    path: &Path,
    submitter_cwd: &Path,
    config: &ClusterConfig,
) -> AppResult<String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        submitter_cwd.join(path)
    };
    if absolute
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err((2, "output path cannot contain '..'".into()));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| (2, "output path must name a file".into()))?;
    let file_name = absolute
        .file_name()
        .ok_or_else(|| (2, "output path must name a file".into()))?;
    // Keep job-ID templates intact, and resolve the existing ancestor without
    // creating directories on the submitter. The Agent expands and checks the
    // concrete path before it creates the task's output directory.
    let canonical_parent = canonicalize_with_missing_suffix(parent).ok_or_else(|| {
        (
            2,
            format!("cannot resolve output directory {}", parent.display()),
        )
    })?;
    let normalized = canonical_parent.join(file_name);
    for mapping in submission_path_mappings(config) {
        let canonical_root = mapping.canonical_visible_root.ok_or_else(|| {
            (
                2,
                format!(
                    "shared output root {} is unavailable: {}",
                    mapping.visible_root.display(),
                    mapping
                        .canonical_error
                        .as_deref()
                        .unwrap_or("could not resolve path")
                ),
            )
        })?;
        if let Ok(relative) = normalized.strip_prefix(canonical_root) {
            return Ok(mapping
                .target_root
                .join(relative)
                .to_string_lossy()
                .into_owned());
        }
    }
    Err((
        2,
        "output paths must be inside the primary or a configured named share".into(),
    ))
}

fn is_read_only_query(command: &str, args: &[String]) -> bool {
    matches!(command, "job" | "queue" | "top")
        || command == "controller" && args.first().is_some_and(|arg| arg == "status")
        || command == "node"
            && args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "-l" | "--list"))
        || command == "fans"
            && args
                .iter()
                .any(|arg| matches!(arg.as_str(), "--status" | "-l"))
}

fn job_listing_uses_local_store(args: &[String]) -> bool {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--all" | "--json" => {}
            "--state" if args.next().is_some() => {}
            _ => return false,
        }
    }
    true
}

fn job(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!(
            "Usage: mjob [JOBID] [--all] [--state STATE] [--json]\n       mjob --request-id UUID\n       mjob --log JOBID [--raw] [--stderr] [--follow]\n\nTask records are read from the local controller database without starting the controller. A stopped controller leaves the last persisted state visible; reading shared logs still requires access to their storage."
        );
        return Ok(());
    }
    let mut all = false;
    let mut json = false;
    let mut state_filter = None;
    let mut request_id = None;
    let mut log_id = None;
    let mut stderr = false;
    let mut follow = false;
    let mut raw = false;
    let mut positional = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--all" => all = true,
            "--json" => json = true,
            "--stderr" => stderr = true,
            "--follow" => follow = true,
            "--raw" => raw = true,
            "--state" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| (2, "missing value for --state".into()))?;
                state_filter = Some(
                    parse_state(value).ok_or_else(|| (2, format!("unknown state '{value}'")))?,
                );
            }
            "--request-id" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| (2, "missing value for --request-id".into()))?;
                request_id = Some(parse_request_id(value)?);
            }
            "--log" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| (2, "missing job ID for --log".into()))?;
                log_id = Some(parse_job_id(value)?);
            }
            value if value.starts_with('-') => {
                return Err((2, format!("unknown mjob option '{value}'")));
            }
            value => {
                if positional.replace(parse_job_id(value)?).is_some() {
                    return Err((2, "mjob accepts at most one job ID".into()));
                }
            }
        }
        index += 1;
    }
    if follow && log_id.is_none() {
        return Err((2, "--follow requires --log JOBID".into()));
    }
    if stderr && log_id.is_none() {
        return Err((2, "--stderr requires --log JOBID".into()));
    }
    if raw && log_id.is_none() {
        return Err((2, "--raw requires --log JOBID".into()));
    }
    if log_id.is_some() && json {
        return Err((2, "--json cannot be combined with --log".into()));
    }
    if request_id.is_some() && positional.is_some() {
        return Err((2, "use either job ID or --request-id".into()));
    }
    let state_dir = state_root(global.state_dir.as_deref())?;
    if job_listing_uses_local_store(args) {
        let jobs = match fs::symlink_metadata(state_dir.join("controller.sqlite3")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                load_config(global.config.as_deref()).map_err(config_error)?;
                Vec::new()
            }
            Err(error) => return Err((1, format!("cannot inspect job database: {error}"))),
            Ok(_) => {
                let storage = ReadOnlyJobStore::open(&state_dir).map_err(operation_error)?;
                if !all && state_filter.is_none() {
                    storage.list_active_jobs().map_err(operation_error)?
                } else {
                    storage.list_jobs(state_filter).map_err(operation_error)?
                }
            }
        };
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&jobs).map_err(|error| (1, error.to_string()))?
            );
        } else {
            print_jobs_table(&jobs);
        }
        return Ok(());
    }
    let storage = ReadOnlyJobStore::open(&state_dir).map_err(operation_error)?;
    if let Some(id) = log_id {
        if positional.is_some() {
            return Err((2, "use either --log JOBID or a positional job ID".into()));
        }
        let record = storage
            .get_job(id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("job {id} not found")))?;
        return stream_job_log(&storage, &record, stderr, follow, raw);
    }
    if let Some(request_id) = request_id {
        let record = storage
            .get_job_by_request_id(request_id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("no job exists for request ID {request_id}")))?;
        return print_job(&record, json);
    }
    if let Some(id) = positional {
        let record = storage
            .get_job(id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("job {id} not found")))?;
        return print_job(&record, json);
    }
    let jobs = if !all && state_filter.is_none() {
        storage.list_active_jobs().map_err(operation_error)?
    } else {
        storage.list_jobs(state_filter).map_err(operation_error)?
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&jobs).map_err(|error| (1, error.to_string()))?
        );
    } else {
        print_jobs_table(&jobs);
    }
    Ok(())
}

fn print_job(record: &JobRecord, json: bool) -> AppResult<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(record).map_err(|error| (1, error.to_string()))?
        );
    } else {
        print!("{}", format_job_details(record));
    }
    Ok(())
}

fn stream_job_log(
    storage: &ReadOnlyJobStore,
    record: &JobRecord,
    stderr: bool,
    follow: bool,
    raw: bool,
) -> AppResult<()> {
    let current_record;
    let publication_pending;
    let verbose = record
        .spec
        .env
        .get(VERBOSE_TASK_LOG_ENV)
        .is_some_and(|value| value == "1");
    if follow {
        if !record.state.is_terminal() || record.log_sync_pending {
            eprintln!(
                "Waiting for job {} to finish and publish its output; press Ctrl-C to stop waiting.",
                record.id
            );
        }
        let mut terminal_sync_since = None;
        loop {
            let latest = storage
                .get_job(record.id)
                .map_err(operation_error)?
                .ok_or_else(|| (1, format!("job {} not found", record.id)))?;
            if latest.state.is_terminal() && !latest.log_sync_pending {
                current_record = latest;
                publication_pending = false;
                break;
            }
            if latest.state.is_terminal() {
                let began = terminal_sync_since.get_or_insert_with(Instant::now);
                if began.elapsed() >= Duration::from_secs(60) {
                    current_record = latest;
                    publication_pending = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    } else {
        let latest = storage
            .get_job(record.id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("job {} not found", record.id)))?;
        if !latest.state.is_terminal() {
            return Err((
                1,
                format!(
                    "job {} is still active; use --follow to wait for its output",
                    record.id
                ),
            ));
        }
        publication_pending = latest.log_sync_pending;
        current_record = latest;
    }

    let raw_path = if stderr {
        &record.spec.stderr_path
    } else {
        &record.spec.stdout_path
    };
    let raw_path = PathBuf::from(raw_path.replace("%j", &record.id.to_string()));
    let enhanced_dir = if verbose {
        record
            .spec
            .env
            .get(VERBOSE_TASK_LOG_ROOT_ENV)
            .map(PathBuf::from)
            .map(|root| record.spec.shared_job_dir(&root, record.id))
    } else {
        None
    };
    let mut selected = if verbose && !raw {
        enhanced_dir
            .as_ref()
            .map(|directory| directory.join("monitor.log"))
            .unwrap_or_else(|| raw_path.clone())
    } else {
        raw_path.clone()
    };
    if current_record.started_unix_ms.is_none() {
        return Ok(());
    }
    let mut filter_stderr = verbose && !raw && stderr;
    let annotation_problem = if verbose && !raw {
        match enhanced_dir.as_ref() {
            None => Some("enhanced log location is missing".to_owned()),
            Some(directory) => match fs::read(directory.join("summary.json")) {
                Err(error) => Some(format!("summary is unavailable: {error}")),
                Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                    Err(error) => Some(format!("summary is invalid: {error}")),
                    Ok(summary) => summary
                        .get("annotation_failed")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| {
                            (!directory.join("monitor.log").is_file())
                                .then(|| "monitor log is missing".to_owned())
                        }),
                },
            },
        }
    } else {
        None
    };
    if verbose && !raw && annotation_problem.is_some() {
        eprintln!(
            "mjob: enhanced log unavailable ({}); showing raw {} instead",
            annotation_problem.as_deref().unwrap_or("unknown error"),
            if stderr { "stderr" } else { "stdout" }
        );
        selected = raw_path.clone();
        filter_stderr = false;
    }
    if record.spec.mode == JobMode::Interactive && stderr {
        eprintln!("mjob: PTY merges stdout and stderr; no separate stderr stream exists");
        return Ok(());
    }
    if publication_pending && selected.exists() {
        eprintln!(
            "mjob: job {} output synchronization remains pending; the available shared copy may be incomplete",
            record.id
        );
    }
    let file = File::open(&selected).map_err(|error| {
        (
            1,
            format!("cannot read shared log {}: {error}", selected.display()),
        )
    })?;
    if filter_stderr {
        let mut input = io::BufReader::new(file);
        let mut line = String::new();
        let mut stdout = io::stdout().lock();
        loop {
            line.clear();
            let count = input
                .read_line(&mut line)
                .map_err(|error| (1, format!("cannot read log line: {error}")))?;
            if count == 0 {
                break;
            }
            let is_stderr = line
                .strip_prefix('[')
                .and_then(|line| line.split_once("] ["))
                .is_some_and(|(header, rest)| {
                    header.contains(" / MEM ")
                        && header.contains(" / CPU ")
                        && (rest.starts_with("stderr] ") || rest.starts_with("stderr:continued] "))
                });
            if is_stderr {
                stdout
                    .write_all(line.as_bytes())
                    .map_err(|error| (1, error.to_string()))?;
            }
        }
    } else {
        let mut input = file;
        io::copy(&mut input, &mut io::stdout().lock()).map_err(|error| (1, error.to_string()))?;
    }
    Ok(())
}

fn print_jobs_table(jobs: &[JobRecord]) {
    print!("{}", format_jobs_table(jobs));
}

fn format_jobs_table(jobs: &[JobRecord]) -> String {
    use std::fmt::Write as _;

    const HEADERS: [&str; 6] = ["JOBID", "STATE", "QUEUE", "NODE", "CREATED(ms)", "NAME"];
    let rows: Vec<[String; 6]> = jobs
        .iter()
        .map(|job| {
            [
                job.id.to_string(),
                format!("{:?}", job.state),
                job.spec.queue.to_string(),
                job.node.as_ref().map_or("-", NodeId::as_str).to_owned(),
                job.created_unix_ms.to_string(),
                escape(&job.spec.name),
            ]
        })
        .collect();
    let widths: [usize; 5] = std::array::from_fn(|column| {
        rows.iter()
            .map(|row| row[column].len())
            .chain(std::iter::once(HEADERS[column].len()))
            .max()
            .unwrap_or(HEADERS[column].len())
    });

    let mut output = String::new();
    for row in std::iter::once(HEADERS.map(str::to_owned)).chain(rows) {
        for column in 0..5 {
            let _ = write!(output, "{:<width$}  ", row[column], width = widths[column]);
        }
        let _ = writeln!(output, "{}", row[5]);
    }
    output
}

fn format_job_details(record: &JobRecord) -> String {
    use std::fmt::Write as _;

    let mut fields = vec![
        ("JobId", record.id.to_string()),
        ("Name", escape(&record.spec.name)),
        ("Queue", record.spec.queue.to_string()),
        ("State", format!("{:?}", record.state)),
        (
            "Node",
            record.node.as_ref().map_or("-", NodeId::as_str).to_owned(),
        ),
        ("Workdir", escape(&record.spec.cwd)),
        ("Created", record.created_unix_ms.to_string()),
        (
            "Snapshot sync",
            if record.snapshot_sync_pending {
                "pending"
            } else {
                "complete"
            }
            .into(),
        ),
        (
            "Log sync",
            if record.log_sync_pending {
                "pending"
            } else {
                "complete"
            }
            .into(),
        ),
    ];
    if let Some(reason) = &record.end_reason {
        fields.push(("Reason", escape(reason)));
    }
    if let Some(reason) = &record.waiting_reason {
        fields.push(("Waiting reason", escape(reason)));
    }
    if let Some(code) = record.exit_code {
        fields.push(("Exit code", code.to_string()));
    }

    let label_width = fields
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);
    let mut output = String::new();
    for (label, value) in fields {
        let _ = writeln!(output, "{label:<label_width$}: {value}");
    }
    output
}

fn queue(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!(
            "Usage: mqueue [-q|--queue QUEUE] [--jobs] [--json] [--watch SECONDS]\n\nReads persisted queue counts locally without starting the controller or probing nodes. --watch rereads committed task state at each interval."
        );
        return Ok(());
    }
    let config = load_config(global.config.as_deref()).map_err(config_error)?;
    let mut selected = None;
    let mut show_jobs = false;
    let mut json = false;
    let mut watch = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-q" | "--queue" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| (2, "missing queue name".into()))?;
                selected =
                    Some(QueueName::new(value.clone()).map_err(|error| (2, error.to_string()))?);
            }
            "--jobs" => show_jobs = true,
            "--json" => json = true,
            "--watch" => {
                index += 1;
                let seconds = args
                    .get(index)
                    .ok_or_else(|| (2, "missing interval for --watch".into()))?
                    .parse::<u64>()
                    .map_err(|_| (2, "--watch interval must be a positive number".into()))?;
                if seconds == 0 {
                    return Err((2, "--watch interval must be positive".into()));
                }
                watch = Some(seconds);
            }
            value if value.starts_with('-') => {
                return Err((2, format!("unknown mqueue option '{value}'")));
            }
            value => return Err((2, format!("unexpected mqueue argument '{value}'"))),
        }
        index += 1;
    }
    let state_dir = state_root(global.state_dir.as_deref())?;
    if let Some(selected) = &selected
        && !config.queues.contains_key(selected.as_str())
    {
        return Err((2, format!("queue '{selected}' is not configured")));
    }
    loop {
        let storage = match fs::symlink_metadata(state_dir.join("controller.sqlite3")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err((1, format!("cannot inspect job database: {error}"))),
            Ok(_) => Some(ReadOnlyJobStore::open(&state_dir).map_err(operation_error)?),
        };
        let counts_by_queue: BTreeMap<_, _> = storage
            .as_ref()
            .map(ReadOnlyJobStore::queue_job_counts)
            .transpose()
            .map_err(operation_error)?
            .unwrap_or_default()
            .into_iter()
            .map(|counts| (counts.queue.clone(), counts))
            .collect();
        let rows: Vec<QueueRow> = config
            .queues
            .keys()
            .filter(|name| {
                selected
                    .as_ref()
                    .is_none_or(|selected| selected.as_str() == name.as_str())
            })
            .map(|name| {
                let counts = counts_by_queue.get(name);
                QueueRow {
                    name: name.clone(),
                    nodes: config.queue_compute_nodes(name),
                    pending: counts.map_or(0, |counts| counts.pending as usize),
                    running: counts.map_or(0, |counts| counts.running as usize),
                    completed: counts.map_or(0, |counts| counts.completed as usize),
                    failed: counts.map_or(0, |counts| counts.failed as usize),
                }
            })
            .collect();
        let jobs = if show_jobs && !json {
            Some(
                storage
                    .as_ref()
                    .map(|storage| storage.list_jobs(None))
                    .transpose()
                    .map_err(operation_error)?
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        drop(storage);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).map_err(|error| (1, error.to_string()))?
            );
        } else {
            let queue_width = rows
                .iter()
                .map(|row| row.name.len())
                .max()
                .unwrap_or(0)
                .max("QUEUE".len());
            let nodes_width = rows
                .iter()
                .map(|row| row.nodes.join(",").len())
                .max()
                .unwrap_or(0)
                .max("NODES".len());
            let pending_width = rows
                .iter()
                .map(|row| row.pending.to_string().len())
                .max()
                .unwrap_or(0)
                .max("PENDING".len());
            let running_width = rows
                .iter()
                .map(|row| row.running.to_string().len())
                .max()
                .unwrap_or(0)
                .max("RUNNING".len());
            let completed_width = rows
                .iter()
                .map(|row| row.completed.to_string().len())
                .max()
                .unwrap_or(0)
                .max("COMPLETED".len());
            let failed_width = rows
                .iter()
                .map(|row| row.failed.to_string().len())
                .max()
                .unwrap_or(0)
                .max("FAILED".len());
            println!(
                "{:<queue_width$}  {:<nodes_width$}  {:<pending_width$}  {:<running_width$}  {:<completed_width$}  {:<failed_width$}",
                "QUEUE", "NODES", "PENDING", "RUNNING", "COMPLETED", "FAILED",
            );
            for row in &rows {
                println!(
                    "{:<queue_width$}  {:<nodes_width$}  {:<pending_width$}  {:<running_width$}  {:<completed_width$}  {:<failed_width$}",
                    row.name,
                    row.nodes.join(","),
                    row.pending,
                    row.running,
                    row.completed,
                    row.failed
                );
            }
            if show_jobs {
                let mut queue_jobs: Vec<_> = jobs
                    .as_ref()
                    .expect("jobs are loaded when --jobs is requested")
                    .iter()
                    .filter(|job| {
                        selected
                            .as_ref()
                            .is_none_or(|queue| job.spec.queue == *queue)
                    })
                    .collect();
                queue_jobs.sort_by_key(|job| job.id);
                print_jobs_table(&queue_jobs.into_iter().cloned().collect::<Vec<_>>());
            }
        }
        let Some(seconds) = watch else {
            break;
        };
        thread::sleep(Duration::from_secs(seconds));
        println!();
    }
    Ok(())
}

fn fans(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    use macluster_protocol::{
        control::{ControlCommand, ControlPayload},
        types::FanPolicy,
    };

    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!(
            "Usage: mfans [--status | --reset | --auto | --power] [--node NODE] [--json]\n\nWithout --node, a policy is applied to every registered node. --auto uses a linear CPU temperature curve from 40°C to 80°C; --power uses a logarithmic curve over the same range. --reset returns the fans to macOS system control."
        );
        return Ok(());
    }
    let mut policy = None;
    let mut mode_seen = false;
    let mut status = false;
    let mut json = false;
    let mut node_id = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--status" | "-l" => {
                if mode_seen || status {
                    return Err((
                        2,
                        "choose only one of --status, --reset, --auto, or --power".into(),
                    ));
                }
                status = true;
            }
            "--reset" => {
                if mode_seen || status {
                    return Err((2, "choose only one fan policy".into()));
                }
                policy = Some(FanPolicy::System);
                mode_seen = true;
            }
            "--auto" => {
                if mode_seen || status {
                    return Err((2, "choose only one fan policy".into()));
                }
                policy = Some(FanPolicy::Auto);
                mode_seen = true;
            }
            "--power" => {
                if mode_seen || status {
                    return Err((2, "choose only one fan policy".into()));
                }
                policy = Some(FanPolicy::Power);
                mode_seen = true;
            }
            "--node" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| (2, "--node requires a node ID".into()))?;
                let parsed = value
                    .parse::<macluster_protocol::identifiers::NodeId>()
                    .map_err(|error| (2, error.to_string()))?;
                if node_id.replace(parsed).is_some() {
                    return Err((2, "--node may be specified only once".into()));
                }
            }
            "--json" => json = true,
            value if value.starts_with('-') => {
                return Err((2, format!("unknown mfans option '{value}'")));
            }
            value => return Err((2, format!("unexpected mfans argument '{value}'"))),
        }
        index += 1;
    }
    if !status && !mode_seen {
        return Err((2, "choose --status, --reset, --auto, or --power".into()));
    }
    if json && !status {
        return Err((2, "--json is supported with --status only".into()));
    }

    let config_path = resolved_config_path(global.config.as_deref());
    let state_dir = state_root(global.state_dir.as_deref())?;
    let mut controller = online_controller(&config_path, &state_dir, false)?
        .ok_or_else(|| (1, "fan control requires the running controller".into()))?;
    controller
        .client
        .set_timeouts(Duration::from_secs(60))
        .map_err(|error| (1, error.to_string()))?;
    let payload = query_control(
        &mut controller.client,
        ControlCommand::FanControl { node_id, policy },
    )?;
    let ControlPayload::FanControl(results) = payload else {
        return Err((
            1,
            "controller returned an invalid fan-control response".into(),
        ));
    };
    if json {
        println!(
            "{}",
            serde_json::to_string(&results).map_err(|error| (1, error.to_string()))?
        );
    } else {
        println!(
            "{:<18} {:<8} {:<8} {:<8} {:<10} STATUS",
            "NODE", "POLICY", "STATE", "TEMP", "TARGET RPM"
        );
        for result in &results {
            if let Some(error) = &result.error {
                println!(
                    "{:<18} {:<8} {:<8} {:<8} {:<10} {error}",
                    result.node_id, "ERROR", "-", "-", "-"
                );
                continue;
            }
            let Some(status) = &result.status else {
                println!(
                    "{:<18} {:<8} {:<8} {:<8} {:<10} no fan status returned",
                    result.node_id, "ERROR", "-", "-", "-"
                );
                continue;
            };
            if !status.supported {
                println!(
                    "{:<18} {:<8} {:<8} {:<8} {:<10} {}",
                    result.node_id,
                    "UNAVAILABLE",
                    "-",
                    "-",
                    "-",
                    status
                        .message
                        .as_deref()
                        .unwrap_or("fan control is unsupported")
                );
                continue;
            }
            let mode = match status.policy {
                FanPolicy::System => "SYSTEM",
                FanPolicy::Auto => "AUTO",
                FanPolicy::Power => "POWER",
            };
            let detail = status.message.as_deref().unwrap_or("");
            let active = match (status.policy, status.active) {
                (FanPolicy::System, _) => "DEFAULT",
                (_, true) => "ACTIVE",
                (_, false) => "ARMED",
            };
            let temperature = status
                .average_temperature_deci_celsius
                .map(|value| format!("{:.1}°C", f32::from(value) / 10.0))
                .unwrap_or_else(|| "N/A".into());
            let target_rpm = status
                .target_rpm
                .map(|value| value.to_string())
                .unwrap_or_else(|| "N/A".into());
            println!(
                "{:<18} {:<8} {:<8} {:<8} {:<10} {}",
                result.node_id, mode, active, temperature, target_rpm, detail
            );
        }
    }
    let failed = results
        .iter()
        .filter(|result| {
            result.error.is_some()
                || (policy.is_some()
                    && result
                        .status
                        .as_ref()
                        .is_none_or(|status| Some(status.policy) != policy))
        })
        .count();
    if failed > 0 {
        return Err((
            1,
            format!(
                "fan policy operation failed on {failed} of {} node(s)",
                results.len()
            ),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct QueueRow {
    name: String,
    nodes: Vec<String>,
    pending: usize,
    running: usize,
    completed: usize,
    failed: usize,
}

fn kill(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!("Usage: mkill [--force] JOBID [JOBID ...]");
        return Ok(());
    }
    let mut force = false;
    let mut ids = Vec::new();
    for arg in args {
        if arg == "--force" {
            force = true;
        } else if arg.starts_with('-') {
            return Err((2, format!("unknown mkill option '{arg}'")));
        } else {
            ids.push(parse_job_id(arg)?);
        }
    }
    if ids.is_empty() {
        return Err((2, "mkill requires one or more job IDs".into()));
    }
    let state_dir = state_root(global.state_dir.as_deref())?;
    let mut online = online_controller(
        &resolved_config_path(global.config.as_deref()),
        &state_dir,
        true,
    )?;
    let storage = Storage::open(&state_dir).map_err(operation_error)?;
    let mut failures = Vec::new();
    let mut changed = false;
    for id in ids {
        let result = if let Some(controller) = &mut online {
            match query_control(
                &mut controller.client,
                ControlCommand::CancelJob { job_id: id, force },
            ) {
                Ok(ControlPayload::Job(record)) => Ok(record),
                Ok(_) => Err((
                    1,
                    "controller returned an invalid cancellation response".into(),
                )),
                Err(error) => Err(error),
            }
        } else {
            storage.request_cancel(id, force).map_err(operation_error)
        };
        match result {
            Ok(record) => {
                changed = true;
                println!("Job {}: {:?}", id, record.state);
            }
            Err((_, error)) => {
                eprintln!("Job {id}: {error}");
                failures.push(id);
            }
        }
    }
    if changed {
        wake_controller_best_effort(storage.root());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err((1, format!("failed to cancel {} job(s)", failures.len())))
    }
}

fn top(global: GlobalOptions, args: &[String], address_migration_deferred: bool) -> AppResult<()> {
    let config = load_config(global.config.as_deref()).map_err(config_error)?;
    let mut once = false;
    let mut json = false;
    let mut selected_queue = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => {
                println!(
                    "Usage: mtop [--once] [--json] [-q QUEUE]\nShows login-node and configured compute-node CPU, memory, disk I/O, network, and power readings. On a terminal it refreshes the current screen; redirected output prints one snapshot."
                );
                return Ok(());
            }
            "--once" => once = true,
            "--json" => {
                json = true;
                once = true;
            }
            "-q" | "--queue" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| (2, "missing queue name".into()))?;
                selected_queue =
                    Some(QueueName::new(value.clone()).map_err(|error| (2, error.to_string()))?);
            }
            value if value.starts_with('-') => {
                return Err((2, format!("unknown mtop option '{value}'")));
            }
            value => return Err((2, format!("unexpected mtop argument '{value}'"))),
        }
        index += 1;
    }
    if let Some(queue) = &selected_queue {
        if !config.queues.contains_key(queue.as_str()) {
            return Err((2, format!("queue '{queue}' is not configured")));
        }
    }
    let term_is_dumb = env::var("TERM").is_ok_and(|value| value == "dumb");
    let state_dir = state_root(global.state_dir.as_deref())?;
    if crate::mtop::should_use_tui(
        once,
        json,
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        term_is_dumb,
    ) {
        let post_action = crate::mtop::run_interactive(
            config,
            state_dir.clone(),
            resolved_config_path(global.config.as_deref()),
            selected_queue.map(|queue| queue.to_string()),
            env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            address_migration_deferred,
        )
        .map_err(|error| (1, error))?;
        if address_migration_deferred || crate::node_admin::address_migration_pending(&state_dir) {
            return Ok(());
        }
        return match post_action {
            Some(crate::mtop::MtopPostAction::CheckBuilds(compatibility))
                if is_macluster_executable() =>
            {
                if compatibility.requires_update() {
                    println!(
                        "Agent build mismatch detected; entering the cluster update workflow."
                    );
                }
                preflight_agent_update_with_compatibility("top", args, &global, Some(compatibility))
            }
            Some(crate::mtop::MtopPostAction::RecoverMaintenance) if is_macluster_executable() => {
                preflight_agent_update("top", args, &global)
            }
            Some(crate::mtop::MtopPostAction::UpdateDeferred) => Ok(()),
            None if is_macluster_executable() => preflight_agent_update("top", args, &global),
            _ => Ok(()),
        };
    }
    let view = sample_cluster(
        &config,
        selected_queue.as_ref(),
        &state_dir,
        &resolved_config_path(global.config.as_deref()),
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&view).map_err(|error| (1, error.to_string()))?
        );
    } else {
        print_cluster_metrics(&view, false, false);
        io::stdout()
            .flush()
            .map_err(|error| (1, error.to_string()))?;
    }
    Ok(())
}

fn controller(global: GlobalOptions, args: &[String], service_child: bool) -> AppResult<()> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: macluster controller start|stop|restart|status\n       macluster controller run [--once] [--interval SECONDS] [--web [--web-port PORT] [--no-open]]\n\nThe controller runs as a per-user LaunchAgent after cluster initialization. `run` remains available for foreground use. Add `--web` to start the read-only browser monitor; if a controller is already running, it starts the monitor there and asks before updating an older controller."
        );
        return Ok(());
    }
    let state_dir = state_root(global.state_dir.as_deref())?;
    match args[0].as_str() {
        "status" => {
            if resolved_config_path(global.config.as_deref()).is_file() {
                match controller_service_manager(&global, &state_dir).and_then(|manager| {
                    manager
                        .inspect(Duration::from_millis(200))
                        .map_err(service_error)
                }) {
                    Ok(status) => {
                        let launch_state = if status.loaded {
                            "loaded"
                        } else {
                            "not loaded"
                        };
                        let readiness =
                            status
                                .hello
                                .as_ref()
                                .map_or("not ready".to_owned(), |hello| {
                                    format!(
                                        "{:?}, epoch {}",
                                        hello.lifecycle, hello.controller_epoch.epoch
                                    )
                                });
                        println!(
                            "Controller service: {launch_state} ({readiness}; intent {:?})",
                            status.intent
                        );
                    }
                    Err((_, error)) => println!("Controller service: unavailable ({error})"),
                }
            } else {
                println!("Controller service: not configured");
            }
            let jobs = match fs::symlink_metadata(state_dir.join("controller.sqlite3")) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err((1, format!("cannot inspect job database: {error}"))),
                Ok(_) => ReadOnlyJobStore::open(&state_dir)
                    .map_err(operation_error)?
                    .list_active_jobs()
                    .map_err(operation_error)?,
            };
            let pending = jobs
                .iter()
                .filter(|job| job.state == JobState::Pending)
                .count();
            let active = jobs
                .iter()
                .filter(|job| {
                    matches!(
                        job.state,
                        JobState::Starting | JobState::Running | JobState::Cancelling
                    )
                })
                .count();
            println!(
                "Controller state database: {}\nPending: {pending}\nActive: {active}",
                state_dir.join("controller.sqlite3").display()
            );
            Ok(())
        }
        "start" => {
            let hello = controller_service_manager(&global, &state_dir)?
                .start(Duration::from_secs(5))
                .map_err(service_error)?;
            println!(
                "Controller ready ({:?}, epoch {}).",
                hello.lifecycle, hello.controller_epoch.epoch
            );
            Ok(())
        }
        "stop" => {
            controller_service_manager(&global, &state_dir)?
                .stop()
                .map_err(service_error)?;
            println!(
                "Controller service stopped. Automatic start is disabled until `macluster controller start`."
            );
            Ok(())
        }
        "restart" => {
            let hello = controller_service_manager(&global, &state_dir)?
                .restart(Duration::from_secs(5))
                .map_err(service_error)?;
            println!(
                "Controller restarted ({:?}, epoch {}).",
                hello.lifecycle, hello.controller_epoch.epoch
            );
            Ok(())
        }
        "run" => {
            let mut once = false;
            let mut interval = 2_u64;
            let mut web = false;
            let mut web_port = None;
            let mut no_open = false;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--once" => once = true,
                    "--web" => web = true,
                    "--no-open" => no_open = true,
                    "--web-port" => {
                        index += 1;
                        let value = args
                            .get(index)
                            .ok_or_else(|| (2, "missing --web-port value".into()))?;
                        web_port = Some(value.parse::<u16>().map_err(|_| {
                            (
                                2,
                                format!("invalid web port '{value}'; expected 0 to 65535"),
                            )
                        })?);
                    }
                    "--interval" => {
                        index += 1;
                        interval = args
                            .get(index)
                            .ok_or_else(|| (2, "missing --interval value".into()))?
                            .parse::<u64>()
                            .map_err(|_| (2, "--interval must be a positive number".into()))?;
                        if interval == 0 {
                            return Err((2, "--interval must be positive".into()));
                        }
                    }
                    value => return Err((2, format!("unknown controller run option '{value}'"))),
                }
                index += 1;
            }
            if no_open && !web {
                return Err((2, "--no-open requires --web".into()));
            }
            if web_port.is_some() && !web {
                return Err((2, "--web-port requires --web".into()));
            }
            if once && web {
                return Err((2, "--web requires a long-running controller".into()));
            }
            let config_file = resolved_config_path(global.config.as_deref());
            if web
                && let Ok(binding) = ServiceBinding::load(&config_file, &state_dir)
                && let Ok(mut client) = crate::control_client::ControlClient::connect(
                    &binding,
                    Duration::from_millis(300),
                )
            {
                let current_build =
                    crate::service::current_executable_build_id().map_err(service_error)?;
                if !controller_supports_web(&client) || client.hello().build_id != current_build {
                    confirm_controller_web_update()?;
                    eprintln!("Updating and restarting the controller for the browser monitor…");
                    crate::service::ServiceManager::current(binding.clone())
                        .map_err(service_error)?
                        .ensure_running(Duration::from_secs(10))
                        .map_err(service_error)?;
                    client = crate::control_client::ControlClient::connect(
                        &binding,
                        Duration::from_secs(5),
                    )
                    .map_err(|error| (1, error.to_string()))?;
                }
                client
                    .set_timeouts(Duration::from_secs(10))
                    .map_err(|error| (1, error.to_string()))?;
                return start_web_monitor(&mut client, web_port, no_open);
            }
            if service_child {
                let binding = ServiceBinding::load(&config_file, &state_dir)
                    .map_err(|error| (1, format!("controller service binding failed: {error}")))?;
                let configured_binding = env::var("MACLUSTER_SERVICE_BINDING").map_err(|_| {
                    (
                        1,
                        "private controller service entry is missing its binding identity".into(),
                    )
                })?;
                if configured_binding != binding.binding_digest() {
                    return Err((
                        1,
                        "private controller service entry has a different binding identity".into(),
                    ));
                }
                match ServiceIntentStore::open(&binding)
                    .and_then(|intent| intent.read())
                    .map_err(|error| (1, error.to_string()))?
                {
                    ServiceIntent::Auto => {}
                    ServiceIntent::Stopped | ServiceIntent::Resetting => return Ok(()),
                }
            }
            crate::init::reset::ensure_no_reset_in_progress(&config_file, &state_dir)?;
            let maintenance_lock = MaintenanceLock::shared(&config_file).map_err(|error| {
                (
                    1,
                    format!("cannot lock cluster config for controller: {error}"),
                )
            })?;
            MaintenanceLock::bind_state_dir(&config_file, &state_dir).map_err(|error| {
                (
                    1,
                    format!("cluster config/state directory binding failed: {error}"),
                )
            })?;
            crate::node_admin::ensure_controller_recovery_clean(&config_file, &state_dir)
                .map_err(|error| (1, error))?;
            let instance =
                macluster_controller::InstanceLock::acquire(&state_dir).map_err(|error| {
                    (
                        1,
                        format!("another controller may already be running: {error}"),
                    )
                })?;
            let config = load_config(global.config.as_deref()).map_err(config_error)?;
            let storage = Storage::open(&state_dir).map_err(operation_error)?;
            let mut service = macluster_controller::ControllerService::new(
                config.clone(),
                storage,
                macluster_controller::transport::ClusterTransport::new_with_namespace(
                    config_file.clone(),
                    config.share_uuid.clone(),
                ),
            )
            .map_err(|error| (1, error.to_string()))?;
            if let Some((_, login)) = config
                .nodes
                .iter()
                .find(|(id, node)| config.is_login_node(id) && node.transport == Transport::Local)
            {
                let state = macluster_agent::default_state_dir();
                let owner = macluster_agent::admin::current_controller(&state)
                    .map_err(|error| (1, error.to_string()))?;
                let namespace = macluster_agent::admin::owner_namespace(&state)
                    .map_err(|error| (1, error.to_string()))?;
                let same_owner = owner
                    .is_some_and(|owner| owner.controller_uuid == service.epoch().controller_uuid)
                    && namespace
                        .as_deref()
                        .is_none_or(|namespace| namespace == config.share_uuid);
                if !same_owner {
                    macluster_agent::validate_node_identity(
                        login,
                        &local_machine_uuid().map_err(|error| (1, error))?,
                        unsafe { libc::geteuid() },
                    )
                    .map_err(|error| (1, error))?;
                    macluster_agent::admin::claim_idle(&state, service.epoch(), &config.share_uuid)
                        .map_err(|error| {
                            (
                                1,
                                format!(
                                    "cannot hand the local login Agent to this controller: {error}"
                                ),
                            )
                        })?;
                }
            }
            let barrier_config = config_file
                .canonicalize()
                .map_err(|error| (1, format!("cannot resolve cluster config: {error}")))?;
            service.set_reset_barrier_context(
                crate::init::reset::journal_path(&barrier_config),
                barrier_config.clone(),
                state_dir.clone(),
            );
            service.set_maintenance_barrier_context(
                macluster_core::maintenance::maintenance_barrier_path(&barrier_config),
                barrier_config,
                state_dir.clone(),
            );
            let sync_pending = crate::node_admin::dispatch_sync_pending(&config_file, &state_dir)
                .map_err(|error| (1, error))?;
            service.set_dispatch_enabled(
                !sync_pending && !crate::node_admin::address_migration_pending(&state_dir),
            );
            if sync_pending {
                eprintln!(
                    "macluster: peer config synchronization is pending; controller will reconcile status and cancellations but will not dispatch new jobs"
                );
            }
            let address_migration = crate::node_admin::address_migration_pending(&state_dir);
            let maintenance_pending =
                macluster_core::maintenance::maintenance_barrier_path(&config_file).exists();
            let lifecycle = if sync_pending || address_migration {
                ControllerLifecycle::RecoveryPending
            } else if maintenance_pending {
                ControllerLifecycle::Paused
            } else {
                ControllerLifecycle::Ready
            };
            let mut control_listener = None;
            let mut control_maintenance = None;
            let control_hello = if once {
                None
            } else {
                let binding = ServiceBinding::load(&config_file, &state_dir)
                    .map_err(|error| (1, format!("controller service binding failed: {error}")))?;
                let config_bytes =
                    fs::read(&config_file).map_err(|error| (1, error.to_string()))?;
                let config_digest =
                    sha256_hex(&config_bytes).map_err(|error| (1, error.to_string()))?;
                let maintenance = macluster_controller::maintenance::MaintenanceCoordinator::open(
                    &state_dir,
                    binding.binding_digest(),
                    &config_digest,
                )
                .map_err(|error| {
                    (
                        1,
                        format!("controller maintenance metadata failed: {error}"),
                    )
                })?;
                if maintenance.startup_config_mismatch() {
                    service.set_maintenance_recovery_blocked(true);
                    eprintln!(
                        "macluster: controller config digest differs from its persisted generation; dispatch is blocked until maintenance recovery completes"
                    );
                }
                let lifecycle = if maintenance.startup_config_mismatch()
                    || maintenance.inspect().is_some_and(|status| {
                        status.phase
                            == macluster_protocol::control::MaintenancePhase::RecoveryRequired
                    }) {
                    ControllerLifecycle::RecoveryPending
                } else {
                    lifecycle
                };
                let hello = ControllerHello {
                    protocol_version: macluster_protocol::control::CONTROL_PROTOCOL_VERSION,
                    binding_digest: binding.binding_digest().to_owned(),
                    namespace: binding.namespace().to_owned(),
                    uid: binding.uid(),
                    build_id: crate::service::current_executable_build_id()
                        .map_err(service_error)?,
                    capabilities: vec![
                        "status.v1".into(),
                        "jobs.v1".into(),
                        "snapshot.upload.v1".into(),
                        "agent.compatibility.v1".into(),
                        "monitor.v1".into(),
                        "maintenance.v1".into(),
                        "web.v1".into(),
                    ],
                    controller_epoch: service.epoch(),
                    config_generation: maintenance.generation(),
                    lifecycle,
                };
                let listener =
                    macluster_controller::ControlListener::bind(&binding, &instance, hello.clone())
                        .map_err(|error| {
                            (1, format!("cannot start local controller IPC: {error}"))
                        })?;
                control_listener = Some(listener);
                control_maintenance = Some(maintenance);
                Some(hello)
            };
            if once {
                service
                    .tick_with_storage_health(macluster_controller::verify_shared_storage(&config))
                    .map_err(|error| (1, error.to_string()))?;
                println!(
                    "Controller pass completed at epoch {}",
                    service.epoch().epoch
                );
                Ok(())
            } else {
                let watcher = crate::node_admin::watch_node_addresses(
                    config_file.clone(),
                    state_dir.clone(),
                )?;
                let pending = watcher.pending_flag();
                let requested = std::sync::Arc::clone(&pending);
                let mut maintenance_lock = Some(maintenance_lock);
                let _signal_guard = ControllerSignalGuard::install()?;
                let listener = control_listener
                    .as_mut()
                    .expect("long-running controller always has a control listener");
                let _web_startup = if web {
                    let binding = listener.binding().clone();
                    Some(
                        schedule_web_monitor_startup(binding, web_port, no_open).map_err(
                            |error| {
                                (
                                    1,
                                    format!("cannot schedule browser monitor startup: {error}"),
                                )
                            },
                        )?,
                    )
                } else {
                    None
                };
                service
                    .run_forever_with_control(interval, listener, control_hello.expect("control hello exists"),
                        config_file.clone(),
                        control_maintenance.take().expect("maintenance coordinator exists"),
                        || CONTROLLER_SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst),
                        || requested.load(std::sync::atomic::Ordering::SeqCst),
                        |service| {
                            drop(maintenance_lock.take());
                            let result = crate::node_admin::refresh_node_addresses(&config_file, &state_dir, true);
                            maintenance_lock = Some(MaintenanceLock::shared(&config_file)?);
                            match result {
                                Ok(_) => {
                                    let next = load_config(global.config.as_deref()).map_err(|error| io::Error::other(error.to_string()))?;
                                    service.apply_idle_address_config(next)?;
                                    service.set_dispatch_enabled(!crate::node_admin::dispatch_sync_pending(&config_file, &state_dir).map_err(io::Error::other)?);
                                    pending.store(false, std::sync::atomic::Ordering::SeqCst);
                                    Ok(true)
                                }
                                Err((_, error)) => {
                                    eprintln!("macluster: address migration needs attention: {error}. If administrator authorization is required, run a foreground macluster command to resume it.");
                                    Ok(false)
                                }
                            }
                        })
                    .map_err(|error| (1, error.to_string()))
            }
        }
        value => Err((2, format!("unknown controller command '{value}'"))),
    }
}

fn controller_service_manager(
    global: &GlobalOptions,
    state_dir: &Path,
) -> AppResult<crate::service::ServiceManager<crate::service::LaunchdServiceLauncher>> {
    let config_path = resolved_config_path(global.config.as_deref());
    let binding = ServiceBinding::load(&config_path, state_dir)
        .map_err(|error| (1, format!("controller service binding failed: {error}")))?;
    crate::service::ServiceManager::current(binding).map_err(service_error)
}

fn service_error(error: crate::service::ServiceLifecycleError) -> (i32, String) {
    (1, error.to_string())
}

struct OnlineController {
    binding: ServiceBinding,
    client: crate::control_client::ControlClient,
}

/// Start the per-user controller on demand. Offline mode is used only when the
/// user explicitly stopped the service or no GUI LaunchAgent session exists.
fn online_controller(
    config_path: &Path,
    state_dir: &Path,
    allow_offline: bool,
) -> AppResult<Option<OnlineController>> {
    if !is_macluster_executable() {
        return Ok(None);
    }
    if env::var_os("MACLUSTER_DISABLE_SERVICE_AUTOSTART").is_some() {
        return Ok(None);
    }
    let binding = ServiceBinding::load(config_path, state_dir)
        .map_err(|error| (1, format!("controller service binding failed: {error}")))?;
    let manager =
        crate::service::ServiceManager::current(binding.clone()).map_err(service_error)?;
    match manager.intent().map_err(service_error)? {
        ServiceIntent::Stopped if allow_offline => return Ok(None),
        ServiceIntent::Stopped => {
            eprintln!("Controller is stopped; starting it for the interactive submission.");
            manager
                .start(Duration::from_secs(5))
                .map_err(service_error)?;
        }
        ServiceIntent::Resetting => {
            return Err((
                1,
                "cluster reset is in progress; finish `macluster init` before this operation"
                    .into(),
            ));
        }
        ServiceIntent::Auto => match manager.ensure_running(Duration::from_secs(5)) {
            Ok(_) => {}
            Err(crate::service::ServiceLifecycleError::NoGuiSession(_)) if allow_offline => {
                return Ok(None);
            }
            Err(error) => return Err(service_error(error)),
        },
    }
    let client = crate::control_client::ControlClient::connect(&binding, Duration::from_secs(5))
        .map_err(|error| (1, error.to_string()))?;
    Ok(Some(OnlineController { binding, client }))
}

fn query_control(
    client: &mut crate::control_client::ControlClient,
    command: ControlCommand,
) -> AppResult<ControlPayload> {
    client
        .request(command)
        .map_err(|error| (1, error.to_string()))
}

fn start_web_monitor(
    client: &mut crate::control_client::ControlClient,
    port: Option<u16>,
    no_open: bool,
) -> AppResult<()> {
    if !controller_supports_web(client) {
        return Err((
            1,
            "the running controller still does not support the browser monitor after its update; rebuild or install a macluster binary with browser monitor support".into(),
        ));
    }
    let payload = query_control(client, ControlCommand::StartWeb { port })?;
    let ControlPayload::WebStarted { port, token, .. } = payload else {
        return Err((
            1,
            "controller returned an invalid browser monitor response".into(),
        ));
    };
    let url = format!("http://127.0.0.1:{port}/#{token}");
    if no_open {
        println!("Web monitor URL: {url}");
    } else if process::Command::new("open").arg(&url).spawn().is_ok() {
        println!("Opened the local web monitor at http://127.0.0.1:{port}/");
    } else {
        println!("Could not launch a browser. Open this one-time URL manually:\n{url}");
    }
    println!("The read-only monitor runs while the controller is active.");
    Ok(())
}

fn controller_supports_web(client: &crate::control_client::ControlClient) -> bool {
    client
        .hello()
        .capabilities
        .iter()
        .any(|capability| capability == "web.v1")
}

fn confirm_controller_web_update() -> AppResult<()> {
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Err((
            2,
            "the running controller needs an update and restart to start the browser monitor; rerun `macluster controller run --web` in Terminal to confirm".into(),
        ));
    }
    eprint!(
        "The running controller needs an update and restart to start the browser monitor. Continue? Active jobs will not be killed; they block the update. [y/N] "
    );
    io::stderr()
        .flush()
        .map_err(|error| (1, error.to_string()))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| (1, error.to_string()))?;
    if matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err((
            1,
            "browser monitor startup cancelled; the controller was left unchanged".into(),
        ))
    }
}

fn schedule_web_monitor_startup(
    binding: ServiceBinding,
    port: Option<u16>,
    no_open: bool,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("macluster-web-startup".into())
        .spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut last_error = "controller IPC did not become ready".to_owned();
            while Instant::now() < deadline {
                match crate::control_client::ControlClient::connect(
                    &binding,
                    Duration::from_secs(2),
                ) {
                    Ok(mut client) => {
                        if let Err(error) = client.set_timeouts(Duration::from_secs(10)) {
                            eprintln!("macluster: browser monitor startup failed: {error}");
                            return;
                        }
                        if let Err((_, error)) = start_web_monitor(&mut client, port, no_open) {
                            eprintln!("macluster: browser monitor startup failed: {error}");
                        }
                        return;
                    }
                    Err(error) => last_error = error.to_string(),
                }
                thread::sleep(Duration::from_millis(100));
            }
            eprintln!("macluster: browser monitor startup failed: {last_error}");
        })
}

static CONTROLLER_SHUTDOWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn controller_signal_handler(_: libc::c_int) {
    CONTROLLER_SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
}

struct ControllerSignalGuard {
    old_term: libc::sigaction,
    old_int: libc::sigaction,
}

impl ControllerSignalGuard {
    fn install() -> AppResult<Self> {
        CONTROLLER_SHUTDOWN.store(false, std::sync::atomic::Ordering::SeqCst);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = controller_signal_handler as usize;
        action.sa_flags = 0;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        let mut old_term: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut old_int: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGTERM, &action, &mut old_term) } != 0 {
            return Err((
                1,
                format!(
                    "cannot install controller SIGTERM handler: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        if unsafe { libc::sigaction(libc::SIGINT, &action, &mut old_int) } != 0 {
            unsafe { libc::sigaction(libc::SIGTERM, &old_term, std::ptr::null_mut()) };
            return Err((
                1,
                format!(
                    "cannot install controller SIGINT handler: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        Ok(Self { old_term, old_int })
    }
}

impl Drop for ControllerSignalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGTERM, &self.old_term, std::ptr::null_mut());
            libc::sigaction(libc::SIGINT, &self.old_int, std::ptr::null_mut());
        }
    }
}

#[derive(Serialize)]
struct NodeMetricRow {
    id: String,
    host: String,
    reachable: bool,
    metrics: Option<MetricSnapshot>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ClusterMetricView {
    sampled_unix_ms: u64,
    login: MetricSnapshot,
    nodes: Vec<NodeMetricRow>,
    missing_nodes: usize,
    pool_total: MetricSnapshot,
    #[serde(skip)]
    login_compute_node_id: Option<String>,
    #[serde(skip)]
    task_counts_by_node: Option<BTreeMap<String, (usize, usize)>>,
}

fn sample_cluster(
    config: &ClusterConfig,
    selected_queue: Option<&QueueName>,
    state_dir: &Path,
    config_path: &Path,
) -> ClusterMetricView {
    let local_uuid = local_machine_uuid().ok();
    let login_compute_node_id = config
        .nodes
        .iter()
        .find(|(id, node)| {
            let is_local = node.transport == Transport::Local
                || local_uuid.as_ref().is_some_and(|uuid| {
                    node.machine_uuid
                        .as_ref()
                        .is_some_and(|node_uuid| node_uuid.eq_ignore_ascii_case(uuid))
                });
            let selected = selected_queue.is_none_or(|queue| {
                config
                    .queue_for_dispatch(queue.as_str())
                    .is_some_and(|queue| queue.nodes.iter().any(|member| member == *id))
            });
            is_local && selected && !config.is_login_node(id)
        })
        .map(|(id, _)| id.clone());
    let (login, samples) = cached_monitor_samples(config, config_path, state_dir, selected_queue)
        .unwrap_or_else(|| {
            crate::mtop::sample_one_shot(config, selected_queue.map(QueueName::as_str))
        });
    let mut rows: Vec<NodeMetricRow> = samples
        .into_iter()
        .map(|(id, node, result)| match result {
            Ok(mut metrics) => {
                explain_legacy_power_agent(&mut metrics);
                NodeMetricRow {
                    id,
                    host: node.host,
                    reachable: true,
                    metrics: Some(metrics),
                    error: None,
                }
            }
            Err(error) => NodeMetricRow {
                id,
                host: node.host,
                reachable: false,
                metrics: None,
                error: Some(error),
            },
        })
        .collect();
    rows.sort_by(|left, right| left.id.cmp(&right.id));
    let missing_nodes = rows.iter().filter(|row| !row.reachable).count();
    let pool_total = aggregate_metrics(&rows);
    ClusterMetricView {
        sampled_unix_ms: now_unix_ms(),
        login,
        nodes: rows,
        missing_nodes,
        pool_total,
        login_compute_node_id,
        task_counts_by_node: one_shot_task_counts(config, state_dir),
    }
}

fn cached_monitor_samples(
    config: &ClusterConfig,
    config_path: &Path,
    state_dir: &Path,
    selected_queue: Option<&QueueName>,
) -> Option<(
    MetricSnapshot,
    Vec<(
        String,
        macluster_core::config::NodeConfig,
        Result<MetricSnapshot, String>,
    )>,
)> {
    let snapshot = crate::mtop::read_cached_monitor_snapshot(config_path, state_dir)?;
    let rows = snapshot
        .nodes
        .into_iter()
        .map(|row| (row.node_id.to_string(), row))
        .collect::<HashMap<_, _>>();
    let fresh = |row: &macluster_protocol::control::NodeMonitorRow| {
        !row.stale && row.age_ms.is_some_and(|age| age < 6_000)
    };
    let current_metrics = |row: &macluster_protocol::control::NodeMonitorRow| {
        let mut metrics = row.metrics.clone();
        if let Some(age_ms) = row.age_ms {
            metrics.power_age_ms = metrics.power_age_ms.map(|age| age.saturating_add(age_ms));
            metrics.gpu_age_ms = metrics.gpu_age_ms.map(|age| age.saturating_add(age_ms));
        }
        metrics
    };
    let login_row = rows.get(config.login_node.as_ref()?.as_str())?;
    if !fresh(login_row) {
        return None;
    }
    let login = current_metrics(login_row);
    let allowed = selected_queue.map(|queue| config.queue_compute_nodes(queue.as_str()));
    let mut nodes = config
        .nodes
        .iter()
        .filter(|(id, _)| {
            !config.is_login_node(id)
                && allowed
                    .as_ref()
                    .is_none_or(|members| members.iter().any(|member| member == *id))
        })
        .map(|(id, node)| (id.clone(), node.clone()))
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.0.cmp(&right.0));
    let samples = nodes
        .into_iter()
        .map(|(id, node)| {
            let result = if node.transport == Transport::Local {
                Ok(login.clone())
            } else {
                rows.get(&id)
                    .filter(|row| fresh(row))
                    .map(|row| Ok(current_metrics(row)))
                    .unwrap_or_else(
                        || Err("controller monitor cache is stale or incomplete".into()),
                    )
            };
            (id, node, result)
        })
        .collect::<Vec<_>>();
    if samples
        .iter()
        .any(|(_, node, result)| node.transport == Transport::Ssh && result.is_err())
    {
        return None;
    }
    Some((login, samples))
}

fn one_shot_task_counts(
    config: &ClusterConfig,
    state_dir: &Path,
) -> Option<BTreeMap<String, (usize, usize)>> {
    let store = ReadOnlyJobStore::open(state_dir).ok()?;
    let jobs = store.list_monitor_jobs().ok()?;
    let mut counts: BTreeMap<String, (usize, usize)> = config
        .nodes
        .keys()
        .filter(|id| !config.is_login_node(id))
        .map(|id| (id.clone(), (0, 0)))
        .collect();

    for job in jobs {
        match job.state {
            JobState::Starting | JobState::Running | JobState::Cancelling => {
                if let Some(node) = job.node.as_ref().and_then(|id| counts.get_mut(id.as_str())) {
                    node.0 += 1;
                }
            }
            JobState::Pending => {
                if let Some(node_id) = job.spec.node.as_ref() {
                    if let Some(node) = counts.get_mut(node_id.as_str()) {
                        node.1 += 1;
                    }
                } else {
                    for node_id in config.queue_compute_nodes(job.spec.queue.as_str()) {
                        if let Some(node) = counts.get_mut(&node_id) {
                            node.1 += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some(counts)
}

fn explain_legacy_power_agent(snapshot: &mut MetricSnapshot) {
    if let Some(reason) = snapshot.errors.get_mut("power")
        && reason == "no supported non-interactive power sampler was found"
    {
        *reason = "remote agent predates power sampling; rerun mnode -a for this node to update it"
            .into();
    }
}

fn aggregate_metrics(nodes: &[NodeMetricRow]) -> MetricSnapshot {
    let available: Vec<_> = nodes
        .iter()
        .filter_map(|node| node.metrics.as_ref())
        .collect();
    if available.is_empty() {
        return macluster_metrics::unavailable(now_unix_ms(), "no compute nodes responded");
    }
    let sum = |get: fn(&MetricSnapshot) -> Option<f64>| -> Option<f64> {
        let values: Option<Vec<_>> = available.iter().map(|metrics| get(metrics)).collect();
        values.map(|values| values.into_iter().sum())
    };
    let sum_u64 = |get: fn(&MetricSnapshot) -> Option<u64>| -> Option<u64> {
        let values: Option<Vec<_>> = available.iter().map(|metrics| get(metrics)).collect();
        values.map(|values| values.into_iter().sum())
    };
    let power_scope = available
        .first()
        .and_then(|metric| metric.power_scope.clone());
    let mixed_power = available
        .iter()
        .any(|metric| metric.power_scope != power_scope);
    let mut errors = BTreeMap::new();
    if mixed_power {
        errors.insert(
            "power".into(),
            "node power scopes differ; aggregate omitted".into(),
        );
    }
    MetricSnapshot {
        sampled_unix_ms: now_unix_ms(),
        cpu_percent: sum(|metric| metric.cpu_percent),
        cpu_max_percent: sum(|metric| metric.cpu_max_percent),
        memory_total_bytes: sum_u64(|metric| metric.memory_total_bytes),
        memory_used_bytes: sum_u64(|metric| metric.memory_used_bytes),
        swap_used_bytes: sum_u64(|metric| metric.swap_used_bytes),
        disk_read_bytes_per_sec: sum(|metric| metric.disk_read_bytes_per_sec),
        disk_write_bytes_per_sec: sum(|metric| metric.disk_write_bytes_per_sec),
        network_rx_bytes_per_sec: sum(|metric| metric.network_rx_bytes_per_sec),
        network_tx_bytes_per_sec: sum(|metric| metric.network_tx_bytes_per_sec),
        power_watts: if mixed_power {
            None
        } else {
            sum(|metric| metric.power_watts)
        },
        power_scope: if mixed_power { None } else { power_scope },
        cpu_temp_celsius: available
            .iter()
            .filter_map(|metric| metric.cpu_temp_celsius)
            .filter(|value| value.is_finite() && *value > 0.0 && *value < 150.0)
            .reduce(f64::max),
        fan_speed_rpm: None,
        fan_readings: None,
        power_age_ms: if mixed_power {
            None
        } else {
            available
                .iter()
                .map(|metric| metric.power_age_ms)
                .collect::<Option<Vec<_>>>()
                .and_then(|ages| ages.into_iter().max())
        },
        gpu_percent: None,
        gpu_source: None,
        gpu_age_ms: None,
        gpu_window_ms: None,
        stale: available.iter().any(|metric| metric.stale),
        errors,
    }
}

const METRIC_HEADERS: [&str; 10] = [
    "NODE",
    "RUN/WAIT",
    "CPU%",
    "MEM(GiB)",
    "GPU%",
    "DISK(R/W)",
    "NET(down/up)",
    "POWER",
    "TEMP",
    "STATE",
];

fn print_cluster_metrics(view: &ClusterMetricView, color: bool, continuous: bool) {
    if color {
        println!("\x1b[1;36mMACLUSTER NODE MONITOR\x1b[0m");
    } else {
        println!("MACLUSTER NODE MONITOR");
    }
    println!(
        "Refresh: 2s  |  compute pool: {}/{} nodes unreachable",
        view.missing_nodes,
        view.nodes.len()
    );

    let mut rows = Vec::with_capacity(view.nodes.len() + 2);
    if view.login_compute_node_id.is_none() {
        rows.push(metric_cells(
            "login",
            Some(&view.login),
            "LOCAL",
            Some("0/0".into()),
        ));
    }
    for node in &view.nodes {
        let task_count = view
            .task_counts_by_node
            .as_ref()
            .and_then(|counts| counts.get(&node.id))
            .map(|(running, waiting)| format!("{running}/{waiting}"));
        rows.push(metric_cells(
            &node.id,
            node.metrics.as_ref(),
            if node.reachable { "ONLINE" } else { "DOWN" },
            task_count,
        ));
    }
    rows.push(metric_cells(
        "POOL TOTAL",
        Some(&view.pool_total),
        "COMPUTE",
        None,
    ));

    let is_tty = io::stdout().is_terminal();
    let terminal_width = is_tty
        .then(|| {
            crossterm::terminal::size()
                .ok()
                .map(|(width, _)| usize::from(width))
        })
        .flatten();
    if terminal_width.is_some() {
        for row in &mut rows {
            row[0] = truncate_display(&sanitize_cell(&row[0]), 24);
        }
    }
    let (visible_columns, widths, compact) = table_layout(&rows, terminal_width);
    if compact {
        println!("{}", compact_metric_table(&rows));
    } else {
        let header = METRIC_HEADERS
            .iter()
            .map(|cell| (*cell).to_owned())
            .collect::<Vec<_>>();
        let line = format_table_line(&header, &visible_columns, &widths, false);
        println!(
            "{}",
            if color {
                format!("\x1b[1m{line}\x1b[0m")
            } else {
                line
            }
        );
        let rule_width = widths.iter().take(visible_columns.len()).sum::<usize>()
            + visible_columns.len().saturating_sub(1) * 2;
        println!("{}", "─".repeat(rule_width));
        for row in &rows {
            let line = format_table_line(row, &visible_columns, &widths, color);
            println!("{line}");
        }
    }
    let mut power_errors = Vec::new();
    if view.login_compute_node_id.is_none()
        && let Some(reason) = view.login.errors.get("power")
    {
        power_errors.push(("login", reason));
    }
    power_errors.extend(view.nodes.iter().filter_map(|node| {
        node.metrics
            .as_ref()
            .and_then(|metrics| metrics.errors.get("power"))
            .map(|reason| (node.id.as_str(), reason))
    }));
    for (node, reason) in power_errors {
        println!("Power {node}: {}", sanitize_cell(reason));
    }
    if continuous {
        println!("\nPress Ctrl-C to exit");
    }
}

fn metric_cells(
    name: &str,
    metric: Option<&MetricSnapshot>,
    state: &str,
    task_count: Option<String>,
) -> Vec<String> {
    let Some(metric) = metric else {
        return vec![
            name.into(),
            task_count.unwrap_or_else(|| "N/A".into()),
            "N/A".into(),
            "N/A".into(),
            "N/A".into(),
            "N/A".into(),
            "N/A".into(),
            "N/A".into(),
            "N/A".into(),
            state.into(),
        ];
    };
    let cpu = format_opt(metric.cpu_percent.map(|value| {
        format!(
            "{value:.0}/{:.0}",
            metric.cpu_max_percent.unwrap_or_default()
        )
    }));
    let memory = format_opt(metric.memory_used_bytes.zip(metric.memory_total_bytes).map(
        |(used, total)| {
            const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
            format!("{:.1}/{:.1}", used as f64 / GIB, total as f64 / GIB)
        },
    ));
    let gpu = format_opt(metric.gpu_percent.map(|value| format!("{value:.0}")));
    let cpu_temperature = format_opt(metric.cpu_temp_celsius.map(|value| format!("{value:.1}°C")));
    let disk = format_pair(
        metric.disk_read_bytes_per_sec,
        metric.disk_write_bytes_per_sec,
        1024.0,
        "KiB/s",
    );
    let network = format_pair(
        metric.network_rx_bytes_per_sec,
        metric.network_tx_bytes_per_sec,
        1024.0 * 1024.0,
        "MiB/s",
    );
    let power = format_power(metric.power_watts, metric.power_scope.as_deref());
    vec![
        name.into(),
        task_count.unwrap_or_else(|| "N/A".into()),
        cpu,
        memory,
        gpu,
        disk,
        network,
        power,
        cpu_temperature,
        state.into(),
    ]
}

#[cfg(test)]
fn metric_table_header() -> String {
    let header = METRIC_HEADERS
        .iter()
        .map(|cell| (*cell).to_owned())
        .collect::<Vec<_>>();
    let columns: Vec<_> = (0..METRIC_HEADERS.len()).collect();
    let widths = natural_column_widths(&header, &[], &columns);
    format_table_line(&header, &columns, &widths, false)
}

#[cfg(test)]
fn metric_row(name: &str, metric: &MetricSnapshot, state: &str, color: bool) -> String {
    let cells = metric_cells(name, Some(metric), state, None);
    let columns: Vec<_> = (0..METRIC_HEADERS.len()).collect();
    let widths = natural_column_widths(
        &METRIC_HEADERS.map(|cell| cell.to_owned()),
        &[cells.clone()],
        &columns,
    );
    format_table_line(&cells, &columns, &widths, color)
}

fn table_layout(
    rows: &[Vec<String>],
    terminal_width: Option<usize>,
) -> (Vec<usize>, Vec<usize>, bool) {
    let all_columns: Vec<_> = (0..METRIC_HEADERS.len()).collect();
    let header = METRIC_HEADERS.map(str::to_owned);
    let selected = if let Some(max_width) = terminal_width {
        let mut columns = vec![0, 1, 2, 3];
        let required = natural_column_widths(&header, rows, &columns);
        if table_width(&required, columns.len()) > max_width {
            return (Vec::new(), Vec::new(), true);
        }
        for column in [4, 5, 6, 7, 8, 9] {
            columns.push(column);
            let widths = natural_column_widths(&header, rows, &columns);
            if table_width(&widths, columns.len()) > max_width {
                columns.pop();
            }
        }
        columns
    } else {
        all_columns
    };
    let widths = natural_column_widths(&header, rows, &selected);
    (selected, widths, false)
}

fn natural_column_widths(header: &[String], rows: &[Vec<String>], columns: &[usize]) -> Vec<usize> {
    columns
        .iter()
        .map(|column| {
            let header_width = display_width(&sanitize_cell(&header[*column]));
            let row_width = rows
                .iter()
                .map(|row| display_width(&sanitize_cell(&row[*column])))
                .max()
                .unwrap_or_default();
            header_width.max(row_width)
        })
        .collect()
}

fn table_width(widths: &[usize], columns: usize) -> usize {
    widths.iter().sum::<usize>() + columns.saturating_sub(1) * 2
}

fn format_table_line(
    cells: &[String],
    columns: &[usize],
    widths: &[usize],
    color_state: bool,
) -> String {
    columns
        .iter()
        .zip(widths)
        .map(|(column, width)| {
            let cell = sanitize_cell(&cells[*column]);
            let cell = pad_cell(&cell, *width);
            if *column == 9 && color_state {
                let state = cells[*column].as_str();
                let style = match state {
                    "DOWN" => "\x1b[1;31m",
                    "ONLINE" | "LOCAL" => "\x1b[1;32m",
                    _ => "\x1b[1;36m",
                };
                format!("{style}{cell}\x1b[0m")
            } else {
                cell
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

fn compact_metric_table(rows: &[Vec<String>]) -> String {
    let mut lines = Vec::new();
    for row in rows {
        lines.push(format!("NODE  {}", sanitize_cell(&row[0])));
        for column in 1..row.len() {
            if column == 9 && row[column] == "COMPUTE" {
                continue;
            }
            lines.push(format!(
                "  {}  {}",
                METRIC_HEADERS[column],
                sanitize_cell(&row[column])
            ));
        }
    }
    lines.join("\n")
}

fn sanitize_cell(value: &str) -> String {
    let mut clean = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => clean.push_str("\\n"),
            '\r' => clean.push_str("\\r"),
            '\t' => clean.push_str("\\t"),
            character if character.is_control() => clean.push('�'),
            character => clean.push(character),
        }
    }
    clean
}

fn display_width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

fn pad_cell(value: &str, width: usize) -> String {
    let padding = width.saturating_sub(display_width(value));
    format!("{value}{}", " ".repeat(padding))
}

fn truncate_display(value: &str, maximum: usize) -> String {
    if display_width(value) <= maximum {
        return value.to_owned();
    }
    if maximum == 0 {
        return String::new();
    }
    let target = maximum.saturating_sub(1);
    let mut output = String::new();
    let mut width = 0;
    for character in value.chars() {
        let char_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if width + char_width > target {
            break;
        }
        output.push(character);
        width += char_width;
    }
    output.push('…');
    output
}

fn format_power(watts: Option<f64>, scope: Option<&str>) -> String {
    let _ = scope;
    match watts {
        Some(watts) => format!("{watts:.1} W"),
        None => "N/A".into(),
    }
}

fn format_pair(first: Option<f64>, second: Option<f64>, scale: f64, suffix: &str) -> String {
    match (first, second) {
        (Some(first), Some(second)) => {
            format!("{:.1}/{:.1} {suffix}", first / scale, second / scale)
        }
        _ => "N/A".into(),
    }
}

fn format_opt(value: Option<String>) -> String {
    value.unwrap_or_else(|| "N/A".into())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn internal(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    match args.first().map(String::as_str) {
        Some("nfs-recovery") => crate::nfs_recovery::run(&args[1..]).map_err(|error| (1, error)),
        Some("controller-service") => {
            if args.len() != 1 {
                return Err((2, "internal controller-service takes no arguments".into()));
            }
            controller(global, &["run".into()], true)
        }
        Some("claim-agent") => {
            let node_id = option_value(args, "--node")?
                .ok_or_else(|| (2, "claim-agent requires --node".into()))?;
            let uuid = option_value(args, "--controller")?
                .ok_or_else(|| (2, "claim-agent requires --controller".into()))?;
            let epoch = option_value(args, "--epoch")?
                .ok_or_else(|| (2, "claim-agent requires --epoch".into()))?
                .parse::<u64>()
                .map_err(|_| (2, "claim-agent epoch must be an integer".into()))?;
            let controller = macluster_protocol::types::ControllerEpoch {
                controller_uuid: macluster_protocol::identifiers::ControllerUuid(
                    Id128::parse(&uuid).map_err(|error| (2, error.to_string()))?,
                ),
                epoch,
            };
            let config = load_config(global.config.as_deref()).map_err(config_error)?;
            let node = config
                .nodes
                .get(&node_id)
                .ok_or_else(|| (2, "claim-agent node is absent from config".into()))?;
            macluster_agent::validate_node_identity(
                node,
                &local_machine_uuid().map_err(|error| (1, error))?,
                unsafe { libc::geteuid() },
            )
            .map_err(|error| (1, error))?;
            let state = global
                .state_dir
                .unwrap_or_else(macluster_agent::default_state_dir);
            macluster_agent::admin::claim_idle(&state, controller, &config.share_uuid)
                .map_err(|error| (1, error.to_string()))
        }
        Some("archive-agent-state") => {
            let namespace = option_value(args, "--share-id")?
                .ok_or_else(|| (2, "archive-agent-state requires --share-id".into()))?;
            let archive = option_value(args, "--archive")?
                .ok_or_else(|| (2, "archive-agent-state requires --archive".into()))?;
            let discard = args.iter().any(|arg| arg == "--discard-terminal-sync");
            let state = global
                .state_dir
                .unwrap_or_else(macluster_agent::default_state_dir);
            let outcome = macluster_agent::admin::archive_idle_namespace(
                &state,
                Path::new(&archive),
                &namespace,
                discard,
            )
            .map_err(|error| (1, error.to_string()))?;
            println!(
                "{}",
                serde_json::to_string(&outcome).map_err(|error| (1, error.to_string()))?
            );
            Ok(())
        }
        Some("commit-enrollment-config") => {
            let destination = option_value(args, "--destination")?
                .ok_or_else(|| (2, "missing enrollment destination".into()))?;
            let staged = option_value(args, "--staged")?
                .ok_or_else(|| (2, "missing staged enrollment config".into()))?;
            let baseline = option_value(args, "--baseline")?
                .ok_or_else(|| (2, "missing enrollment config baseline".into()))?;
            crate::node_admin::commit_enrollment_config(
                Path::new(&destination),
                Path::new(&staged),
                &baseline,
            )
        }
        Some("power-helper") => {
            if args.get(1).map(String::as_str) != Some("--version") || args.len() != 2 {
                return Err((2, "internal power-helper only supports --version".into()));
            }
            let helper =
                crate::embedded_power::ExtractedHelper::new().map_err(|error| (1, error))?;
            let output = process::Command::new(helper.path())
                .arg("--version")
                .output()
                .map_err(|error| (1, format!("cannot inspect embedded power helper: {error}")))?;
            if !output.status.success() {
                return Err((
                    1,
                    format!(
                        "embedded power helper failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ),
                ));
            }
            print!("{}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        }
        Some("publish-snapshot") => {
            let state_dir = global
                .state_dir
                .ok_or_else(|| (2, "publish-snapshot requires --state-dir PATH".into()))?;
            let job_id = option_value(args, "--job-id")?
                .ok_or_else(|| (2, "publish-snapshot requires --job-id ID".into()))?
                .parse::<u64>()
                .map_err(|_| (2, "invalid snapshot job ID".into()))?;
            let shared_root = option_value(args, "--shared-root")?
                .ok_or_else(|| (2, "publish-snapshot requires --shared-root PATH".into()))?;
            let storage = Storage::open(state_dir).map_err(operation_error)?;
            storage
                .publish_snapshot(job_id, Path::new(&shared_root))
                .map_err(operation_error)
        }
        Some("local-share-source-check") => {
            let path = option_value(args, "--path")?
                .ok_or_else(|| (2, "local-share-source-check requires --path PATH".into()))?;
            verify_local_share_source(Path::new(&path)).map_err(|error| (1, error))
        }
        Some("primary-share-check") => {
            let root = option_value(args, "--root")?
                .ok_or_else(|| (2, "primary-share-check requires --root PATH".into()))?;
            let source_root = option_value(args, "--source-root")?.unwrap_or_else(|| root.clone());
            let uuid = option_value(args, "--uuid")?
                .ok_or_else(|| (2, "primary-share-check requires --uuid UUID".into()))?;
            let host = option_value(args, "--host")?
                .ok_or_else(|| (2, "primary-share-check requires --host IPv4".into()))?;
            let local_server = match option_value(args, "--local-server")?.as_deref() {
                Some("yes") => true,
                Some("no") => false,
                _ => {
                    return Err((
                        2,
                        "primary-share-check requires --local-server yes|no".into(),
                    ));
                }
            };
            if macluster_controller::verify_primary_share_direct(
                Path::new(&root),
                Path::new(&source_root),
                &uuid,
                &host,
                local_server,
            ) {
                Ok(())
            } else {
                Err((1, "primary shared storage check failed".into()))
            }
        }
        Some("node-check") => {
            let node = option_value(args, "--node")?
                .ok_or_else(|| (2, "node-check requires --node ID".into()))?;
            let config = load_config(global.config.as_deref()).map_err(config_error)?;
            if !config.nodes.contains_key(&node) {
                return Err((2, format!("node '{node}' is not present in this config")));
            }
            let response = macluster_agent::handle_request(
                macluster_protocol::types::Request {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: RequestId::random(),
                    operation: macluster_protocol::types::Operation::Health,
                },
                &config,
                &macluster_agent::default_state_dir(),
                &node,
            );
            let health = response.result.ok().and_then(|body| match body {
                macluster_protocol::types::ResponseBody::Health(health) => Some(health),
                _ => None,
            });
            let report = RemoteNodeCheck {
                node,
                machine_uuid: health
                    .as_ref()
                    .map(|health| health.machine_uuid.clone())
                    .or_else(|| local_machine_uuid().ok()),
                shared_storage_ready: health
                    .as_ref()
                    .is_some_and(|health| health.primary_share_ready),
                shares: health.map(|health| health.shares).unwrap_or_default(),
            };
            println!(
                "{}",
                serde_json::to_string(&report).map_err(|error| (1, error.to_string()))?
            );
            Ok(())
        }
        Some("local-share-check") => {
            let config = load_config(global.config.as_deref()).map_err(config_error)?;
            if macluster_controller::verify_shared_storage(&config) {
                Ok(())
            } else {
                Err((
                    1,
                    "configured NFS share is not mounted or its marker/source is invalid".into(),
                ))
            }
        }
        Some("verify-file") => {
            let path = option_value(args, "--path")?
                .ok_or_else(|| (2, "verify-file requires --path".into()))?;
            let digest = option_value(args, "--sha256")?
                .ok_or_else(|| (2, "verify-file requires --sha256".into()))?;
            let bytes = fs::read(&path).map_err(|error| (1, error.to_string()))?;
            let actual = sha256_hex(&bytes).map_err(|error| (1, error.to_string()))?;
            if actual == digest {
                Ok(())
            } else {
                Err((1, "file digest did not match".into()))
            }
        }
        Some("metrics") => {
            if args.iter().any(|arg| arg == "--json") {
                if args.iter().any(|arg| arg == "--fast") {
                    let snapshot = macluster_metrics::sample_local_fast();
                    println!(
                        "{}",
                        serde_json::to_string(&serde_json::json!({
                            "sample_phase": "initial",
                            "snapshot": snapshot,
                        }))
                        .map_err(|error| (1, error.to_string()))?
                    );
                } else {
                    let snapshot = macluster_metrics::sample_local();
                    println!(
                        "{}",
                        serde_json::to_string(&snapshot).map_err(|error| (1, error.to_string()))?
                    );
                }
                Ok(())
            } else {
                Err((2, "internal metrics only supports --json".into()))
            }
        }
        Some("capabilities") => {
            if args.iter().any(|arg| arg == "--json") {
                let report = serde_json::json!({
                    "protocol_version": PROTOCOL_VERSION,
                    "features": [
                        "config.local-transport.v1",
                        "config.named-shares.v1",
                        "agent.node-health.v1",
                        "config.execution-digest.v1",
                        "config.primary-storage-source.v1",
                        "metrics.cpu-temperature.v1",
                        METRICS_FAN_SPEED_FEATURE,
                        INTERACTIVE_PTY_FEATURE,
                        macluster_protocol::types::NAMESPACED_JOBS_FEATURE
                        , "agent.idle-handoff.v1"
                    ]
                });
                println!("{}", serde_json::to_string(&report).unwrap());
                Ok(())
            } else {
                Err((2, "internal capabilities only supports --json".into()))
            }
        }
        Some("agent-stdio") => {
            let node = option_value(args, "--node")?
                .ok_or_else(|| (2, "agent-stdio requires --node ID".into()))?;
            let config = load_config(global.config.as_deref()).map_err(config_error)?;
            let state_dir = global
                .state_dir
                .unwrap_or_else(macluster_agent::default_state_dir);
            let stdin = io::stdin();
            let stdout = io::stdout();
            macluster_agent::serve_stdio(
                &mut stdin.lock(),
                &mut stdout.lock(),
                &config,
                &state_dir,
                &node,
            )
            .map_err(|error| (1, error.to_string()))
        }
        Some("agent-attach") => {
            let node = option_value(args, "--node")?
                .ok_or_else(|| (2, "agent-attach requires --node ID".into()))?;
            let job_id = option_value(args, "--job-id")?
                .ok_or_else(|| (2, "agent-attach requires --job-id ID".into()))?
                .parse::<u64>()
                .map_err(|_| (2, "invalid interactive job ID".into()))?;
            let token = option_value(args, "--start-token")?
                .ok_or_else(|| (2, "agent-attach requires --start-token TOKEN".into()))?;
            let token = StartToken(Id128::parse(&token).map_err(|error| (2, error.to_string()))?);
            let state_dir = global
                .state_dir
                .unwrap_or_else(macluster_agent::default_state_dir);
            let stdin = io::stdin();
            let stdout = io::stdout();
            let mut input = stdin.lock();
            let mut output = stdout.lock();
            macluster_agent::serve_attach_stdio(
                &mut input,
                &mut output,
                &state_dir,
                &node,
                job_id,
                token,
            )
            .map_err(|error| (1, error.to_string()))
        }
        Some("stop-log-sync") => {
            let state = global
                .state_dir
                .ok_or_else(|| (2, "stop-log-sync requires --state-dir".into()))?;
            let share = option_value(args, "--share-id")?
                .ok_or_else(|| (2, "stop-log-sync requires --share-id".into()))?;
            let reset = option_value(args, "--reset-id")?
                .ok_or_else(|| (2, "stop-log-sync requires --reset-id".into()))?;
            let share = Id128::parse(&share).map_err(|error| (2, error.to_string()))?;
            let reset = Id128::parse(&reset).map_err(|error| (2, error.to_string()))?;
            macluster_agent::log_sync::quiesce(&state, share, reset, Duration::from_secs(5))
                .map_err(|error| (1, error.to_string()))
        }
        Some("log-sync") => {
            let state_dir = global
                .state_dir
                .ok_or_else(|| (2, "log-sync requires --state-dir".into()))?;
            let job_id = option_value(args, "--job-id")?
                .ok_or_else(|| (2, "log-sync requires --job-id".into()))?
                .parse::<u64>()
                .map_err(|_| (2, "invalid log-sync job ID".into()))?;
            let token = option_value(args, "--start-token")?
                .ok_or_else(|| (2, "log-sync requires --start-token".into()))?;
            let token = StartToken(Id128::parse(&token).map_err(|error| (2, error.to_string()))?);
            let timeout = option_value(args, "--idle-timeout-ms")?
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map(std::time::Duration::from_millis)
                        .map_err(|_| (2, "invalid log-sync idle timeout".into()))
                })
                .transpose()?
                .unwrap_or(macluster_agent::log_sync::DEFAULT_IDLE_TIMEOUT);
            macluster_agent::log_sync::run(&state_dir, job_id, token, timeout)
                .map_err(|error| (1, error.to_string()))
        }
        Some("runner") => {
            let state_dir = global
                .state_dir
                .ok_or_else(|| (2, "runner requires --state-dir".into()))?;
            let job_id = option_value(args, "--job-id")?
                .ok_or_else(|| (2, "runner requires --job-id".into()))?
                .parse::<u64>()
                .map_err(|_| (2, "invalid runner job ID".into()))?;
            let token = option_value(args, "--start-token")?
                .ok_or_else(|| (2, "runner requires --start-token".into()))?;
            let token = StartToken(Id128::parse(&token).map_err(|error| (2, error.to_string()))?);
            let code = macluster_agent::run_runner(&state_dir, job_id, token);
            if code == 0 {
                Ok(())
            } else {
                Err((1, format!("runner exited with status {code}")))
            }
        }
        _ => Err((2, "unknown internal command".into())),
    }
}

fn option_value(args: &[String], option: &str) -> AppResult<Option<String>> {
    for (index, argument) in args.iter().enumerate() {
        if argument == option {
            return args
                .get(index + 1)
                .cloned()
                .map(Some)
                .ok_or_else(|| (2, format!("missing value for {option}")));
        }
    }
    Ok(None)
}

fn load_config(override_path: Option<&Path>) -> Result<ClusterConfig, String> {
    let path = resolved_config_path(override_path);
    let source = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read config {}: {error}", path.display()))?;
    ClusterConfig::parse(&source).map_err(|error| format!("{}: {error}", path.display()))
}

fn resolved_config_path(override_path: Option<&Path>) -> PathBuf {
    override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home_dir().join(".config/macluster/config.toml"))
}

#[derive(Serialize)]
struct RemoteNodeCheck {
    node: String,
    machine_uuid: Option<String>,
    shared_storage_ready: bool,
    #[serde(default)]
    shares: BTreeMap<String, bool>,
}

fn local_machine_uuid() -> Result<String, String> {
    let output = process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("ioreg failed".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = text
        .lines()
        .find(|line| line.contains("IOPlatformUUID"))
        .and_then(|line| line.rsplit_once('=').map(|(_, value)| value.trim()))
        .map(|value| value.trim_matches('"').trim())
        .ok_or_else(|| "IOPlatformUUID was not present in ioreg output".to_owned())?;
    Id128::parse(value).map_err(|error| error.to_string())?;
    Ok(value.to_ascii_lowercase())
}

fn node_admin(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    let config_path = resolved_config_path(global.config.as_deref());
    let state_dir = state_root(global.state_dir.as_deref())?;
    crate::init::reset::ensure_no_reset_in_progress(&config_path, &state_dir)?;
    crate::node_admin::run(config_path, state_dir, args)
}

fn state_root(override_path: Option<&Path>) -> AppResult<PathBuf> {
    let path = override_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home_dir().join("Library/Application Support/macluster/controller"));
    if !path.is_absolute() {
        return Err((2, "--state-dir must be an absolute path".into()));
    }
    Ok(path)
}

fn home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/Users/unknown"))
}

fn load_submission_cache(
    root: &Path,
    request_id: RequestId,
) -> AppResult<Option<(JobSpec, Vec<u8>)>> {
    let dir = root.join("client-submissions");
    let metadata = dir.join(format!("{request_id}.json"));
    if !metadata.exists() {
        return Ok(None);
    }
    let cached: CachedSubmission =
        serde_json::from_slice(&fs::read(&metadata).map_err(|error| (1, error.to_string()))?)
            .map_err(|error| {
                (
                    1,
                    format!("invalid cached submission {request_id}: {error}"),
                )
            })?;
    let script = fs::read(dir.join(format!("{request_id}.script"))).map_err(|error| {
        (
            1,
            format!("cached script for {request_id} is unavailable: {error}"),
        )
    })?;
    if let Some(snapshot) = cached.spec.snapshot.as_ref() {
        let digest = sha256_hex(&script).map_err(|error| (1, error.to_string()))?;
        if digest != snapshot.sha256 || script.len() as u64 != snapshot.size_bytes {
            return Err((
                1,
                format!("cached script for {request_id} failed its digest check"),
            ));
        }
    } else if !script.is_empty() {
        return Err((
            1,
            format!("cached interactive shell for {request_id} contains a script"),
        ));
    }
    Ok(Some((cached.spec, script)))
}

fn save_submission_cache(
    root: &Path,
    request_id: RequestId,
    spec: &JobSpec,
    script: &[u8],
) -> AppResult<()> {
    let dir = root.join("client-submissions");
    fs::create_dir_all(&dir).map_err(|error| (1, error.to_string()))?;
    let metadata = serde_json::to_vec(&CachedSubmission { spec: spec.clone() })
        .map_err(|error| (1, error.to_string()))?;
    atomic_write(&dir.join(format!("{request_id}.script")), script)?;
    atomic_write(&dir.join(format!("{request_id}.json")), &metadata)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| (1, "cache path has no parent".into()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(OsStr::to_str).unwrap_or("cache"),
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
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result.map_err(|error| (1, error.to_string()))
}

fn verify_local_share_source(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "share source {} is not a real directory",
            path.display()
        ));
    }
    #[cfg(target_vendor = "apple")]
    {
        use std::mem::MaybeUninit;

        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "share source path contains NUL".to_owned())?;
        let mut info = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::statfs(path_c.as_ptr(), info.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let info = unsafe { info.assume_init() };
        let filesystem = unsafe { CStr::from_ptr(info.f_fstypename.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        if info.f_flags & (libc::MNT_LOCAL as u32) == 0
            || filesystem.eq_ignore_ascii_case("nfs")
            || filesystem.eq_ignore_ascii_case("smbfs")
        {
            return Err(format!(
                "share source {} is on non-local filesystem '{filesystem}'",
                path.display()
            ));
        }
        // Local does not imply exportable: an ExFAT volume can be read and
        // written normally but lack the file handles required by the NFS server.
        // Query the volume once, without sudo, before changing exports/markers.
        #[repr(C)]
        struct VolumeCapabilities {
            length: u32,
            values: libc::vol_capabilities_attr_t,
        }
        let mut attributes: libc::attrlist = unsafe { std::mem::zeroed() };
        attributes.bitmapcount = libc::ATTR_BIT_MAP_COUNT as _;
        attributes.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES;
        let mut capabilities = MaybeUninit::<VolumeCapabilities>::zeroed();
        if unsafe {
            libc::getattrlist(
                path_c.as_ptr(),
                (&mut attributes as *mut libc::attrlist).cast(),
                capabilities.as_mut_ptr().cast(),
                std::mem::size_of::<VolumeCapabilities>(),
                0,
            )
        } != 0
        {
            return Err(format!(
                "cannot inspect NFS export capability of {}: {}",
                path.display(),
                io::Error::last_os_error()
            ));
        }
        let capabilities = unsafe { capabilities.assume_init() };
        let interfaces = libc::VOL_CAPABILITIES_INTERFACES;
        let export = libc::VOL_CAP_INT_NFSEXPORT;
        if capabilities.values.valid[interfaces] & export != 0
            && capabilities.values.capabilities[interfaces] & export == 0
        {
            return Err(format!(
                "share source {} uses filesystem '{filesystem}', which does not support macOS NFS export; choose a directory on an NFS-capable volume, such as APFS. Administrator authorization cannot enable this filesystem capability",
                path.display()
            ));
        }
        Ok(())
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        Err("local filesystem source checks are supported only on macOS".into())
    }
}

fn parse_state(value: &str) -> Option<JobState> {
    Some(match value.to_ascii_uppercase().as_str() {
        "PENDING" => JobState::Pending,
        "STARTING" => JobState::Starting,
        "RUNNING" => JobState::Running,
        "CANCELLING" => JobState::Cancelling,
        "COMPLETED" => JobState::Completed,
        "FAILED" => JobState::Failed,
        "CANCELLED" => JobState::Cancelled,
        "TIMEOUT" => JobState::Timeout,
        "NODE_LOST" => JobState::NodeLost,
        _ => return None,
    })
}

fn parse_job_id(value: &str) -> AppResult<u64> {
    let id = value
        .parse::<u64>()
        .map_err(|_| (2, format!("invalid job ID '{value}'")))?;
    if id == 0 {
        return Err((2, "job IDs start at 1".into()));
    }
    Ok(id)
}

fn parse_request_id(value: &str) -> AppResult<RequestId> {
    Id128::parse(value)
        .map(RequestId)
        .map_err(|error| (2, error.to_string()))
}

fn escape(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn operation_error(error: SubmitError) -> (i32, String) {
    (1, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        thread,
        time::{Duration, Instant},
    };

    use super::{
        ACTIVE_ENV_PREFIX_ENV, ClusterMetricView, EXPLICIT_TASK_PATH_ENV, NodeMetricRow,
        aggregate_metrics, build_submission, cached_monitor_samples,
        can_defer_agent_update_for_work, controller_should_resume_after_agent_update,
        explain_legacy_power_agent, format_job_details, format_jobs_table, format_power,
        is_macluster_binary_path, maybe_run_agent_update, metric_row, metric_table_header,
        prepare_task_environment, promote_inline_command,
        should_block_agent_update_for_pending_node_recovery, should_defer_address_migration,
        should_defer_agent_update_for_node_recovery, should_preflight_agent_update,
    };
    use macluster_core::config::ClusterConfig;
    use macluster_protocol::{
        control::{
            AgentCompatibilityRecord, AgentCompatibilityState, CONTROL_PROTOCOL_VERSION,
            ControlCommand, ControlPayload, ControllerHello, ControllerLifecycle, MonitorSnapshot,
            NodeMonitorRow,
        },
        identifiers::{Id128, NodeId, QueueName},
        types::{ControllerEpoch, JobMode, JobRecord, JobSpec, JobState, MetricSnapshot},
    };

    #[test]
    fn interactive_completion_recovers_and_reads_terminal_state() {
        let job = std::cell::RefCell::new(sample_job(1, JobState::Running, "mini01", None, "wrap"));
        let attempts = std::cell::Cell::new(0);
        super::wait_for_interactive_completion_with(
            1,
            Duration::from_millis(200),
            Duration::from_millis(1),
            || Ok(job.borrow().clone()),
            || {
                attempts.set(attempts.get() + 1);
                job.borrow_mut().state = JobState::Completed;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn interactive_completion_is_bounded_and_preserves_job_on_recovery_failure() {
        let job = sample_job(7, JobState::Running, "mini01", None, "wrap");
        let started = Instant::now();
        let error = super::wait_for_interactive_completion_with(
            7,
            Duration::from_millis(30),
            Duration::from_millis(1),
            || Ok(job.clone()),
            || Err((1, "controller unavailable".into())),
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(error.1.contains("mjob 7"));
        assert!(error.1.contains("controller unavailable"));
        assert_eq!(job.state, JobState::Running);
    }

    #[test]
    fn operational_agent_update_preflight_keeps_init_recovery_independent() {
        for (command, args) in [
            ("internal", vec!["capabilities".into(), "--json".into()]),
            ("agent", vec!["--stdio".into()]),
            ("top", vec!["--help".into()]),
            ("node", vec!["-h".into()]),
            ("init", vec!["--help".into()]),
            ("init", vec![]),
            ("init", vec!["--force".into()]),
        ] {
            assert!(
                !should_preflight_agent_update(command, &args),
                "{command} {args:?} must bypass build preflight"
            );
        }
        for command in [
            "submit",
            "job",
            "queue",
            "kill",
            "top",
            "node",
            "controller",
        ] {
            assert!(
                should_preflight_agent_update(command, &[]),
                "{command} must run build preflight"
            );
        }
        assert!(should_preflight_agent_update(
            "submit",
            &["--wrap".into(), "python".into(), "-h".into()]
        ));
        assert!(!should_preflight_agent_update("submit", &["--help".into()]));
        assert!(should_preflight_agent_update(
            "submit",
            &["python".into(), "-h".into()]
        ));
        assert!(!super::should_refresh_node_addresses("init", &[]));
        for lifecycle_command in ["start", "stop", "restart", "status"] {
            assert!(!should_preflight_agent_update(
                "controller",
                &[lifecycle_command.into()]
            ));
            assert!(!super::should_refresh_node_addresses(
                "controller",
                &[lifecycle_command.into()]
            ));
        }
    }

    #[test]
    fn node_removal_can_recover_an_endpoint_before_any_agent_update() {
        for flag in ["-rm", "--remove"] {
            assert!(!should_preflight_agent_update(
                "node",
                &[flag.into(), "worker".into()]
            ));
            assert!(!should_preflight_agent_update(
                "node",
                &[
                    flag.into(),
                    "worker".into(),
                    "--connect".into(),
                    "operator@192.0.2.20".into()
                ]
            ));
        }
        assert!(should_preflight_agent_update(
            "node",
            &["-a".into(), "operator@192.0.2.20".into()]
        ));
    }

    #[test]
    fn node_admin_recovery_can_run_before_the_global_agent_update() {
        assert!(should_defer_agent_update_for_node_recovery("node", true));
        assert!(should_defer_agent_update_for_node_recovery("init", true));
        assert!(!should_defer_agent_update_for_node_recovery("submit", true));
        assert!(!should_defer_agent_update_for_node_recovery("node", false));
        assert!(!should_defer_agent_update_for_node_recovery("init", false));
    }

    #[test]
    fn only_status_and_cancel_commands_can_defer_an_agent_update_for_active_work() {
        for command in ["job", "queue", "kill", "top"] {
            assert!(can_defer_agent_update_for_work(command, &[]), "{command}");
        }
        for args in [vec!["-l".into()], vec!["--list".into()]] {
            assert!(can_defer_agent_update_for_work("node", &args));
        }
        for (command, args) in [
            ("submit", vec![]),
            ("node", vec!["-a".into(), "user@192.0.2.1".into()]),
            ("node", vec!["-rm".into(), "worker".into()]),
            ("init", vec![]),
            ("controller", vec!["run".into()]),
        ] {
            assert!(
                !can_defer_agent_update_for_work(command, &args),
                "{command} {args:?} must stay blocked"
            );
        }
    }

    #[test]
    fn address_migration_is_deferred_for_status_commands_only_while_jobs_are_active() {
        assert!(should_defer_address_migration(true, true));
        assert!(!should_defer_address_migration(true, false));
        assert!(!should_defer_address_migration(false, true));
        assert!(!should_defer_address_migration(false, false));
    }

    #[test]
    fn read_only_query_policy_excludes_cluster_mutations() {
        for (command, args) in [
            ("job", vec!["--log", "1", "--follow"]),
            ("queue", vec!["--watch", "1"]),
            ("top", vec!["--once"]),
            ("node", vec!["-l"]),
            ("node", vec!["--list"]),
            ("fans", vec!["--status"]),
        ] {
            assert!(super::is_read_only_query(
                command,
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
            ));
        }
        for (command, args) in [
            ("submit", vec![]),
            ("kill", vec!["1"]),
            ("init", vec![]),
            ("node", vec!["-a", "local"]),
            ("node", vec!["-rm", "worker"]),
            ("fans", vec!["--auto"]),
        ] {
            assert!(!super::is_read_only_query(
                command,
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
            ));
        }
    }

    #[test]
    fn local_job_listing_excludes_lookups_and_log_following() {
        for args in [
            vec![],
            vec!["--json"],
            vec!["--all", "--json"],
            vec!["--state", "Running"],
        ] {
            assert!(super::job_listing_uses_local_store(
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
            ));
        }
        for args in [
            vec!["1"],
            vec!["--log", "1", "--follow"],
            vec!["--request-id", "id"],
            vec!["--state"],
            vec!["--help"],
        ] {
            assert!(!super::job_listing_uses_local_store(
                &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
            ));
        }
    }

    #[test]
    fn pending_node_admin_work_blocks_update_without_controller_prompt() {
        assert!(should_block_agent_update_for_pending_node_recovery(
            "submit", true, true
        ));
        assert!(!should_block_agent_update_for_pending_node_recovery(
            "submit", true, false
        ));
        assert!(!should_block_agent_update_for_pending_node_recovery(
            "node", true, true
        ));
        assert!(!should_block_agent_update_for_pending_node_recovery(
            "init", true, true
        ));
    }

    #[test]
    fn executable_aliases_are_recognized_by_their_resolved_binary() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("macluster-exe-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        let binary = root.join("macluster");
        let alias = root.join("msub");
        let other = root.join("commands-test");
        fs::write(&binary, "binary").unwrap();
        fs::write(&other, "binary").unwrap();
        symlink(&binary, &alias).unwrap();

        assert!(is_macluster_binary_path(&alias));
        assert!(!is_macluster_binary_path(&other));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_agent_preflight_runs_update_without_generic_confirmation() {
        let mut update_called = false;
        let updated = maybe_run_agent_update(true, || {
            update_called = true;
            Ok(false)
        })
        .unwrap();
        assert_eq!(updated, Some(false));
        assert!(update_called);

        assert_eq!(
            maybe_run_agent_update(false, || panic!("current Agents need no update")).unwrap(),
            None
        );
    }

    #[test]
    fn agent_update_resumes_controller_before_continuing_requested_command() {
        assert!(controller_should_resume_after_agent_update(
            "submit",
            &[],
            true
        ));
        assert!(controller_should_resume_after_agent_update(
            "job",
            &[],
            true
        ));
        assert!(!controller_should_resume_after_agent_update(
            "controller",
            &["run".into()],
            true
        ));
        assert!(!controller_should_resume_after_agent_update(
            "submit",
            &[],
            false
        ));
    }

    fn sample_job(
        id: u64,
        state: JobState,
        queue: &str,
        node: Option<&str>,
        name: &str,
    ) -> JobRecord {
        JobRecord {
            id,
            spec: JobSpec {
                storage_namespace: None,
                queue: QueueName::new(queue).unwrap(),
                node: None,
                name: name.into(),
                cwd: "/Users/Shared/macluster".into(),
                stdout_path: "/Users/Shared/macluster/jobs/%j/stdout.log".into(),
                stderr_path: "/Users/Shared/macluster/jobs/%j/stderr.log".into(),
                walltime_secs: None,
                env: BTreeMap::new(),
                mode: JobMode::Batch,
                snapshot: None,
            },
            state,
            node: node.map(|node| NodeId::new(node).unwrap()),
            start_token: None,
            cancel_force: false,
            created_unix_ms: 1792831567000 + id,
            started_unix_ms: None,
            finished_unix_ms: None,
            exit_code: None,
            end_reason: None,
            snapshot_sync_pending: false,
            log_sync_pending: false,
            waiting_reason: None,
        }
    }

    #[test]
    fn mjob_table_columns_are_left_aligned() {
        let jobs = vec![
            sample_job(7, JobState::Pending, "mini01", None, "short"),
            sample_job(
                128,
                JobState::Cancelled,
                "mini01-long-queue",
                Some("mini01-compute-02"),
                "run analysis\tjob",
            ),
        ];
        let rendered = format_jobs_table(&jobs);
        let lines: Vec<_> = rendered.lines().collect();
        let header = lines[0];
        let row = lines[2];

        for (header_cell, row_cell) in [
            ("JOBID", "128"),
            ("STATE", "Cancelled"),
            ("QUEUE", "mini01-long-queue"),
            ("NODE", "mini01-compute-02"),
            ("CREATED(ms)", "1792831567128"),
        ] {
            assert_eq!(
                header.find(header_cell),
                row.find(row_cell),
                "{header_cell}"
            );
        }
        assert!(row.ends_with("run analysis job"));
    }

    #[test]
    fn mjob_details_align_values_with_optional_fields() {
        let mut job = sample_job(42, JobState::Failed, "mini01", Some("mini01-a"), "analysis");
        job.end_reason = Some("worker failed".into());
        job.waiting_reason = Some("storage was unavailable".into());
        job.exit_code = Some(127);

        let rendered = format_job_details(&job);
        let value_columns: Vec<_> = rendered
            .lines()
            .map(|line| line.find(": ").unwrap() + 2)
            .collect();
        assert!(
            value_columns
                .iter()
                .all(|column| *column == value_columns[0])
        );
        assert!(rendered.contains("Reason        : worker failed"));
        assert!(rendered.contains("Waiting reason: storage was unavailable"));
        assert!(rendered.contains("Exit code     : 127"));

        let without_optional =
            format_job_details(&sample_job(43, JobState::Pending, "mini01", None, "short"));
        assert!(!without_optional.contains("Reason:"));
        assert!(!without_optional.contains("Waiting reason:"));
        assert!(!without_optional.contains("Exit code:"));
    }

    #[test]
    fn submission_rejects_login_node_even_if_legacy_queue_lists_it() {
        use macluster_core::{config::ClusterConfig, storage::Storage};
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-submit-login-rejected-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let shared_root = root.join("shared");
        fs::create_dir_all(&shared_root).unwrap();
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"mini01\"\nlogin_node = \"login\"\nshared_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"login\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"login\", \"worker\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.worker]\nhost = \"192.0.2.2\"\ntransport = \"ssh\"\n",
            shared_root.display()
        ))
        .unwrap();
        let storage = Storage::open(root.join("controller")).unwrap();
        let options =
            crate::arguments::parse_submit_args(["--node", "login", "--wrap", "true"]).unwrap();

        let error = build_submission(&config, &options)
            .expect_err("login node must not run submitted jobs");

        assert!(
            error.1.contains("login node 'login' cannot accept jobs"),
            "{error:?}"
        );
        drop(storage);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn online_submission_preserves_the_login_environment_through_controller_ipc() {
        use std::{
            fs, thread,
            time::{Duration, Instant},
        };

        use macluster_controller::{ControlApi, ControlListener, InstanceLock};
        use macluster_core::{service::ServiceBinding, storage::Storage};
        use macluster_protocol::{
            control::{
                CONTROL_PROTOCOL_VERSION, ControlCommand, ControlPayload, ControllerHello,
                ControllerLifecycle,
            },
            identifiers::{ControllerUuid, Id128, NodeId, QueueName, RequestId},
            types::{ControllerEpoch, JobMode},
        };

        let root = std::env::temp_dir().join(format!(
            "macluster-online-env-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let shared_root = root.join("shared");
        let software_root = root.join("mamba");
        let environment_root = software_root.join("envs/analysis");
        let toolchain_root = software_root.join("toolchain");
        let state_dir = root.join("state");
        fs::create_dir_all(shared_root.join("jobs")).unwrap();
        fs::create_dir_all(environment_root.join("bin")).unwrap();
        fs::create_dir_all(toolchain_root.join("bin")).unwrap();
        fs::create_dir_all(toolchain_root.join("lib")).unwrap();
        for binary in ["python", "clang", "clang++", "rustc"] {
            fs::write(toolchain_root.join("bin").join(binary), "test tool").unwrap();
        }
        fs::write(environment_root.join("bin/python"), "test python").unwrap();
        fs::create_dir_all(&state_dir).unwrap();
        let config_path = root.join("config.toml");
        fs::write(
            &config_path,
            format!(
                "[cluster]\nname=\"online-env\"\nlogin_node=\"login\"\ndefault_queue=\"compute\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.compute]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker]\nhost=\"192.0.2.20\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\n[shares.mamba]\nserver=\"login\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"340edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\n",
                shared_root.display(),
                unsafe { libc::geteuid() },
                software_root.display(),
                software_root.display(),
            ),
        )
        .unwrap();
        let config = ClusterConfig::parse(&fs::read_to_string(&config_path).unwrap()).unwrap();
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!(
                    "{}:{}:/usr/bin:/bin",
                    environment_root.join("bin").display(),
                    toolchain_root.join("bin").display()
                ),
            ),
            (
                "VIRTUAL_ENV".into(),
                environment_root.to_string_lossy().into_owned(),
            ),
            (
                "CC".into(),
                toolchain_root
                    .join("bin/clang")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "CXX".into(),
                toolchain_root
                    .join("bin/clang++")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RUSTC".into(),
                toolchain_root
                    .join("bin/rustc")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "RUSTFLAGS".into(),
                format!("-L native={}", toolchain_root.join("lib").display()),
            ),
        ]);
        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();
        let spec = JobSpec {
            storage_namespace: Some(Id128::parse("240edfcc-0fe5-4fa8-83a2-29c6ede02b42").unwrap()),
            queue: QueueName::new("compute").unwrap(),
            node: Some(NodeId::new("worker").unwrap()),
            name: "login-environment".into(),
            cwd: shared_root.display().to_string(),
            stdout_path: shared_root.join("jobs/out.log").display().to_string(),
            stderr_path: shared_root.join("jobs/err.log").display().to_string(),
            walltime_secs: None,
            env: task_env.clone(),
            mode: JobMode::Batch,
            snapshot: Some(super::snapshot_reference(b"#!/bin/sh\ntrue\n").unwrap()),
        };
        let script = b"#!/bin/sh\ntrue\n".to_vec();

        let binding = ServiceBinding::load(&config_path, &state_dir).unwrap();
        let hello = ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().into(),
            namespace: binding.namespace().into(),
            uid: binding.uid(),
            build_id: "environment-test-controller".into(),
            capabilities: vec!["jobs.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 0,
            lifecycle: ControllerLifecycle::Ready,
        };
        let instance = Box::leak(Box::new(InstanceLock::acquire(&state_dir).unwrap()));
        let mut listener = ControlListener::bind(&binding, instance, hello.clone()).unwrap();
        let storage = Storage::open(&state_dir).unwrap();
        let mut api = ControlApi::new(config, storage, hello);
        let client =
            crate::control_client::ControlClient::connect(&binding, Duration::from_secs(2))
                .unwrap();
        let mut online = super::OnlineController { binding, client };
        let request_id = RequestId::random();
        let submitter = thread::spawn(move || {
            super::submit_online(&mut online, request_id, spec, &script).unwrap()
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.poll_event() {
                Some(macluster_controller::PendingControlEvent::Request(request)) => {
                    let command = request.request().command.clone();
                    let response = api.handle(request.client_session(), request.request().clone());
                    if matches!(command, ControlCommand::Submit { .. }) {
                        // Simulate a controller process/connection failure after the durable
                        // commit but before the submit acknowledgement reaches the client.
                        drop(request);
                        continue;
                    }
                    let resolved = matches!(
                        (&command, &response),
                        (
                            ControlCommand::LookupRequest { .. },
                            Ok(ControlPayload::Lookup(Some(_)))
                        )
                    );
                    request.respond(response).unwrap();
                    if resolved {
                        break;
                    }
                }
                Some(macluster_controller::PendingControlEvent::Disconnected(session)) => {
                    api.disconnect(session);
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "submission IPC request timed out"
                    );
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
        let record = submitter.join().unwrap();
        assert_eq!(record.spec.env, task_env);
        assert_eq!(
            record.spec.env["VIRTUAL_ENV"],
            environment_root.to_string_lossy()
        );
        assert_eq!(
            record.spec.env["CC"],
            toolchain_root
                .join("bin/clang")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        );
        assert_eq!(
            record.spec.env["CXX"],
            toolchain_root
                .join("bin/clang++")
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        );
        assert!(
            record.spec.env["RUSTFLAGS"]
                .contains(&toolchain_root.join("lib").display().to_string())
        );

        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn submitter_homebrew_paths_are_remapped_only_when_they_are_shared() {
        use macluster_core::config::ClusterConfig;
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-submit-env-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let shared_root = root.join("shared");
        let homebrew_source = root.join("homebrew");
        let homebrew_mount = root.join("mounted-homebrew");
        fs::create_dir_all(&shared_root).unwrap();
        fs::create_dir_all(homebrew_source.join("bin")).unwrap();
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"compute\"\nlogin_node = \"login\"\nshared_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"login\"\nprotocol_version = 1\n\n[queues.compute]\nnodes = [\"worker\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.worker]\nhost = \"192.0.2.2\"\ntransport = \"ssh\"\n\n[shares.homebrew]\nserver = \"login\"\nsource_root = \"{}\"\nmount_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000002\"\n",
            shared_root.display(),
            homebrew_source.display(),
            homebrew_mount.display()
        ))
        .unwrap();

        let login_path = format!(
            "{}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
            homebrew_source.join("bin").display()
        );
        let task_path = super::remap_environment_paths(&config, "PATH", &login_path);
        let homebrew_prefix = super::remap_environment_paths(
            &config,
            "HOMEBREW_PREFIX",
            &homebrew_source.to_string_lossy(),
        );
        let homebrew_cellar = super::remap_environment_paths(
            &config,
            "HOMEBREW_CELLAR",
            &homebrew_source.join("Cellar").to_string_lossy(),
        );

        assert_eq!(
            task_path,
            format!("{}:/usr/bin:/bin", homebrew_mount.join("bin").display())
        );
        assert_eq!(homebrew_prefix, homebrew_mount.to_string_lossy());
        assert_eq!(
            homebrew_cellar,
            homebrew_mount.join("Cellar").to_string_lossy()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn environment_fixture(root: &Path, mount_root: &Path) -> (ClusterConfig, PathBuf, PathBuf) {
        use macluster_core::config::ClusterConfig;
        use std::fs;

        let shared_root = root.join("shared");
        let software_root = root.join("mamba");
        fs::create_dir_all(&shared_root).unwrap();
        fs::create_dir_all(software_root.join("bin")).unwrap();
        let config = ClusterConfig::parse(&format!(
            "[cluster]\nname = \"test\"\ndefault_queue = \"compute\"\nlogin_node = \"login\"\nshared_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"login\"\nprotocol_version = 1\n\n[queues.compute]\nnodes = [\"worker\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n\n[nodes.worker]\nhost = \"192.0.2.2\"\ntransport = \"ssh\"\n\n[shares.mamba]\nserver = \"login\"\nsource_root = \"{}\"\nmount_root = \"{}\"\nshare_uuid = \"00000000-0000-4000-8000-000000000002\"\n",
            shared_root.display(),
            software_root.display(),
            mount_root.display()
        ))
        .unwrap();
        (config, shared_root, software_root)
    }

    #[test]
    fn msub_selects_and_remaps_active_shared_environment() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-active-env-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let virtualenv = software_root.join("envs/venv");
        let conda = software_root.join("envs/conda");
        fs::create_dir_all(virtualenv.join("bin")).unwrap();
        fs::create_dir_all(conda.join("bin")).unwrap();
        fs::write(virtualenv.join("bin/python"), "python").unwrap();
        fs::write(conda.join("bin/python"), "python").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!(
                    "{}:{}:{}:/usr/bin:/bin",
                    software_root.join("bin").display(),
                    virtualenv.join("bin").display(),
                    conda.join("bin").display()
                ),
            ),
            (
                "VIRTUAL_ENV".into(),
                virtualenv.to_string_lossy().into_owned(),
            ),
            ("CONDA_PREFIX".into(), conda.to_string_lossy().into_owned()),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(
            task_env["PATH"].split(':').next(),
            Some(
                virtualenv
                    .join("bin")
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert_eq!(task_env["VIRTUAL_ENV"], virtualenv.to_string_lossy());
        assert_eq!(task_env["CONDA_PREFIX"], conda.to_string_lossy());
        assert_eq!(
            task_env[ACTIVE_ENV_PREFIX_ENV],
            virtualenv.canonicalize().unwrap().to_string_lossy()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_path_override_does_not_prepend_an_active_environment() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-explicit-path-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let prefix = root.join("mamba/envs/analysis");
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::write(prefix.join("bin/python"), "python").unwrap();
        let (config, _, _) = environment_fixture(&root, &root.join("mamba"));
        let inherited = BTreeMap::from([
            ("CONDA_PREFIX".into(), prefix.to_string_lossy().into_owned()),
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", prefix.join("bin").display()),
            ),
        ]);
        let overrides = BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]);

        let task_env = prepare_task_environment(&config, inherited, overrides).unwrap();

        assert_eq!(task_env["PATH"], "/usr/bin:/bin");
        assert_eq!(task_env[EXPLICIT_TASK_PATH_ENV], "1");
        assert!(!task_env.contains_key(ACTIVE_ENV_PREFIX_ENV));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_promotes_a_command_available_only_in_the_active_prefix() {
        use std::{fs, path::PathBuf};

        let root = std::env::temp_dir().join(format!(
            "macluster-active-command-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let prefix = root.join("mamba/envs/analysis");
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::write(prefix.join("bin/python"), "python").unwrap();
        let options = super::SubmitOptions {
            script: Some(PathBuf::from("python")),
            env: BTreeMap::from([("CONDA_PREFIX".into(), prefix.to_string_lossy().into_owned())]),
            ..super::SubmitOptions::default()
        };

        let promoted = promote_inline_command(options);

        assert!(promoted.script.is_none());
        assert_eq!(promoted.wrap.as_deref(), Some("python"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_rejects_unshared_or_relocated_active_environment() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-active-env-reject-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let unshared = root.join("unshared-env");
        fs::create_dir_all(software_root.join("envs/test/bin")).unwrap();
        fs::create_dir_all(unshared.join("bin")).unwrap();
        fs::write(software_root.join("envs/test/bin/python"), "python").unwrap();
        fs::write(unshared.join("bin/python"), "python").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let unshared_env = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin", unshared.join("bin").display()),
            ),
            (
                "CONDA_PREFIX".into(),
                unshared.to_string_lossy().into_owned(),
            ),
        ]);
        let error = prepare_task_environment(&config, unshared_env, BTreeMap::new())
            .expect_err("login-only active environment must be rejected");
        assert!(
            error.1.contains("outside every configured shared path"),
            "{error:?}"
        );

        let relocated_config = environment_fixture(&root, &root.join("compute-mount")).0;
        let active = software_root.join("envs/test");
        let relocated_env = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin", active.join("bin").display()),
            ),
            ("CONDA_PREFIX".into(), active.to_string_lossy().into_owned()),
        ]);
        let error = prepare_task_environment(&relocated_config, relocated_env, BTreeMap::new())
            .expect_err("a relocated software mount cannot preserve environment executables");
        assert!(error.1.contains("same absolute path"), "{error:?}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_accepts_environment_python_linked_to_another_path_in_the_same_share() {
        use std::{fs, os::unix::fs::symlink};

        let root = std::env::temp_dir().join(format!(
            "macluster-env-python-link-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let prefix = software_root.join("envs/analysis");
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::write(software_root.join("bin/python"), "python").unwrap();
        symlink("../../../bin/python", prefix.join("bin/python")).unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", prefix.join("bin").display()),
            ),
            ("CONDA_PREFIX".into(), prefix.to_string_lossy().into_owned()),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new())
            .expect("an interpreter link within the registered software root is portable");

        assert_eq!(
            task_env["PATH"].split(':').next(),
            Some(
                prefix
                    .join("bin")
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_accepts_a_shared_active_toolchain_without_python() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-active-toolchain-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let prefix = software_root.join("envs/clang-only");
        fs::create_dir_all(prefix.join("bin")).unwrap();
        fs::write(prefix.join("bin/clang"), "compiler").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", prefix.join("bin").display()),
            ),
            ("CONDA_PREFIX".into(), prefix.to_string_lossy().into_owned()),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new())
            .expect("a shared compiler-only environment does not require Python");

        assert_eq!(
            task_env["PATH"].split(':').next(),
            Some(
                prefix
                    .join("bin")
                    .canonicalize()
                    .unwrap()
                    .to_string_lossy()
                    .as_ref()
            )
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_remaps_cargo_and_rustup_homes() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-rust-env-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let active = software_root.join("envs/rust");
        fs::create_dir_all(active.join("bin")).unwrap();
        fs::write(active.join("bin/python"), "python").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", active.join("bin").display()),
            ),
            ("CONDA_PREFIX".into(), active.to_string_lossy().into_owned()),
            (
                "CARGO_HOME".into(),
                software_root.join(".cargo").to_string_lossy().into_owned(),
            ),
            (
                "RUSTUP_HOME".into(),
                software_root.join(".rustup").to_string_lossy().into_owned(),
            ),
            (
                "CARGO_TARGET_DIR".into(),
                software_root.join("target").to_string_lossy().into_owned(),
            ),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(
            task_env["CARGO_HOME"],
            software_root.join(".cargo").to_string_lossy()
        );
        assert_eq!(
            task_env["RUSTUP_HOME"],
            software_root.join(".rustup").to_string_lossy()
        );
        assert_eq!(
            task_env["CARGO_TARGET_DIR"],
            software_root.join("target").to_string_lossy()
        );
        assert_eq!(
            super::remap_environment_paths(&config, "CARGO_TARGET_DIR", "target"),
            "target"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_remaps_shared_c_compiler_and_build_paths() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-c-toolchain-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::create_dir_all(software_root.join("include")).unwrap();
        fs::create_dir_all(software_root.join("lib/pkgconfig")).unwrap();
        fs::write(software_root.join("bin/clang"), "clang").unwrap();
        fs::write(software_root.join("bin/clang++"), "clang++").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let login_path = format!("{}:/usr/bin:/bin", software_root.join("bin").display());
        let flags = format!(
            "-I{} -isystem {} -DNAME='Hello World'",
            software_root.join("include").display(),
            software_root.join("include").display()
        );
        let linker_flags = format!(
            "-L{} -Wl,-rpath,{}",
            software_root.join("lib").display(),
            software_root.join("lib").display()
        );
        let environment = BTreeMap::from([
            ("PATH".into(), login_path),
            ("CC".into(), "clang".into()),
            ("CXX".into(), "clang++".into()),
            ("CFLAGS".into(), flags),
            ("LDFLAGS".into(), linker_flags),
            (
                "CMAKE_PREFIX_PATH".into(),
                software_root.to_string_lossy().into_owned(),
            ),
            (
                "PKG_CONFIG_PATH".into(),
                software_root
                    .join("lib/pkgconfig")
                    .to_string_lossy()
                    .into_owned(),
            ),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert!(task_env["CC"].contains(&software_root.join("bin/clang").display().to_string()));
        assert!(task_env["CXX"].contains(&software_root.join("bin/clang++").display().to_string()));
        assert!(task_env["CFLAGS"].contains(&software_root.join("include").display().to_string()));
        assert!(task_env["CFLAGS"].contains("Hello World"));
        assert!(task_env["LDFLAGS"].contains(&software_root.join("lib").display().to_string()));
        assert_eq!(
            task_env["CMAKE_PREFIX_PATH"],
            software_root.to_string_lossy()
        );
        assert_eq!(
            task_env["PKG_CONFIG_PATH"],
            software_root.join("lib/pkgconfig").to_string_lossy()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_preserves_compiler_environment_without_shell_quotes() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-quoted-compiler-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let compiler = software_root.join("envs/analysis/bin/arm64-apple-darwin20.0.0-clang++");
        fs::create_dir_all(compiler.parent().unwrap()).unwrap();
        fs::write(&compiler, "clang++").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let compiler_path = fs::canonicalize(&compiler)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", compiler.parent().unwrap().display()),
            ),
            ("CXX".into(), format!("'{compiler_path}'")),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(task_env["CXX"], compiler_path);
        assert!(!task_env["CXX"].contains(['\'', '"']));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_preserves_non_toolchain_environment_variables_unchanged() {
        let root = std::env::temp_dir().join(format!(
            "macluster-env-pass-through-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let (config, _, _) = environment_fixture(&root, &root.join("mounted-mamba"));
        let environment = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("CC_ENABLE_DEBUG_OUTPUT".into(), "1".into()),
            ("CC_FORCE_DISABLE".into(), "0".into()),
            ("CC_KNOWN_WRAPPER_CUSTOM".into(), "custom-compiler".into()),
            ("CUSTOM_FLAGS".into(), "--mode='fast build'".into()),
            ("CUSTOM_HOME".into(), "/Users/login/custom-home".into()),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(task_env["CC_ENABLE_DEBUG_OUTPUT"], "1");
        assert_eq!(task_env["CC_FORCE_DISABLE"], "0");
        assert_eq!(task_env["CC_KNOWN_WRAPPER_CUSTOM"], "custom-compiler");
        assert_eq!(task_env["CUSTOM_FLAGS"], "--mode='fast build'");
        assert_eq!(task_env["CUSTOM_HOME"], "/Users/login/custom-home");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn msub_preserves_explicit_shell_parsing_for_remapped_cc_flags() {
        let root = std::env::temp_dir().join(format!(
            "macluster-cc-flags-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let (config, _, _) = environment_fixture(&root, &root.join("mounted-mamba"));
        let environment = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("CFLAGS".into(), "-DNAME='Hello World'".into()),
            ("CC_SHELL_ESCAPED_FLAGS".into(), "1".into()),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(task_env["CC_SHELL_ESCAPED_FLAGS"], "1");
        assert_eq!(
            super::tokenize_shell_words(&task_env["CFLAGS"]).unwrap(),
            vec!["-DNAME=Hello World"]
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn msub_preserves_whitespace_split_cc_flags_when_shell_parsing_is_disabled() {
        let root = std::env::temp_dir().join(format!(
            "macluster-cc-flags-disabled-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let (config, _, _) = environment_fixture(&root, &root.join("mounted-mamba"));
        let environment = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("CC_SHELL_ESCAPED_FLAGS".into(), "0".into()),
            ("CXXFLAGS".into(), "-DNAME='Hello World'".into()),
        ]);

        let mapped = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();
        assert_eq!(mapped["CC_SHELL_ESCAPED_FLAGS"], "0");
        assert_eq!(mapped["CXXFLAGS"], "-DNAME='Hello World'");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn msub_rejects_unshared_absolute_compiler_and_build_paths() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-unshared-toolchain-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let unshared_root = root.join("unshared");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::create_dir_all(unshared_root.join("bin")).unwrap();
        fs::create_dir_all(unshared_root.join("include")).unwrap();
        fs::write(unshared_root.join("bin/clang"), "clang").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let compiler = BTreeMap::from([(
            "CC".into(),
            unshared_root
                .join("bin/clang")
                .to_string_lossy()
                .into_owned(),
        )]);
        let error = prepare_task_environment(&config, compiler, BTreeMap::new())
            .expect_err("an absolute compiler outside NFS must fail early");
        assert!(error.1.contains("unshared"), "{error:?}");
        assert!(error.1.contains("clang"), "{error:?}");

        let build_path = BTreeMap::from([(
            "CFLAGS".into(),
            format!("-I{}", unshared_root.join("include").display()),
        )]);
        let error = prepare_task_environment(&config, build_path, BTreeMap::new())
            .expect_err("an absolute include path outside NFS must fail early");
        assert!(error.1.contains("unshared"), "{error:?}");
        assert!(error.1.contains("CFLAGS"), "{error:?}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_remaps_ccache_compiler_wrapper_from_login_path() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-ccache-wrapper-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::write(software_root.join("bin/ccache"), "ccache").unwrap();
        fs::write(software_root.join("bin/clang"), "clang").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", software_root.join("bin").display()),
            ),
            (
                "CC".into(),
                "ccache clang -target arm64-apple-macosx".into(),
            ),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert!(task_env["CC"].contains(&software_root.join("bin/ccache").display().to_string()));
        assert!(task_env["CC"].contains(&software_root.join("bin/clang").display().to_string()));
        assert!(task_env["CC"].contains("-target"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_preserves_compiler_symlink_invocation_name() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-compiler-symlink-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::write(software_root.join("bin/rustup"), "rustup proxy").unwrap();
        std::os::unix::fs::symlink("rustup", software_root.join("bin/rustc")).unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let rustc = software_root.join("bin/rustc");
        let environment = BTreeMap::from([("RUSTC".into(), rustc.display().to_string())]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(
            super::tokenize_shell_words(&task_env["RUSTC"]).unwrap(),
            vec![
                super::canonicalize_parent_preserving_leaf(&rustc)
                    .unwrap()
                    .display()
                    .to_string()
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regression_cc_flags_preserve_the_source_parser_and_string_macros() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let root = std::env::temp_dir().join(format!("macluster-cc-macros-{}", Id128::random()));
        let (config, _, _) = environment_fixture(&root, &root.join("software"));
        for key in ["CFLAGS", "CXXFLAGS", "CFLAGS_aarch64_apple_darwin"] {
            for mode in [None, Some("0"), Some("false"), Some("1")] {
                let flags = if mode == Some("1") {
                    r#"-DMESSAGE="\"hello world\"""#
                } else {
                    r#"-DMESSAGE="hello""#
                };
                let mut env = BTreeMap::from([
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    (key.into(), flags.into()),
                ]);
                if let Some(mode) = mode {
                    env.insert("CC_SHELL_ESCAPED_FLAGS".into(), mode.into());
                }
                let mapped = prepare_task_environment(&config, env, BTreeMap::new()).unwrap();
                let shell_mode = mapped
                    .get("CC_SHELL_ESCAPED_FLAGS")
                    .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "no"));
                let args = if shell_mode {
                    super::tokenize_shell_words(&mapped[key]).unwrap()
                } else {
                    mapped[key]
                        .split_ascii_whitespace()
                        .map(str::to_owned)
                        .collect()
                };
                let mut child = Command::new("/usr/bin/cc")
                    .args([
                        "-x",
                        if key == "CXXFLAGS" { "c++" } else { "c" },
                        "-fsyntax-only",
                    ])
                    .args(&args)
                    .arg("-")
                    .stdin(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(b"const char *message = MESSAGE;\n")
                    .unwrap();
                let result = child.wait_with_output().unwrap();
                assert!(
                    result.status.success(),
                    "{key} mode={mode:?}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert_eq!(
                    mapped.get("CC_SHELL_ESCAPED_FLAGS").map(String::as_str),
                    mode
                );
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regression_custom_verbose_output_preserves_job_template() {
        let root =
            std::env::temp_dir().join(format!("macluster-output-template-{}", Id128::random()));
        let (config, shared, _) = environment_fixture(&root, &root.join("software"));
        let output = shared.join("logs/%j/monitor.log");
        let options = crate::arguments::SubmitOptions {
            verbose: true,
            wrap: Some("echo done".into()),
            cwd: Some(shared.clone()),
            stdout_path: Some(output.clone()),
            env: BTreeMap::from([
                ("CONDA_PREFIX".into(), "".into()),
                ("VIRTUAL_ENV".into(), "".into()),
                ("PATH".into(), "/usr/bin:/bin".into()),
            ]),
            ..Default::default()
        };
        let (spec, _) = build_submission(&config, &options).unwrap();
        assert_eq!(Path::new(&spec.stdout_path), output);
        assert!(!shared.join("logs").exists());
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, shared.join("escape")).unwrap();
        let mut invalid = options;
        invalid.stdout_path = Some(shared.join("escape/missing/monitor.log"));
        let error = match build_submission(&config, &invalid) {
            Err(error) => error,
            Ok(_) => panic!("an output directory symlink must not escape the share"),
        };
        assert!(error.1.contains("inside"), "{error:?}");
        assert!(!outside.join("missing").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regression_verbose_submission_rejects_reserved_sidecar_outputs() {
        let root = std::env::temp_dir().join(format!("macluster-log-reserved-{}", Id128::random()));
        let (config, shared, _) = environment_fixture(&root, &root.join("software"));
        let jobs = shared.join("jobs").join(&config.share_uuid);
        fs::create_dir_all(jobs.join("0")).unwrap();
        fs::create_dir_all(jobs.join("1")).unwrap();
        for interactive in [false, true] {
            for path in [
                jobs.join("%j/monitor.log"),
                jobs.join("1/resources.jsonl"),
                jobs.join("%j/summary.json"),
                jobs.join("1/MONITOR.LOG"),
                shared
                    .join("JOBS")
                    .join(config.share_uuid.to_uppercase())
                    .join("%j/SUMMARY.JSON"),
                jobs.join("%j"),
                jobs.clone(),
                shared.join("jobs"),
            ] {
                let options = crate::arguments::SubmitOptions {
                    verbose: true,
                    interactive,
                    wrap: Some("echo done".into()),
                    cwd: Some(shared.clone()),
                    stdout_path: Some(path),
                    env: BTreeMap::from([
                        ("CONDA_PREFIX".into(), "".into()),
                        ("VIRTUAL_ENV".into(), "".into()),
                        ("PATH".into(), "/usr/bin:/bin".into()),
                    ]),
                    ..Default::default()
                };
                let error = match build_submission(&config, &options) {
                    Err(error) => error,
                    Ok(_) => panic!("reserved sidecar output must be rejected before submission"),
                };
                assert!(error.1.contains("reserved"), "{error:?}");
            }
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_rustflags_remain_usable_by_cargo() {
        use std::process::Command;

        let root = std::env::temp_dir().join(format!("macluster-rustflags-{}", Id128::random()));
        let (config, _, _) = environment_fixture(&root, &root.join("software"));
        fs::create_dir_all(root.join("project/src")).unwrap();
        fs::write(root.join("project/Cargo.toml"), "[package]\nname = \"rustflags-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n").unwrap();
        fs::write(root.join("project/src/lib.rs"), "#[cfg(not(macluster_probe = \"inherited\"))]\ncompile_error!(\"quoted cfg value was not inherited\");\npub fn probe() {}\n").unwrap();
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let version = Command::new(rustc).arg("-vV").output().unwrap();
        assert!(version.status.success());
        let version = String::from_utf8(version.stdout).unwrap();
        let host = version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap();
        let target_key = format!(
            "CARGO_TARGET_{}_RUSTFLAGS",
            host.replace('-', "_").to_uppercase()
        );
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        for key in ["RUSTFLAGS", target_key.as_str()] {
            let task_env = prepare_task_environment(
                &config,
                BTreeMap::from([
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    (
                        key.into(),
                        "-C opt-level=1 --cfg macluster_probe=\"inherited\"".into(),
                    ),
                ]),
                BTreeMap::new(),
            )
            .unwrap();
            let output = Command::new(&cargo)
                .args(["check", "--offline", "--quiet", "--target", host])
                .current_dir(root.join("project"))
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_RUSTFLAGS")
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env("CARGO_TARGET_DIR", root.join("target").join(key))
                .env(key, &task_env[key])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{key}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_remaps_generic_rust_and_cpp_build_environment() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-generic-build-env-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::create_dir_all(software_root.join("lib")).unwrap();
        fs::create_dir_all(software_root.join("include")).unwrap();
        fs::write(software_root.join("bin/protoc"), "protoc").unwrap();
        fs::write(software_root.join("bin/clang"), "clang").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let library = software_root.join("lib");
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", software_root.join("bin").display()),
            ),
            ("PROTOC".into(), "protoc".into()),
            (
                "OPENSSL_DIR".into(),
                software_root.to_string_lossy().into_owned(),
            ),
            (
                "VCPKG_ROOT".into(),
                software_root.to_string_lossy().into_owned(),
            ),
            (
                "RUSTFLAGS".into(),
                format!(
                    "-L native={} -C link-arg=-Wl,-rpath,{}",
                    library.display(),
                    library.display()
                ),
            ),
            (
                "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER".into(),
                "clang".into(),
            ),
            ("CC_aarch64_apple_darwin".into(), "clang".into()),
            (
                "CFLAGS_aarch64_apple_darwin".into(),
                format!("-I{}", software_root.join("include").display()),
            ),
            (
                "BINDGEN_EXTRA_CLANG_ARGS".into(),
                format!(
                    "--sysroot={} -I{}",
                    software_root.display(),
                    software_root.join("include").display()
                ),
            ),
            (
                "CARGO_ENCODED_RUSTFLAGS".into(),
                format!(
                    "-Lnative={}\u{1f}-C\u{1f}link-arg=-L{}",
                    library.display(),
                    library.display()
                ),
            ),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert!(
            task_env["PROTOC"].contains(&software_root.join("bin/protoc").display().to_string())
        );
        assert_eq!(task_env["OPENSSL_DIR"], software_root.to_string_lossy());
        assert_eq!(task_env["VCPKG_ROOT"], software_root.to_string_lossy());
        assert!(task_env["RUSTFLAGS"].contains(&library.display().to_string()));
        assert!(
            task_env["CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"]
                .contains(&software_root.join("bin/clang").display().to_string())
        );
        assert!(
            task_env["CC_aarch64_apple_darwin"]
                .contains(&software_root.join("bin/clang").display().to_string())
        );
        assert!(
            task_env["CFLAGS_aarch64_apple_darwin"]
                .contains(&software_root.join("include").display().to_string())
        );
        assert!(
            task_env["BINDGEN_EXTRA_CLANG_ARGS"]
                .contains(&software_root.join("include").display().to_string())
        );
        assert!(task_env["CARGO_ENCODED_RUSTFLAGS"].contains(&library.display().to_string()));
        assert!(task_env["CARGO_ENCODED_RUSTFLAGS"].contains('\u{1f}'));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_remaps_paths_in_compiler_command_arguments() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-compiler-command-args-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let mount_root = root.join("mounted-mamba");
        fs::create_dir_all(software_root.join("sdk")).unwrap();
        fs::create_dir_all(software_root.join("include")).unwrap();
        let (config, _, _) = environment_fixture(&root, &mount_root);
        let environment = BTreeMap::from([(
            "CC".into(),
            format!(
                "/usr/bin/true --sysroot={} -I {}",
                software_root.join("sdk").display(),
                software_root.join("include").display()
            ),
        )]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();
        let command = super::tokenize_shell_words(&task_env["CC"]).unwrap();

        assert_eq!(command[0], "/usr/bin/true");
        assert_eq!(
            command[1],
            format!("--sysroot={}/sdk", mount_root.display())
        );
        assert_eq!(command[2], "-I");
        assert_eq!(command[3], format!("{}/include", mount_root.display()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_rejects_unshared_generic_build_roots_and_toolchains() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-unshared-generic-build-env-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        let unshared = root.join("unshared");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        fs::create_dir_all(unshared.join("bin")).unwrap();
        fs::write(unshared.join("bin/protoc"), "protoc").unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);

        let error = prepare_task_environment(
            &config,
            BTreeMap::from([(
                "PROTOC".into(),
                unshared.join("bin/protoc").display().to_string(),
            )]),
            BTreeMap::new(),
        )
        .expect_err("unshared executable paths must fail before dispatch");
        assert!(error.1.contains("PROTOC"), "{error:?}");
        assert!(error.1.contains("unshared"), "{error:?}");

        let error = prepare_task_environment(
            &config,
            BTreeMap::from([("VCPKG_ROOT".into(), unshared.display().to_string())]),
            BTreeMap::new(),
        )
        .expect_err("unshared package-manager roots must fail before dispatch");
        assert!(error.1.contains("VCPKG_ROOT"), "{error:?}");
        assert!(error.1.contains("unshared"), "{error:?}");

        let inherited_cache = BTreeMap::from([(
            "CARGO_HOME".into(),
            unshared.join("cargo-home").display().to_string(),
        )]);
        let task_env = prepare_task_environment(&config, inherited_cache, BTreeMap::new())
            .expect("an unshared inherited cache should switch to the node-local cache");
        assert_eq!(task_env["CARGO_HOME"], "");

        let inherited_target = BTreeMap::from([(
            "CARGO_TARGET_DIR".into(),
            unshared.join("cargo-target").display().to_string(),
        )]);
        let task_env = prepare_task_environment(&config, inherited_target, BTreeMap::new())
            .expect("an unshared inherited target should switch to a node-local target cache");
        assert_eq!(task_env["CARGO_TARGET_DIR"], "");

        let explicit_cache = BTreeMap::from([(
            "CARGO_HOME".into(),
            unshared.join("cargo-home").display().to_string(),
        )]);
        let error = prepare_task_environment(&config, BTreeMap::new(), explicit_cache)
            .expect_err("an explicitly selected unshared Cargo home must be rejected");
        assert!(error.1.contains("CARGO_HOME"), "{error:?}");

        let explicit_target = BTreeMap::from([(
            "CARGO_TARGET_DIR".into(),
            unshared.join("cargo-target").display().to_string(),
        )]);
        let error = prepare_task_environment(&config, BTreeMap::new(), explicit_target)
            .expect_err("an explicitly selected unshared Cargo target must be rejected");
        assert!(error.1.contains("CARGO_TARGET_DIR"), "{error:?}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn msub_filters_unshared_runtime_library_paths_and_optional_package_metadata() {
        use std::fs;

        let root = std::env::temp_dir().join(format!(
            "macluster-runtime-library-path-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let software_root = root.join("mamba");
        fs::create_dir_all(software_root.join("bin")).unwrap();
        let (config, _, _) = environment_fixture(&root, &software_root);
        let unshared_runtime = root.join("login-only/lib");
        fs::create_dir_all(&unshared_runtime).unwrap();
        let environment = BTreeMap::from([
            (
                "DYLD_FALLBACK_LIBRARY_PATH".into(),
                format!("{}:/usr/lib", unshared_runtime.display()),
            ),
            ("HOMEBREW_PREFIX".into(), "/opt/homebrew".into()),
            ("MAMBA_ROOT_PREFIX".into(), "/Users/login/mamba".into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ]);

        let task_env = prepare_task_environment(&config, environment, BTreeMap::new()).unwrap();

        assert_eq!(task_env["DYLD_FALLBACK_LIBRARY_PATH"], "/usr/lib");
        assert_eq!(task_env["HOMEBREW_PREFIX"], "");
        assert_eq!(task_env["MAMBA_ROOT_PREFIX"], "");
        assert_eq!(task_env["PATH"], "/usr/bin:/bin");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn power_display_includes_measured_scope() {
        assert_eq!(format_power(Some(9.8), Some("SoC")), "9.8 W");
        assert_eq!(format_power(Some(4.2), Some("CPU")), "4.2 W");
    }

    #[test]
    fn power_display_uses_watts_even_without_scope() {
        assert_eq!(format_power(None, Some("CPU")), "N/A");
        assert_eq!(format_power(Some(9.8), None), "9.8 W");
    }

    #[test]
    fn one_shot_monitor_uses_compact_metric_headers_and_values() {
        let header = metric_table_header();
        for label in ["CPU%", "MEM(GiB)", "TEMP", "DISK(R/W)", "NET(down/up)"] {
            assert!(header.contains(label), "header: {header:?}");
        }
        for old_label in ["MEMORY", "CPU TEMP", "DISK R/W", "NET RX/TX"] {
            assert!(!header.contains(old_label), "header: {header:?}");
        }

        let mut metric = macluster_metrics::unavailable(1, "fixture");
        metric.cpu_percent = Some(100.0);
        metric.cpu_max_percent = Some(800.0);
        metric.memory_used_bytes = Some(4 * 1024 * 1024 * 1024);
        metric.memory_total_bytes = Some(16 * 1024 * 1024 * 1024);
        metric.cpu_temp_celsius = Some(74.3);

        let row = metric_row("arm-a", &metric, "ONLINE", false);
        assert!(row.contains("100/800"), "row: {row:?}");
        assert!(!row.contains("100/800%"), "row: {row:?}");
        assert!(row.contains("4.0/16.0"), "row: {row:?}");
        assert!(!row.contains("GiB"), "row: {row:?}");
        assert!(row.contains("74.3°C"), "row: {row:?}");
    }

    #[test]
    fn legacy_remote_power_error_explains_how_to_update_the_node() {
        let mut snapshot = macluster_metrics::unavailable(1, "test");
        snapshot.errors.insert(
            "power".into(),
            "no supported non-interactive power sampler was found".into(),
        );

        explain_legacy_power_agent(&mut snapshot);

        assert!(snapshot.errors["power"].contains("rerun mnode -a"));
    }

    #[test]
    fn monitor_json_keeps_legacy_shape_and_strict_pool_totals() {
        let mut first = macluster_metrics::unavailable(10, "fixture");
        let mut first_json = serde_json::to_value(first).unwrap();
        first_json["cpu_temp_celsius"] = serde_json::json!(74.3);
        first = serde_json::from_value(first_json).unwrap();
        first.cpu_percent = Some(100.0);
        first.cpu_max_percent = Some(800.0);
        let mut second = macluster_metrics::unavailable(10, "fixture");
        let mut second_json = serde_json::to_value(second).unwrap();
        second_json["cpu_temp_celsius"] = serde_json::json!(35.4);
        second = serde_json::from_value(second_json).unwrap();
        let nodes = vec![
            NodeMetricRow {
                id: "mini01-a".into(),
                host: "192.168.2.1".into(),
                reachable: true,
                metrics: Some(first),
                error: None,
            },
            NodeMetricRow {
                id: "mini01-b".into(),
                host: "192.168.2.2".into(),
                reachable: true,
                metrics: Some(second),
                error: None,
            },
        ];
        let pool_total = aggregate_metrics(&nodes);
        assert_eq!(pool_total.cpu_percent, None);
        let view = ClusterMetricView {
            sampled_unix_ms: 10,
            login: macluster_metrics::unavailable(10, "fixture"),
            missing_nodes: 0,
            nodes,
            pool_total,
            login_compute_node_id: None,
            task_counts_by_node: None,
        };
        let encoded = serde_json::to_value(view).unwrap();
        let object = encoded.as_object().unwrap();
        let keys: Vec<_> = object.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "login",
                "missing_nodes",
                "nodes",
                "pool_total",
                "sampled_unix_ms"
            ]
        );
        assert_eq!(encoded["nodes"][0]["reachable"], true);
        assert!(encoded["nodes"][0].get("metrics").is_some());
        assert!(encoded["pool_total"].get("cpu_percent").is_some());
        assert_eq!(encoded["pool_total"]["cpu_temp_celsius"], 74.3);
        assert_eq!(
            encoded["pool_total"]["errors"],
            serde_json::json!(BTreeMap::<String, String>::new())
        );
    }

    fn query_cached_monitor_for_test(
        age_ms: u64,
        stale: bool,
    ) -> Option<(
        MetricSnapshot,
        Vec<(
            String,
            macluster_core::config::NodeConfig,
            Result<MetricSnapshot, String>,
        )>,
    )> {
        let root = std::env::temp_dir().join(format!(
            "macluster-monitor-cache-test-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        fs::create_dir_all(root.join("state")).unwrap();
        let config_path = root.join("config.toml");
        fs::write(
            &config_path,
            format!(
                "[cluster]\nname=\"monitor-cache\"\nlogin_node=\"login\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker]\nhost=\"192.0.2.50\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\nssh_user=\"worker\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036be\"\n",
                root.join("shared").display(),
                unsafe { libc::geteuid() }
            ),
        )
        .unwrap();
        let state_dir = root.join("state");
        let config = ClusterConfig::parse(&fs::read_to_string(&config_path).unwrap()).unwrap();
        let queue = QueueName::new("q").unwrap();
        let binding =
            macluster_core::service::ServiceBinding::load(&config_path, &state_dir).unwrap();
        let instance = macluster_controller::InstanceLock::acquire(&state_dir).unwrap();
        let hello = ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().into(),
            namespace: binding.namespace().into(),
            uid: binding.uid(),
            build_id: "monitor-cache-test".into(),
            capabilities: vec!["monitor.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: macluster_protocol::identifiers::ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 9,
            lifecycle: ControllerLifecycle::Ready,
        };
        let mut listener =
            macluster_controller::ControlListener::bind(&binding, &instance, hello).unwrap();
        let request = thread::spawn(move || {
            cached_monitor_samples(&config, &config_path, &state_dir, Some(&queue))
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let control_request = loop {
            if let Some(request) = listener.poll_request() {
                break request;
            }
            assert!(
                Instant::now() < deadline,
                "monitor cache query did not arrive"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert!(matches!(
            &control_request.request().command,
            ControlCommand::MonitorSnapshot { page: 0 }
        ));
        let mut login = macluster_metrics::unavailable(10, "fixture");
        login.cpu_percent = Some(10.0);
        login.power_age_ms = Some(20);
        let mut worker = macluster_metrics::unavailable(10, "fixture");
        worker.cpu_percent = Some(50.0);
        worker.power_age_ms = Some(30);
        control_request
            .respond(Ok(ControlPayload::MonitorSnapshot(MonitorSnapshot {
                sequence: 4,
                sampled_unix_ms: 10,
                generation: 9,
                page: 0,
                total_pages: 1,
                nodes: vec![
                    NodeMonitorRow {
                        node_id: "login".parse().unwrap(),
                        metrics: login,
                        age_ms: Some(age_ms),
                        stale,
                        sample_error: None,
                        request_latency_ms: None,
                        running_tasks: 0,
                        waiting_tasks: 0,
                        processes: None,
                        process_age_ms: None,
                        process_stale: false,
                        process_error: None,
                    },
                    NodeMonitorRow {
                        node_id: "worker".parse().unwrap(),
                        metrics: worker,
                        age_ms: Some(age_ms),
                        stale,
                        sample_error: None,
                        request_latency_ms: None,
                        running_tasks: 0,
                        waiting_tasks: 0,
                        processes: None,
                        process_age_ms: None,
                        process_stale: false,
                        process_error: None,
                    },
                ],
            })))
            .unwrap();
        let result = request.join().unwrap();
        drop(listener);
        drop(instance);
        let _ = fs::remove_dir_all(root);
        result
    }

    #[test]
    fn one_shot_uses_only_fresh_controller_monitor_cache_and_preserves_source_age() {
        let (login, nodes) = query_cached_monitor_for_test(500, false).unwrap();
        assert_eq!(login.cpu_percent, Some(10.0));
        assert_eq!(nodes.len(), 1);
        let worker = nodes[0].2.as_ref().unwrap();
        assert_eq!(worker.cpu_percent, Some(50.0));
        assert_eq!(worker.power_age_ms, Some(530));
    }

    #[test]
    fn one_shot_rejects_stale_controller_monitor_cache() {
        assert!(query_cached_monitor_for_test(6_000, true).is_none());
    }

    fn query_agent_cache_from_fake_controller(
        records: Vec<AgentCompatibilityRecord>,
    ) -> Option<crate::node_admin::AgentBuildCompatibility> {
        let root =
            std::env::temp_dir().join(format!("macluster-preflight-ipc-{}", Id128::random()));
        fs::create_dir_all(&root).unwrap();
        fs::create_dir(root.join("state")).unwrap();
        fs::write(
            root.join("config.toml"),
            format!(
                "[cluster]\nname=\"preflight\"\nlogin_node=\"login\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker]\nhost=\"192.0.2.50\"\ntransport=\"ssh\"\nremote_binary=\"/tmp/macluster\"\nssh_user=\"worker\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036be\"\n",
                root.display(),
                unsafe { libc::geteuid() }
            ),
        )
        .unwrap();
        let config_path = root.join("config.toml");
        let state_dir = root.join("state");
        let config = ClusterConfig::parse(&fs::read_to_string(&config_path).unwrap()).unwrap();
        let binding =
            macluster_core::service::ServiceBinding::load(&config_path, &state_dir).unwrap();
        let instance = macluster_controller::InstanceLock::acquire(&state_dir).unwrap();
        let hello = ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().into(),
            namespace: binding.namespace().into(),
            uid: binding.uid(),
            build_id: "test-controller".into(),
            capabilities: vec!["agent.compatibility.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: macluster_protocol::identifiers::ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: 0,
            lifecycle: ControllerLifecycle::Ready,
        };
        let mut listener =
            macluster_controller::ControlListener::bind(&binding, &instance, hello).unwrap();
        let expected_records = records.clone();
        let query = thread::spawn(move || {
            super::query_controller_agent_compatibility(&config_path, &state_dir, &config)
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        let request = loop {
            if let Some(request) = listener.poll_request() {
                break request;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for preflight query"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert!(matches!(
            &request.request().command,
            ControlCommand::QueryAgentCompatibility { .. }
        ));
        request
            .respond(Ok(ControlPayload::AgentCompatibility(expected_records)))
            .unwrap();
        let result = query.join().unwrap();
        drop(listener);
        drop(instance);
        let _ = fs::remove_dir_all(root);
        result
    }

    #[test]
    fn preflight_accepts_fresh_controller_cache_and_keeps_mismatch_visible() {
        let records = vec![
            AgentCompatibilityRecord {
                node_id: "login".parse().unwrap(),
                state: AgentCompatibilityState::Current,
                age_ms: Some(30),
            },
            AgentCompatibilityRecord {
                node_id: "worker".parse().unwrap(),
                state: AgentCompatibilityState::Mismatch,
                age_ms: Some(50),
            },
        ];
        let compatibility = query_agent_cache_from_fake_controller(records).unwrap();
        assert_eq!(compatibility.current, ["login"]);
        assert_eq!(compatibility.stale, ["worker"]);
        assert!(compatibility.unknown.is_empty());
        assert!(compatibility.requires_update());
    }

    #[test]
    fn preflight_does_not_treat_an_uninitialized_service_cache_as_current() {
        let records = vec![
            AgentCompatibilityRecord {
                node_id: "login".parse().unwrap(),
                state: AgentCompatibilityState::Unknown,
                age_ms: None,
            },
            AgentCompatibilityRecord {
                node_id: "worker".parse().unwrap(),
                state: AgentCompatibilityState::Unknown,
                age_ms: None,
            },
        ];
        assert!(query_agent_cache_from_fake_controller(records).is_none());
    }
}

fn config_error(error: String) -> (i32, String) {
    (2, error)
}
fn cli_error(error: CliError) -> (i32, String) {
    (2, error.to_string())
}

fn print_help() {
    println!(
        "macluster — macOS cluster task manager\n\nUsage: macluster <submit|job|queue|kill|top|node|fans|controller|init> [OPTIONS]\n\nAliases: msub, mjob, mqueue, mkill, mtop, mnode, mfans\nGlobal options: --config PATH, --state-dir PATH"
    );
}

fn print_submit_help() {
    println!(
        "Usage: msub [-v|--verbose] [-q QUEUE] [--node NODE] [-J NAME] [-t HH:MM:SS] [--cwd PATH] [-o PATH] [-e PATH] [--env KEY=VALUE] SCRIPT|COMMAND [ARGS...]\n       msub -Is [-q QUEUE] [--node NODE] [OPTIONS] [SCRIPT|COMMAND [ARGS...]]\n       msub [--request-id UUID]\n       msub --wrap COMMAND\n\n-v enables detailed timestamped output and CPU/memory logs for this task; it is off by default. The submitting process's exported environment is forwarded to the task by default; --env overrides individual values. When a task uses the active VIRTUAL_ENV or CONDA_PREFIX, that environment must belong to a registered share mounted at the same absolute path on every node. Its bin/ directory is put first in PATH; when both are active, PATH order selects the environment. Simple commands resolved outside that environment do not require its interpreter to be shared. If PATH is explicitly overridden with --env PATH=..., that filtered PATH stays authoritative. Unshared or relocated active environments are rejected instead of falling back to compute-local tools. PATH otherwise keeps registered shared paths plus standard macOS commands; unshared login-only paths are omitted. Batch and interactive tasks do not read compute-node shell startup files. Node-local HOME, user, temporary-directory, and SSH-agent values are not copied. Avoid exporting secrets to jobs. A command may be passed as argv, for example `msub -Is pip install . --break-system-packages`; flags after the command belong to the task. A single quoted command such as `msub -Is 'pwd; echo done'` retains shell syntax. Use --wrap for explicit raw shell input. Inline commands default to the configured shared root when submitted from outside it; --cwd overrides this. Cargo uses a reusable node-local target cache unless CARGO_TARGET_DIR is set. Do not run concurrent pip installs into the same shared environment. `-Is` opens an attached interactive shell when no command is provided, or runs the supplied script/command in a remote PTY. It requires terminal stdin and stdout. Task submission and cluster changes validate configured Agent builds and capabilities. Read-only commands check locally available build evidence and enter the update workflow for known mismatches; they do not run remote validation or address discovery first. mjob and mqueue read persisted records without starting the controller. Internal Agent RPCs, the unimplemented `agent` command, and help bypass this check. Ctrl-C while waiting cancels the job; after attachment it is sent to the foreground process. Jobs occupy one complete node; core and memory request flags are not supported."
    );
}

#[cfg(test)]
mod update_terminal_regressions {
    use super::*;
    #[test]
    fn noninteractive_cancellation_and_inspection_survive_pending_update() {
        assert_eq!(
            defer_update_without_terminal("submit", &[], false, false),
            Ok(false)
        );
        for command in ["kill", "job", "queue", "top"] {
            assert_eq!(
                defer_update_without_terminal(command, &[], false, true),
                Ok(true)
            );
        }
        assert_eq!(
            defer_update_without_terminal("node", &["-l".into()], false, true),
            Ok(true)
        );
        assert!(defer_update_without_terminal("submit", &[], false, true).is_err());
        assert_eq!(
            defer_update_without_terminal("submit", &[], true, true),
            Ok(false)
        );
    }
}
