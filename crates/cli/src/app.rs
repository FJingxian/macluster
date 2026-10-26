use std::{
    collections::BTreeMap,
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
    storage::{ReadOnlyJobStore, Storage, SubmitError},
};
use macluster_protocol::{
    framing::{MAX_SNAPSHOT_BYTES, sha256_hex},
    identifiers::{Id128, NodeId, QueueName, RequestId, StartToken},
    types::{
        ACTIVE_ENV_PREFIX_ENV, EXPLICIT_TASK_PATH_ENV, INTERACTIVE_PTY_FEATURE, JobMode, JobRecord,
        JobSpec, JobState, METRICS_FAN_SPEED_FEATURE, MetricSnapshot, PROTOCOL_VERSION,
        VERBOSE_TASK_LOG_ENV, VERBOSE_TASK_LOG_ROOT_ENV,
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
    let defer_mtop_preflight = command == "top" && top_will_use_tui(&args);
    if should_preflight_agent_update(&command, &args)
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
        "top" => top(global, &args),
        "controller" => controller(global, &args),
        "init" => crate::init::run(
            resolved_config_path(global.config.as_deref()),
            state_root(global.state_dir.as_deref())?,
            &args,
        ),
        "node" => node_admin(global, &args),
        "internal" => internal(global, &args),
        "agent" => Err((1, format!("`{command}` is not implemented yet"))),
        _ => unreachable!(),
    }
}

fn should_preflight_agent_update(command: &str, args: &[String]) -> bool {
    let help_requested = if command == "submit" {
        submit_help_requested(args)
    } else {
        args.iter()
            .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    };
    !matches!(command, "internal" | "agent") && !help_requested
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
    let compatibility = match checked_compatibility {
        Some(_) if command == "top" => {
            crate::node_admin::configured_agent_build_compatibility_cached(
                &config,
                &state_dir.join("mtop-cache"),
            )
            .map_err(|(code, error)| {
                (
                    code,
                    format!("cannot revalidate configured Agent builds: {error}"),
                )
            })?
        }
        Some(compatibility) => compatibility,
        None => crate::node_admin::configured_agent_build_compatibility(&config).map_err(
            |(code, error)| {
                (
                    code,
                    format!("cannot check configured Agent builds: {error}"),
                )
            },
        )?,
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
    let update_required = recovery_pending || compatibility.requires_update();
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
    if maybe_run_agent_update(update_required, || {
        crate::node_admin::update_all_agents_for_preflight(&config_path, &state_dir)
    })?
    .is_some_and(|controller_was_running| {
        update_requires_restart_retry(command, args, controller_was_running)
    }) {
        return Err((
            1,
            "Agent update completed and stopped the controller. Run `macluster controller run`, then retry the requested command.".into(),
        ));
    }
    Ok(())
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
        if loaded_from_cache {
            let staged = storage.stage_snapshot(&script).map_err(operation_error)?;
            if &staged != expected {
                return Err((
                    1,
                    "cached script does not match the cached submission".into(),
                ));
            }
        }
    } else if loaded_from_cache && !script.is_empty() {
        return Err((
            1,
            "cached interactive shell unexpectedly contains a script".into(),
        ));
    } else if !script.is_empty() {
        spec.snapshot = Some(storage.stage_snapshot(&script).map_err(operation_error)?);
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
    let record = storage
        .submit_once(request_id, spec)
        .map_err(operation_error)?;
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

fn update_requires_restart_retry(
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
            let transport =
                macluster_controller::transport::ClusterTransport::new(config_path.to_path_buf());
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
            return wait_for_interactive_completion(storage, job.id);
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

fn wait_for_interactive_completion(storage: &Storage, job_id: u64) -> AppResult<()> {
    loop {
        let job = storage
            .get_job(job_id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("job {job_id} disappeared")))?;
        if job.state.is_terminal() {
            return interactive_job_result(&job);
        }
        thread::sleep(Duration::from_millis(100));
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
    let mut task_env = prepare_task_environment(config, inherited_task_environment(), merged.env)?;
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

fn prepare_task_environment(
    config: &ClusterConfig,
    mut task_env: BTreeMap<String, String>,
    overrides: BTreeMap<String, String>,
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
    let has_cc_flags = task_env.keys().any(|key| is_cc_rs_flags_variable(key));
    let cc_shell_escaped_flags =
        if let Some(value) = task_env.get("CC_SHELL_ESCAPED_FLAGS").cloned() {
            !matches!(value.as_str(), "" | "0" | "false" | "no")
        } else if has_cc_flags {
            // remap_compiler_flags uses shell quoting so that values containing
            // spaces survive the trip through the job record. Tell cc-rs to parse
            // those flags with the same shell rules instead of splitting literally
            // on whitespace.
            task_env.insert("CC_SHELL_ESCAPED_FLAGS".into(), "1".into());
            true
        } else {
            false
        };
    if explicit_path {
        task_env.insert(EXPLICIT_TASK_PATH_ENV.into(), "1".into());
    }
    let selected_prefix = select_active_environment(&task_env)?;
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
    for (visible_root, mount_root) in shared_path_mappings(config) {
        let Ok(visible_root) = visible_root.canonicalize() else {
            continue;
        };
        let Ok(relative) = prefix.strip_prefix(&visible_root) else {
            continue;
        };
        matched = Some((visible_root, mount_root.join(relative)));
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
    let resolved_path = canonicalize_with_missing_suffix(path)?;
    for (visible_root, target_root) in shared_path_mappings(config) {
        let Ok(visible_root) = visible_root.canonicalize() else {
            continue;
        };
        if let Ok(relative) = resolved_path.strip_prefix(&visible_root) {
            return Some(if relative.as_os_str().is_empty() {
                target_root
            } else {
                target_root.join(relative)
            });
        }
    }
    None
}

// Resolve parent-directory aliases while retaining the final filename. Compiler
// shims such as rustup's `rustc` are symlinks whose name is part of their
// invocation contract (`argv[0]`).
fn canonicalize_parent_preserving_leaf(path: &Path) -> Option<PathBuf> {
    let leaf = path.file_name()?;
    Some(path.parent()?.canonicalize().ok()?.join(leaf))
}

fn remap_shared_invocation_path(config: &ClusterConfig, path: &Path) -> Option<PathBuf> {
    let invocation_path = canonicalize_parent_preserving_leaf(path)?;
    for (visible_root, target_root) in shared_path_mappings(config) {
        let Ok(visible_root) = visible_root.canonicalize() else {
            continue;
        };
        if let Ok(relative) = invocation_path.strip_prefix(&visible_root) {
            return Some(if relative.as_os_str().is_empty() {
                target_root
            } else {
                target_root.join(relative)
            });
        }
    }
    None
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
    let checked = absolute.to_string_lossy().replace("%j", "0");
    let checked = PathBuf::from(checked);
    if checked
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err((2, "output path cannot contain '..'".into()));
    }
    let parent = checked
        .parent()
        .ok_or_else(|| (2, "output path must name a file".into()))?;
    let file_name = absolute
        .file_name()
        .ok_or_else(|| (2, "output path must name a file".into()))?;
    let canonical_parent = parent.canonicalize().map_err(|error| {
        (
            2,
            format!(
                "output directory {} must exist and resolve: {error}",
                parent.display()
            ),
        )
    })?;
    let normalized = canonical_parent.join(file_name);
    for (visible_root, target_root) in shared_path_mappings(config) {
        let canonical_root = visible_root.canonicalize().map_err(|error| {
            (
                2,
                format!(
                    "shared output root {} is unavailable: {error}",
                    visible_root.display()
                ),
            )
        })?;
        if let Ok(relative) = normalized.strip_prefix(canonical_root) {
            return Ok(target_root.join(relative).to_string_lossy().into_owned());
        }
    }
    Err((
        2,
        "output paths must be inside the primary or a configured named share".into(),
    ))
}

fn job(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        println!(
            "Usage: mjob [JOBID] [--all] [--state STATE] [--json]\n       mjob --request-id UUID\n       mjob --log JOBID [--raw] [--stderr] [--follow]"
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
    let storage =
        Storage::open(state_root(global.state_dir.as_deref())?).map_err(operation_error)?;
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
        print_job(&record, json)?;
        return Ok(());
    }
    if let Some(id) = positional {
        let record = storage
            .get_job(id)
            .map_err(operation_error)?
            .ok_or_else(|| (1, format!("job {id} not found")))?;
        print_job(&record, json)?;
        return Ok(());
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
    storage: &Storage,
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
            if line.contains("] [stderr]") || line.contains("] [stderr:continued]") {
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
        println!("Usage: mqueue [-q|--queue QUEUE] [--jobs] [--json] [--watch SECONDS]");
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
    let storage =
        Storage::open(state_root(global.state_dir.as_deref())?).map_err(operation_error)?;
    loop {
        let counts_by_queue: BTreeMap<_, _> = storage
            .queue_job_counts()
            .map_err(operation_error)?
            .into_iter()
            .map(|counts| (counts.queue.clone(), counts))
            .collect();
        let jobs = show_jobs
            .then(|| storage.list_jobs(None))
            .transpose()
            .map_err(operation_error)?;
        let mut rows = Vec::new();
        for name in config.queues.keys() {
            if selected
                .as_ref()
                .is_some_and(|selected| selected.as_str() != name)
            {
                continue;
            }
            let counts = counts_by_queue.get(name);
            rows.push(QueueRow {
                name: name.clone(),
                nodes: config.queue_compute_nodes(name),
                pending: counts.map_or(0, |counts| counts.pending as usize),
                running: counts.map_or(0, |counts| counts.running as usize),
                completed: counts.map_or(0, |counts| counts.completed as usize),
                failed: counts.map_or(0, |counts| counts.failed as usize),
            });
        }
        if selected
            .as_ref()
            .is_some_and(|selected| !config.queues.contains_key(selected.as_str()))
        {
            return Err((
                2,
                format!("queue '{}' is not configured", selected.unwrap()),
            ));
        }
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
    let storage =
        Storage::open(state_root(global.state_dir.as_deref())?).map_err(operation_error)?;
    let mut failures = Vec::new();
    let mut changed = false;
    for id in ids {
        match storage.request_cancel(id, force) {
            Ok(record) => {
                changed = true;
                println!("Job {}: {:?}", id, record.state);
            }
            Err(error) => {
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

fn top(global: GlobalOptions, args: &[String]) -> AppResult<()> {
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
            state_dir,
            resolved_config_path(global.config.as_deref()),
            selected_queue.map(|queue| queue.to_string()),
            env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
        )
        .map_err(|error| (1, error))?;
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
            None if is_macluster_executable() => preflight_agent_update("top", args, &global),
            _ => Ok(()),
        };
    }
    let view = sample_cluster(&config, selected_queue.as_ref(), &state_dir);
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

fn controller(global: GlobalOptions, args: &[String]) -> AppResult<()> {
    if args.is_empty() || args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!(
            "Usage: macluster controller run [--once] [--interval SECONDS]\n       macluster controller status\n\nThe controller must run continuously to dispatch jobs and reconcile node status."
        );
        return Ok(());
    }
    let state_dir = state_root(global.state_dir.as_deref())?;
    match args[0].as_str() {
        "status" => {
            let storage = Storage::open(&state_dir).map_err(operation_error)?;
            let jobs = storage.list_jobs(None).map_err(operation_error)?;
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
        "run" => {
            let mut once = false;
            let mut interval = 2_u64;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--once" => once = true,
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
            let config_file = resolved_config_path(global.config.as_deref());
            crate::init::reset::ensure_no_reset_in_progress(&config_file, &state_dir)?;
            let _maintenance = MaintenanceLock::shared(&config_file).map_err(|error| {
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
            let _instance =
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
                macluster_controller::transport::ClusterTransport::new(config_file.clone()),
            )
            .map_err(|error| (1, error.to_string()))?;
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
            service.set_dispatch_enabled(!sync_pending);
            if sync_pending {
                eprintln!(
                    "macluster: peer config synchronization is pending; controller will reconcile status and cancellations but will not dispatch new jobs"
                );
            }
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
                service
                    .run_forever(interval)
                    .map_err(|error| (1, error.to_string()))
            }
        }
        value => Err((2, format!("unknown controller command '{value}'"))),
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
    let (login, samples) =
        crate::mtop::sample_one_shot(config, selected_queue.map(QueueName::as_str));
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
                let snapshot = macluster_metrics::sample_local();
                println!(
                    "{}",
                    serde_json::to_string(&snapshot).map_err(|error| (1, error.to_string()))?
                );
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
    };

    use super::{
        ACTIVE_ENV_PREFIX_ENV, ClusterMetricView, EXPLICIT_TASK_PATH_ENV, NodeMetricRow,
        aggregate_metrics, build_submission, explain_legacy_power_agent, format_job_details,
        format_jobs_table, format_power, is_macluster_binary_path, maybe_run_agent_update,
        metric_row, metric_table_header, prepare_task_environment, promote_inline_command,
        should_block_agent_update_for_pending_node_recovery,
        should_defer_agent_update_for_node_recovery, should_preflight_agent_update,
        update_requires_restart_retry,
    };
    use macluster_core::config::ClusterConfig;
    use macluster_protocol::{
        identifiers::{Id128, NodeId, QueueName},
        types::{JobMode, JobRecord, JobSpec, JobState},
    };

    #[test]
    fn operational_agent_update_preflight_skips_internal_and_help_but_checks_init() {
        for (command, args) in [
            ("internal", vec!["capabilities".into(), "--json".into()]),
            ("agent", vec!["--stdio".into()]),
            ("top", vec!["--help".into()]),
            ("node", vec!["-h".into()]),
            ("init", vec!["--help".into()]),
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
            "init",
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
        assert!(should_preflight_agent_update("init", &["--force".into()]));
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
    fn update_that_stops_controller_requires_restart_and_retry_except_controller_run() {
        assert!(update_requires_restart_retry("submit", &[], true));
        assert!(!update_requires_restart_retry(
            "controller",
            &["run".into()],
            true
        ));
        assert!(!update_requires_restart_retry("submit", &[], false));
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
        let error = prepare_task_environment(&config, BTreeMap::new(), unshared_env)
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
        let error = prepare_task_environment(&relocated_config, BTreeMap::new(), relocated_env)
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
    fn msub_enables_shell_parsing_for_remapped_cc_flags() {
        let root = std::env::temp_dir().join(format!(
            "macluster-cc-flags-{}-{}",
            std::process::id(),
            Id128::random()
        ));
        let (config, _, _) = environment_fixture(&root, &root.join("mounted-mamba"));
        let environment = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("CFLAGS".into(), "-DNAME='Hello World'".into()),
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
    fn msub_rejects_spaced_cc_flags_when_shell_parsing_is_disabled() {
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

        let error = prepare_task_environment(&config, environment, BTreeMap::new())
            .expect_err("cc-rs cannot preserve a spaced flag with whitespace splitting");

        assert!(error.1.contains("CC_SHELL_ESCAPED_FLAGS"), "{error:?}");
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
}

fn config_error(error: String) -> (i32, String) {
    (2, error)
}
fn cli_error(error: CliError) -> (i32, String) {
    (2, error.to_string())
}

fn print_help() {
    println!(
        "macluster — macOS cluster task manager\n\nUsage: macluster <submit|job|queue|kill|top|node|controller|init> [OPTIONS]\n\nAliases: msub, mjob, mqueue, mkill, mtop, mnode\nGlobal options: --config PATH, --state-dir PATH"
    );
}

fn print_submit_help() {
    println!(
        "Usage: msub [-v|--verbose] [-q QUEUE] [--node NODE] [-J NAME] [-t HH:MM:SS] [--cwd PATH] [-o PATH] [-e PATH] [--env KEY=VALUE] SCRIPT|COMMAND [ARGS...]\n       msub -Is [-q QUEUE] [--node NODE] [OPTIONS] [SCRIPT|COMMAND [ARGS...]]\n       msub [--request-id UUID]\n       msub --wrap COMMAND\n\n-v enables detailed timestamped output and CPU/memory logs for this task; it is off by default. The submitting process's exported environment is forwarded to the task by default; --env overrides individual values. A nonempty active VIRTUAL_ENV or CONDA_PREFIX must belong to a registered share mounted at the same absolute path on every node. Its bin/ directory is put first in PATH; when both are active, PATH order selects the environment. If PATH is explicitly overridden with --env PATH=..., that filtered PATH stays authoritative. Unshared or relocated active environments are rejected instead of falling back to compute-local tools. PATH otherwise keeps registered shared paths plus standard macOS commands; unshared login-only paths are omitted. Batch and interactive tasks do not read compute-node shell startup files. Node-local HOME, user, temporary-directory, and SSH-agent values are not copied. Avoid exporting secrets to jobs. A command may be passed as argv, for example `msub -Is pip install . --break-system-packages`; flags after the command belong to the task. A single quoted command such as `msub -Is 'pwd; echo done'` retains shell syntax. Use --wrap for explicit raw shell input. Inline commands default to the configured shared root when submitted from outside it; --cwd overrides this. Cargo uses a reusable node-local target cache unless CARGO_TARGET_DIR is set. Do not run concurrent pip installs into the same shared environment. `-Is` opens an attached interactive shell when no command is provided, or runs the supplied script/command in a remote PTY. It requires terminal stdin and stdout. Before every operational command and before `init` with an existing valid config, macluster checks all configured Agent version/hash values and automatically updates every node when a known mismatch exists. If that update stops a running controller, restart it and retry the command. Internal Agent RPCs, the unimplemented `agent` command, and help bypass this check. Ctrl-C while waiting cancels the job; after attachment it is sent to the foreground process. Jobs occupy one complete node; core and memory request flags are not supported."
    );
}
