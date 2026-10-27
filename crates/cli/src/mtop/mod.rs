mod jobs;
mod model;
mod processes;
mod sampler;
mod ssh;
mod terminal;
mod ui;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod ui_tests;

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
    path::PathBuf,
    sync::{Once, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crossterm::event::{self, Event, KeyEventKind};
use macluster_core::config::{ClusterConfig, Transport};
use macluster_protocol::types::{JobRecord, JobState, MetricSnapshot};

use self::{
    jobs::JobPoller,
    model::{
        ConfiguredNode, CpuHistory, DisplayNodeIdentity, LoginIdentity, MetricView,
        NodeMetricCache, NodeRole, display_node_identities,
    },
    processes::{ProcessCache, ProcessSampler, ProcessTarget, ProcessView},
    sampler::{MetricSampler, SampleTarget},
    terminal::{TerminalGuard, install_panic_restore_hook},
    ui::{AppState, InputAction, UiNode, handle_key, render},
};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(2);
const EVENT_POLL: Duration = Duration::from_millis(100);
const REDRAW_INTERVAL: Duration = Duration::from_millis(200);
const ONE_SHOT_DEADLINE: Duration = Duration::from_secs(10);
const PROCESS_SAMPLE_INTERVAL: Duration = Duration::from_secs(3);

pub(crate) enum MtopPostAction {
    CheckBuilds(crate::node_admin::AgentBuildCompatibility),
    RecoverMaintenance,
    UpdateDeferred,
}

enum StartupValidation {
    AddressMigration,
    Builds(crate::node_admin::AgentBuildCompatibility),
    RecoverMaintenance,
    UpdateDeferred,
}

fn should_defer_startup_update(
    recovery_pending: bool,
    update_required: bool,
    work_pending: bool,
) -> bool {
    work_pending && (recovery_pending || update_required)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn should_use_tui(
    once: bool,
    json: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    term_is_dumb: bool,
) -> bool {
    !once && !json && stdin_is_terminal && stdout_is_terminal && !term_is_dumb
}

pub(crate) fn sample_one_shot(
    config: &ClusterConfig,
    selected_queue: Option<&str>,
) -> (
    MetricSnapshot,
    Vec<(
        String,
        macluster_core::config::NodeConfig,
        Result<MetricSnapshot, String>,
    )>,
) {
    let allowed: Option<Vec<String>> = selected_queue.and_then(|queue| {
        config
            .queues
            .contains_key(queue)
            .then(|| config.queue_compute_nodes(queue))
    });
    let nodes: Vec<_> = config
        .nodes
        .iter()
        .filter(|(id, _)| {
            !config.is_login_node(id)
                && allowed
                    .as_ref()
                    .is_none_or(|members| members.iter().any(|member| member == *id))
        })
        .map(|(id, node)| (id.clone(), node.clone()))
        .collect();
    let mut targets = vec![("@login".to_owned(), SampleTarget::Local)];
    targets.extend(
        nodes
            .iter()
            .filter(|(_, node)| node.transport == Transport::Ssh)
            .map(|(id, node)| (id.clone(), SampleTarget::for_node(node))),
    );
    let target_lookup: HashMap<_, _> = targets.iter().cloned().collect();
    let mut round: VecDeque<_> = targets.iter().map(|(id, _)| id.clone()).collect();
    let mut sampler = MetricSampler::new(4);
    let deadline = Instant::now() + ONE_SHOT_DEADLINE;
    let mut results = HashMap::new();
    while results.len() < targets.len() && Instant::now() < deadline {
        schedule_round(&mut round, &target_lookup, &mut sampler, false);
        for result in sampler.poll() {
            results.insert(result.id, result.result);
        }
        if results.len() < targets.len() {
            thread::sleep(Duration::from_millis(10));
        }
    }
    let login_result = results
        .remove("@login")
        .unwrap_or_else(|| Err("local metric sample exceeded the 10s snapshot deadline".into()));
    let login_snapshot = match &login_result {
        Ok(snapshot) => snapshot.clone(),
        Err(reason) => macluster_metrics::unavailable(now_unix_ms(), reason),
    };
    let node_results = nodes
        .into_iter()
        .map(|(id, node)| {
            let result = if node.transport == Transport::Local {
                login_result.clone()
            } else {
                results.remove(&id).unwrap_or_else(|| {
                    Err("node metric sample exceeded the 10s snapshot deadline".into())
                })
            };
            (id, node, result)
        })
        .collect();
    (login_snapshot, node_results)
}

pub fn run_interactive(
    config: ClusterConfig,
    state_dir: PathBuf,
    config_path: PathBuf,
    selected_queue: Option<String>,
    no_color: bool,
    address_migration_deferred: bool,
) -> Result<Option<MtopPostAction>, String> {
    static PANIC_HOOK: Once = Once::new();
    PANIC_HOOK.call_once(install_panic_restore_hook);

    let queue_filter = selected_queue.as_deref();
    let local_node = config
        .nodes
        .values()
        .find(|node| node.transport == Transport::Local);
    let login = LoginIdentity {
        host: local_node
            .map(|node| node.host.clone())
            .unwrap_or_else(|| "localhost".into()),
        machine_uuid: local_node.and_then(|node| node.machine_uuid.clone()),
    };
    let configured = configured_node_identities(&config);
    let mut identities = display_node_identities(&login, &configured, queue_filter);
    let mut targets = Vec::with_capacity(identities.len());
    let mut process_targets_by_id = HashMap::new();
    for identity in &identities {
        let target = match identity.role {
            NodeRole::Login => SampleTarget::Local,
            NodeRole::Compute | NodeRole::LoginCompute => {
                let node = config.nodes.get(&identity.id).ok_or_else(|| {
                    format!(
                        "configuration lost node '{}' while starting mtop",
                        identity.id
                    )
                })?;
                if node.transport == Transport::Local
                    || login.machine_uuid.as_ref().is_some_and(|uuid| {
                        node.machine_uuid
                            .as_ref()
                            .is_some_and(|node_uuid| node_uuid.eq_ignore_ascii_case(uuid))
                    })
                {
                    SampleTarget::Local
                } else {
                    SampleTarget::for_node(node)
                }
            }
        };
        let process_target = match &target {
            SampleTarget::Local => ProcessTarget::Local,
            SampleTarget::Node(node) => ProcessTarget::for_node(node),
        };
        process_targets_by_id.insert(identity.id.clone(), process_target);
        targets.push((identity.id.clone(), target));
    }
    let mut targets_by_id: HashMap<_, _> = targets.iter().cloned().collect();
    let target_ids: Vec<_> = targets.iter().map(|(id, _)| id.clone()).collect();

    let mut state = AppState::empty(
        selected_queue
            .clone()
            .unwrap_or_else(|| "all queues".into()),
    );
    state.no_color = no_color;
    state.status_message = Some("Agent validation: CHECKING all configured nodes".into());
    state.job_store_error = Some("reading local task database".into());
    state.nodes = identities
        .iter()
        .map(|identity| UiNode {
            identity: identity.clone(),
            metrics: MetricView::Loading,
            jobs: Vec::new(),
            cpu_history: Vec::new(),
            last_error: None,
            processes: ProcessView::Loading,
        })
        .collect();
    state.selected_id = state.nodes.first().map(|node| node.identity.id.clone());

    let mut sampler = MetricSampler::new(4.min(targets.len().max(1)));
    let mut process_sampler = ProcessSampler::new();
    let mut process_caches: BTreeMap<String, ProcessCache> = BTreeMap::new();
    let mut process_selection: Option<String> = None;
    let mut next_process_sample = Instant::now();
    let jobs = JobPoller::spawn(state_dir.clone());
    let mut caches: BTreeMap<String, NodeMetricCache> = BTreeMap::new();
    let mut histories: BTreeMap<String, CpuHistory> = BTreeMap::new();
    let mut auto_round: Option<VecDeque<String>> = Some(target_ids.iter().cloned().collect());
    let mut initial_auto_round = true;
    let mut manual_round: Option<VecDeque<String>> = None;
    let mut next_sample = Instant::now() + SAMPLE_INTERVAL;
    let mut status_message: Option<String> = None;
    let (validation_tx, validation_rx) = mpsc::sync_channel::<Result<StartupValidation, String>>(1);
    let validation_config = config.clone();
    let validation_state_dir = state_dir.clone();
    let validation_config_path = config_path.clone();
    thread::Builder::new()
        .name("mtop-agent-validation".into())
        .spawn(move || {
            let result = (|| {
                if address_migration_deferred
                    || crate::node_admin::address_migration_pending(&validation_state_dir)
                {
                    return Ok(StartupValidation::AddressMigration);
                }
                let node_recovery = crate::node_admin::node_admin_recovery_pending(
                    &validation_config_path,
                    &validation_state_dir,
                )?;
                let update_recovery = crate::node_admin::agent_update_recovery_pending(
                    &validation_config_path,
                    &validation_state_dir,
                )?;
                if node_recovery || update_recovery {
                    let work_pending =
                        crate::node_admin::agent_update_blocked_by_work(&validation_state_dir)?;
                    if should_defer_startup_update(true, false, work_pending) {
                        return Ok(StartupValidation::UpdateDeferred);
                    }
                    return Ok(StartupValidation::RecoverMaintenance);
                }
                let compatibility = crate::node_admin::configured_agent_build_compatibility_cached(
                    &validation_config,
                    &validation_state_dir.join("mtop-cache"),
                )
                .map_err(|(_, error)| error)?;
                if compatibility.requires_update() {
                    let work_pending =
                        crate::node_admin::agent_update_blocked_by_work(&validation_state_dir)?;
                    if should_defer_startup_update(false, true, work_pending) {
                        return Ok(StartupValidation::UpdateDeferred);
                    }
                }
                Ok(StartupValidation::Builds(compatibility))
            })();
            let _ = validation_tx.send(result);
        })
        .map_err(|error| format!("could not start background Agent validation: {error}"))?;
    let mut validation_finished = false;
    let mut address_migration_waiting = false;
    let mut post_action = None;
    let mut last_draw = Instant::now() - REDRAW_INTERVAL;
    let mut next_age_tick = Instant::now() + Duration::from_secs(1);
    let mut dirty = true;

    let mut terminal = TerminalGuard::enter()
        .map_err(|error| format!("could not enter mtop terminal mode: {error}"))?;
    let result = (|| {
        loop {
            let now = Instant::now();
            if !validation_finished {
                match validation_rx.try_recv() {
                    Ok(Ok(StartupValidation::AddressMigration)) => {
                        validation_finished = true;
                        status_message = Some("Node address recovery needs attention; Agent updates are deferred and monitoring remains available".into());
                    }
                    Ok(Ok(StartupValidation::RecoverMaintenance)) => {
                        validation_finished = true;
                        state.status_message = Some(
                            "Agent maintenance recovery required; leaving mtop to resume it".into(),
                        );
                        post_action = Some(MtopPostAction::RecoverMaintenance);
                        break;
                    }
                    Ok(Ok(StartupValidation::UpdateDeferred)) => {
                        validation_finished = true;
                        status_message = Some(
                            "Agent update deferred while active tasks or output synchronization remain".into(),
                        );
                        post_action = Some(MtopPostAction::UpdateDeferred);
                    }
                    Ok(Ok(StartupValidation::Builds(compatibility))) => {
                        validation_finished = true;
                        if compatibility.requires_update() {
                            post_action = Some(MtopPostAction::CheckBuilds(compatibility));
                            break;
                        }
                        status_message = Some(format!(
                            "Agent validation complete: {} current, {} unknown/offline",
                            compatibility.current.len(),
                            compatibility.unknown.len()
                        ));
                        post_action = Some(MtopPostAction::CheckBuilds(compatibility));
                    }
                    Ok(Err(error)) => {
                        validation_finished = true;
                        status_message = Some(format!("Agent validation failed: {error}"));
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        validation_finished = true;
                        status_message =
                            Some("Agent validation worker stopped unexpectedly".into());
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if state.refresh_requested {
                state.refresh_requested = false;
                enqueue_manual_refresh(&mut manual_round, &target_ids);
                auto_round = None;
                initial_auto_round = false;
                next_sample = now + SAMPLE_INTERVAL;
                status_message = Some("refresh requested".into());
                dirty = true;
            }

            if let Some(round) = &mut manual_round {
                schedule_round(round, &targets_by_id, &mut sampler, false);
                if round.is_empty() {
                    manual_round = None;
                    status_message = Some("refresh scheduled".into());
                    dirty = true;
                }
            } else {
                if now >= next_sample && auto_round.is_none() && sampler.in_flight_count() == 0 {
                    auto_round = Some(target_ids.iter().cloned().collect());
                    next_sample = now + SAMPLE_INTERVAL;
                } else if now >= next_sample && sampler.in_flight_count() > 0 {
                    // Skip this interval instead of queuing catch-up work.
                    next_sample = now + SAMPLE_INTERVAL;
                }
                if let Some(round) = &mut auto_round {
                    schedule_round(round, &targets_by_id, &mut sampler, initial_auto_round);
                    if round.is_empty() {
                        auto_round = None;
                        initial_auto_round = false;
                    }
                }
            }

            for completed in sampler.poll() {
                let request_latency = completed
                    .received_at
                    .saturating_duration_since(completed.started_at);
                state
                    .sample_latency
                    .insert(completed.id.clone(), request_latency);
                match completed.result {
                    Ok(mut snapshot) => {
                        if let Some(age_ms) = snapshot.power_age_ms.as_mut() {
                            let latency_ms =
                                request_latency.as_millis().min(u64::MAX as u128) as u64;
                            *age_ms = age_ms.saturating_add(latency_ms);
                        }
                        let cache = caches.entry(completed.id.clone()).or_default();
                        cache.apply_success(snapshot.clone(), completed.received_at);
                        if completed.final_result {
                            histories.entry(completed.id).or_default().record(
                                completed.received_at,
                                snapshot.cpu_percent,
                                snapshot.cpu_max_percent,
                            );
                        }
                    }
                    Err(error) => {
                        caches
                            .entry(completed.id.clone())
                            .or_default()
                            .apply_error(error);
                        histories.entry(completed.id).or_default().record(
                            completed.received_at,
                            None,
                            None,
                        );
                    }
                }
                state.updated_at = Some(completed.received_at);
                dirty = true;
            }

            for completed in process_sampler.poll() {
                let cache = process_caches.entry(completed.id).or_default();
                match completed.result {
                    Ok(rows) => cache.apply_success(rows, completed.received_at),
                    Err(error) => cache.apply_error(error),
                }
                dirty = true;
            }

            if state.expanded {
                if let Some(selected_id) = state.selected_id.as_deref() {
                    if process_selection.as_deref() != Some(selected_id) {
                        process_selection = Some(selected_id.to_owned());
                        next_process_sample = now;
                    }
                    if now >= next_process_sample && !process_sampler.is_in_flight() {
                        if let Some(target) = process_targets_by_id.get(selected_id) {
                            if process_sampler.request(selected_id.to_owned(), target.clone()) {
                                next_process_sample = now + PROCESS_SAMPLE_INTERVAL;
                            }
                        }
                    }
                }
            } else {
                process_selection = None;
            }

            if let Some(update) = jobs.poll() {
                let mut visible_jobs = update.jobs;
                if let Some(queue) = selected_queue.as_deref() {
                    visible_jobs.retain(|job| job.spec.queue.as_str() == queue);
                }
                state.jobs = visible_jobs;
                state.job_store_error = update.error;
                state.jobs_updated_at = Some(update.sampled_at);
                dirty = true;
            }

            update_visible_nodes(
                &mut state,
                &identities,
                &caches,
                &histories,
                &process_caches,
                Instant::now(),
            );
            if let Some(message) = status_message.take()
                && state.status_message.as_deref() != Some(message.as_str())
            {
                state.status_message = Some(message);
            }

            let now = Instant::now();
            if now >= next_age_tick {
                let migrating = crate::node_admin::address_migration_pending(&state_dir);
                if migrating && !address_migration_waiting {
                    address_migration_waiting = true;
                    status_message = Some(
                        "Node addresses changed; migration will finish when active tasks stop"
                            .into(),
                    );
                } else if !migrating && address_migration_waiting {
                    address_migration_waiting = false;
                    if let Ok(source) = fs::read_to_string(&config_path)
                        && let Ok(current) = ClusterConfig::parse(&source)
                    {
                        for identity in &mut identities {
                            let node = current.nodes.get(&identity.id).or_else(|| {
                                matches!(identity.role, NodeRole::Login)
                                    .then(|| {
                                        current
                                            .nodes
                                            .values()
                                            .find(|node| node.transport == Transport::Local)
                                    })
                                    .flatten()
                            });
                            if let Some(node) = node {
                                identity.host = node.host.clone();
                                targets_by_id
                                    .insert(identity.id.clone(), SampleTarget::for_node(node));
                                process_targets_by_id
                                    .insert(identity.id.clone(), ProcessTarget::for_node(node));
                            }
                        }
                    }
                    status_message = Some(
                        "Node address migration completed; monitoring current endpoints".into(),
                    );
                }
                dirty = true;
                next_age_tick = now + Duration::from_secs(1);
            }

            let mut quit = false;
            let wait = if dirty {
                EVENT_POLL.min(REDRAW_INTERVAL.saturating_sub(last_draw.elapsed()))
            } else {
                EVENT_POLL
            };
            if event::poll(wait).map_err(|error| format!("mtop event polling failed: {error}"))? {
                match event::read().map_err(|error| format!("mtop event read failed: {error}"))? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        quit = handle_key(&mut state, key) == InputAction::Quit;
                        dirty = true;
                        if !state.show_help && state.status_message.is_some() {
                            state.status_message = None;
                        }
                    }
                    Event::Resize(_, _) => dirty = true,
                    _ => {}
                }
            }
            if quit {
                break;
            }
            if dirty && last_draw.elapsed() >= REDRAW_INTERVAL {
                terminal
                    .terminal_mut()
                    .draw(|frame| render(frame, &state))
                    .map_err(|error| format!("mtop draw failed: {error}"))?;
                last_draw = Instant::now();
                dirty = false;
            }
        }
        Ok::<(), String>(())
    })();
    let restore = terminal
        .restore()
        .map_err(|error| format!("could not restore terminal after mtop: {error}"));
    match (result, restore) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(post_action),
    }
}

fn configured_node_identities(config: &ClusterConfig) -> Vec<ConfiguredNode> {
    config
        .nodes
        .iter()
        .map(|(id, node)| ConfiguredNode {
            id: id.clone(),
            host: node.host.clone(),
            machine_uuid: node.machine_uuid.clone(),
            queues: config
                .queues
                .iter()
                .filter(|(_, queue)| {
                    queue.nodes.iter().any(|member| member == id) && !config.is_login_node(id)
                })
                .map(|(name, _)| name.clone())
                .collect(),
            local_transport: node.transport == Transport::Local,
        })
        .collect()
}

fn update_visible_nodes(
    state: &mut AppState,
    identities: &[DisplayNodeIdentity],
    caches: &BTreeMap<String, NodeMetricCache>,
    histories: &BTreeMap<String, CpuHistory>,
    process_caches: &BTreeMap<String, ProcessCache>,
    now: Instant,
) {
    let old_selection = state.selected_id.clone();
    state.nodes = identities
        .iter()
        .map(|identity| {
            let cache = caches.get(&identity.id);
            let metrics = cache.map_or(MetricView::Loading, |cache| cache.view_at(now));
            let last_error = cache
                .and_then(NodeMetricCache::last_error)
                .map(str::to_owned);
            let jobs = state
                .jobs
                .iter()
                .filter(|job| job_targets_node(job, &identity.id))
                .cloned()
                .collect();
            let cpu_history = histories
                .get(&identity.id)
                .map(|history| {
                    history
                        .points()
                        .iter()
                        .map(|point| {
                            point
                                .percent
                                .zip(point.maximum)
                                .filter(|(_, maximum)| *maximum > 0.0)
                                .map(|(value, maximum)| value / maximum * 100.0)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let processes = process_caches
                .get(&identity.id)
                .map_or(ProcessView::Loading, |cache| cache.view_at(now));
            UiNode {
                identity: identity.clone(),
                metrics,
                jobs,
                cpu_history,
                last_error,
                processes,
            }
        })
        .collect();
    state.selected_id = old_selection
        .filter(|id| state.nodes.iter().any(|node| &node.identity.id == id))
        .or_else(|| state.nodes.first().map(|node| node.identity.id.clone()));
    state.sort_nodes();
}

fn job_targets_node(job: &JobRecord, id: &str) -> bool {
    job.node.as_ref().is_some_and(|node| node.as_str() == id)
        || (job.state == JobState::Pending
            && job
                .spec
                .node
                .as_ref()
                .is_some_and(|node| node.as_str() == id))
}

fn schedule_round(
    round: &mut VecDeque<String>,
    targets: &HashMap<String, SampleTarget>,
    sampler: &mut MetricSampler,
    initial: bool,
) {
    let tries = round.len();
    for _ in 0..tries {
        if !sampler.has_capacity() {
            break;
        }
        let Some(id) = round.pop_front() else {
            break;
        };
        if let Some(target) = targets.get(&id) {
            let accepted = if initial {
                sampler.request_initial(id.clone(), target.clone())
            } else {
                sampler.request(id.clone(), target.clone())
            };
            if !accepted {
                round.push_back(id);
            }
        }
    }
}

fn enqueue_manual_refresh(round: &mut Option<VecDeque<String>>, target_ids: &[String]) {
    if round.is_none() {
        *round = Some(target_ids.iter().cloned().collect());
    }
}

#[cfg(test)]
mod scheduling_tests {
    use std::collections::VecDeque;

    use super::enqueue_manual_refresh;

    #[test]
    fn repeated_manual_refreshes_coalesce_into_one_pending_round() {
        let ids = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let mut round: Option<VecDeque<String>> = None;

        enqueue_manual_refresh(&mut round, &ids);
        round.as_mut().unwrap().pop_front();
        enqueue_manual_refresh(&mut round, &ids);

        assert_eq!(round.unwrap().into_iter().collect::<Vec<_>>(), ["b", "c"]);
    }
}
