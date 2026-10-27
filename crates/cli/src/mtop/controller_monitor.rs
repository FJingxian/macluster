use std::{
    fs,
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::{config::ClusterConfig, service::ServiceBinding};
use macluster_protocol::{
    control::{
        ControlCommand, ControlPayload, MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES, MonitorSnapshot,
        NodeMonitorRow,
    },
    identifiers::NodeId,
};

use crate::control_client::ControlClient;
use crate::control_client::ControlClientError;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);
const RENEW_INTERVAL: Duration = Duration::from_secs(10);
const RECONNECT_INITIAL_DELAY: Duration = Duration::from_millis(250);
const RECONNECT_MAX_DELAY: Duration = Duration::from_secs(5);

pub struct MonitorFeed {
    updates: Arc<Mutex<Option<MonitorUpdate>>>,
    selection: Arc<Mutex<Option<Option<NodeId>>>>,
    shutdown: Arc<Mutex<Option<UnixStream>>>,
    generation: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
}

pub struct MonitorUpdate {
    pub generation: u64,
    pub sequence: u64,
    pub rows: Vec<NodeMonitorRow>,
    pub received_at: Instant,
}

impl MonitorFeed {
    pub fn connect(
        config_path: &std::path::Path,
        state_dir: &std::path::Path,
        nodes: Vec<NodeId>,
    ) -> Option<Self> {
        if nodes.len() > MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES {
            return None;
        }
        let binding = ServiceBinding::load(config_path, state_dir).ok()?;
        let client = ControlClient::connect(&binding, CONNECT_TIMEOUT).ok()?;
        if !client
            .hello()
            .capabilities
            .iter()
            .any(|capability| capability == "monitor.v1")
        {
            return None;
        }
        let generation = Arc::new(AtomicU64::new(client.hello().config_generation));
        let shutdown = Arc::new(Mutex::new(Some(client.shutdown_handle().ok()?)));
        client.set_timeouts(SESSION_TIMEOUT).ok()?;

        let updates = Arc::new(Mutex::new(None));
        let update_sender = Arc::clone(&updates);
        let selection = Arc::new(Mutex::new(None));
        let worker_selection = Arc::clone(&selection);
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker_generation = Arc::clone(&generation);
        let worker_shutdown = Arc::clone(&shutdown);
        let config_path = config_path.to_path_buf();
        let state_dir = state_dir.to_path_buf();
        thread::Builder::new()
            .name("mtop-controller-monitor".into())
            .spawn(move || {
                monitor_loop(
                    client,
                    config_path,
                    state_dir,
                    nodes,
                    worker_selection,
                    update_sender,
                    worker_running,
                    worker_generation,
                    worker_shutdown,
                )
            })
            .ok()?;
        Some(Self {
            updates,
            selection,
            shutdown,
            generation,
            running,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn poll(&self) -> Option<MonitorUpdate> {
        self.updates.lock().ok()?.take()
    }

    pub fn watch(&self, node_id: Option<NodeId>) {
        if let Ok(mut selection) = self.selection.lock() {
            *selection = Some(node_id);
        }
    }
}

impl Drop for MonitorFeed {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Ok(mut active) = self.shutdown.lock()
            && let Some(stream) = active.take()
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn monitor_loop(
    mut client: ControlClient,
    config_path: PathBuf,
    state_dir: PathBuf,
    mut nodes: Vec<NodeId>,
    selections: Arc<Mutex<Option<Option<NodeId>>>>,
    updates: Arc<Mutex<Option<MonitorUpdate>>>,
    running: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    shutdown: Arc<Mutex<Option<UnixStream>>>,
) {
    let mut last_process_watch: Option<Option<NodeId>> = None;
    if subscribe_monitor(&mut client, &nodes).is_err() {
        let Some((reconnected, refreshed_nodes, restored_watch)) = reconnect_monitor(
            &config_path,
            &state_dir,
            &nodes,
            None,
            &running,
            &generation,
            &shutdown,
        ) else {
            return;
        };
        client = reconnected;
        nodes = refreshed_nodes;
        last_process_watch = Some(restored_watch);
    }
    let mut next_snapshot = Instant::now();
    let mut next_renewal = Instant::now() + RENEW_INTERVAL;

    while running.load(Ordering::Acquire) {
        let requested_watch = selections
            .lock()
            .ok()
            .and_then(|mut selection| selection.take());
        if let Some(requested_watch) = requested_watch
            && last_process_watch.as_ref() != Some(&requested_watch)
        {
            let node_id = requested_watch.filter(|node| nodes.contains(node));
            match watch_processes(&mut client, node_id.clone()) {
                Ok(()) => last_process_watch = Some(node_id),
                Err(MonitorError::Client) => {
                    let Some((reconnected, refreshed_nodes, restored_watch)) = reconnect_monitor(
                        &config_path,
                        &state_dir,
                        &nodes,
                        last_process_watch.clone().flatten(),
                        &running,
                        &generation,
                        &shutdown,
                    ) else {
                        return;
                    };
                    client = reconnected;
                    nodes = refreshed_nodes;
                    last_process_watch = Some(restored_watch);
                    next_snapshot = Instant::now();
                    next_renewal = Instant::now() + RENEW_INTERVAL;
                    continue;
                }
                Err(MonitorError::InvalidResponse) => {}
            }
        }

        let now = Instant::now();
        if now >= next_renewal {
            if let Err(MonitorError::Client) = subscribe_monitor(&mut client, &nodes) {
                let Some((reconnected, refreshed_nodes, restored_watch)) = reconnect_monitor(
                    &config_path,
                    &state_dir,
                    &nodes,
                    last_process_watch.clone().flatten(),
                    &running,
                    &generation,
                    &shutdown,
                ) else {
                    return;
                };
                client = reconnected;
                nodes = refreshed_nodes;
                last_process_watch = Some(restored_watch);
                next_snapshot = Instant::now();
                next_renewal = Instant::now() + RENEW_INTERVAL;
                continue;
            }
            next_renewal = Instant::now() + RENEW_INTERVAL;
        }
        if now >= next_snapshot {
            match collect_snapshot(&mut client) {
                Ok(snapshot) => {
                    let update = MonitorUpdate {
                        generation: snapshot.generation,
                        sequence: snapshot.sequence,
                        rows: snapshot.nodes,
                        received_at: Instant::now(),
                    };
                    store_latest(&updates, update);
                }
                Err(MonitorError::Client) => {
                    let Some((reconnected, refreshed_nodes, restored_watch)) = reconnect_monitor(
                        &config_path,
                        &state_dir,
                        &nodes,
                        last_process_watch.clone().flatten(),
                        &running,
                        &generation,
                        &shutdown,
                    ) else {
                        return;
                    };
                    client = reconnected;
                    nodes = refreshed_nodes;
                    last_process_watch = Some(restored_watch);
                    next_snapshot = Instant::now();
                    next_renewal = Instant::now() + RENEW_INTERVAL;
                    continue;
                }
                Err(MonitorError::InvalidResponse) => {}
            }
            next_snapshot = Instant::now() + SNAPSHOT_INTERVAL;
        }
        let remaining = next_snapshot
            .min(next_renewal)
            .saturating_duration_since(Instant::now());
        thread::sleep(remaining);
    }
}

#[derive(Debug)]
enum MonitorError {
    Client,
    InvalidResponse,
}

fn subscribe_monitor(client: &mut ControlClient, nodes: &[NodeId]) -> Result<(), MonitorError> {
    match client.request(ControlCommand::SubscribeMonitor {
        node_ids: nodes.to_vec(),
    })? {
        ControlPayload::MonitorSubscribed => Ok(()),
        _ => Err(MonitorError::InvalidResponse),
    }
}

fn watch_processes(
    client: &mut ControlClient,
    node_id: Option<NodeId>,
) -> Result<(), MonitorError> {
    match client.request(ControlCommand::WatchProcesses { node_id })? {
        ControlPayload::MonitorAcknowledged => Ok(()),
        _ => Err(MonitorError::InvalidResponse),
    }
}

impl From<ControlClientError> for MonitorError {
    fn from(_: ControlClientError) -> Self {
        Self::Client
    }
}

fn reconnect_monitor(
    config_path: &Path,
    state_dir: &Path,
    requested_nodes: &[NodeId],
    requested_watch: Option<NodeId>,
    running: &AtomicBool,
    generation: &AtomicU64,
    shutdown: &Mutex<Option<UnixStream>>,
) -> Option<(ControlClient, Vec<NodeId>, Option<NodeId>)> {
    let mut delay = RECONNECT_INITIAL_DELAY;
    while running.load(Ordering::Acquire) {
        if let Ok(binding) = ServiceBinding::load(config_path, state_dir)
            && let Ok(mut client) = ControlClient::connect(&binding, CONNECT_TIMEOUT)
            && client
                .hello()
                .capabilities
                .iter()
                .any(|capability| capability == "monitor.v1")
            && client.set_timeouts(SESSION_TIMEOUT).is_ok()
            && let Some(nodes) = configured_monitor_nodes(config_path, requested_nodes)
        {
            let watch = requested_watch.clone().filter(|node| nodes.contains(node));
            if subscribe_monitor(&mut client, &nodes).is_ok()
                && watch_processes(&mut client, watch.clone()).is_ok()
                && let Ok(new_shutdown) = client.shutdown_handle()
            {
                if let Ok(mut active) = shutdown.lock() {
                    *active = Some(new_shutdown);
                }
                generation.store(client.hello().config_generation, Ordering::Release);
                return Some((client, nodes, watch));
            }
        }
        thread::sleep(delay);
        delay = delay.saturating_mul(2).min(RECONNECT_MAX_DELAY);
    }
    None
}

fn configured_monitor_nodes(config_path: &Path, requested_nodes: &[NodeId]) -> Option<Vec<NodeId>> {
    let source = fs::read_to_string(config_path).ok()?;
    let config = ClusterConfig::parse(&source).ok()?;
    Some(
        requested_nodes
            .iter()
            .filter(|node_id| config.nodes.contains_key(node_id.as_str()))
            .cloned()
            .collect(),
    )
}

pub fn read_cached_snapshot(
    config_path: &std::path::Path,
    state_dir: &std::path::Path,
) -> Option<MonitorSnapshot> {
    let binding = ServiceBinding::load(config_path, state_dir).ok()?;
    let mut client = ControlClient::connect(&binding, CONNECT_TIMEOUT).ok()?;
    if !client
        .hello()
        .capabilities
        .iter()
        .any(|capability| capability == "monitor.v1")
    {
        return None;
    }
    collect_snapshot(&mut client).ok()
}

fn collect_snapshot(client: &mut ControlClient) -> Result<MonitorSnapshot, MonitorError> {
    let ControlPayload::MonitorSnapshot(first) =
        client.request(ControlCommand::MonitorSnapshot { page: 0 })?
    else {
        return Err(MonitorError::InvalidResponse);
    };
    if first.total_pages <= 1 {
        return Ok(first);
    }
    if first.total_pages > 32 {
        return Err(MonitorError::InvalidResponse);
    }
    let mut rows = first.nodes.clone();
    for page in 1..first.total_pages {
        let ControlPayload::MonitorSnapshot(snapshot) =
            client.request(ControlCommand::MonitorSnapshot { page })?
        else {
            return Err(MonitorError::InvalidResponse);
        };
        if snapshot.sequence != first.sequence
            || snapshot.generation != first.generation
            || snapshot.total_pages != first.total_pages
            || snapshot.page != page
        {
            return Err(MonitorError::InvalidResponse);
        }
        rows.extend(snapshot.nodes);
    }
    Ok(MonitorSnapshot {
        nodes: rows,
        ..first
    })
}

fn store_latest(slot: &Mutex<Option<MonitorUpdate>>, update: MonitorUpdate) {
    if let Ok(mut latest) = slot.lock() {
        *latest = Some(update);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };

    use macluster_controller::{ControlListener, InstanceLock, PendingControlEvent};
    use macluster_core::service::ServiceBinding;
    use macluster_protocol::{
        control::{
            CONTROL_PROTOCOL_VERSION, ControlCommand, ControlError, ControlErrorCode,
            ControlPayload, ControllerHello, ControllerLifecycle, MonitorSnapshot,
        },
        identifiers::{ControllerUuid, Id128},
        types::ControllerEpoch,
    };

    use super::{MonitorFeed, MonitorUpdate, store_latest};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("macluster-monitor-reconnect-{}", Id128::random()));
            fs::create_dir_all(root.join("state")).unwrap();
            fs::create_dir_all(root.join("shared")).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(
                root.join("config.toml"),
                format!(
                    "[cluster]\nname=\"monitor-test\"\nlogin_node=\"login\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-a83a-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n",
                    root.join("shared").display(),
                    unsafe { libc::geteuid() }
                ),
            )
            .unwrap();
            Self(root)
        }

        fn config_path(&self) -> PathBuf {
            self.0.join("config.toml")
        }

        fn state_dir(&self) -> PathBuf {
            self.0.join("state")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hello(binding: &ServiceBinding, generation: u64) -> ControllerHello {
        ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: binding.binding_digest().to_owned(),
            namespace: binding.namespace().to_owned(),
            uid: binding.uid(),
            build_id: "monitor-test-controller".into(),
            capabilities: vec!["monitor.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid::random(),
                epoch: 1,
            },
            config_generation: generation,
            lifecycle: ControllerLifecycle::Ready,
        }
    }

    fn wait_for_update(feed: &MonitorFeed, generation: u64, timeout: Duration) -> MonitorUpdate {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(update) = feed.poll()
                && update.generation == generation
            {
                return update;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("monitor feed did not produce generation {generation}");
    }

    #[test]
    fn slow_ui_keeps_only_the_newest_monitor_frame() {
        let slot = Mutex::new(None);
        for sequence in 1..=4 {
            store_latest(
                &slot,
                MonitorUpdate {
                    generation: 3,
                    sequence,
                    rows: Vec::new(),
                    received_at: Instant::now(),
                },
            );
        }
        let latest = slot.lock().unwrap().take().unwrap();
        assert_eq!(latest.sequence, 4);
        assert!(slot.lock().unwrap().is_none());
    }

    #[test]
    fn monitor_feed_reconnects_after_controller_generation_changes() {
        let fixture = Fixture::new();
        let binding = ServiceBinding::load(&fixture.config_path(), &fixture.state_dir()).unwrap();
        let server_binding = binding.clone();
        let state_dir = fixture.state_dir();
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (generation_sender, generation_receiver) = mpsc::sync_channel(1);
        let server_stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&server_stop);
        let server = thread::spawn(move || {
            let instance = InstanceLock::acquire(&state_dir).unwrap();
            let mut current_hello = hello(&server_binding, 1);
            let mut listener =
                ControlListener::bind(&server_binding, &instance, current_hello.clone()).unwrap();
            ready_sender.send(()).unwrap();
            while !stop_server.load(Ordering::Acquire) {
                if let Ok(generation) = generation_receiver.try_recv() {
                    current_hello.config_generation = generation;
                    listener.set_hello(current_hello.clone()).unwrap();
                }
                match listener.poll_event() {
                    Some(PendingControlEvent::Request(request)) => {
                        let response = match request.request().command {
                            ControlCommand::SubscribeMonitor { .. } => {
                                Ok(ControlPayload::MonitorSubscribed)
                            }
                            ControlCommand::WatchProcesses { .. } => {
                                Ok(ControlPayload::MonitorAcknowledged)
                            }
                            ControlCommand::MonitorSnapshot { page } if page == 0 => {
                                Ok(ControlPayload::MonitorSnapshot(MonitorSnapshot {
                                    sequence: current_hello.config_generation,
                                    sampled_unix_ms: 1,
                                    generation: current_hello.config_generation,
                                    page: 0,
                                    total_pages: 1,
                                    nodes: Vec::new(),
                                }))
                            }
                            _ => Err(ControlError {
                                code: ControlErrorCode::InvalidRequest,
                                message: "unexpected monitor test request".into(),
                            }),
                        };
                        request.respond(response).unwrap();
                    }
                    Some(PendingControlEvent::Disconnected(_)) | None => {
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        });
        ready_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

        let feed = MonitorFeed::connect(&fixture.config_path(), &fixture.state_dir(), Vec::new())
            .expect("monitor service should be available");
        wait_for_update(&feed, 1, Duration::from_secs(2));
        generation_sender.send(2).unwrap();

        let update = wait_for_update(&feed, 2, Duration::from_secs(5));
        assert_eq!(feed.generation(), 2);
        assert_eq!(update.sequence, 2);

        drop(feed);
        server_stop.store(true, Ordering::Release);
        server.join().unwrap();
    }
}
