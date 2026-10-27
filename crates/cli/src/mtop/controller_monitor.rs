use std::{
    net::Shutdown,
    os::unix::net::UnixStream,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_core::service::ServiceBinding;
use macluster_protocol::{
    control::{
        ControlCommand, ControlPayload, MAX_CONTROL_MONITOR_SUBSCRIPTION_NODES, MonitorSnapshot,
        NodeMonitorRow,
    },
    identifiers::NodeId,
};

use crate::control_client::ControlClient;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);
const RENEW_INTERVAL: Duration = Duration::from_secs(10);

pub struct MonitorFeed {
    updates: Arc<Mutex<Option<MonitorUpdate>>>,
    selection: Arc<Mutex<Option<Option<NodeId>>>>,
    shutdown: UnixStream,
    generation: u64,
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
        let generation = client.hello().config_generation;
        let shutdown = client.shutdown_handle().ok()?;
        client.set_timeouts(SESSION_TIMEOUT).ok()?;

        let updates = Arc::new(Mutex::new(None));
        let update_sender = Arc::clone(&updates);
        let selection = Arc::new(Mutex::new(None));
        let worker_selection = Arc::clone(&selection);
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        thread::Builder::new()
            .name("mtop-controller-monitor".into())
            .spawn(move || {
                monitor_loop(
                    client,
                    nodes,
                    worker_selection,
                    update_sender,
                    worker_running,
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
        self.generation
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
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
}

fn monitor_loop(
    mut client: ControlClient,
    nodes: Vec<NodeId>,
    selections: Arc<Mutex<Option<Option<NodeId>>>>,
    updates: Arc<Mutex<Option<MonitorUpdate>>>,
    running: Arc<AtomicBool>,
) {
    if !matches!(
        client.request(ControlCommand::SubscribeMonitor {
            node_ids: nodes.clone(),
        }),
        Ok(ControlPayload::MonitorSubscribed)
    ) {
        return;
    }
    let mut last_process_watch: Option<Option<NodeId>> = None;
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
            let node_id = requested_watch.clone();
            if matches!(
                client.request(ControlCommand::WatchProcesses {
                    node_id: node_id.clone(),
                }),
                Ok(ControlPayload::MonitorAcknowledged)
            ) {
                last_process_watch = Some(requested_watch);
            }
        }

        let now = Instant::now();
        if now >= next_renewal {
            if !matches!(
                client.request(ControlCommand::SubscribeMonitor {
                    node_ids: nodes.clone(),
                }),
                Ok(ControlPayload::MonitorSubscribed)
            ) {
                return;
            }
            next_renewal = Instant::now() + RENEW_INTERVAL;
        }
        if now >= next_snapshot {
            if let Some(snapshot) = collect_snapshot(&mut client) {
                let update = MonitorUpdate {
                    generation: snapshot.generation,
                    sequence: snapshot.sequence,
                    rows: snapshot.nodes,
                    received_at: Instant::now(),
                };
                store_latest(&updates, update);
            }
            next_snapshot = Instant::now() + SNAPSHOT_INTERVAL;
        }
        let remaining = next_snapshot
            .min(next_renewal)
            .saturating_duration_since(Instant::now());
        thread::sleep(remaining);
    }
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
    collect_snapshot(&mut client)
}

fn collect_snapshot(client: &mut ControlClient) -> Option<MonitorSnapshot> {
    let ControlPayload::MonitorSnapshot(first) = client
        .request(ControlCommand::MonitorSnapshot { page: 0 })
        .ok()?
    else {
        return None;
    };
    if first.total_pages <= 1 {
        return Some(first);
    }
    if first.total_pages > 32 {
        return None;
    }
    let mut rows = first.nodes.clone();
    for page in 1..first.total_pages {
        let ControlPayload::MonitorSnapshot(snapshot) = client
            .request(ControlCommand::MonitorSnapshot { page })
            .ok()?
        else {
            return None;
        };
        if snapshot.sequence != first.sequence
            || snapshot.generation != first.generation
            || snapshot.total_pages != first.total_pages
            || snapshot.page != page
        {
            return None;
        }
        rows.extend(snapshot.nodes);
    }
    Some(MonitorSnapshot {
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
    use std::{sync::Mutex, time::Instant};

    use super::{MonitorUpdate, store_latest};

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
}
