use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use macluster_controller::monitor::{MetricSampleFn, MonitorHub, ProcessSampleFn};
use macluster_core::config::ClusterConfig;
use macluster_protocol::{
    identifiers::{Id128, NodeId},
    types::MetricSnapshot,
};

fn config() -> ClusterConfig {
    ClusterConfig::parse(&format!(
        "[cluster]\nname=\"monitor-test\"\ndefault_queue=\"q\"\nlogin_node=\"login\"\nshared_root=\"/tmp/macluster-monitor-test\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/usr/local/bin/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n[nodes.worker]\nhost=\"192.0.2.50\"\ntransport=\"ssh\"\nremote_binary=\"/usr/local/bin/macluster\"\nssh_user=\"worker\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036be\"\n",
        unsafe { libc::geteuid() }
    ))
    .unwrap()
}

fn snapshot() -> MetricSnapshot {
    let mut snapshot = macluster_metrics::unavailable(1, "sample pending");
    snapshot.cpu_percent = Some(42.0);
    snapshot.cpu_max_percent = Some(800.0);
    snapshot.power_watts = Some(19.0);
    snapshot.power_age_ms = Some(250);
    snapshot
}

#[test]
fn two_monitor_subscribers_share_one_metric_sample_without_real_ssh() {
    let metric_calls = Arc::new(AtomicUsize::new(0));
    let metric_calls_for_sample = Arc::clone(&metric_calls);
    let sample_metrics: Arc<MetricSampleFn> = Arc::new(move |_, _| {
        metric_calls_for_sample.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(20));
        Ok(snapshot())
    });
    let sample_processes: Arc<ProcessSampleFn> = Arc::new(|_, _| Ok(Vec::new()));
    let mut hub = MonitorHub::with_samplers(config(), sample_metrics, sample_processes);
    let node: NodeId = "worker".parse().unwrap();
    let first_client = Id128::random();
    let second_client = Id128::random();
    let started = Instant::now();

    hub.subscribe(first_client, vec![node.clone()], started);
    hub.subscribe(second_client, vec![node.clone()], started);

    let deadline = Instant::now() + Duration::from_secs(2);
    let page = loop {
        let page = hub.snapshot(0, 0, Instant::now());
        if page
            .nodes
            .iter()
            .any(|row| row.node_id == node && row.metrics.cpu_percent == Some(42.0))
        {
            break page;
        }
        assert!(
            Instant::now() < deadline,
            "shared monitor sample did not arrive"
        );
        thread::sleep(Duration::from_millis(5));
    };

    assert_eq!(metric_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        page.nodes.iter().filter(|row| row.node_id == node).count(),
        1
    );
}

#[test]
fn expired_monitor_lease_stops_new_metric_and_process_sampling() {
    let metric_calls = Arc::new(AtomicUsize::new(0));
    let process_calls = Arc::new(AtomicUsize::new(0));
    let metric_counter = Arc::clone(&metric_calls);
    let process_counter = Arc::clone(&process_calls);
    let sample_metrics: Arc<MetricSampleFn> = Arc::new(move |_, _| {
        metric_counter.fetch_add(1, Ordering::SeqCst);
        Ok(snapshot())
    });
    let sample_processes: Arc<ProcessSampleFn> = Arc::new(move |_, _| {
        process_counter.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    });
    let mut hub = MonitorHub::with_samplers(config(), sample_metrics, sample_processes);
    let node: NodeId = "worker".parse().unwrap();
    let client = Id128::random();
    let started = Instant::now();
    hub.subscribe(client, vec![node.clone()], started);
    assert!(hub.watch_processes(client, Some(node), started));

    let deadline = Instant::now() + Duration::from_secs(1);
    while (metric_calls.load(Ordering::SeqCst) == 0 || process_calls.load(Ordering::SeqCst) == 0)
        && Instant::now() < deadline
    {
        let _ = hub.snapshot(1, 0, Instant::now());
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(metric_calls.load(Ordering::SeqCst), 1);
    assert_eq!(process_calls.load(Ordering::SeqCst), 1);

    hub.expire(started + Duration::from_secs(31));
    assert_eq!(hub.active_subscribers(), 0);
    let metrics_before = metric_calls.load(Ordering::SeqCst);
    let processes_before = process_calls.load(Ordering::SeqCst);
    let _ = hub.snapshot(1, 0, started + Duration::from_secs(40));
    thread::sleep(Duration::from_millis(20));
    assert_eq!(metric_calls.load(Ordering::SeqCst), metrics_before);
    assert_eq!(process_calls.load(Ordering::SeqCst), processes_before);
}

#[test]
fn switching_details_discards_the_unwatched_process_result() {
    let process_calls = Arc::new(AtomicUsize::new(0));
    let process_counter = Arc::clone(&process_calls);
    let sample_metrics: Arc<MetricSampleFn> = Arc::new(|_, _| Ok(snapshot()));
    let sample_processes: Arc<ProcessSampleFn> = Arc::new(move |_, _| {
        process_counter.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(40));
        Ok(Vec::new())
    });
    let mut hub = MonitorHub::with_samplers(config(), sample_metrics, sample_processes);
    let node: NodeId = "worker".parse().unwrap();
    let client = Id128::random();
    let now = Instant::now();
    hub.subscribe(client, vec![node.clone()], now);
    assert!(hub.watch_processes(client, Some(node.clone()), now));
    assert_eq!(hub.snapshot(1, 0, now).nodes[1].processes, None);

    assert!(hub.watch_processes(client, None, now + Duration::from_millis(1)));
    let deadline = Instant::now() + Duration::from_secs(1);
    while process_calls.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    thread::sleep(Duration::from_millis(60));
    let snapshot = hub.snapshot(1, 0, now + Duration::from_secs(1));
    let worker = snapshot
        .nodes
        .iter()
        .find(|row| row.node_id == node)
        .unwrap();
    assert!(worker.processes.is_none());
    assert_eq!(process_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn offline_node_keeps_last_metric_and_reports_monotonic_staleness() {
    let metric_calls = Arc::new(AtomicUsize::new(0));
    let metric_counter = Arc::clone(&metric_calls);
    let sample_metrics: Arc<MetricSampleFn> = Arc::new(move |_, _| {
        if metric_counter.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(snapshot())
        } else {
            Err("node is offline".into())
        }
    });
    let sample_processes: Arc<ProcessSampleFn> = Arc::new(|_, _| Ok(Vec::new()));
    let mut hub = MonitorHub::with_samplers(config(), sample_metrics, sample_processes);
    let node: NodeId = "worker".parse().unwrap();
    let started = Instant::now();
    let client = Id128::random();
    hub.subscribe(client, vec![node.clone()], started);

    let mut first = None;
    let deadline = Instant::now() + Duration::from_secs(1);
    while first.is_none() && Instant::now() < deadline {
        let current = hub.snapshot(1, 0, started + Duration::from_millis(10));
        first = current
            .nodes
            .into_iter()
            .find(|row| row.node_id == node && row.metrics.cpu_percent == Some(42.0));
        thread::sleep(Duration::from_millis(5));
    }
    assert!(first.is_some());

    let failure_deadline = Instant::now() + Duration::from_secs(1);
    let mut failure_seen = false;
    while !failure_seen && Instant::now() < failure_deadline {
        let current = hub.snapshot(1, 0, started + Duration::from_secs(3));
        failure_seen = current.nodes.iter().any(|row| {
            row.node_id == node && row.sample_error.as_deref() == Some("node is offline")
        });
        thread::sleep(Duration::from_millis(5));
    }
    assert!(failure_seen);

    let stale = hub.snapshot(1, 0, started + Duration::from_secs(8));
    let worker = stale.nodes.iter().find(|row| row.node_id == node).unwrap();
    assert_eq!(worker.metrics.cpu_percent, Some(42.0));
    assert!(worker.stale);
    assert_eq!(worker.sample_error.as_deref(), Some("node is offline"));
}

#[test]
fn monitor_pages_are_bounded_and_same_cache_state_has_one_sequence() {
    let workers = (0..129)
        .map(|index| format!("worker-{index:03}"))
        .collect::<Vec<_>>();
    let mut text = format!(
        "[cluster]\nname=\"monitor-pages\"\ndefault_queue=\"q\"\nlogin_node=\"login\"\nshared_root=\"/tmp/macluster-monitor-pages\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes={workers:?}\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/usr/local/bin/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n",
        unsafe { libc::geteuid() }
    );
    for (index, worker) in workers.iter().enumerate() {
        text.push_str(&format!(
            "[nodes.{worker}]\nhost=\"192.0.2.{index}\"\ntransport=\"ssh\"\nremote_binary=\"/usr/local/bin/macluster\"\nssh_user=\"worker\"\n"
        ));
    }
    let config = ClusterConfig::parse(&text).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let sample_calls = Arc::clone(&calls);
    let sample_metrics: Arc<MetricSampleFn> = Arc::new(move |_, _| {
        sample_calls.fetch_add(1, Ordering::SeqCst);
        Ok(snapshot())
    });
    let sample_processes: Arc<ProcessSampleFn> = Arc::new(|_, _| Ok(Vec::new()));
    let mut hub = MonitorHub::with_samplers(config, sample_metrics, sample_processes);

    let first = hub.snapshot(3, 0, Instant::now());
    let second = hub.snapshot(3, 1, Instant::now());

    assert_eq!(first.total_pages, 2);
    assert_eq!(second.total_pages, 2);
    assert_eq!(first.nodes.len(), 128);
    assert_eq!(second.nodes.len(), 2);
    assert_eq!(first.sequence, second.sequence);
    assert!(
        first
            .nodes
            .iter()
            .all(|row| row.stale && row.age_ms.is_none())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
