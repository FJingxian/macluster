use std::time::{Duration, Instant};

use super::model::{
    ConfiguredNode, CpuHistory, LoginIdentity, MetricView, NodeMetricCache, NodeRole,
    ResourceValues, SortDirection, SortKey, SortRow, aggregate_cpu, aggregate_disk,
    aggregate_memory, aggregate_network, aggregate_power, display_node_identities, sort_rows,
};
use super::{apply_monitor_row, job_targets_node};
use macluster_metrics::unavailable;
use macluster_protocol::types::{JobRecord, MetricSnapshot};
use macluster_protocol::{control::NodeMonitorRow, identifiers::NodeId};
use std::collections::{BTreeMap, HashMap};

fn metric(cpu: Option<f64>, max: Option<f64>, power: Option<(f64, &str)>) -> MetricSnapshot {
    let mut value = unavailable(1, "fixture");
    value.cpu_percent = cpu;
    value.cpu_max_percent = max;
    if let Some((watts, scope)) = power {
        value.power_watts = Some(watts);
        value.power_scope = Some(scope.to_owned());
    }
    value
}

fn job_record(state: &str, assigned_node: Option<&str>, pinned_node: Option<&str>) -> JobRecord {
    serde_json::from_value(serde_json::json!({
        "id": 1001,
        "spec": {
            "queue": "mini01",
            "node": pinned_node,
            "name": "node-task-count",
            "cwd": "/share",
            "stdout_path": "",
            "stderr_path": "",
            "walltime_secs": null,
            "env": {},
            "snapshot": null
        },
        "state": state,
        "node": assigned_node,
        "created_unix_ms": 0,
        "started_unix_ms": null,
        "finished_unix_ms": null,
        "exit_code": null,
        "end_reason": null,
        "snapshot_sync_pending": false,
        "log_sync_pending": false,
        "waiting_reason": null
    }))
    .unwrap()
}

#[test]
fn node_task_counts_include_active_and_node_pinned_pending_jobs() {
    let running = job_record("RUNNING", Some("mini01-a"), None);
    let pinned_pending = job_record("PENDING", None, Some("mini01-a"));
    let unpinned_pending = job_record("PENDING", None, None);

    assert!(job_targets_node(&running, "mini01-a"));
    assert!(job_targets_node(&pinned_pending, "mini01-a"));
    assert!(!job_targets_node(&pinned_pending, "mini01-b"));
    assert!(!job_targets_node(&unpinned_pending, "mini01-a"));
}

#[test]
fn controller_monitor_request_latency_reaches_node_details() {
    let received_at = Instant::now();
    let row = NodeMonitorRow {
        node_id: NodeId::new("worker-a").unwrap(),
        metrics: metric(Some(50.0), Some(800.0), None),
        age_ms: Some(0),
        request_latency_ms: Some(87),
        stale: false,
        sample_error: None,
        running_tasks: 0,
        waiting_tasks: 0,
        processes: None,
        process_age_ms: None,
        process_stale: false,
        process_error: None,
    };
    let mut metrics = BTreeMap::new();
    let mut processes = BTreeMap::new();
    let mut histories = BTreeMap::new();
    let mut sample_latency = HashMap::new();

    apply_monitor_row(
        &mut metrics,
        &mut processes,
        &mut histories,
        &mut sample_latency,
        "worker-a",
        &row,
        received_at,
        true,
    );

    assert_eq!(
        sample_latency.get("worker-a"),
        Some(&Duration::from_millis(87))
    );
}

#[test]
fn login_compute_identity_is_merged_by_machine_uuid_once() {
    let login = LoginIdentity {
        host: "192.168.2.2".into(),
        machine_uuid: Some("login-uuid".into()),
    };
    let nodes = vec![
        ConfiguredNode {
            id: "mini01-c".into(),
            host: "192.168.2.2".into(),
            machine_uuid: Some("login-uuid".into()),
            queues: vec!["mini01".into()],
            local_transport: false,
        },
        ConfiguredNode {
            id: "mini01-a".into(),
            host: "192.168.2.1".into(),
            machine_uuid: Some("mini-uuid".into()),
            queues: vec!["mini01".into()],
            local_transport: false,
        },
    ];

    let rows = display_node_identities(&login, &nodes, None);

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, "mini01-a");
    let local = rows.iter().find(|row| row.id == "mini01-c").unwrap();
    assert_eq!(local.role, NodeRole::LoginCompute);
    assert_eq!(local.host, "192.168.2.2");
}

#[test]
fn queue_filter_keeps_out_of_queue_login_separate() {
    let login = LoginIdentity {
        host: "192.168.2.2".into(),
        machine_uuid: Some("login-uuid".into()),
    };
    let nodes = vec![
        ConfiguredNode {
            id: "mini01-c".into(),
            host: "192.168.2.2".into(),
            machine_uuid: Some("login-uuid".into()),
            queues: vec!["other".into()],
            local_transport: true,
        },
        ConfiguredNode {
            id: "mini01-a".into(),
            host: "192.168.2.1".into(),
            machine_uuid: Some("mini-uuid".into()),
            queues: vec!["mini01".into()],
            local_transport: false,
        },
    ];

    let rows = display_node_identities(&login, &nodes, Some("mini01"));

    assert_eq!(rows.len(), 2);
    let login_row = rows.iter().find(|row| row.id == "@login").unwrap();
    assert_eq!(login_row.role, NodeRole::Login);
    assert!(!rows.iter().any(|row| row.id == "mini01-c"));
    assert!(rows.iter().any(|row| row.id == "mini01-a"));
}

#[test]
fn login_without_compute_membership_stays_separate_in_full_cluster_view() {
    let login = LoginIdentity {
        host: "192.168.2.2".into(),
        machine_uuid: Some("login-uuid".into()),
    };
    let nodes = vec![ConfiguredNode {
        id: "login-01".into(),
        host: "192.168.2.2".into(),
        machine_uuid: Some("login-uuid".into()),
        queues: Vec::new(),
        local_transport: true,
    }];

    let rows = display_node_identities(&login, &nodes, None);

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, "@login");
    assert_eq!(rows[0].role, NodeRole::Login);
    assert!(!rows[0].compute_member);
}

#[test]
fn one_shot_monitor_does_not_return_login_as_a_compute_node_without_queue_filter() {
    use macluster_core::config::ClusterConfig;

    let config = ClusterConfig::parse(
        "[cluster]\nname = \"test\"\nlogin_node = \"login\"\ndefault_queue = \"mini01\"\nshared_root = \"/Users/Shared/macluster\"\nshare_uuid = \"00000000-0000-4000-8000-000000000001\"\nstorage_server = \"login\"\nprotocol_version = 1\n\n[queues.mini01]\nnodes = [\"login\"]\nscheduler = \"fifo\"\n\n[nodes.login]\nhost = \"192.0.2.1\"\ntransport = \"local\"\nmachine_uuid = \"01234567-89ab-cdef-0123-456789abcdef\"\nexecution_uid = 501\n",
    )
    .unwrap();

    let (_, compute_nodes) = super::sample_one_shot(&config, None);

    assert!(compute_nodes.is_empty());
}

#[test]
fn synthetic_login_key_cannot_collide_with_a_configured_node_id() {
    let login = LoginIdentity {
        host: "localhost".into(),
        machine_uuid: None,
    };
    let nodes = vec![ConfiguredNode {
        id: "login".into(),
        host: "192.168.2.9".into(),
        machine_uuid: None,
        queues: vec!["mini01".into()],
        local_transport: false,
    }];

    let rows = display_node_identities(&login, &nodes, None);

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, "@login");
    assert_eq!(rows[1].id, "login");
    assert_ne!(rows[0].id, rows[1].id);
}

#[test]
fn failed_request_keeps_last_sample_and_marks_it_stale_by_age() {
    let started = Instant::now();
    let mut cache = NodeMetricCache::default();
    cache.apply_success(metric(Some(77.0), Some(800.0), None), started);
    cache.apply_error("SSH timeout".into());

    match cache.view_at(started + Duration::from_secs(5)) {
        MetricView::Available {
            snapshot, stale, ..
        } => {
            assert_eq!(snapshot.cpu_percent, Some(77.0));
            assert!(!stale);
        }
        other => panic!("expected retained sample, got {other:?}"),
    }
    match cache.view_at(started + Duration::from_secs(6)) {
        MetricView::Available {
            snapshot, stale, ..
        } => {
            assert_eq!(snapshot.cpu_percent, Some(77.0));
            assert!(stale);
        }
        other => panic!("expected stale retained sample, got {other:?}"),
    }
}

#[test]
fn sort_keeps_unknown_and_stale_values_last_even_descending() {
    let mut rows = vec![
        SortRow::new(
            "b",
            ResourceValues {
                fresh: true,
                cpu_percent: Some(100.0),
                cpu_max_percent: Some(800.0),
                ..Default::default()
            },
        ),
        SortRow::new(
            "a",
            ResourceValues {
                fresh: false,
                cpu_percent: Some(700.0),
                cpu_max_percent: Some(800.0),
                ..Default::default()
            },
        ),
        SortRow::new("c", ResourceValues::default()),
    ];

    sort_rows(&mut rows, SortKey::Cpu, SortDirection::Descending);

    assert_eq!(
        rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
        ["b", "a", "c"]
    );
}

#[test]
fn power_keeps_its_longer_freshness_window_after_cpu_values_stale() {
    let mut rows = vec![
        SortRow::new(
            "low-power",
            ResourceValues {
                fresh: false,
                power_fresh: true,
                power_watts: Some(8.0),
                power_scope: Some("SoC".into()),
                ..Default::default()
            },
        ),
        SortRow::new(
            "high-power",
            ResourceValues {
                fresh: false,
                power_fresh: true,
                power_watts: Some(18.0),
                power_scope: Some("SoC".into()),
                ..Default::default()
            },
        ),
    ];

    sort_rows(&mut rows, SortKey::Power, SortDirection::Descending);

    assert_eq!(rows[0].id, "high-power");
    assert_eq!(rows[1].id, "low-power");
}

#[test]
fn cpu_history_keeps_gaps_and_resets_when_capacity_changes() {
    let start = Instant::now();
    let mut history = CpuHistory::default();
    history.record(start, Some(120.0), Some(800.0));
    history.record(start + Duration::from_secs(1), None, Some(800.0));

    assert_eq!(history.points().len(), 2);
    assert_eq!(history.points()[1].percent, None);

    history.record(start + Duration::from_secs(2), Some(50.0), Some(1200.0));

    assert_eq!(history.points().len(), 1);
    assert_eq!(history.points()[0].percent, Some(50.0));
}

#[test]
fn pool_cpu_shows_partial_coverage_and_power_is_grouped_by_scope() {
    let rows = [
        ResourceValues {
            fresh: true,
            cpu_percent: Some(100.0),
            cpu_max_percent: Some(800.0),
            power_watts: Some(8.0),
            power_scope: Some("SoC".into()),
            power_fresh: true,
            ..Default::default()
        },
        ResourceValues {
            fresh: true,
            cpu_percent: None,
            cpu_max_percent: None,
            power_watts: Some(2.0),
            power_scope: Some("CPU".into()),
            power_fresh: true,
            ..Default::default()
        },
        ResourceValues {
            fresh: false,
            cpu_percent: Some(400.0),
            cpu_max_percent: Some(800.0),
            power_watts: Some(9.0),
            power_scope: Some("SoC".into()),
            power_fresh: false,
            ..Default::default()
        },
    ];

    let cpu = aggregate_cpu(&rows);
    let power = aggregate_power(&rows);

    assert_eq!(cpu.cpu_percent, Some(100.0));
    assert_eq!(cpu.valid_nodes, 1);
    assert_eq!(cpu.total_nodes, 3);
    assert_eq!(power.len(), 2);
    assert_eq!(power["CPU"].watts, 2.0);
    assert_eq!(power["SoC"].watts, 8.0);
}

#[test]
fn pool_memory_disk_and_network_sum_only_fresh_complete_pairs() {
    let rows = [
        ResourceValues {
            fresh: true,
            memory_used_bytes: Some(4),
            memory_total_bytes: Some(8),
            disk_read_bytes_per_sec: Some(2.0),
            disk_write_bytes_per_sec: Some(1.0),
            network_rx_bytes_per_sec: Some(4.0),
            network_tx_bytes_per_sec: Some(3.0),
            ..Default::default()
        },
        ResourceValues {
            fresh: true,
            disk_read_bytes_per_sec: Some(0.0),
            disk_write_bytes_per_sec: Some(5.0),
            network_rx_bytes_per_sec: Some(1.0),
            network_tx_bytes_per_sec: Some(4.0),
            ..Default::default()
        },
        ResourceValues {
            fresh: false,
            memory_used_bytes: Some(100),
            memory_total_bytes: Some(100),
            disk_read_bytes_per_sec: Some(100.0),
            disk_write_bytes_per_sec: Some(100.0),
            network_rx_bytes_per_sec: Some(100.0),
            network_tx_bytes_per_sec: Some(100.0),
            ..Default::default()
        },
    ];

    let memory = aggregate_memory(&rows);
    let disk = aggregate_disk(&rows);
    let network = aggregate_network(&rows);

    assert_eq!((memory.used_bytes, memory.total_bytes), (Some(4), Some(8)));
    assert_eq!((memory.valid_nodes, memory.total_nodes), (1, 3));
    assert_eq!(
        (disk.read_bytes_per_sec, disk.write_bytes_per_sec),
        (Some(2.0), Some(6.0))
    );
    assert_eq!(
        (network.rx_bytes_per_sec, network.tx_bytes_per_sec),
        (Some(5.0), Some(7.0))
    );
    assert_eq!((network.valid_nodes, network.total_nodes), (2, 3));
}
