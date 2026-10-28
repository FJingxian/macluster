use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use macluster_protocol::types::JobRecord;
use ratatui::{Terminal, backend::TestBackend, layout::Rect, style::Color};

use super::{
    model::{DisplayNodeIdentity, MetricView, NodeRole, SortKey, aggregate_power},
    processes::{ProcessInfo, ProcessView},
    ui::{
        AppState, InputAction, LayoutMode, handle_key, job_label, layout_mode, power_text, render,
        resources,
    },
};

fn rendered_lines(width: u16, height: u16, state: &AppState) -> Vec<String> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render(frame, state)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .chunks(width as usize)
        .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect()
}

fn job_record(
    id: u64,
    state: &str,
    assigned_node: Option<&str>,
    pinned_node: Option<&str>,
) -> JobRecord {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "spec": {
            "queue": "mini01",
            "node": pinned_node,
            "name": "layout-test",
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
fn tui_requires_both_terminals_and_no_one_shot_mode() {
    assert!(super::should_use_tui(false, false, true, true, false));
    assert!(!super::should_use_tui(true, false, true, true, false));
    assert!(!super::should_use_tui(false, true, true, true, false));
    assert!(!super::should_use_tui(false, false, false, true, false));
    assert!(!super::should_use_tui(false, false, true, false, false));
    assert!(!super::should_use_tui(false, false, true, true, true));
}

#[test]
fn mtop_defers_recovery_or_required_update_only_while_work_is_pending() {
    assert!(super::should_defer_startup_update(true, false, true));
    assert!(super::should_defer_startup_update(false, true, true));
    assert!(!super::should_defer_startup_update(false, false, true));
    assert!(!super::should_defer_startup_update(true, false, false));
}

#[test]
fn renderer_handles_wide_medium_compact_and_small_terminals() {
    for (width, height, expected) in [
        (160, 40, LayoutMode::Wide),
        (120, 30, LayoutMode::Medium),
        (80, 24, LayoutMode::Compact),
        (79, 20, LayoutMode::Compact),
    ] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let state = AppState::empty("mini01");
        terminal.draw(|frame| render(frame, &state)).unwrap();
        assert_eq!(layout_mode(Rect::new(0, 0, width, height)), expected);
    }
}

#[test]
fn node_columns_expand_in_priority_order_as_width_allows() {
    let mut state = AppState::empty("mini01");
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Loading,
        jobs: Vec::new(),
        cpu_history: Vec::new(),
        last_error: None,
        processes: Default::default(),
    });

    for (width, expected, hidden) in [
        (
            70,
            vec!["NODE", "RUN/WAIT", "CPU%", "MEM(GiB)", "GPU%", "DISK(R/W)"],
            "NET(down/up)",
        ),
        (
            80,
            vec![
                "NODE",
                "RUN/WAIT",
                "CPU%",
                "MEM(GiB)",
                "GPU%",
                "DISK(R/W)",
                "NET(down/up)",
                "POWER",
            ],
            "TEMP",
        ),
        (
            88,
            vec![
                "NODE",
                "RUN/WAIT",
                "CPU%",
                "MEM(GiB)",
                "GPU%",
                "DISK(R/W)",
                "NET(down/up)",
                "POWER",
                "TEMP",
            ],
            "QUEUES",
        ),
        (
            100,
            vec![
                "NODE",
                "RUN/WAIT",
                "CPU%",
                "MEM(GiB)",
                "GPU%",
                "DISK(R/W)",
                "NET(down/up)",
                "POWER",
                "TEMP",
                "QUEUES",
                "AGE",
            ],
            "",
        ),
    ] {
        let lines = rendered_lines(width, 24, &state);
        let header = lines
            .iter()
            .find(|line| line.contains("NODE") && line.contains("CPU"))
            .unwrap_or_else(|| panic!("node header missing at width {width}: {lines:?}"));
        let positions = expected
            .iter()
            .map(|label| {
                header
                    .find(label)
                    .unwrap_or_else(|| panic!("{label} missing at width {width}: {header:?}"))
            })
            .collect::<Vec<_>>();
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "column order at width {width}: {header:?}"
        );
        if !hidden.is_empty() {
            assert!(
                !header.contains(hidden),
                "{hidden} should wait for more width at {width}: {header:?}"
            );
        }
    }
}

#[test]
fn metric_units_are_in_headers_and_table_values_are_compact() {
    let mut snapshot = macluster_metrics::unavailable(1, "fixture");
    snapshot.cpu_percent = Some(100.0);
    snapshot.cpu_max_percent = Some(800.0);
    snapshot.memory_used_bytes = Some(4 * 1024 * 1024 * 1024);
    snapshot.memory_total_bytes = Some(16 * 1024 * 1024 * 1024);
    snapshot.gpu_percent = Some(72.5);
    snapshot.gpu_age_ms = Some(0);
    snapshot.power_watts = Some(11.2);
    snapshot.power_scope = Some("System".into());
    snapshot.power_age_ms = Some(0);
    snapshot.cpu_temp_celsius = Some(74.3);

    let mut state = AppState::empty("mini01");
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot,
            age: std::time::Duration::ZERO,
            stale: false,
        },
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: Default::default(),
    });

    let lines = rendered_lines(160, 24, &state);
    let header = lines
        .iter()
        .find(|line| line.contains("NODE") && line.contains("CPU%") && line.contains("MEM(GiB)"))
        .unwrap();
    let row = lines.iter().find(|line| line.contains("mini01-a")).unwrap();
    assert!(header.contains("GPU%"), "header: {header:?}");
    assert!(header.contains("TEMP"), "header: {header:?}");
    assert!(row.contains("100/800"), "row: {row:?}");
    assert!(!row.contains("100/800%"), "row: {row:?}");
    assert!(row.contains("4.0/16.0"), "row: {row:?}");
    assert!(!row.contains("GiB"), "row: {row:?}");
    assert!(row.contains("72.5"), "row: {row:?}");
    assert!(!row.contains("72.5%"), "row: {row:?}");
    assert!(row.contains("11.2W"), "row: {row:?}");
    assert!(!row.contains("System"), "row: {row:?}");
    let summary_metrics = lines
        .iter()
        .find(|line| line.contains("CPU% 100/800"))
        .unwrap();
    assert!(summary_metrics.contains("MEM(GiB) 4.0 / 16.0"));

    state.selected_id = Some("mini01-a".into());
    state.expanded = true;
    let details = rendered_lines(160, 24, &state).join("\n");
    assert!(details.contains("CPU% 100/800"), "details: {details:?}");
    assert!(
        details.contains("MEM(GiB) 4.0/16.0"),
        "details: {details:?}"
    );
    assert!(details.contains("GPU% 72.5"), "details: {details:?}");
    assert!(details.contains("TEMP 74.3°C"), "details: {details:?}");

    state.expanded = false;
    let compact = rendered_lines(80, 24, &state).join("\n");
    assert!(
        compact.contains("CPU% 100/800"),
        "compact summary: {compact:?}"
    );
    assert!(
        compact.contains("MEM(GiB) 4.0/16.0"),
        "compact summary: {compact:?}"
    );
}

#[test]
fn node_columns_grow_to_fit_visible_content_and_shrink_on_narrow_terminals() {
    let mut state = AppState::empty("mini01");
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "compute-node-identifier".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["long-queue-name".into()],
            compute_member: true,
        },
        metrics: MetricView::Loading,
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: Default::default(),
    });

    let narrow = rendered_lines(80, 24, &state).join("\n");
    let wide = rendered_lines(160, 24, &state).join("\n");
    assert!(!narrow.contains("compute-node-identifier"));
    assert!(
        wide.contains("compute-node-identifier"),
        "wide screen: {wide:?}"
    );
    assert!(wide.contains("long-queue-name"), "wide screen: {wide:?}");

    let mut previous_name_width = 0;
    for width in 32..=200 {
        let lines = rendered_lines(width, 24, &state);
        let row = lines.iter().find(|line| line.contains("0/0")).unwrap();
        let name = row
            .split_once("0/0")
            .unwrap()
            .0
            .trim_start_matches('│')
            .trim();
        let name_width = unicode_width::UnicodeWidthStr::width(name);
        assert!(
            name_width >= previous_name_width,
            "node name shrank at terminal width {width}: {row:?}"
        );
        previous_name_width = name_width;
    }
}

#[test]
fn visible_numeric_columns_keep_full_values_and_power_freshness_markers() {
    let mut snapshot = macluster_metrics::unavailable(1, "fixture");
    snapshot.cpu_percent = Some(100.0);
    snapshot.cpu_max_percent = Some(1200.0);
    snapshot.disk_read_bytes_per_sec = Some(1_000_000_000.0);
    snapshot.disk_write_bytes_per_sec = Some(2_000_000_000.0);
    snapshot.power_watts = Some(123.4);
    snapshot.power_scope = Some("System".into());
    snapshot.power_age_ms = Some(18_000);
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("mini01-a".into());
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot,
            age: std::time::Duration::ZERO,
            stale: false,
        },
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: Default::default(),
    });
    for width in 40..=200 {
        let lines = rendered_lines(width, 24, &state);
        let header = lines.iter().find(|line| line.contains("NODE")).unwrap();
        let row = lines.iter().find(|line| line.contains("0/0")).unwrap();
        for (label, value) in [
            ("CPU%", "100/1200"),
            ("DISK(R/W)", "1000.0/2000.0 MB/s"),
            ("POWER", "123.4W*"),
        ] {
            if header.contains(label) {
                assert!(
                    row.contains(value),
                    "{label} clipped at width {width}: {row:?}"
                );
            }
        }
    }
}

#[test]
fn gpu_column_and_details_show_real_zero_and_expired_samples_as_na() {
    let make_snapshot = |gpu_percent, gpu_age_ms| {
        let mut snapshot = macluster_metrics::unavailable(1, "fixture");
        snapshot.gpu_percent = gpu_percent;
        snapshot.gpu_source = Some("macmon".into());
        snapshot.gpu_age_ms = Some(gpu_age_ms);
        snapshot.gpu_window_ms = Some(100);
        snapshot
    };
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("node-idle".into());
    for (id, percent, age, stale) in [
        ("node-idle", Some(0.0), 0, false),
        ("node-busy", Some(73.5), 0, false),
        ("node-stale", Some(88.0), 9_000, false),
        ("node-legacy", None, 0, false),
    ] {
        state.nodes.push(super::ui::UiNode {
            identity: DisplayNodeIdentity {
                id: id.into(),
                host: "192.0.2.11".into(),
                role: NodeRole::Compute,
                queues: vec!["mini01".into()],
                compute_member: true,
            },
            metrics: MetricView::Available {
                snapshot: make_snapshot(percent, age),
                age: std::time::Duration::ZERO,
                stale,
            },
            jobs: vec![],
            cpu_history: vec![],
            last_error: None,
            processes: Default::default(),
        });
    }

    let lines = rendered_lines(110, 24, &state);
    let header = lines.iter().find(|line| line.contains("GPU%")).unwrap();
    assert!(header.contains("GPU%"));
    let idle = lines
        .iter()
        .find(|line| line.contains("node-idle"))
        .unwrap();
    let busy = lines
        .iter()
        .find(|line| line.contains("node-busy"))
        .unwrap();
    let stale = lines
        .iter()
        .find(|line| line.contains("node-stale"))
        .unwrap();
    let legacy = lines
        .iter()
        .find(|line| line.contains("node-legacy"))
        .unwrap();
    assert!(idle.contains("0.0"), "idle row: {idle:?}");
    assert!(!idle.contains("0.0%"), "idle row: {idle:?}");
    assert!(busy.contains("73.5"), "busy row: {busy:?}");
    assert!(!busy.contains("73.5%"), "busy row: {busy:?}");
    assert!(stale.contains("N/A"), "stale row: {stale:?}");
    assert!(legacy.contains("N/A"), "legacy row: {legacy:?}");

    state.expanded = true;
    let details = rendered_lines(80, 24, &state).join("\n");
    assert!(details.contains("GPU% 0.0"), "details: {details:?}");
}

#[test]
fn node_task_column_shows_running_over_waiting_counts_and_zero_when_idle() {
    let mut state = AppState::empty("mini01");
    let pending = job_record(2, "PENDING", None, None);
    state.jobs.push(pending.clone());
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Loading,
        jobs: vec![job_record(1, "RUNNING", Some("mini01-a"), None)],
        cpu_history: Vec::new(),
        last_error: None,
        processes: Default::default(),
    });
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-b".into(),
            host: "192.0.2.12".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Loading,
        jobs: Vec::new(),
        cpu_history: Vec::new(),
        last_error: None,
        processes: Default::default(),
    });
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-c".into(),
            host: "192.0.2.13".into(),
            role: NodeRole::Compute,
            queues: vec!["other".into()],
            compute_member: true,
        },
        metrics: MetricView::Loading,
        jobs: Vec::new(),
        cpu_history: Vec::new(),
        last_error: None,
        processes: Default::default(),
    });

    let lines = rendered_lines(80, 24, &state);
    let active = lines.iter().find(|line| line.contains("mini01-a")).unwrap();
    let eligible = lines.iter().find(|line| line.contains("mini01-b")).unwrap();
    let other_queue = lines.iter().find(|line| line.contains("mini01-c")).unwrap();
    assert!(active.contains("1/1"), "active node row: {active:?}");
    assert!(eligible.contains("0/1"), "eligible node row: {eligible:?}");
    assert!(
        other_queue.contains("0/0"),
        "other queue row: {other_queue:?}"
    );

    state.selected_id = Some("mini01-a".into());
    state.expanded = true;
    let details = rendered_lines(120, 30, &state).join("\n");
    assert!(details.contains("RUN/WAIT 1/1"), "details: {details:?}");
}

#[test]
fn details_show_average_fan_speed_or_na_with_compact_metric_names() {
    let mut snapshot = macluster_metrics::unavailable(1, "fixture");
    let mut value = serde_json::to_value(snapshot).unwrap();
    value["fan_speed_rpm"] = serde_json::json!(1375.5);
    snapshot = serde_json::from_value(value).unwrap();
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("mini01-a".into());
    state.expanded = true;
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot,
            age: std::time::Duration::ZERO,
            stale: false,
        },
        jobs: Vec::new(),
        cpu_history: Vec::new(),
        last_error: None,
        processes: Default::default(),
    });

    let screen = rendered_lines(160, 24, &state).join("\n");
    assert!(screen.contains("FAN 1376 RPM"), "details: {screen:?}");
    assert!(screen.contains("MEM(GiB)"), "details: {screen:?}");
    assert!(screen.contains("DISK(R/W)"), "details: {screen:?}");
    assert!(screen.contains("NET(down/up)"), "details: {screen:?}");

    let narrow_screen = rendered_lines(80, 30, &state).join("\n");
    assert!(
        narrow_screen.contains("FAN 1376 RPM"),
        "narrow details: {narrow_screen:?}"
    );

    let mut no_fan = macluster_metrics::unavailable(1, "fixture");
    let mut value = serde_json::to_value(no_fan).unwrap();
    value["fan_speed_rpm"] = serde_json::Value::Null;
    no_fan = serde_json::from_value(value).unwrap();
    state.nodes[0].metrics = MetricView::Available {
        snapshot: no_fan,
        age: std::time::Duration::ZERO,
        stale: false,
    };
    let screen = rendered_lines(160, 24, &state).join("\n");
    assert!(screen.contains("FAN N/A"), "details: {screen:?}");
}

#[test]
fn old_agents_explain_why_fan_speed_is_unavailable_in_both_detail_modes() {
    let mut snapshot = macluster_metrics::unavailable(1, "fixture");
    snapshot.errors.insert(
        "fan_speed".into(),
        "remote Agent predates fan-speed telemetry; update the Agent before fan RPM can be shown"
            .into(),
    );
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("mini01-a".into());
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot,
            age: std::time::Duration::ZERO,
            stale: false,
        },
        jobs: Vec::new(),
        cpu_history: Vec::new(),
        last_error: None,
        processes: Default::default(),
    });

    state.expanded = true;
    let expanded = rendered_lines(160, 24, &state).join("\n");
    assert!(
        expanded.contains("FAN N/A (update Agent)"),
        "expanded details: {expanded:?}"
    );

    state.expanded = false;
    let compact = rendered_lines(160, 24, &state).join("\n");
    assert!(
        compact.contains("FAN N/A (update Agent)"),
        "compact details: {compact:?}"
    );
}

#[test]
fn renderer_draws_cluster_and_control_labels() {
    let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
    let state = AppState::empty("mini01");
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(screen.contains("mini01"), "rendered buffer: {screen:?}");
    assert!(screen.contains("node ID"), "rendered buffer: {screen:?}");
    assert!(screen.contains("q Quit"), "rendered buffer: {screen:?}");
}

#[test]
fn power_column_omits_soc_and_system_labels_but_keeps_other_scopes() {
    let make_node = |id: &str, watts: f64, scope: &str| {
        let mut snapshot = macluster_metrics::unavailable(1, "fixture");
        snapshot.power_watts = Some(watts);
        snapshot.power_scope = Some(scope.into());
        snapshot.power_age_ms = Some(0);
        super::ui::UiNode {
            identity: DisplayNodeIdentity {
                id: id.into(),
                host: "192.0.2.11".into(),
                role: NodeRole::Compute,
                queues: vec!["mini01".into()],
                compute_member: true,
            },
            metrics: MetricView::Available {
                snapshot,
                age: std::time::Duration::ZERO,
                stale: false,
            },
            jobs: Vec::new(),
            cpu_history: Vec::new(),
            last_error: None,
            processes: Default::default(),
        }
    };
    let mut state = AppState::empty("mini01");
    state.nodes.push(make_node("mini01-soc", 11.2, "SoC"));
    state.nodes.push(make_node("mini01-cpu", 4.5, "CPU"));
    state.nodes.push(make_node("mini01-system", 13.8, "System"));

    let lines = rendered_lines(140, 24, &state);
    let soc_row = lines
        .iter()
        .find(|line| line.contains("mini01-soc"))
        .unwrap();
    let cpu_row = lines
        .iter()
        .find(|line| line.contains("mini01-cpu"))
        .unwrap();
    let system_row = lines
        .iter()
        .find(|line| line.contains("mini01-system"))
        .unwrap();

    assert!(soc_row.contains("11.2W"), "SoC row: {soc_row:?}");
    assert!(!soc_row.contains("SoC"), "SoC row: {soc_row:?}");
    assert!(cpu_row.contains("4.5W CPU"), "CPU row: {cpu_row:?}");
    assert!(system_row.contains("13.8W"), "system row: {system_row:?}");
    assert!(!system_row.contains("System"), "system row: {system_row:?}");
}

#[test]
fn node_table_hides_role_and_link_columns_and_colors_disconnected_id_red() {
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("mini01-down".into());
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-down".into(),
            host: "192.0.2.50".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Unavailable {
            reason: "SSH disconnected".into(),
        },
        jobs: vec![],
        cpu_history: vec![],
        last_error: Some("SSH disconnected".into()),
        processes: Default::default(),
    });

    for (width, height) in [(160, 30), (120, 30), (80, 24)] {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &state)).unwrap();
        let buffer = terminal.backend().buffer();
        let lines = buffer
            .content()
            .chunks(width as usize)
            .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>();
        let screen = lines.join("\n");
        assert!(!lines.iter().any(|line| line.contains("ROLE")));
        assert!(!lines.iter().any(|line| line.contains("LINK")));
        assert!(!screen.contains(" · compute · "));
        assert!(!screen.contains("DOWN"));
        let node_y = lines
            .iter()
            .position(|line| line.contains("mini01-down"))
            .unwrap() as u16;
        let node_x = lines[node_y as usize].find("mini01-down").unwrap() as u16;
        assert_eq!(buffer[(node_x, node_y)].fg, Color::Red);
    }
}

#[test]
fn renderer_defers_cpu_temperature_table_column_until_room_is_available() {
    let snapshot = |temperature| {
        let mut snapshot = macluster_metrics::unavailable(1, "fixture");
        let mut value = serde_json::to_value(snapshot).unwrap();
        value["cpu_temp_celsius"] = serde_json::json!(temperature);
        snapshot = serde_json::from_value(value).unwrap();
        snapshot
    };
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("mini01-c".into());
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-c".into(),
            host: "192.0.2.12".into(),
            role: NodeRole::LoginCompute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot: snapshot(74.3),
            age: std::time::Duration::from_secs(1),
            stale: false,
        },
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: Default::default(),
    });
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-b".into(),
            host: "192.0.2.13".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot: snapshot(99.9),
            age: std::time::Duration::from_secs(7),
            stale: true,
        },
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: Default::default(),
    });
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-a".into(),
            host: "192.0.2.11".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Available {
            snapshot: snapshot(35.4),
            age: std::time::Duration::from_secs(1),
            stale: false,
        },
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: Default::default(),
    });

    for (width, height) in [(160, 40), (80, 24)] {
        let lines = rendered_lines(width, height, &state);
        let screen = lines.join("\n");
        assert!(screen.contains("74.3°C"), "rendered buffer: {screen:?}");
        let summary_temperature = if width < 100 {
            "TEMP max 74.3°C 2/3"
        } else {
            "TEMP max 74.3°C · 2/3"
        };
        assert!(
            screen.contains(summary_temperature),
            "rendered buffer: {screen:?}"
        );
        let node_header = lines.iter().find(|line| line.contains("NODE")).unwrap();
        assert!(
            node_header.contains("MEM(GiB)"),
            "rendered buffer: {screen:?}"
        );
        if width >= 88 {
            assert!(node_header.contains("TEMP"), "rendered buffer: {screen:?}");
            assert!(screen.contains("99.9°C"), "rendered buffer: {screen:?}");
        } else {
            assert!(!node_header.contains("TEMP"), "rendered buffer: {screen:?}");
            assert!(!screen.contains("99.9°C"), "rendered buffer: {screen:?}");
        }
    }
}

#[test]
fn renderer_scrolls_selected_node_into_the_visible_table() {
    let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
    let mut state = AppState::empty("mini01");
    state.nodes = (0..30)
        .map(|index| super::ui::UiNode {
            identity: DisplayNodeIdentity {
                id: format!("node-{index:02}"),
                host: format!("192.0.2.{index}"),
                role: NodeRole::Compute,
                queues: vec!["mini01".into()],
                compute_member: true,
            },
            metrics: MetricView::Loading,
            jobs: vec![],
            cpu_history: Vec::new(),
            last_error: None,
            processes: Default::default(),
        })
        .collect();
    state.selected_id = Some("node-29".into());
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let screen = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(screen.contains("node-29"), "rendered buffer: {screen:?}");
    assert!(!screen.contains("node-00"), "rendered buffer: {screen:?}");
}

#[test]
fn renderer_keeps_quit_hint_visible_at_low_height() {
    let mut terminal = Terminal::new(TestBackend::new(79, 8)).unwrap();
    let state = AppState::empty("mini01");
    terminal.draw(|frame| render(frame, &state)).unwrap();
    assert_eq!(layout_mode(Rect::new(0, 0, 79, 8)), LayoutMode::TooSmall);
}

#[test]
fn power_age_is_shown_and_unknown_age_is_excluded_from_pool_totals() {
    let started = std::time::Instant::now();
    let mut snapshot = macluster_metrics::unavailable(1, "fixture");
    snapshot.power_watts = Some(11.2);
    snapshot.power_scope = Some("SoC".into());
    snapshot.power_age_ms = Some(2_000);
    let fresh = MetricView::Available {
        snapshot: snapshot.clone(),
        age: std::time::Duration::from_secs(1),
        stale: false,
    };
    assert_eq!(power_text(&fresh), "11.2 W SoC · age 3s");
    assert!(resources(&fresh).power_fresh);

    snapshot.power_age_ms = None;
    let unknown_age = MetricView::Available {
        snapshot,
        age: started.elapsed(),
        stale: false,
    };
    assert_eq!(power_text(&unknown_age), "11.2 W SoC · age ?");
    assert!(!resources(&unknown_age).power_fresh);
}

#[test]
fn cached_power_remains_in_pool_totals_until_the_helper_cache_expires() {
    let mut snapshot = macluster_metrics::unavailable(1, "fixture");
    snapshot.power_watts = Some(11.2);
    snapshot.power_scope = Some("System".into());
    snapshot.power_age_ms = Some(30_000);
    let cached = MetricView::Available {
        snapshot: snapshot.clone(),
        age: std::time::Duration::from_secs(1),
        stale: false,
    };

    assert_eq!(power_text(&cached), "11.2 W System · STALE 31s");
    let totals = aggregate_power(&[resources(&cached)]);
    assert_eq!(totals["System"].watts, 11.2);

    snapshot.power_age_ms = Some(60_001);
    let expired = MetricView::Available {
        snapshot,
        age: std::time::Duration::ZERO,
        stale: false,
    };
    assert!(aggregate_power(&[resources(&expired)]).is_empty());
    assert_eq!(power_text(&expired), "N/A");
}

#[test]
fn expanded_details_show_cpu_sorted_node_processes_and_collapsed_details_hide_them() {
    let mut state = AppState::empty("mini01");
    state.selected_id = Some("mini01-c".into());
    state.nodes.push(super::ui::UiNode {
        identity: DisplayNodeIdentity {
            id: "mini01-c".into(),
            host: "192.0.2.12".into(),
            role: NodeRole::Compute,
            queues: vec!["mini01".into()],
            compute_member: true,
        },
        metrics: MetricView::Loading,
        jobs: vec![],
        cpu_history: vec![],
        last_error: None,
        processes: ProcessView::Available {
            rows: vec![
                ProcessInfo {
                    pid: 42,
                    cpu_percent: 85.0,
                    memory: "32M".into(),
                    cpu_time: "00:01.20".into(),
                    command: "hot_worker".into(),
                },
                ProcessInfo {
                    pid: 17,
                    cpu_percent: 5.0,
                    memory: "128M".into(),
                    cpu_time: "00:00.10".into(),
                    command: "cool_worker".into(),
                },
            ],
            age: std::time::Duration::from_secs(1),
            stale: false,
            warning: None,
        },
    });

    let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
    state.expanded = true;
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let lines = terminal
        .backend()
        .buffer()
        .content()
        .chunks(160)
        .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>();
    let hot_line = lines.iter().position(|line| line.contains("hot_worker"));
    let cool_line = lines.iter().position(|line| line.contains("cool_worker"));
    assert!(lines.iter().any(|line| line.contains("PID")));
    assert!(hot_line.is_some(), "rendered lines: {lines:?}");
    assert!(cool_line.is_some(), "rendered lines: {lines:?}");
    assert!(
        hot_line.unwrap() < cool_line.unwrap(),
        "rendered lines: {lines:?}"
    );

    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
    );
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let memory_lines = terminal
        .backend()
        .buffer()
        .content()
        .chunks(160)
        .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>();
    let cool_line = memory_lines
        .iter()
        .position(|line| line.contains("cool_worker"));
    let hot_line = memory_lines
        .iter()
        .position(|line| line.contains("hot_worker"));
    assert!(
        memory_lines.iter().any(|line| line.contains("Memory ↓")),
        "rendered lines: {memory_lines:?}"
    );
    assert!(
        cool_line.unwrap() < hot_line.unwrap(),
        "rendered lines: {memory_lines:?}"
    );

    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
    );
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let cpu_lines = terminal
        .backend()
        .buffer()
        .content()
        .chunks(160)
        .map(|line| line.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>();
    let hot_line = cpu_lines
        .iter()
        .position(|line| line.contains("hot_worker"));
    let cool_line = cpu_lines
        .iter()
        .position(|line| line.contains("cool_worker"));
    assert!(
        hot_line.unwrap() < cool_line.unwrap(),
        "rendered lines: {cpu_lines:?}"
    );

    state.expanded = false;
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let collapsed = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(
        !collapsed.contains("hot_worker"),
        "rendered buffer: {collapsed:?}"
    );
}

#[test]
fn c_and_m_sort_processes_only_while_details_are_open() {
    let mut state = AppState::empty("mini01");
    state.nodes = ["node-b", "node-a"]
        .into_iter()
        .map(|id| super::ui::UiNode {
            identity: DisplayNodeIdentity {
                id: id.into(),
                host: format!("{id}.local"),
                role: NodeRole::Compute,
                queues: vec!["mini01".into()],
                compute_member: true,
            },
            metrics: MetricView::Loading,
            jobs: vec![],
            cpu_history: vec![],
            last_error: None,
            processes: Default::default(),
        })
        .collect();
    state.expanded = true;

    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
    );
    assert_eq!(state.sort_key, SortKey::Id);
    assert_eq!(state.nodes[0].identity.id, "node-b");
    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
    );
    assert_eq!(state.sort_key, SortKey::Id);
    assert_eq!(state.nodes[0].identity.id, "node-b");

    state.expanded = false;
    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
    );
    assert_eq!(state.sort_key, SortKey::Cpu);
}

#[test]
fn multiple_active_jobs_for_one_node_are_labeled_as_conflict() {
    let first: JobRecord = serde_json::from_value(serde_json::json!({
        "id": 1001,
        "spec": {
            "queue": "mini01",
            "node": null,
            "name": "one",
            "cwd": "/share",
            "stdout_path": "",
            "stderr_path": "",
            "walltime_secs": null,
            "env": {},
            "snapshot": {"sha256": "0", "size_bytes": 0}
        },
        "state": "RUNNING",
        "node": "mini01-a",
        "created_unix_ms": 0,
        "started_unix_ms": 0,
        "finished_unix_ms": null,
        "exit_code": null,
        "end_reason": null,
        "snapshot_sync_pending": false,
        "log_sync_pending": false,
        "waiting_reason": null
    }))
    .unwrap();
    let mut second = first.clone();
    second.id = 1002;

    assert_eq!(job_label(&[first.clone()]), "1001 Running");
    assert_eq!(job_label(&[first, second]), "CONFLICT");
}

#[test]
fn input_sorts_and_keeps_selected_node_stable() {
    let mut state = AppState::empty("mini01");
    state.nodes = ["b", "a", "c"]
        .into_iter()
        .map(|id| super::ui::UiNode {
            identity: DisplayNodeIdentity {
                id: id.into(),
                host: format!("{id}.local"),
                role: NodeRole::Compute,
                queues: vec!["mini01".into()],
                compute_member: true,
            },
            metrics: MetricView::Loading,
            jobs: vec![],
            cpu_history: vec![],
            last_error: None,
            processes: Default::default(),
        })
        .collect();
    state.selected_id = Some("b".into());

    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
    );
    assert_eq!(state.sort_key, SortKey::Cpu);
    assert_eq!(state.nodes[0].identity.id, "a");
    assert_eq!(state.selected_id.as_deref(), Some("b"));
    handle_key(&mut state, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(state.selected_id.as_deref(), Some("c"));
    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
    );
    assert!(state.refresh_requested);
}

#[test]
fn input_toggles_help_and_quits_with_q_or_ctrl_c() {
    let mut state = AppState::empty("mini01");
    handle_key(
        &mut state,
        KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
    );
    assert!(state.show_help);
    handle_key(&mut state, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(!state.show_help);
    assert_eq!(
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)
        ),
        InputAction::Quit
    );
    assert_eq!(
        handle_key(
            &mut state,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
        ),
        InputAction::Quit
    );
}
