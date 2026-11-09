use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

const SPINNER: &[u8] = b"|/-\\";
const TTY_REFRESH: Duration = Duration::from_millis(120);
const PIPE_NOTICE_INTERVAL: Duration = Duration::from_secs(30);

pub(super) struct MaintenanceProgress {
    operation: String,
    deferred_nodes: usize,
    started: Instant,
    last_render: Instant,
    last_phase: String,
    frame: usize,
    terminal: bool,
    rendered: bool,
    last_pipe_notice: Option<Instant>,
}

impl MaintenanceProgress {
    pub(super) fn new(operation: &str, deferred_nodes: usize) -> Self {
        Self {
            operation: operation.to_owned(),
            deferred_nodes,
            started: Instant::now(),
            last_render: Instant::now() - TTY_REFRESH,
            last_phase: String::new(),
            frame: 0,
            terminal: io::stderr().is_terminal(),
            rendered: false,
            last_pipe_notice: None,
        }
    }

    pub(super) fn update(&mut self, phase: &str, blockers: &[String]) {
        let elapsed = self.started.elapsed();
        if self.terminal {
            if elapsed < Duration::from_millis(350)
                || (self.last_phase == phase && self.last_render.elapsed() < TTY_REFRESH)
            {
                return;
            }
            let frame = SPINNER[self.frame % SPINNER.len()] as char;
            self.frame = self.frame.wrapping_add(1);
            let line = progress_text(
                &frame.to_string(),
                &self.operation,
                phase,
                elapsed,
                blockers,
                self.deferred_nodes,
            );
            eprint!("\r\x1b[2K{line}");
            let _ = io::stderr().flush();
            self.last_render = Instant::now();
            self.last_phase = phase.to_owned();
            self.rendered = true;
        } else if elapsed >= PIPE_NOTICE_INTERVAL
            && self
                .last_pipe_notice
                .is_none_or(|last| last.elapsed() >= PIPE_NOTICE_INTERVAL)
        {
            let line = progress_text(
                "…",
                &self.operation,
                phase,
                elapsed,
                blockers,
                self.deferred_nodes,
            );
            eprintln!("{line}");
            self.last_pipe_notice = Some(Instant::now());
        }
    }

    pub(super) fn finish(&mut self) {
        if self.terminal && self.rendered {
            eprint!("\r\x1b[2K\n");
            let _ = io::stderr().flush();
            self.rendered = false;
        }
    }
}

impl Drop for MaintenanceProgress {
    fn drop(&mut self) {
        self.finish();
    }
}

fn progress_text(
    frame: &str,
    operation: &str,
    phase: &str,
    elapsed: Duration,
    blockers: &[String],
    _deferred_nodes: usize,
) -> String {
    let elapsed_secs = elapsed.as_secs();
    let time = format!("{:02}:{:02}", elapsed_secs / 60, elapsed_secs % 60);
    let blocker_count = blockers.len();
    let wait = if phase == "finalizing" {
        "finalizing maintenance"
    } else if blockers.iter().any(|blocker| blocker.starts_with("job ")) {
        "waiting for active jobs"
    } else if blockers
        .iter()
        .any(|blocker| blocker.contains("output synchronization"))
    {
        "waiting for output sync"
    } else if !blockers.is_empty() {
        "checking node status"
    } else if phase == "controller" {
        "waiting for controller"
    } else {
        "waiting for maintenance"
    };
    let node_status = match blocker_count {
        0 => wait.to_owned(),
        1 => format!("{wait} (1 blocker)"),
        count => format!("{wait} ({count} blockers)"),
    };
    format!("{frame} {operation} · {node_status} · {time}")
}

#[cfg(test)]
mod tests {
    use super::progress_text;
    use std::time::Duration;

    #[test]
    fn progress_text_summarizes_wait_without_listing_offline_nodes() {
        let blockers = vec!["node default-003 execution verification failed".into()];
        let line = progress_text(
            "|",
            "Agent update",
            "draining",
            Duration::from_secs(12),
            &blockers,
            100,
        );

        assert_eq!(
            line,
            "| Agent update · checking node status (1 blocker) · 00:12"
        );
        assert!(!line.contains("default-003"));
    }
}
