use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use macluster_core::storage::ReadOnlyJobStore;
use macluster_protocol::types::JobRecord;

pub struct JobUpdate {
    pub jobs: Vec<JobRecord>,
    pub error: Option<String>,
    pub sampled_at: Instant,
}

pub struct JobPoller {
    updates: Receiver<JobUpdate>,
    stop: Sender<()>,
}

impl JobPoller {
    pub fn spawn(state_dir: PathBuf) -> Self {
        let (updates_tx, updates) = mpsc::channel();
        let (stop, stop_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut store = None;
            let mut next_open = Instant::now();
            loop {
                if store.is_none() && Instant::now() >= next_open {
                    match ReadOnlyJobStore::open(&state_dir) {
                        Ok(opened) => store = Some(opened),
                        Err(error) => {
                            let _ = updates_tx.send(JobUpdate {
                                jobs: Vec::new(),
                                error: Some(error.to_string()),
                                sampled_at: Instant::now(),
                            });
                            next_open = Instant::now() + Duration::from_secs(2);
                        }
                    }
                }
                let mut reopen = false;
                if let Some(opened) = &store {
                    match opened.list_monitor_jobs() {
                        Ok(jobs) => {
                            let _ = updates_tx.send(JobUpdate {
                                jobs,
                                error: None,
                                sampled_at: Instant::now(),
                            });
                        }
                        Err(error) => {
                            let _ = updates_tx.send(JobUpdate {
                                jobs: Vec::new(),
                                error: Some(error.to_string()),
                                sampled_at: Instant::now(),
                            });
                            reopen = true;
                        }
                    }
                }
                if reopen {
                    store = None;
                    next_open = Instant::now() + Duration::from_secs(2);
                }
                if stop_rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                    return;
                }
            }
        });
        Self { updates, stop }
    }

    pub fn poll(&self) -> Option<JobUpdate> {
        let mut latest = None;
        loop {
            match self.updates.try_recv() {
                Ok(update) => latest = Some(update),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return latest,
            }
        }
    }
}

impl Drop for JobPoller {
    fn drop(&mut self) {
        let _ = self.stop.send(());
    }
}
