use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use macluster_cli::service::{
    HelloProbeError, LaunchState, ServiceLauncher, ServiceLifecycleError, ServiceManager,
};
use macluster_core::service::{ServiceBinding, ServiceIntent};
use macluster_protocol::{
    control::{CONTROL_PROTOCOL_VERSION, ControllerHello, ControllerLifecycle},
    framing::sha256_hex,
    identifiers::{ControllerUuid, Id128, NodeId, QueueName, RequestId},
    types::{ControllerEpoch, JobMode, JobSpec},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("macluster-service-lifecycle-{}", Id128::random()));
        fs::create_dir_all(root.join("state")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        let execution_uid = unsafe { libc::geteuid() };
        fs::write(
            root.join("config.toml"),
            format!(
                "[cluster]\nname=\"lifecycle\"\ndefault_queue=\"q\"\nlogin_node=\"login\"\nshared_root=\"{}\"\nshare_uuid=\"240edfcc-0fe5-4fa8-83a2-29c6ede02b42\"\nstorage_server=\"login\"\nprotocol_version=1\n[queues.q]\nnodes=[]\nscheduler=\"fifo\"\n[nodes.login]\nhost=\"127.0.0.1\"\ntransport=\"local\"\nremote_binary=\"/tmp/macluster\"\nmachine_uuid=\"962f7a62-961f-5dd2-aa71-c978863036bd\"\nexecution_uid={}\n",
                root.display(),
                execution_uid
            ),
        )
        .unwrap();
        Self(root)
    }

    fn root(&self) -> &Path {
        &self.0
    }

    fn binding(&self) -> ServiceBinding {
        ServiceBinding::load(&self.0.join("config.toml"), &self.0.join("state")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FakeLauncher {
    loaded: AtomicBool,
    ready: AtomicBool,
    bootstraps: AtomicUsize,
    kickstarts: AtomicUsize,
    bootouts: AtomicUsize,
    unload_delay_inspections: AtomicUsize,
    unload_pending: AtomicBool,
    wrong_hello: AtomicBool,
    stale_build: AtomicBool,
    lifecycle: Mutex<ControllerLifecycle>,
    inspect_error: Mutex<Option<String>>,
}

impl Default for FakeLauncher {
    fn default() -> Self {
        Self {
            loaded: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            bootstraps: AtomicUsize::new(0),
            kickstarts: AtomicUsize::new(0),
            bootouts: AtomicUsize::new(0),
            unload_delay_inspections: AtomicUsize::new(0),
            unload_pending: AtomicBool::new(false),
            wrong_hello: AtomicBool::new(false),
            stale_build: AtomicBool::new(false),
            lifecycle: Mutex::new(ControllerLifecycle::Ready),
            inspect_error: Mutex::new(None),
        }
    }
}

impl FakeLauncher {
    fn active() -> Self {
        Self {
            loaded: AtomicBool::new(true),
            ready: AtomicBool::new(true),
            lifecycle: Mutex::new(ControllerLifecycle::Ready),
            ..Self::default()
        }
    }

    fn hello_for(&self, binding: &ServiceBinding) -> ControllerHello {
        ControllerHello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            binding_digest: if self.wrong_hello.load(Ordering::SeqCst) {
                "wrong-binding".into()
            } else {
                binding.binding_digest().to_owned()
            },
            namespace: binding.namespace().to_owned(),
            uid: binding.uid(),
            build_id: if self.stale_build.load(Ordering::SeqCst) {
                "previous-build".into()
            } else {
                sha256_hex(b"fake executable").unwrap()
            },
            capabilities: vec!["status.v1".into()],
            controller_epoch: ControllerEpoch {
                controller_uuid: ControllerUuid(Id128::random()),
                epoch: 1,
            },
            config_generation: 0,
            lifecycle: *self.lifecycle.lock().unwrap(),
        }
    }
}

impl ServiceLauncher for FakeLauncher {
    fn inspect(&self, _label: &str) -> Result<LaunchState, String> {
        if let Some(error) = self.inspect_error.lock().unwrap().clone() {
            return Err(error);
        }
        if self.unload_pending.load(Ordering::SeqCst) {
            let remaining = self.unload_delay_inspections.fetch_sub(1, Ordering::SeqCst);
            if remaining <= 1 {
                self.unload_pending.store(false, Ordering::SeqCst);
                self.loaded.store(false, Ordering::SeqCst);
                self.ready.store(false, Ordering::SeqCst);
            }
        }
        Ok(if !self.loaded.load(Ordering::SeqCst) {
            LaunchState::NotLoaded
        } else if self.ready.load(Ordering::SeqCst) {
            LaunchState::Running
        } else {
            LaunchState::Loaded
        })
    }

    fn bootstrap(&self, _label: &str, _plist: &Path) -> Result<(), String> {
        if self.loaded.load(Ordering::SeqCst) {
            return Err("LaunchAgent is still loaded after bootout".into());
        }
        self.bootstraps.fetch_add(1, Ordering::SeqCst);
        self.loaded.store(true, Ordering::SeqCst);
        self.ready.store(true, Ordering::SeqCst);
        self.stale_build.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn kickstart(&self, _label: &str) -> Result<(), String> {
        self.kickstarts.fetch_add(1, Ordering::SeqCst);
        self.loaded.store(true, Ordering::SeqCst);
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn bootout(&self, _label: &str) -> Result<(), String> {
        self.bootouts.fetch_add(1, Ordering::SeqCst);
        if self.unload_delay_inspections.load(Ordering::SeqCst) == 0 {
            self.loaded.store(false, Ordering::SeqCst);
            self.ready.store(false, Ordering::SeqCst);
        } else {
            self.unload_pending.store(true, Ordering::SeqCst);
        }
        Ok(())
    }

    fn controller_hello(
        &self,
        binding: &ServiceBinding,
        _timeout: Duration,
    ) -> Result<Option<ControllerHello>, HelloProbeError> {
        Ok(self
            .ready
            .load(Ordering::SeqCst)
            .then(|| self.hello_for(binding)))
    }
}

#[test]
fn missing_gui_session_is_reported_as_an_offline_service_condition() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    *launcher.inspect_error.lock().unwrap() =
        Some("launchctl: no active GUI session for uid 501".into());
    let service = manager(&fixture, Arc::clone(&launcher), source);

    let error = service
        .ensure_running(Duration::from_millis(100))
        .unwrap_err();

    assert!(matches!(error, ServiceLifecycleError::NoGuiSession(_)));
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
}

fn manager(
    fixture: &Fixture,
    launcher: Arc<FakeLauncher>,
    source: PathBuf,
) -> ServiceManager<FakeLauncher> {
    ServiceManager::with_launcher(
        fixture.binding(),
        launcher,
        source,
        fixture.root().join("home"),
    )
}

#[test]
fn twenty_concurrent_ensures_start_only_one_controller() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let barrier = Arc::new(Barrier::new(20));
    let threads = (0..20)
        .map(|_| {
            let service = manager(&fixture, Arc::clone(&launcher), source.clone());
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                service.ensure_running(Duration::from_secs(2)).unwrap()
            })
        })
        .collect::<Vec<_>>();

    for thread in threads {
        assert_eq!(thread.join().unwrap().lifecycle, ControllerLifecycle::Ready);
    }
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 1);
}

#[test]
fn installed_version_survives_moving_the_source_binary() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let service = manager(&fixture, Arc::clone(&launcher), source.clone());

    service.ensure_running(Duration::from_secs(2)).unwrap();
    let installed = service.installed_binary_path().unwrap();
    assert!(installed.is_file());
    fs::remove_file(source).unwrap();
    let restarted_service = manager(
        &fixture,
        Arc::new(FakeLauncher::default()),
        fixture.root().join("macluster-source"),
    );
    assert_eq!(
        restarted_service
            .ensure_running(Duration::from_secs(2))
            .unwrap()
            .namespace,
        fixture.binding().namespace()
    );
    assert!(installed.is_file());
}

#[test]
fn restart_waits_for_launchd_to_finish_bootout_before_bootstrap() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::active());
    launcher.unload_delay_inspections.store(2, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);

    let hello = service.restart(Duration::from_secs(2)).unwrap();

    assert_eq!(hello.lifecycle, ControllerLifecycle::Ready);
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 1);
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 1);
}

#[test]
fn an_authenticated_hello_with_wrong_binding_is_never_ready() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    launcher.wrong_hello.store(true, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);

    let error = service.ensure_running(Duration::from_secs(2)).unwrap_err();
    assert!(error.to_string().contains("binding"));
}

#[test]
fn stopped_or_resetting_intent_prevents_automatic_start() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::active());
    let service = manager(&fixture, Arc::clone(&launcher), source);

    service.stop().unwrap();
    assert_eq!(service.intent().unwrap(), ServiceIntent::Stopped);
    assert!(service.ensure_running(Duration::from_millis(100)).is_err());
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 1);

    service.set_intent(ServiceIntent::Resetting).unwrap();
    assert!(service.ensure_running(Duration::from_millis(100)).is_err());
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
}

#[test]
fn recovery_pending_controller_is_healthy_but_remains_paused() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::active());
    *launcher.lifecycle.lock().unwrap() = ControllerLifecycle::RecoveryPending;
    let service = manager(&fixture, launcher, source);

    assert_eq!(
        service
            .ensure_running(Duration::from_secs(1))
            .unwrap()
            .lifecycle,
        ControllerLifecycle::RecoveryPending
    );
}

#[test]
fn a_foreground_controller_is_reused_without_launchctl_start() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::active());
    launcher.loaded.store(false, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);

    service.ensure_running(Duration::from_secs(1)).unwrap();
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
    assert_eq!(launcher.kickstarts.load(Ordering::SeqCst), 0);
}

#[test]
fn a_loaded_but_crashed_service_is_kickstarted_for_recovery() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    launcher.loaded.store(true, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);

    service.ensure_running(Duration::from_secs(1)).unwrap();
    assert_eq!(launcher.kickstarts.load(Ordering::SeqCst), 1);
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
}

#[test]
fn inspect_never_starts_an_unloaded_controller() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let service = manager(&fixture, Arc::clone(&launcher), source);

    let state = service.inspect(Duration::from_millis(100)).unwrap();
    assert!(!state.loaded);
    assert!(state.hello.is_none());
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
}

#[test]
fn generated_launch_agent_uses_the_stable_binary_and_binding() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let service = manager(&fixture, launcher, source);

    service.ensure_running(Duration::from_secs(2)).unwrap();
    let plist = fs::read_to_string(service.plist_path()).unwrap();
    assert!(plist.contains(&service.label()));
    assert!(plist.contains(service.binding().binding_digest()));
    assert!(
        plist.contains(
            &service
                .installed_binary_path()
                .unwrap()
                .display()
                .to_string()
        )
    );
    assert!(plist.contains("controller-service"));
    assert!(plist.contains("<key>SuccessfulExit</key><false/>"));
}

#[test]
fn a_foreign_plist_for_the_same_namespace_is_preserved() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let service = manager(&fixture, Arc::clone(&launcher), source);
    let plist_path = service.plist_path();
    fs::create_dir_all(plist_path.parent().unwrap()).unwrap();
    fs::write(&plist_path, "foreign plist").unwrap();

    assert!(service.ensure_running(Duration::from_secs(2)).is_err());
    assert_eq!(fs::read_to_string(plist_path).unwrap(), "foreign plist");
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
}

#[test]
fn stop_refuses_to_claim_a_foreground_controller_was_stopped() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::active());
    launcher.loaded.store(false, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);

    assert!(
        service
            .stop()
            .unwrap_err()
            .to_string()
            .contains("foreground")
    );
    assert_eq!(service.intent().unwrap(), ServiceIntent::Auto);
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 0);
}

#[test]
fn reset_intent_unloads_and_removes_only_its_managed_launch_agent() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let service = manager(&fixture, Arc::clone(&launcher), source);
    service.ensure_running(Duration::from_secs(2)).unwrap();
    assert!(service.plist_path().exists());

    service.begin_reset().unwrap();

    assert_eq!(service.intent().unwrap(), ServiceIntent::Resetting);
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 1);
    assert!(!service.plist_path().exists());
    assert!(service.ensure_running(Duration::from_millis(100)).is_err());
}

#[test]
fn an_idle_controller_with_an_old_binary_is_replaced_by_the_current_build() {
    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::active());
    launcher.stale_build.store(true, Ordering::SeqCst);
    launcher.unload_delay_inspections.store(2, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);

    let hello = service.ensure_running(Duration::from_secs(2)).unwrap();

    assert_eq!(hello.build_id, sha256_hex(b"fake executable").unwrap());
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 1);
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 1);
}

#[test]
fn a_build_update_waits_for_active_jobs_and_does_not_stop_the_old_controller() {
    use macluster_core::storage::Storage;

    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let storage = Storage::open(fixture.root().join("state")).unwrap();
    let snapshot = storage.stage_snapshot(b"true\n").unwrap();
    let job = storage
        .submit_once(
            RequestId::random(),
            JobSpec {
                storage_namespace: None,
                queue: QueueName::new("q").unwrap(),
                node: None,
                name: "active".into(),
                cwd: fixture.root().display().to_string(),
                stdout_path: String::new(),
                stderr_path: String::new(),
                walltime_secs: None,
                env: Default::default(),
                mode: JobMode::Batch,
                snapshot: Some(snapshot),
            },
        )
        .unwrap();
    storage
        .reserve_job(job.id, NodeId::new("worker-a").unwrap())
        .unwrap();
    storage.mark_running(job.id).unwrap();
    drop(storage);

    let launcher = Arc::new(FakeLauncher::active());
    launcher.stale_build.store(true, Ordering::SeqCst);
    let service = manager(&fixture, Arc::clone(&launcher), source);
    let error = service.ensure_running(Duration::from_secs(1)).unwrap_err();

    assert!(error.to_string().contains("1 jobs are active"));
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 0);
    assert_eq!(launcher.bootstraps.load(Ordering::SeqCst), 0);
}

#[test]
fn a_stopped_same_build_controller_restarts_to_reconcile_active_jobs() {
    use macluster_core::storage::Storage;

    let fixture = Fixture::new();
    let source = fixture.root().join("macluster-source");
    fs::write(&source, b"fake executable").unwrap();
    let launcher = Arc::new(FakeLauncher::default());
    let service = manager(&fixture, Arc::clone(&launcher), source);
    service.ensure_running(Duration::from_secs(2)).unwrap();

    let storage = Storage::open(fixture.root().join("state")).unwrap();
    let snapshot = storage.stage_snapshot(b"true\n").unwrap();
    let job = storage
        .submit_once(
            RequestId::random(),
            JobSpec {
                storage_namespace: None,
                queue: QueueName::new("q").unwrap(),
                node: None,
                name: "active".into(),
                cwd: fixture.root().display().to_string(),
                stdout_path: String::new(),
                stderr_path: String::new(),
                walltime_secs: None,
                env: Default::default(),
                mode: JobMode::Batch,
                snapshot: Some(snapshot),
            },
        )
        .unwrap();
    storage
        .reserve_job(job.id, NodeId::new("worker-a").unwrap())
        .unwrap();
    storage.mark_running(job.id).unwrap();
    drop(storage);
    launcher.loaded.store(true, Ordering::SeqCst);
    launcher.ready.store(false, Ordering::SeqCst);

    let hello = service.ensure_running(Duration::from_secs(2)).unwrap();

    assert_eq!(hello.build_id, sha256_hex(b"fake executable").unwrap());
    assert_eq!(launcher.kickstarts.load(Ordering::SeqCst), 1);
    assert_eq!(launcher.bootouts.load(Ordering::SeqCst), 0);
}
