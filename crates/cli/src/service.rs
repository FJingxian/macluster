//! User-session LaunchAgent lifecycle and its stable, versioned executable.

use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use macluster_core::{
    service::{ServiceBinding, ServiceError, ServiceIntent, ServiceIntentStore},
    storage::ReadOnlyJobStore,
};
use macluster_protocol::{
    control::{CONTROL_PROTOCOL_VERSION, ControllerHello},
    framing::sha256_hex,
    identifiers::Id128,
};
use thiserror::Error;

use crate::control_client::{ControlClient, ControlClientError};

const MAX_READY_WAIT: Duration = Duration::from_secs(5);
const START_LOCK_POLL: Duration = Duration::from_millis(10);
const UNLOAD_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchState {
    Loaded,
    Running,
    NotLoaded,
}

#[derive(Debug)]
pub enum HelloProbeError {
    Unavailable(String),
    WrongIdentity(String),
}

/// Launchd operations are isolated behind this trait for deterministic tests.
pub trait ServiceLauncher: Send + Sync + 'static {
    fn inspect(&self, label: &str) -> Result<LaunchState, String>;
    fn bootstrap(&self, label: &str, plist: &Path) -> Result<(), String>;
    fn kickstart(&self, label: &str) -> Result<(), String>;
    fn bootout(&self, label: &str) -> Result<(), String>;
    fn controller_hello(
        &self,
        binding: &ServiceBinding,
        timeout: Duration,
    ) -> Result<Option<ControllerHello>, HelloProbeError>;
}

#[derive(Debug, Error)]
pub enum ServiceLifecycleError {
    #[error("controller service binding failed: {0}")]
    Binding(#[from] ServiceError),
    #[error("cannot access controller service path {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error(
        "controller service is manually stopped; run `macluster controller start` to enable it"
    )]
    ManuallyStopped,
    #[error("controller service is resetting; finish `macluster init` before starting it")]
    Resetting,
    #[error(
        "controller is running in the foreground; stop it with Ctrl-C before using the LaunchAgent command"
    )]
    ForegroundController,
    #[error("cannot manage a LaunchAgent without the user's active macOS GUI login session: {0}")]
    NoGuiSession(String),
    #[error("launchd operation failed: {0}")]
    Launchd(String),
    #[error("another controller startup is still in progress")]
    StartupLockTimeout,
    #[error("controller did not become ready within {0:?}")]
    ReadyTimeout(Duration),
    #[error("controller LaunchAgent did not unload within {0:?}")]
    UnloadTimeout(Duration),
    #[error("controller hello belongs to a different service binding: {0}")]
    WrongHello(String),
    #[error(
        "controller build {running} differs from this binary {current}, and {active_jobs} jobs are active; let them finish, then retry"
    )]
    ActiveJobsPreventUpdate {
        running: String,
        current: String,
        active_jobs: usize,
    },
    #[error(
        "controller could not be verified while {active_jobs} jobs are active; it was left untouched"
    )]
    ControllerUnavailableWithActiveJobs { active_jobs: usize },
    #[error("cannot verify active controller jobs before replacing its binary: {0}")]
    CannotVerifyActiveJobs(String),
    #[error("controller restart is blocked while {0} jobs are active")]
    ActiveJobsPreventRestart(usize),
    #[error("service label {label} already has a plist for a different binding at {path}")]
    BindingConflict { label: String, path: PathBuf },
    #[error("cannot resolve executable {path}: {source}")]
    ExecutablePath { path: PathBuf, source: io::Error },
    #[error("controller executable {0} is not a regular file")]
    InvalidExecutable(PathBuf),
    #[error("controller service has no installed binary and its source executable is missing")]
    NoBinary,
    #[error("controller service binary digest is invalid at {0}")]
    InvalidDigest(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceInspection {
    pub intent: ServiceIntent,
    pub loaded: bool,
    pub hello: Option<ControllerHello>,
}

pub struct ServiceManager<L: ServiceLauncher> {
    binding: ServiceBinding,
    launcher: Arc<L>,
    source_executable: PathBuf,
    home: PathBuf,
}

impl<L: ServiceLauncher> Clone for ServiceManager<L> {
    fn clone(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            launcher: Arc::clone(&self.launcher),
            source_executable: self.source_executable.clone(),
            home: self.home.clone(),
        }
    }
}

impl ServiceManager<LaunchdServiceLauncher> {
    pub fn current(binding: ServiceBinding) -> Result<Self, ServiceLifecycleError> {
        let source_executable =
            env::current_exe().map_err(|source| ServiceLifecycleError::ExecutablePath {
                path: PathBuf::from("current_exe"),
                source,
            })?;
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| ServiceLifecycleError::Launchd("HOME is not set".into()))?;
        Ok(Self::with_launcher(
            binding,
            Arc::new(LaunchdServiceLauncher::new(home.clone(), unsafe {
                libc::geteuid()
            })),
            source_executable,
            home,
        ))
    }
}

impl<L: ServiceLauncher> ServiceManager<L> {
    pub fn with_launcher(
        binding: ServiceBinding,
        launcher: Arc<L>,
        source_executable: PathBuf,
        home: PathBuf,
    ) -> Self {
        Self {
            binding,
            launcher,
            source_executable,
            home,
        }
    }

    pub fn binding(&self) -> &ServiceBinding {
        &self.binding
    }

    pub fn label(&self) -> String {
        format!("org.macluster.controller.{}", self.binding.namespace())
    }

    pub fn intent(&self) -> Result<ServiceIntent, ServiceLifecycleError> {
        Ok(ServiceIntentStore::open(&self.binding)?.read()?)
    }

    pub fn set_intent(&self, intent: ServiceIntent) -> Result<(), ServiceLifecycleError> {
        ServiceIntentStore::open(&self.binding)?.write(intent)?;
        Ok(())
    }

    pub fn service_dir(&self) -> PathBuf {
        self.binding.state_dir().join("service")
    }

    pub fn installed_binary_path(&self) -> Result<PathBuf, ServiceLifecycleError> {
        let digest = self.resolve_digest()?;
        Ok(self
            .service_dir()
            .join("versions")
            .join(digest)
            .join("macluster"))
    }

    pub fn plist_path(&self) -> PathBuf {
        self.home
            .join("Library/LaunchAgents")
            .join(format!("{}.plist", self.label()))
    }

    pub fn ensure_running(
        &self,
        timeout: Duration,
    ) -> Result<ControllerHello, ServiceLifecycleError> {
        let timeout = timeout.min(MAX_READY_WAIT);
        let deadline = Instant::now() + timeout;
        let intent = self.intent()?;
        ensure_auto(intent)?;
        let _start_lock =
            ServiceStartLock::acquire(&self.service_dir(), self.binding.uid(), deadline)?;
        let intent = self.intent()?;
        ensure_auto(intent)?;
        self.ensure_running_locked(deadline, timeout)
    }

    pub fn start(&self, timeout: Duration) -> Result<ControllerHello, ServiceLifecycleError> {
        let timeout = timeout.min(MAX_READY_WAIT);
        let deadline = Instant::now() + timeout;
        let _start_lock =
            ServiceStartLock::acquire(&self.service_dir(), self.binding.uid(), deadline)?;
        self.set_intent(ServiceIntent::Auto)?;
        self.ensure_running_locked(deadline, timeout)
    }

    pub fn stop(&self) -> Result<(), ServiceLifecycleError> {
        let deadline = Instant::now() + MAX_READY_WAIT;
        let _start_lock =
            ServiceStartLock::acquire(&self.service_dir(), self.binding.uid(), deadline)?;
        let launch_state = self
            .launcher
            .inspect(&self.label())
            .map_err(map_launchd_error)?;
        let loaded = launch_state != LaunchState::NotLoaded;
        if !loaded && self.probe_once(Duration::from_millis(100))?.is_some() {
            return Err(ServiceLifecycleError::ForegroundController);
        }
        self.set_intent(ServiceIntent::Stopped)?;
        if loaded {
            self.bootout_and_wait(Instant::now() + MAX_READY_WAIT, MAX_READY_WAIT)?;
        }
        Ok(())
    }

    pub fn begin_reset(&self) -> Result<(), ServiceLifecycleError> {
        let deadline = Instant::now() + MAX_READY_WAIT;
        let _start_lock =
            ServiceStartLock::acquire(&self.service_dir(), self.binding.uid(), deadline)?;
        let launch_state = match self.launcher.inspect(&self.label()) {
            Ok(state) => state,
            Err(error) => match map_launchd_error(error) {
                ServiceLifecycleError::NoGuiSession(_) => LaunchState::NotLoaded,
                error => return Err(error),
            },
        };
        let loaded = launch_state != LaunchState::NotLoaded;
        if !loaded && self.probe_once(Duration::from_millis(100))?.is_some() {
            return Err(ServiceLifecycleError::ForegroundController);
        }
        let plist = self.plist_path();
        let plist_exists = match fs::symlink_metadata(&plist) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == self.binding.uid()
                    && metadata.permissions().mode() & 0o777 == 0o600 =>
            {
                let contents =
                    fs::read_to_string(&plist).map_err(|source| ServiceLifecycleError::Io {
                        path: plist.clone(),
                        source,
                    })?;
                if !contents.contains(&format!(
                    "<string>{}</string>",
                    self.binding.binding_digest()
                )) {
                    return Err(ServiceLifecycleError::BindingConflict {
                        label: self.label(),
                        path: plist,
                    });
                }
                true
            }
            Ok(_) => {
                return Err(ServiceLifecycleError::BindingConflict {
                    label: self.label(),
                    path: plist,
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(ServiceLifecycleError::Io {
                    path: plist,
                    source,
                });
            }
        };
        self.set_intent(ServiceIntent::Resetting)?;
        if loaded {
            self.bootout_and_wait(Instant::now() + MAX_READY_WAIT, MAX_READY_WAIT)?;
        }
        if plist_exists {
            fs::remove_file(&plist).map_err(|source| ServiceLifecycleError::Io {
                path: plist.clone(),
                source,
            })?;
            if let Some(parent) = plist.parent() {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|source| ServiceLifecycleError::Io {
                        path: parent.to_path_buf(),
                        source,
                    })?;
            }
        }
        Ok(())
    }

    pub fn restart(&self, timeout: Duration) -> Result<ControllerHello, ServiceLifecycleError> {
        let timeout = timeout.min(MAX_READY_WAIT);
        let deadline = Instant::now() + timeout;
        let _start_lock =
            ServiceStartLock::acquire(&self.service_dir(), self.binding.uid(), deadline)?;
        let launch_state = self
            .launcher
            .inspect(&self.label())
            .map_err(map_launchd_error)?;
        let loaded = launch_state != LaunchState::NotLoaded;
        if !loaded && self.probe_once(Duration::from_millis(100))?.is_some() {
            return Err(ServiceLifecycleError::ForegroundController);
        }
        if loaded {
            let active_jobs = self.active_job_count()?;
            if active_jobs > 0 {
                return Err(ServiceLifecycleError::ActiveJobsPreventRestart(active_jobs));
            }
        }
        self.set_intent(ServiceIntent::Auto)?;
        let expected_build = self.resolve_digest()?;
        self.install_stable_binary()?;
        let plist = self.install_plist()?;
        if loaded {
            self.bootout_and_wait(deadline, timeout)?;
        }
        self.launcher
            .bootstrap(&self.label(), &plist)
            .map_err(map_launchd_error)?;
        self.wait_for_hello(deadline, timeout, &expected_build)
    }

    pub fn inspect(&self, timeout: Duration) -> Result<ServiceInspection, ServiceLifecycleError> {
        let intent = self.intent()?;
        let launch_state = self
            .launcher
            .inspect(&self.label())
            .map_err(map_launchd_error)?;
        let loaded = launch_state != LaunchState::NotLoaded;
        let hello = if loaded {
            match self
                .launcher
                .controller_hello(&self.binding, timeout.min(MAX_READY_WAIT))
            {
                Ok(hello) => hello,
                Err(HelloProbeError::Unavailable(_)) => None,
                Err(error @ HelloProbeError::WrongIdentity(_)) => {
                    return Err(map_probe_error(error));
                }
            }
        } else {
            None
        };
        if let Some(hello) = &hello {
            validate_hello(&self.binding, hello)?;
        }
        Ok(ServiceInspection {
            intent,
            loaded,
            hello,
        })
    }

    fn ensure_running_locked(
        &self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<ControllerHello, ServiceLifecycleError> {
        let expected_build = self.resolve_digest()?;
        if let Some(hello) = self.probe_once(Duration::from_millis(100))? {
            if hello.build_id == expected_build {
                return Ok(hello);
            }
            let launch_state = self
                .launcher
                .inspect(&self.label())
                .map_err(map_launchd_error)?;
            let loaded = launch_state != LaunchState::NotLoaded;
            if !loaded {
                return Err(ServiceLifecycleError::ForegroundController);
            }
            let active_jobs = self.active_job_count()?;
            if active_jobs > 0 {
                return Err(ServiceLifecycleError::ActiveJobsPreventUpdate {
                    running: hello.build_id,
                    current: expected_build,
                    active_jobs,
                });
            }
            self.install_stable_binary()?;
            let plist = self.install_plist()?;
            self.bootout_and_wait(deadline, timeout)?;
            self.launcher
                .bootstrap(&self.label(), &plist)
                .map_err(map_launchd_error)?;
            return self.wait_for_hello(deadline, timeout, &expected_build);
        }
        let launch_state = self
            .launcher
            .inspect(&self.label())
            .map_err(map_launchd_error)?;
        let loaded = launch_state != LaunchState::NotLoaded;
        if loaded {
            let active_jobs = self.active_job_count()?;
            if active_jobs > 0 {
                if launch_state == LaunchState::Running {
                    return self.wait_for_existing_hello(deadline, &expected_build, active_jobs);
                }
                if self.plist_targets_build(&expected_build)? {
                    self.launcher
                        .kickstart(&self.label())
                        .map_err(map_launchd_error)?;
                    return self.wait_for_hello(deadline, timeout, &expected_build);
                }
                return self.wait_for_existing_hello(deadline, &expected_build, active_jobs);
            }
        }
        self.install_stable_binary()?;
        let plist = self.install_plist()?;
        match launch_state {
            LaunchState::Running | LaunchState::Loaded => self
                .launcher
                .kickstart(&self.label())
                .map_err(map_launchd_error)?,
            LaunchState::NotLoaded => self
                .launcher
                .bootstrap(&self.label(), &plist)
                .map_err(map_launchd_error)?,
        }
        self.wait_for_hello(deadline, timeout, &expected_build)
    }

    fn bootout_and_wait(
        &self,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), ServiceLifecycleError> {
        self.launcher
            .bootout(&self.label())
            .map_err(map_launchd_error)?;
        loop {
            if self
                .launcher
                .inspect(&self.label())
                .map_err(map_launchd_error)?
                == LaunchState::NotLoaded
            {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ServiceLifecycleError::UnloadTimeout(timeout));
            }
            thread::sleep(remaining.min(UNLOAD_POLL_INTERVAL));
        }
    }

    fn wait_for_hello(
        &self,
        deadline: Instant,
        timeout: Duration,
        expected_build: &str,
    ) -> Result<ControllerHello, ServiceLifecycleError> {
        loop {
            if Instant::now() >= deadline {
                return Err(ServiceLifecycleError::ReadyTimeout(timeout));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(hello) = self.probe_once(remaining.min(Duration::from_millis(200)))? {
                if hello.build_id != expected_build {
                    return Err(ServiceLifecycleError::WrongHello(format!(
                        "controller build {} did not match the installed build {expected_build}",
                        hello.build_id
                    )));
                }
                return Ok(hello);
            }
            thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }

    fn probe_once(
        &self,
        timeout: Duration,
    ) -> Result<Option<ControllerHello>, ServiceLifecycleError> {
        match self.launcher.controller_hello(&self.binding, timeout) {
            Ok(Some(hello)) => {
                validate_hello(&self.binding, &hello)?;
                Ok(Some(hello))
            }
            Ok(None) | Err(HelloProbeError::Unavailable(_)) => Ok(None),
            Err(error @ HelloProbeError::WrongIdentity(_)) => Err(map_probe_error(error)),
        }
    }

    fn wait_for_existing_hello(
        &self,
        deadline: Instant,
        expected_build: &str,
        active_jobs: usize,
    ) -> Result<ControllerHello, ServiceLifecycleError> {
        loop {
            if Instant::now() >= deadline {
                return Err(ServiceLifecycleError::ControllerUnavailableWithActiveJobs {
                    active_jobs,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Some(hello) = self.probe_once(remaining.min(Duration::from_millis(200)))? {
                if hello.build_id != expected_build {
                    return Err(ServiceLifecycleError::ActiveJobsPreventUpdate {
                        running: hello.build_id,
                        current: expected_build.to_owned(),
                        active_jobs,
                    });
                }
                return Ok(hello);
            }
            thread::sleep(remaining.min(Duration::from_millis(25)));
        }
    }

    fn active_job_count(&self) -> Result<usize, ServiceLifecycleError> {
        let database = self.binding.state_dir().join("controller.sqlite3");
        match fs::symlink_metadata(&database) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(error) => {
                return Err(ServiceLifecycleError::CannotVerifyActiveJobs(
                    error.to_string(),
                ));
            }
            Ok(metadata)
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != self.binding.uid() =>
            {
                return Err(ServiceLifecycleError::CannotVerifyActiveJobs(
                    "controller database is not a regular file owned by this user".into(),
                ));
            }
            Ok(_) => {}
        }
        let storage = ReadOnlyJobStore::open(self.binding.state_dir())
            .map_err(|error| ServiceLifecycleError::CannotVerifyActiveJobs(error.to_string()))?;
        let jobs = storage
            .list_jobs(None)
            .map_err(|error| ServiceLifecycleError::CannotVerifyActiveJobs(error.to_string()))?;
        Ok(jobs
            .iter()
            .filter(|job| {
                matches!(
                    job.state,
                    macluster_protocol::types::JobState::Starting
                        | macluster_protocol::types::JobState::Running
                        | macluster_protocol::types::JobState::Cancelling
                )
            })
            .count())
    }

    fn plist_targets_build(&self, digest: &str) -> Result<bool, ServiceLifecycleError> {
        let path = self.plist_path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(ServiceLifecycleError::Io { path, source });
            }
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != self.binding.uid()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ServiceLifecycleError::BindingConflict {
                label: self.label(),
                path,
            });
        }
        let contents = fs::read_to_string(&path).map_err(|source| ServiceLifecycleError::Io {
            path: path.clone(),
            source,
        })?;
        if !contents.contains(&format!(
            "<string>{}</string>",
            self.binding.binding_digest()
        )) {
            return Err(ServiceLifecycleError::BindingConflict {
                label: self.label(),
                path,
            });
        }
        let binary = self
            .service_dir()
            .join("versions")
            .join(digest)
            .join("macluster");
        Ok(contents.contains(&format!(
            "<string>{}</string>",
            xml_escape(&binary.to_string_lossy())
        )))
    }

    fn resolve_digest(&self) -> Result<String, ServiceLifecycleError> {
        if let Ok(source) = self.source_executable.canonicalize() {
            let metadata =
                fs::metadata(&source).map_err(|source| ServiceLifecycleError::ExecutablePath {
                    path: self.source_executable.clone(),
                    source,
                })?;
            if metadata.is_file() {
                return cached_file_digest(&source);
            }
        }
        let manifest = self.service_dir().join("active-version");
        let text = fs::read_to_string(&manifest).map_err(|_| ServiceLifecycleError::NoBinary)?;
        let digest = text.trim();
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ServiceLifecycleError::InvalidDigest(manifest));
        }
        Ok(digest.to_owned())
    }

    fn install_stable_binary(&self) -> Result<PathBuf, ServiceLifecycleError> {
        let digest = self.resolve_digest()?;
        let service_dir = self.service_dir();
        ensure_private_directory(&service_dir, self.binding.uid())?;
        let versions_dir = service_dir.join("versions");
        ensure_private_directory(&versions_dir, self.binding.uid())?;
        let version_dir = versions_dir.join(&digest);
        ensure_private_directory(&version_dir, self.binding.uid())?;
        let destination = version_dir.join("macluster");
        if !destination.exists() {
            let source = self.canonical_source()?;
            let bytes =
                fs::read(&source).map_err(|error| ServiceLifecycleError::ExecutablePath {
                    path: source.clone(),
                    source: error,
                })?;
            let actual = sha256_hex(&bytes).map_err(|error| {
                ServiceLifecycleError::Launchd(format!(
                    "cannot hash controller executable: {error}"
                ))
            })?;
            if actual != digest {
                return Err(ServiceLifecycleError::InvalidDigest(source));
            }
            let temporary = version_dir.join(format!(".macluster-{}.tmp", Id128::random()));
            let result = (|| {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o700)
                    .open(&temporary)
                    .map_err(|source| ServiceLifecycleError::Io {
                        path: temporary.clone(),
                        source,
                    })?;
                use std::io::Write;
                file.write_all(&bytes)
                    .map_err(|source| ServiceLifecycleError::Io {
                        path: temporary.clone(),
                        source,
                    })?;
                file.sync_all()
                    .map_err(|source| ServiceLifecycleError::Io {
                        path: temporary.clone(),
                        source,
                    })?;
                fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(
                    |source| ServiceLifecycleError::Io {
                        path: temporary.clone(),
                        source,
                    },
                )?;
                let staged = fs::read(&temporary).map_err(|source| ServiceLifecycleError::Io {
                    path: temporary.clone(),
                    source,
                })?;
                if sha256_hex(&staged).map_err(|error| {
                    ServiceLifecycleError::Launchd(format!(
                        "cannot verify staged executable: {error}"
                    ))
                })? != digest
                {
                    return Err(ServiceLifecycleError::InvalidDigest(temporary.clone()));
                }
                fs::rename(&temporary, &destination).map_err(|source| {
                    ServiceLifecycleError::Io {
                        path: destination.clone(),
                        source,
                    }
                })?;
                File::open(&version_dir)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|source| ServiceLifecycleError::Io {
                        path: version_dir.clone(),
                        source,
                    })?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary);
            }
            result?;
        }
        validate_installed_binary(&destination, self.binding.uid())?;
        atomic_write_private(
            &service_dir.join("active-version"),
            digest.as_bytes(),
            self.binding.uid(),
        )?;
        Ok(destination)
    }

    fn canonical_source(&self) -> Result<PathBuf, ServiceLifecycleError> {
        let source = self.source_executable.canonicalize().map_err(|source| {
            ServiceLifecycleError::ExecutablePath {
                path: self.source_executable.clone(),
                source,
            }
        })?;
        let metadata = fs::symlink_metadata(&source).map_err(|error| {
            ServiceLifecycleError::ExecutablePath {
                path: source.clone(),
                source: error,
            }
        })?;
        if !metadata.is_file() {
            return Err(ServiceLifecycleError::InvalidExecutable(source));
        }
        Ok(source)
    }

    fn install_plist(&self) -> Result<PathBuf, ServiceLifecycleError> {
        let binary = self.install_stable_binary()?;
        let path = self.plist_path();
        let label = self.label();
        let binding = self.binding.binding_digest();
        if fs::symlink_metadata(&path).is_ok() {
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| ServiceLifecycleError::Io {
                    path: path.clone(),
                    source,
                })?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != self.binding.uid()
                || metadata.permissions().mode() & 0o777 != 0o600
            {
                return Err(ServiceLifecycleError::BindingConflict { label, path });
            }
            let existing =
                fs::read_to_string(&path).map_err(|source| ServiceLifecycleError::Io {
                    path: path.clone(),
                    source,
                })?;
            if !existing.contains(&format!("<string>{binding}</string>")) {
                return Err(ServiceLifecycleError::BindingConflict { label, path });
            }
        }
        let launch_agents = path.parent().expect("LaunchAgent plist has parent");
        fs::create_dir_all(launch_agents).map_err(|source| ServiceLifecycleError::Io {
            path: launch_agents.to_path_buf(),
            source,
        })?;
        let logs = self.home.join("Library/Logs/macluster");
        fs::create_dir_all(&logs).map_err(|source| ServiceLifecycleError::Io {
            path: logs.clone(),
            source,
        })?;
        let config = xml_escape(&self.binding.config_path().to_string_lossy());
        let state = xml_escape(&self.binding.state_dir().to_string_lossy());
        let binary = xml_escape(&binary.to_string_lossy());
        let stdout = xml_escape(&logs.join("controller.out.log").to_string_lossy());
        let stderr = xml_escape(&logs.join("controller.err.log").to_string_lossy());
        let label_xml = xml_escape(&label);
        let contents = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{label_xml}</string>\n  <key>ProgramArguments</key><array><string>{binary}</string><string>--config</string><string>{config}</string><string>--state-dir</string><string>{state}</string><string>internal</string><string>controller-service</string></array>\n  <key>EnvironmentVariables</key><dict><key>MACLUSTER_SERVICE_BINDING</key><string>{binding}</string></dict>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n  <key>ProcessType</key><string>Background</string>\n  <key>ThrottleInterval</key><integer>5</integer>\n  <key>StandardOutPath</key><string>{stdout}</string>\n  <key>StandardErrorPath</key><string>{stderr}</string>\n</dict>\n</plist>\n"
        );
        atomic_write_private(&path, contents.as_bytes(), self.binding.uid())?;
        Ok(path)
    }
}

fn ensure_auto(intent: ServiceIntent) -> Result<(), ServiceLifecycleError> {
    match intent {
        ServiceIntent::Auto => Ok(()),
        ServiceIntent::Stopped => Err(ServiceLifecycleError::ManuallyStopped),
        ServiceIntent::Resetting => Err(ServiceLifecycleError::Resetting),
    }
}

fn map_launchd_error(message: String) -> ServiceLifecycleError {
    if message.contains("no active GUI session") {
        ServiceLifecycleError::NoGuiSession(message)
    } else {
        ServiceLifecycleError::Launchd(message)
    }
}

fn validate_hello(
    binding: &ServiceBinding,
    hello: &ControllerHello,
) -> Result<(), ServiceLifecycleError> {
    if hello.protocol_version != CONTROL_PROTOCOL_VERSION
        || hello.binding_digest != binding.binding_digest()
        || hello.namespace != binding.namespace()
        || hello.uid != binding.uid()
        || hello.build_id.is_empty()
    {
        return Err(ServiceLifecycleError::WrongHello(
            "namespace, UID, protocol, build ID, or binding digest did not match".into(),
        ));
    }
    Ok(())
}

fn map_probe_error(error: HelloProbeError) -> ServiceLifecycleError {
    match error {
        HelloProbeError::Unavailable(message) => ServiceLifecycleError::Launchd(message),
        HelloProbeError::WrongIdentity(message) => ServiceLifecycleError::WrongHello(message),
    }
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

fn cached_file_digest(path: &Path) -> Result<String, ServiceLifecycleError> {
    static CACHE: OnceLock<Mutex<HashMap<FileIdentity, String>>> = OnceLock::new();
    let canonical =
        path.canonicalize()
            .map_err(|source| ServiceLifecycleError::ExecutablePath {
                path: path.to_path_buf(),
                source,
            })?;
    let metadata =
        fs::metadata(&canonical).map_err(|source| ServiceLifecycleError::ExecutablePath {
            path: canonical.clone(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(ServiceLifecycleError::InvalidExecutable(canonical));
    }
    let identity = FileIdentity {
        path: canonical.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
    };
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(digest) = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&identity)
    {
        return Ok(digest.clone());
    }
    let bytes = fs::read(&canonical).map_err(|source| ServiceLifecycleError::ExecutablePath {
        path: canonical.clone(),
        source,
    })?;
    let digest = sha256_hex(&bytes).map_err(|error| {
        ServiceLifecycleError::Launchd(format!("cannot hash controller executable: {error}"))
    })?;
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.retain(|key, _| key.path != canonical);
    cache.insert(identity, digest.clone());
    Ok(digest)
}

/// Returns the content hash used in controller handshakes for the running executable.
pub fn current_executable_build_id() -> Result<String, ServiceLifecycleError> {
    let executable =
        env::current_exe().map_err(|source| ServiceLifecycleError::ExecutablePath {
            path: PathBuf::from("current_exe"),
            source,
        })?;
    cached_file_digest(&executable)
}

fn ensure_private_directory(path: &Path, uid: u32) -> Result<(), ServiceLifecycleError> {
    match fs::create_dir_all(path) {
        Ok(()) => {}
        Err(source) => {
            return Err(ServiceLifecycleError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| ServiceLifecycleError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(ServiceLifecycleError::Binding(
            ServiceError::UnsafeServiceDirectory(path.to_path_buf(), uid),
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ServiceLifecycleError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    let verified = fs::symlink_metadata(path).map_err(|source| ServiceLifecycleError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !verified.is_dir()
        || verified.file_type().is_symlink()
        || verified.uid() != uid
        || verified.permissions().mode() & 0o777 != 0o700
    {
        return Err(ServiceLifecycleError::Binding(
            ServiceError::UnsafeServiceDirectory(path.to_path_buf(), uid),
        ));
    }
    Ok(())
}

fn validate_installed_binary(path: &Path, uid: u32) -> Result<(), ServiceLifecycleError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ServiceLifecycleError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(ServiceLifecycleError::InvalidExecutable(path.to_path_buf()));
    }
    Ok(())
}

fn atomic_write_private(path: &Path, bytes: &[u8], uid: u32) -> Result<(), ServiceLifecycleError> {
    let parent = path.parent().expect("private file has parent");
    if path.file_name().is_none() {
        return Err(ServiceLifecycleError::InvalidExecutable(path.to_path_buf()));
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        Id128::random()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|source| ServiceLifecycleError::Io {
                path: temporary.clone(),
                source,
            })?;
        use std::io::Write;
        file.write_all(bytes)
            .map_err(|source| ServiceLifecycleError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| ServiceLifecycleError::Io {
                path: temporary.clone(),
                source,
            })?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ServiceLifecycleError::Io {
                path: temporary.clone(),
                source,
            }
        })?;
        fs::rename(&temporary, path).map_err(|source| ServiceLifecycleError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ServiceLifecycleError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        let metadata = fs::symlink_metadata(path).map_err(|source| ServiceLifecycleError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ServiceLifecycleError::InvalidExecutable(path.to_path_buf()));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

struct ServiceStartLock(File);

impl ServiceStartLock {
    fn acquire(
        service_dir: &Path,
        uid: u32,
        deadline: Instant,
    ) -> Result<Self, ServiceLifecycleError> {
        ensure_private_directory(service_dir, uid)?;
        let path = service_dir.join("start.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|source| ServiceLifecycleError::Io {
                path: path.clone(),
                source,
            })?;
        let metadata = file
            .metadata()
            .map_err(|source| ServiceLifecycleError::Io {
                path: path.clone(),
                source,
            })?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(ServiceLifecycleError::InvalidExecutable(path));
        }
        loop {
            let result = unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&file),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            };
            if result == 0 {
                return Ok(Self(file));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::WouldBlock
                && error.raw_os_error() != Some(libc::EAGAIN)
            {
                return Err(ServiceLifecycleError::Io {
                    path,
                    source: error,
                });
            }
            if Instant::now() >= deadline {
                return Err(ServiceLifecycleError::StartupLockTimeout);
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(START_LOCK_POLL),
            );
        }
    }
}

impl Drop for ServiceStartLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN);
        }
    }
}

#[derive(Clone, Debug)]
pub struct LaunchdServiceLauncher {
    uid: u32,
}

impl LaunchdServiceLauncher {
    pub fn new(_home: PathBuf, uid: u32) -> Self {
        Self { uid }
    }

    fn target(&self, label: &str) -> String {
        format!("gui/{}/{}", self.uid, label)
    }

    fn command(&self, args: &[&str]) -> Result<(), String> {
        let output = Command::new("/bin/launchctl")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("cannot run launchctl: {error}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "launchctl {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    fn require_gui_session(&self) -> Result<(), String> {
        self.command(&["print", &format!("gui/{}", self.uid)])
            .map_err(|error| format!("no active GUI session for uid {}: {error}", self.uid))
    }
}

impl ServiceLauncher for LaunchdServiceLauncher {
    fn inspect(&self, label: &str) -> Result<LaunchState, String> {
        self.require_gui_session()?;
        let output = Command::new("/bin/launchctl")
            .args(["print", &self.target(label)])
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("cannot inspect launchd service: {error}"))?;
        if !output.status.success() {
            return Ok(LaunchState::NotLoaded);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(
            if stdout.lines().any(|line| line.trim() == "state = running") {
                LaunchState::Running
            } else {
                LaunchState::Loaded
            },
        )
    }

    fn bootstrap(&self, label: &str, plist: &Path) -> Result<(), String> {
        self.require_gui_session()?;
        let domain = format!("gui/{}", self.uid);
        self.command(&["bootstrap", &domain, &plist.to_string_lossy()])
            .map_err(|error| format!("cannot bootstrap {label}: {error}"))
    }

    fn kickstart(&self, label: &str) -> Result<(), String> {
        self.require_gui_session()?;
        self.command(&["kickstart", "-k", &self.target(label)])
    }

    fn bootout(&self, label: &str) -> Result<(), String> {
        self.require_gui_session()?;
        self.command(&["bootout", &self.target(label)])
    }

    fn controller_hello(
        &self,
        binding: &ServiceBinding,
        timeout: Duration,
    ) -> Result<Option<ControllerHello>, HelloProbeError> {
        match ControlClient::connect(binding, timeout) {
            Ok(client) => Ok(Some(client.hello().clone())),
            Err(ControlClientError::WrongCluster) => Err(HelloProbeError::WrongIdentity(
                "control socket answered for a different cluster binding".into(),
            )),
            Err(ControlClientError::Remote { code, message })
                if code == macluster_protocol::control::ControlErrorCode::WrongCluster
                    || code == macluster_protocol::control::ControlErrorCode::WrongPeer =>
            {
                Err(HelloProbeError::WrongIdentity(message))
            }
            Err(error) => Err(HelloProbeError::Unavailable(error.to_string())),
        }
    }
}
