//! Loopback-only, read-only browser monitor served by the controller.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    net::{SocketAddr, TcpListener},
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        net::UnixStream,
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path as AxumPath, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{
        Html, IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post, put},
};
use futures_util::stream;
use macluster_core::{
    config::ClusterConfig,
    service::{ServiceBinding, peer_uid},
};
use macluster_protocol::{
    control::{
        CONTROL_PROTOCOL_VERSION, ClientHello, ControlCommand, ControlErrorCode, ControlPayload,
        ControlRequest, ControlResponse, ControllerHello, HelloResponse, JobPage, MonitorSnapshot,
        QueueSummary,
    },
    framing::{read_frame, write_frame},
    identifiers::{Id128, NodeId, RequestId},
    types::{JobRecord, JobState, MetricSnapshot},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::TcpListener as TokioTcpListener,
    runtime::Builder as TokioRuntimeBuilder,
    sync::{Notify, oneshot, watch},
};

const TOKEN_TTL: Duration = Duration::from_secs(60);
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const VIEW_TTL: Duration = Duration::from_secs(60);
const MAX_ENTRY_TOKENS: usize = 8;
const MAX_SESSIONS: usize = 8;
const MAX_VIEWS: usize = 32;
const MAX_VIEWS_PER_SESSION: usize = 4;
const MAX_PROCESS_VIEWS: usize = 4;
const MAX_SSE_CONNECTIONS: usize = 16;
const MAX_WEB_NODES: usize = 128;
const HISTORY_SAMPLES: usize = 150;
const HISTORY_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_LOG_BYTES: usize = 64 * 1024;
const MAX_LOG_READS: usize = 4;
const LOG_READ_TIMEOUT: Duration = Duration::from_secs(4);
const IPC_TIMEOUT: Duration = Duration::from_secs(3);
const MONITOR_INTERVAL: Duration = Duration::from_secs(2);
const BACKGROUND_MONITOR_INTERVAL: Duration = Duration::from_secs(10);
const JOB_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const QUEUE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE_CSS: &str = include_str!("../web/style.css");

#[derive(Debug, Error)]
pub enum WebError {
    #[error("port {0} is already in use or cannot be bound on 127.0.0.1")]
    PortConflict(u16),
    #[error("a web monitor is already running on port {running}; requested port {requested}")]
    RunningPortConflict { running: u16, requested: u16 },
    #[error("web monitor startup failed: {0}")]
    Startup(String),
    #[error("web monitor token store is full; wait one minute and retry")]
    TokenStoreFull,
}

/// The runtime owns this value, so the listener and sessions disappear when
/// the controller process exits.
pub struct WebService {
    port: u16,
    state: Arc<WebState>,
    shutdown: Option<oneshot::Sender<()>>,
    shutdown_flag: Arc<AtomicBool>,
    shutdown_watch: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl WebService {
    pub fn bind_and_start(
        binding: ServiceBinding,
        config: ClusterConfig,
        requested_port: Option<u16>,
    ) -> Result<(Self, ControlPayload), WebError> {
        let listener = bind_loopback(requested_port)?;
        let port = listener
            .local_addr()
            .map_err(|error| WebError::Startup(error.to_string()))?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|error| WebError::Startup(error.to_string()))?;

        let (shutdown_watch, shutdown_receiver) = watch::channel(false);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let state = Arc::new(WebState {
            binding,
            config: RwLock::new(config),
            expected_host: format!("127.0.0.1:{port}"),
            expected_origin: format!("http://127.0.0.1:{port}"),
            auth: Mutex::new(AuthStore::default()),
            history: Mutex::new(HistoryStore::default()),
            next_event_id: AtomicU64::new(1),
            active_sse: AtomicUsize::new(0),
            active_http: AtomicUsize::new(0),
            log_read_slots: Arc::new(AtomicUsize::new(0)),
            shutdown_flag: Arc::clone(&shutdown_flag),
            shutdown_receiver,
        });
        let (server_shutdown, server_shutdown_receiver) = oneshot::channel();
        let (ready_sender, ready_receiver) = mpsc::sync_channel::<Result<(), String>>(1);
        let thread_state = Arc::clone(&state);
        let thread = thread::Builder::new()
            .name("macluster-web".into())
            .spawn(move || {
                let runtime = match TokioRuntimeBuilder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .thread_name("macluster-web-io")
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match TokioTcpListener::from_std(listener) {
                        Ok(listener) => listener,
                        Err(error) => {
                            let _ = ready_sender.send(Err(error.to_string()));
                            return;
                        }
                    };
                    let _ = ready_sender.send(Ok(()));
                    let mut stop = thread_state.shutdown_receiver.clone();
                    let server = axum::serve(listener, make_router(thread_state));
                    let graceful = server.with_graceful_shutdown(async move {
                        let _ = server_shutdown_receiver.await;
                    });
                    tokio::select! {
                        _ = graceful => {}
                        _ = async {
                            let _ = stop.wait_for(|stopped| *stopped).await;
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        } => {}
                    }
                });
                // IPC blocking tasks have socket deadlines; do not let their
                // runtime teardown hold the controller indefinitely.
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .map_err(|error| WebError::Startup(error.to_string()))?;
        let startup = match ready_receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(result) => result,
            Err(error) => Err(error.to_string()),
        };
        if let Err(error) = startup {
            shutdown_flag.store(true, Ordering::Release);
            let _ = shutdown_watch.send(true);
            let _ = server_shutdown.send(());
            // A slow initializer may become ready later. Its shutdown signals
            // are already set; never join it on the scheduler's timeout path.
            finish_web_thread(thread, Duration::ZERO);
            return Err(WebError::Startup(error));
        }
        let mut service = Self {
            port,
            state,
            shutdown: Some(server_shutdown),
            shutdown_flag,
            shutdown_watch,
            thread: Some(thread),
        };
        let payload = service.start_response(false)?;
        Ok((service, payload))
    }

    pub fn start_or_reuse(
        &mut self,
        requested_port: Option<u16>,
    ) -> Result<ControlPayload, WebError> {
        if let Some(requested_port) = requested_port.filter(|port| *port != 0)
            && requested_port != self.port
        {
            return Err(WebError::RunningPortConflict {
                running: self.port,
                requested: requested_port,
            });
        }
        self.start_response(true)
    }

    fn start_response(&mut self, reused: bool) -> Result<ControlPayload, WebError> {
        let token = self
            .state
            .auth
            .lock()
            .map_err(|_| WebError::Startup("web authentication state is unavailable".into()))?
            .issue_entry_token()?;
        Ok(ControlPayload::WebStarted {
            port: self.port,
            token,
            reused,
        })
    }

    pub fn update_config(&self, config: ClusterConfig) {
        if let Ok(mut current) = self.state.config.write() {
            *current = config;
        }
    }
}

impl Drop for WebService {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        let _ = self.shutdown_watch.send(true);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            finish_web_thread(thread, Duration::from_secs(4));
        }
    }
}

fn bind_loopback(requested_port: Option<u16>) -> Result<TcpListener, WebError> {
    let port = requested_port.unwrap_or(0);
    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .map_err(|_| WebError::PortConflict(port))
}

struct WebState {
    binding: ServiceBinding,
    config: RwLock<ClusterConfig>,
    expected_host: String,
    expected_origin: String,
    auth: Mutex<AuthStore>,
    history: Mutex<HistoryStore>,
    next_event_id: AtomicU64,
    active_sse: AtomicUsize,
    active_http: AtomicUsize,
    log_read_slots: Arc<AtomicUsize>,
    shutdown_flag: Arc<AtomicBool>,
    shutdown_receiver: watch::Receiver<bool>,
}

#[derive(Default)]
struct AuthStore {
    entry_tokens: HashMap<String, Instant>,
    sessions: HashMap<String, Instant>,
    views: HashMap<(String, String), ViewRecord>,
}

#[derive(Clone)]
struct ViewRecord {
    visible_nodes: Vec<String>,
    detail_node: Option<String>,
    monitor_interval: Duration,
    cadence_changed: Arc<Notify>,
    touched_at: Instant,
}

impl AuthStore {
    fn prune(&mut self, now: Instant) {
        self.entry_tokens.retain(|_, expires| *expires > now);
        self.sessions.retain(|_, expires| *expires > now);
        let sessions = &self.sessions;
        self.views.retain(|(session, _), view| {
            sessions.contains_key(session) && now.duration_since(view.touched_at) < VIEW_TTL
        });
    }

    fn issue_entry_token(&mut self) -> Result<String, WebError> {
        self.prune(Instant::now());
        if self.entry_tokens.len() >= MAX_ENTRY_TOKENS {
            return Err(WebError::TokenStoreFull);
        }
        let token = Id128::random().to_string();
        self.entry_tokens
            .insert(token.clone(), Instant::now() + TOKEN_TTL);
        Ok(token)
    }

    fn redeem(&mut self, token: &str) -> Result<String, ApiError> {
        let now = Instant::now();
        self.prune(now);
        if self.entry_tokens.remove(token).is_none() {
            return Err(ApiError::unauthorized(
                "This monitor link expired or was already used. Run `macluster controller run --web` again.",
            ));
        }
        if self.sessions.len() >= MAX_SESSIONS {
            return Err(ApiError::too_many("Too many browser sessions are open."));
        }
        let session = Id128::random().to_string();
        self.sessions.insert(session.clone(), now + SESSION_TTL);
        Ok(session)
    }

    fn authenticate(&mut self, session: &str) -> Result<(), ApiError> {
        let now = Instant::now();
        self.prune(now);
        let Some(expires) = self.sessions.get_mut(session) else {
            return Err(ApiError::unauthorized(
                "The monitor session expired. Run `macluster controller run --web` again.",
            ));
        };
        *expires = now + SESSION_TTL;
        Ok(())
    }

    fn update_view(
        &mut self,
        session: &str,
        view_id: String,
        visible_nodes: Vec<String>,
        detail_node: Option<String>,
        monitor_interval: Duration,
    ) -> Result<(), ApiError> {
        self.prune(Instant::now());
        if view_id.len() < 16
            || view_id.len() > 64
            || !view_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ApiError::bad_request("Invalid browser view ID."));
        }
        if visible_nodes.len() > MAX_WEB_NODES {
            return Err(ApiError::bad_request("Too many visible nodes."));
        }
        let key = (session.to_owned(), view_id.clone());
        let current = self.views.contains_key(&key);
        if !current {
            let session_views = self
                .views
                .keys()
                .filter(|(view_session, _)| view_session == session)
                .count();
            if self.views.len() >= MAX_VIEWS || session_views >= MAX_VIEWS_PER_SESSION {
                return Err(ApiError::too_many(
                    "Too many browser tabs are monitoring this cluster.",
                ));
            }
        }
        if detail_node.is_some() {
            let current_process_views = self
                .views
                .iter()
                .filter(|(existing_key, view)| *existing_key != &key && view.detail_node.is_some())
                .count();
            if current_process_views >= MAX_PROCESS_VIEWS {
                return Err(ApiError::too_many(
                    "The process view limit is reached. Close another node detail view first.",
                ));
            }
        }
        if let Some(view) = self.views.get_mut(&key) {
            view.visible_nodes = visible_nodes;
            view.detail_node = detail_node;
            view.monitor_interval = monitor_interval;
            view.touched_at = Instant::now();
            view.cadence_changed.notify_one();
        } else {
            self.views.insert(
                key,
                ViewRecord {
                    visible_nodes,
                    detail_node,
                    monitor_interval,
                    cadence_changed: Arc::new(Notify::new()),
                    touched_at: Instant::now(),
                },
            );
        }
        Ok(())
    }

    fn touch_view(&mut self, session: &str, view_id: &str) -> Option<ViewRecord> {
        self.prune(Instant::now());
        let view = self
            .views
            .get_mut(&(session.to_owned(), view_id.to_owned()))?;
        view.touched_at = Instant::now();
        Some(view.clone())
    }
}

#[derive(Default)]
struct HistoryStore {
    nodes: HashMap<String, VecDeque<MetricSnapshot>>,
}

impl HistoryStore {
    fn push(&mut self, snapshot: &MonitorSnapshot) {
        let cutoff = now_unix_ms().saturating_sub(HISTORY_WINDOW.as_millis() as u64);
        for row in &snapshot.nodes {
            let key = row.node_id.to_string();
            if !self.nodes.contains_key(&key) && self.nodes.len() >= MAX_WEB_NODES {
                continue;
            }
            let samples = self.nodes.entry(key).or_default();
            if samples
                .back()
                .is_some_and(|last| last.sampled_unix_ms >= row.metrics.sampled_unix_ms)
            {
                continue;
            }
            if row.metrics.cpu_percent.is_some()
                || row.metrics.memory_used_bytes.is_some()
                || row.metrics.power_watts.is_some()
            {
                let mut history_sample = row.metrics.clone();
                history_sample.fan_readings = None;
                samples.push_back(history_sample);
            }
            while samples.len() > HISTORY_SAMPLES
                || samples
                    .front()
                    .is_some_and(|sample| sample.sampled_unix_ms < cutoff)
            {
                samples.pop_front();
            }
        }
    }

    fn get(&self, node_id: &str) -> Vec<MetricSnapshot> {
        self.nodes
            .get(node_id)
            .map(|samples| samples.iter().cloned().collect())
            .unwrap_or_default()
    }
}

fn make_router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/app.js", get(app_js))
        .route("/assets/style.css", get(style_css))
        .route("/api/v1/session", post(redeem_session))
        .route("/api/v1/bootstrap", get(bootstrap))
        .route("/api/v1/view", put(update_view))
        .route("/api/v1/events", get(events))
        .route("/api/v1/nodes/{node_id}/history", get(node_history))
        .route("/api/v1/jobs", get(jobs))
        .route("/api/v1/jobs/{job_id}", get(job_detail))
        .route("/api/v1/jobs/{job_id}/logs", get(job_logs))
        .route("/api/v1/queues", get(queues))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            security_headers,
        ))
        .with_state(state)
}

async fn security_headers(
    State(state): State<Arc<WebState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if let Err(error) = validate_host_origin(request.headers(), &state, false) {
        return error.into_response();
    }
    if state.active_http.fetch_add(1, Ordering::AcqRel) >= 32 {
        state.active_http.fetch_sub(1, Ordering::AcqRel);
        return ApiError::too_many("The local monitor request limit is reached.").into_response();
    }
    let mut response = next.run(request).await;
    state.active_http.fetch_sub(1, Ordering::AcqRel);
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn validate_host_origin(
    headers: &HeaderMap,
    state: &WebState,
    require_origin: bool,
) -> Result<(), ApiError> {
    if headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        != Some(state.expected_host.as_str())
        || headers.contains_key("forwarded")
        || headers.contains_key("x-forwarded-host")
    {
        return Err(ApiError::bad_request("Request host is not allowed."));
    }
    match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        Some(origin) if origin == state.expected_origin => Ok(()),
        Some(_) => Err(ApiError::forbidden("Request origin is not allowed.")),
        None if require_origin => Err(ApiError::forbidden("A same-origin request is required.")),
        None => Ok(()),
    }
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn app_js() -> Response {
    asset_response("text/javascript; charset=utf-8", APP_JS)
}

async fn style_css() -> Response {
    asset_response("text/css; charset=utf-8", STYLE_CSS)
}

fn asset_response(content_type: &'static str, source: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(source))
        .expect("static response headers are valid")
}

#[derive(Deserialize)]
struct RedeemRequest {
    token: String,
}

async fn redeem_session(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(request): Json<RedeemRequest>,
) -> Result<Response, ApiError> {
    validate_host_origin(&headers, &state, true)?;
    if request.token.len() != 36 {
        return Err(ApiError::unauthorized("Invalid monitor link."));
    }
    let session = state
        .auth
        .lock()
        .map_err(|_| ApiError::unavailable("Authentication state is unavailable."))?
        .redeem(&request.token)?;
    let cookie = format!("macluster_web={session}; Path=/; HttpOnly; SameSite=Strict");
    let mut response = Json(serde_json::json!({"ok": true})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| ApiError::internal("Could not set session cookie."))?,
    );
    Ok(response)
}

fn require_session(
    state: &WebState,
    headers: &HeaderMap,
    require_origin: bool,
) -> Result<String, ApiError> {
    validate_host_origin(headers, state, require_origin)?;
    let session = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let (name, value) = cookie.trim().split_once('=')?;
                (name == "macluster_web").then_some(value.to_owned())
            })
        })
        .ok_or_else(|| ApiError::unauthorized("Monitor session is missing."))?;
    state
        .auth
        .lock()
        .map_err(|_| ApiError::unavailable("Authentication state is unavailable."))?
        .authenticate(&session)?;
    Ok(session)
}

#[derive(Serialize)]
struct WebNodeInfo {
    id: String,
    role: String,
    queues: Vec<String>,
}

#[derive(Serialize)]
struct WebJob {
    id: u64,
    name: String,
    state: JobState,
    queue: String,
    node: Option<String>,
    created_unix_ms: u64,
    started_unix_ms: Option<u64>,
    finished_unix_ms: Option<u64>,
    exit_code: Option<i32>,
    end_reason: Option<String>,
    waiting_reason: Option<String>,
    cwd: String,
    stdout_path: String,
    stderr_path: String,
    snapshot_sync_pending: bool,
    log_sync_pending: bool,
}

impl From<JobRecord> for WebJob {
    fn from(job: JobRecord) -> Self {
        Self {
            id: job.id,
            name: job.spec.name,
            state: job.state,
            queue: job.spec.queue.to_string(),
            node: job.node.map(|node| node.to_string()),
            created_unix_ms: job.created_unix_ms,
            started_unix_ms: job.started_unix_ms,
            finished_unix_ms: job.finished_unix_ms,
            exit_code: job.exit_code,
            end_reason: job.end_reason,
            waiting_reason: job.waiting_reason,
            cwd: job.spec.cwd,
            stdout_path: job.spec.stdout_path,
            stderr_path: job.spec.stderr_path,
            snapshot_sync_pending: job.snapshot_sync_pending,
            log_sync_pending: job.log_sync_pending,
        }
    }
}

#[derive(Serialize)]
struct WebJobPage {
    jobs: Vec<WebJob>,
    next_offset: Option<usize>,
}

impl From<JobPage> for WebJobPage {
    fn from(page: JobPage) -> Self {
        Self {
            jobs: page.jobs.into_iter().map(WebJob::from).collect(),
            next_offset: page.next_offset,
        }
    }
}

#[derive(Serialize)]
struct BootstrapResponse {
    cluster_name: String,
    controller: ControllerHello,
    configured_nodes: Vec<WebNodeInfo>,
    monitor: MonitorSnapshot,
    jobs: WebJobPage,
    queues: Vec<QueueSummary>,
    node_limit: usize,
    truncated_nodes: bool,
}

async fn bootstrap(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Result<Json<BootstrapResponse>, ApiError> {
    require_session(&state, &headers, false)?;
    let binding = state.binding.clone();
    let config = state
        .config
        .read()
        .map_err(|_| ApiError::unavailable("Cluster configuration is unavailable."))?
        .clone();
    let data = tokio::task::spawn_blocking(move || fetch_bootstrap(&binding, &config))
        .await
        .map_err(|error| ApiError::unavailable(format!("Controller query failed: {error}")))??;
    Ok(Json(data))
}

fn fetch_bootstrap(
    binding: &ServiceBinding,
    config: &ClusterConfig,
) -> Result<BootstrapResponse, ApiError> {
    let mut client = WebControlClient::connect(binding)?;
    let controller = match client.request(ControlCommand::Status)? {
        ControlPayload::Status(hello) => hello,
        _ => {
            return Err(ApiError::unavailable(
                "Controller returned an invalid status.",
            ));
        }
    };
    let monitor = match client.request(ControlCommand::MonitorSnapshot { page: 0 })? {
        ControlPayload::MonitorSnapshot(snapshot) => snapshot,
        _ => {
            return Err(ApiError::unavailable(
                "Controller returned invalid monitor data.",
            ));
        }
    };
    let jobs = match client.request(ControlCommand::QueryJobs {
        offset: 0,
        limit: 50,
        state: None,
        active_only: true,
    })? {
        ControlPayload::Jobs(page) => WebJobPage::from(page),
        _ => {
            return Err(ApiError::unavailable(
                "Controller returned invalid job data.",
            ));
        }
    };
    let queues = match client.request(ControlCommand::QueryQueues)? {
        ControlPayload::Queues(queues) => queues,
        _ => {
            return Err(ApiError::unavailable(
                "Controller returned invalid queue data.",
            ));
        }
    };
    let all_nodes = config
        .nodes
        .keys()
        .map(|id| {
            let queues = config
                .queues
                .iter()
                .filter(|(_, queue)| queue.nodes.iter().any(|node| node == id))
                .map(|(name, _)| name.clone())
                .collect();
            WebNodeInfo {
                id: id.clone(),
                role: if config.is_login_node(id) {
                    "login"
                } else {
                    "compute"
                }
                .into(),
                queues,
            }
        })
        .collect::<Vec<_>>();
    let truncated_nodes = all_nodes.len() > MAX_WEB_NODES || monitor.total_pages > 1;
    Ok(BootstrapResponse {
        cluster_name: config.name.clone(),
        controller,
        configured_nodes: all_nodes.into_iter().take(MAX_WEB_NODES).collect(),
        monitor,
        jobs,
        queues,
        node_limit: MAX_WEB_NODES,
        truncated_nodes,
    })
}

#[derive(Deserialize)]
struct ViewUpdate {
    view_id: String,
    visible_nodes: Vec<String>,
    detail_node: Option<String>,
    #[serde(default = "default_monitor_interval_ms")]
    monitor_interval_ms: u64,
}

fn default_monitor_interval_ms() -> u64 {
    MONITOR_INTERVAL.as_millis() as u64
}

#[derive(Serialize)]
struct ViewUpdateResponse {
    view_id: String,
    subscribed_nodes: usize,
}

async fn update_view(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(update): Json<ViewUpdate>,
) -> Result<Json<ViewUpdateResponse>, ApiError> {
    let session = require_session(&state, &headers, true)?;
    let config = state
        .config
        .read()
        .map_err(|_| ApiError::unavailable("Cluster configuration is unavailable."))?;
    if update.visible_nodes.len() > MAX_WEB_NODES {
        return Err(ApiError::bad_request("Too many visible nodes."));
    }
    let mut nodes = Vec::with_capacity(update.visible_nodes.len());
    let mut seen = std::collections::HashSet::new();
    for node_id in update.visible_nodes {
        let node = NodeId::new(node_id.clone())
            .map_err(|_| ApiError::bad_request("View contains an invalid node ID."))?;
        if !config.nodes.contains_key(node.as_str()) {
            return Err(ApiError::bad_request("View contains an unknown node."));
        }
        if !seen.insert(node_id.clone()) {
            return Err(ApiError::bad_request("View contains a duplicate node."));
        }
        nodes.push(node_id);
    }
    let detail_node = if let Some(node_id) = update.detail_node {
        let node = NodeId::new(node_id.clone())
            .map_err(|_| ApiError::bad_request("Detail view contains an invalid node ID."))?;
        if !config.nodes.contains_key(node.as_str()) {
            return Err(ApiError::bad_request(
                "Detail view contains an unknown node.",
            ));
        }
        if !seen.contains(&node_id) {
            if nodes.len() >= MAX_WEB_NODES {
                return Err(ApiError::bad_request(
                    "Detail node exceeds the view node limit.",
                ));
            }
            nodes.push(node_id.clone());
        }
        Some(node_id)
    } else {
        None
    };
    let monitor_interval = match update.monitor_interval_ms {
        2_000 => MONITOR_INTERVAL,
        10_000 => BACKGROUND_MONITOR_INTERVAL,
        _ => {
            return Err(ApiError::bad_request(
                "Monitor interval must be 2000 or 10000 milliseconds.",
            ));
        }
    };
    let count = nodes.len();
    state
        .auth
        .lock()
        .map_err(|_| ApiError::unavailable("View state is unavailable."))?
        .update_view(
            &session,
            update.view_id.clone(),
            nodes,
            detail_node,
            monitor_interval,
        )?;
    Ok(Json(ViewUpdateResponse {
        view_id: update.view_id,
        subscribed_nodes: count,
    }))
}

#[derive(Deserialize)]
struct EventsQuery {
    view: String,
}

async fn events(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers, false)?;
    {
        let mut auth = state
            .auth
            .lock()
            .map_err(|_| ApiError::unavailable("View state is unavailable."))?;
        if auth.touch_view(&session, &query.view).is_none() {
            return Err(ApiError::bad_request(
                "This browser view expired. Refresh the page.",
            ));
        }
    }
    if state.active_sse.fetch_add(1, Ordering::AcqRel) >= MAX_SSE_CONNECTIONS {
        state.active_sse.fetch_sub(1, Ordering::AcqRel);
        return Err(ApiError::too_many(
            "The live monitor connection limit is reached.",
        ));
    }
    let feed = EventFeed::new(Arc::clone(&state), session, query.view);
    let stream = stream::unfold(feed, |mut feed| async move {
        if feed.first {
            feed.first = false;
        } else {
            let (wait, cadence_changed) = feed.next_wait();
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = cadence_changed.notified() => {}
                changed = feed.shutdown_receiver.changed() => {
                    if changed.is_err() || *feed.shutdown_receiver.borrow() {
                        return None;
                    }
                }
            }
        }
        if feed.state.shutdown_flag.load(Ordering::Acquire) {
            return None;
        }
        let task = tokio::task::spawn_blocking(move || {
            let update = feed.fetch_update();
            (feed, update)
        });
        let (feed, update) = match task.await {
            Ok(value) => value,
            Err(_) => return None,
        };
        let event = match serde_json::to_string(&update) {
            Ok(data) => Event::default()
                .id(update.event_id.to_string())
                .event("update")
                .data(data),
            Err(_) => Event::default()
                .event("error")
                .data("{\"error\":\"Could not serialize monitor data.\"}"),
        };
        Some((Ok::<Event, Infallible>(event), feed))
    });
    let response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    Ok(response)
}

struct EventFeed {
    state: Arc<WebState>,
    session: String,
    view_id: String,
    client: Option<WebControlClient>,
    subscribed_nodes: Option<Vec<String>>,
    watched_node: Option<String>,
    next_renew: Instant,
    next_job_refresh: Instant,
    next_queue_refresh: Instant,
    next_status_refresh: Instant,
    next_connect: Instant,
    backoff: Duration,
    first: bool,
    shutdown_receiver: watch::Receiver<bool>,
}

impl EventFeed {
    fn new(state: Arc<WebState>, session: String, view_id: String) -> Self {
        Self {
            shutdown_receiver: state.shutdown_receiver.clone(),
            state,
            session,
            view_id,
            client: None,
            subscribed_nodes: None,
            watched_node: None,
            next_renew: Instant::now(),
            next_job_refresh: Instant::now(),
            next_queue_refresh: Instant::now(),
            next_status_refresh: Instant::now(),
            next_connect: Instant::now(),
            backoff: Duration::from_secs(1),
            first: true,
        }
    }

    fn next_wait(&self) -> (Duration, Arc<Notify>) {
        let now = Instant::now();
        if self.client.is_none() && self.next_connect > now {
            return (
                self.next_connect
                    .saturating_duration_since(now)
                    .max(Duration::from_secs(1)),
                Arc::new(Notify::new()),
            );
        }
        let view = self.state.auth.lock().ok().and_then(|mut auth| {
            auth.authenticate(&self.session).ok()?;
            auth.touch_view(&self.session, &self.view_id)
        });
        match view {
            Some(view) => (view.monitor_interval, view.cadence_changed),
            None => (BACKGROUND_MONITOR_INTERVAL, Arc::new(Notify::new())),
        }
    }

    fn fetch_update(&mut self) -> WebEvent {
        let event_id = self.state.next_event_id.fetch_add(1, Ordering::Relaxed);
        let Some(view) = self.state.auth.lock().ok().and_then(|mut auth| {
            auth.authenticate(&self.session).ok()?;
            auth.touch_view(&self.session, &self.view_id)
        }) else {
            return WebEvent::error(event_id, "Browser view expired. Refresh the page.");
        };
        let now = Instant::now();
        if self.client.is_none() {
            if now < self.next_connect {
                return WebEvent::error(event_id, "Reconnecting to the controller…");
            }
            match WebControlClient::connect(&self.state.binding) {
                Ok(client) => {
                    self.client = Some(client);
                    self.backoff = Duration::from_secs(1);
                    self.next_connect = now;
                    self.subscribed_nodes = None;
                }
                Err(error) => {
                    self.schedule_retry(now);
                    return WebEvent::error(
                        event_id,
                        format!("Controller unavailable: {error}. Reconnecting."),
                    );
                }
            }
        }
        let Some(client) = self.client.as_mut() else {
            return WebEvent::error(event_id, "Controller connection is unavailable.");
        };
        let selected_nodes = view.visible_nodes.clone();
        let selected_detail = view.detail_node.clone();
        let needs_subscription = self.subscribed_nodes.as_ref() != Some(&selected_nodes)
            || self.watched_node != selected_detail
            || now >= self.next_renew;
        if needs_subscription {
            let ids = selected_nodes
                .iter()
                .filter_map(|node| NodeId::new(node.clone()).ok())
                .collect();
            if let Err(error) = client.request(ControlCommand::SubscribeMonitor { node_ids: ids }) {
                self.disconnect_for_retry(now);
                return WebEvent::error(event_id, format!("Monitor subscription failed: {error}"));
            }
            let detail = selected_detail
                .as_deref()
                .and_then(|node| NodeId::new(node.to_owned()).ok());
            if let Err(error) = client.request(ControlCommand::WatchProcesses { node_id: detail }) {
                self.disconnect_for_retry(now);
                return WebEvent::error(event_id, format!("Process subscription failed: {error}"));
            }
            self.subscribed_nodes = Some(selected_nodes.clone());
            self.watched_node = selected_detail;
            self.next_renew = now + Duration::from_secs(15);
        }
        let mut monitor = match client.request(ControlCommand::MonitorSnapshot { page: 0 }) {
            Ok(ControlPayload::MonitorSnapshot(snapshot)) => snapshot,
            Ok(_) => {
                self.disconnect_for_retry(now);
                return WebEvent::error(event_id, "Controller returned invalid monitor data.");
            }
            Err(error) => {
                self.disconnect_for_retry(now);
                return WebEvent::error(event_id, format!("Monitor query failed: {error}"));
            }
        };
        let visible = selected_nodes
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        monitor
            .nodes
            .retain(|node| visible.contains(node.node_id.as_str()));
        if let Ok(mut history) = self.state.history.lock() {
            history.push(&monitor);
        }
        let mut update = WebEvent {
            event_id,
            controller: Some(client.hello().clone()),
            monitor: Some(monitor),
            jobs: None,
            queues: None,
            error: None,
            truncated_nodes: self
                .state
                .config
                .read()
                .map(|config| config.nodes.len() > MAX_WEB_NODES)
                .unwrap_or(true),
        };
        if now >= self.next_status_refresh {
            if let Ok(ControlPayload::Status(status)) = client.request(ControlCommand::Status) {
                update.controller = Some(status);
            }
            self.next_status_refresh = now + Duration::from_secs(5);
        }
        if now >= self.next_job_refresh {
            match client.request(ControlCommand::QueryJobs {
                offset: 0,
                limit: 50,
                state: None,
                active_only: true,
            }) {
                Ok(ControlPayload::Jobs(page)) => update.jobs = Some(WebJobPage::from(page)),
                Ok(_) => update.error = Some("Controller returned invalid job data.".into()),
                Err(error) => update.error = Some(format!("Job query failed: {error}")),
            }
            self.next_job_refresh = now + JOB_REFRESH_INTERVAL;
        }
        if now >= self.next_queue_refresh {
            match client.request(ControlCommand::QueryQueues) {
                Ok(ControlPayload::Queues(queues)) => update.queues = Some(queues),
                Ok(_) => update.error = Some("Controller returned invalid queue data.".into()),
                Err(error) => update.error = Some(format!("Queue query failed: {error}")),
            }
            self.next_queue_refresh = now + QUEUE_REFRESH_INTERVAL;
        }
        update
    }

    fn schedule_retry(&mut self, now: Instant) {
        self.next_connect = now + self.backoff;
        self.backoff = (self.backoff * 2).min(Duration::from_secs(30));
    }

    fn disconnect_for_retry(&mut self, now: Instant) {
        self.client = None;
        self.subscribed_nodes = None;
        self.watched_node = None;
        self.schedule_retry(now);
    }
}

impl Drop for EventFeed {
    fn drop(&mut self) {
        self.state.active_sse.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Serialize)]
struct WebEvent {
    event_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller: Option<ControllerHello>,
    #[serde(skip_serializing_if = "Option::is_none")]
    monitor: Option<MonitorSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jobs: Option<WebJobPage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    queues: Option<Vec<QueueSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    truncated_nodes: bool,
}

impl WebEvent {
    fn error(event_id: u64, message: impl Into<String>) -> Self {
        Self {
            event_id,
            controller: None,
            monitor: None,
            jobs: None,
            queues: None,
            error: Some(message.into()),
            truncated_nodes: false,
        }
    }
}

#[derive(Deserialize)]
struct HistoryQuery {
    minutes: Option<u8>,
}

async fn node_history(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    AxumPath(node_id): AxumPath<String>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<MetricSnapshot>>, ApiError> {
    require_session(&state, &headers, false)?;
    if !state
        .config
        .read()
        .map_err(|_| ApiError::unavailable("Cluster configuration is unavailable."))?
        .nodes
        .contains_key(&node_id)
    {
        return Err(ApiError::bad_request("Unknown node."));
    }
    let samples = state
        .history
        .lock()
        .map_err(|_| ApiError::unavailable("Monitor history is unavailable."))?
        .get(&node_id);
    let minutes = query.minutes.unwrap_or(5).clamp(1, 5) as u64;
    let cutoff = now_unix_ms().saturating_sub(minutes * 60_000);
    Ok(Json(
        samples
            .into_iter()
            .filter(|sample| sample.sampled_unix_ms >= cutoff)
            .collect(),
    ))
}

#[derive(Deserialize)]
struct JobsQuery {
    offset: Option<usize>,
    limit: Option<usize>,
    state: Option<String>,
    active_only: Option<bool>,
}

async fn jobs(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(query): Query<JobsQuery>,
) -> Result<Json<WebJobPage>, ApiError> {
    require_session(&state, &headers, false)?;
    let offset = query.offset.unwrap_or(0).min(10_000_000);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let job_state = query.state.as_deref().map(parse_job_state).transpose()?;
    let state = state.binding.clone();
    let active_only = query.active_only.unwrap_or(false);
    let page = tokio::task::spawn_blocking(move || {
        let mut client = WebControlClient::connect(&state)?;
        match client.request(ControlCommand::QueryJobs {
            offset,
            limit,
            state: job_state,
            active_only,
        })? {
            ControlPayload::Jobs(page) => Ok(WebJobPage::from(page)),
            _ => Err(ApiError::unavailable(
                "Controller returned invalid job data.",
            )),
        }
    })
    .await
    .map_err(|error| ApiError::unavailable(format!("Job query failed: {error}")))??;
    Ok(Json(page))
}

fn parse_job_state(value: &str) -> Result<JobState, ApiError> {
    match value.to_ascii_uppercase().as_str() {
        "PENDING" => Ok(JobState::Pending),
        "STARTING" => Ok(JobState::Starting),
        "RUNNING" => Ok(JobState::Running),
        "CANCELLING" => Ok(JobState::Cancelling),
        "COMPLETED" => Ok(JobState::Completed),
        "FAILED" => Ok(JobState::Failed),
        "CANCELLED" => Ok(JobState::Cancelled),
        "TIMEOUT" => Ok(JobState::Timeout),
        "NODE_LOST" => Ok(JobState::NodeLost),
        _ => Err(ApiError::bad_request("Unknown job state filter.")),
    }
}

async fn job_detail(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<u64>,
) -> Result<Json<WebJob>, ApiError> {
    require_session(&state, &headers, false)?;
    let binding = state.binding.clone();
    let job = tokio::task::spawn_blocking(move || {
        let mut client = WebControlClient::connect(&binding)?;
        match client.request(ControlCommand::LookupJob { job_id })? {
            ControlPayload::Job(job) => Ok(WebJob::from(job)),
            _ => Err(ApiError::unavailable(
                "Controller returned invalid job details.",
            )),
        }
    })
    .await
    .map_err(|error| ApiError::unavailable(format!("Job lookup failed: {error}")))??;
    Ok(Json(job))
}

async fn queues(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<QueueSummary>>, ApiError> {
    require_session(&state, &headers, false)?;
    let binding = state.binding.clone();
    let queues = tokio::task::spawn_blocking(move || {
        let mut client = WebControlClient::connect(&binding)?;
        match client.request(ControlCommand::QueryQueues)? {
            ControlPayload::Queues(queues) => Ok(queues),
            _ => Err(ApiError::unavailable(
                "Controller returned invalid queue data.",
            )),
        }
    })
    .await
    .map_err(|error| ApiError::unavailable(format!("Queue query failed: {error}")))??;
    Ok(Json(queues))
}

#[derive(Deserialize)]
struct LogQuery {
    stream: Option<String>,
    offset: Option<u64>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct LogSlice {
    job_id: u64,
    stream: String,
    content: String,
    start_offset: u64,
    end_offset: u64,
    total_bytes: u64,
    file_identity: String,
    truncated: bool,
    reset: bool,
    sync_pending: bool,
}

async fn job_logs(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<u64>,
    Query(query): Query<LogQuery>,
) -> Result<Json<LogSlice>, ApiError> {
    require_session(&state, &headers, false)?;
    let stream_name = query.stream.unwrap_or_else(|| "stdout".into());
    if !matches!(stream_name.as_str(), "stdout" | "stderr") {
        return Err(ApiError::bad_request("Stream must be stdout or stderr."));
    }
    let limit = query.limit.unwrap_or(MAX_LOG_BYTES).clamp(1, MAX_LOG_BYTES);
    let binding = state.binding.clone();
    let config = state
        .config
        .read()
        .map_err(|_| ApiError::unavailable("Cluster configuration is unavailable."))?
        .clone();
    let requested_offset = query.offset;
    let slice = isolated_log_read(
        Arc::clone(&state.log_read_slots),
        LOG_READ_TIMEOUT,
        move || {
            let mut client = WebControlClient::connect(&binding)?;
            let job = match client.request(ControlCommand::LookupJob { job_id })? {
                ControlPayload::Job(job) => job,
                _ => {
                    return Err(ApiError::unavailable(
                        "Controller returned invalid job details.",
                    ));
                }
            };
            if job.log_sync_pending {
                return Err(ApiError::conflict(
                    "Task output is waiting for synchronization; try again after it completes.",
                ));
            }
            read_job_log(&config, &job, &stream_name, requested_offset, limit)
        },
    )
    .await?;
    Ok(Json(slice))
}

// NFS syscalls can outlive an async timeout. Dedicated, capped threads keep
// them outside Tokio teardown and retain their permit until the syscall ends.
struct LogReadPermit(Arc<AtomicUsize>);
impl Drop for LogReadPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
async fn isolated_log_read<T: Send + 'static>(
    slots: Arc<AtomicUsize>,
    timeout: Duration,
    read: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    let mut active = slots.load(Ordering::Acquire);
    loop {
        if active >= MAX_LOG_READS {
            return Err(ApiError::too_many(
                "Log readers are busy; shared storage may be unavailable.",
            ));
        }
        match slots.compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(actual) => active = actual,
        }
    }
    let permit = LogReadPermit(slots);
    let (send, receive) = oneshot::channel();
    thread::Builder::new()
        .name("macluster-web-log".into())
        .spawn(move || {
            let result = read();
            drop(permit);
            let _ = send.send(result);
        })
        .map_err(|error| ApiError::unavailable(format!("Could not start log reader: {error}")))?;
    tokio::time::timeout(timeout, receive)
        .await
        .map_err(|_| {
            ApiError::unavailable("Log read timed out; shared storage may be unavailable.")
        })?
        .map_err(|_| ApiError::unavailable("Log reader stopped unexpectedly."))?
}

fn finish_web_thread(thread: JoinHandle<()>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !thread.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    if thread.is_finished() {
        let _ = thread.join();
    }
    // Dropping an unfinished handle detaches it, so scheduling/shutdown remains bounded.
}

fn read_job_log(
    config: &ClusterConfig,
    job: &JobRecord,
    stream_name: &str,
    requested_offset: Option<u64>,
    limit: usize,
) -> Result<LogSlice, ApiError> {
    let stored_path = if stream_name == "stdout" {
        &job.spec.stdout_path
    } else {
        &job.spec.stderr_path
    };
    let candidate = PathBuf::from(stored_path.replace("%j", &job.id.to_string()));
    let file = open_log_beneath_shared_root(config, &candidate)?;
    let metadata = file
        .metadata()
        .map_err(|_| ApiError::not_found("Task output is not available."))?;
    if !metadata.is_file() {
        return Err(ApiError::forbidden("Task output is not a regular file."));
    }
    let total_bytes = metadata.len();
    let file_identity = format!("{}:{}", metadata.dev(), metadata.ino());
    let (start_offset, reset) = match requested_offset {
        Some(offset) if offset <= total_bytes => (offset, false),
        Some(_) => (total_bytes.saturating_sub(limit as u64), true),
        None => (total_bytes.saturating_sub(limit as u64), false),
    };
    let mut file = file;
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|_| ApiError::not_found("Task output is not available."))?;
    let mut bytes =
        Vec::with_capacity(limit.min(total_bytes.saturating_sub(start_offset) as usize));
    file.take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::not_found("Task output is not available."))?;
    let end_offset = start_offset.saturating_add(bytes.len() as u64);
    Ok(LogSlice {
        job_id: job.id,
        stream: stream_name.into(),
        content: String::from_utf8_lossy(&bytes).into_owned(),
        start_offset,
        end_offset,
        total_bytes,
        file_identity,
        truncated: start_offset > 0,
        reset,
        sync_pending: job.log_sync_pending,
    })
}

fn open_log_beneath_shared_root(
    config: &ClusterConfig,
    candidate: &Path,
) -> Result<File, ApiError> {
    if !candidate.is_absolute() {
        return Err(ApiError::forbidden("Task output path is not absolute."));
    }
    let parent = candidate
        .parent()
        .ok_or_else(|| ApiError::forbidden("Task output path is invalid."))?
        .canonicalize()
        .map_err(|_| ApiError::not_found("Task output is not available."))?;
    let filename = candidate
        .file_name()
        .ok_or_else(|| ApiError::forbidden("Task output path is invalid."))?;
    let resolved = parent.join(filename);
    let mut roots = vec![config.shared_root.clone()];
    for share in config.shares.values() {
        roots.push(share.mount_root.clone());
        roots.push(share.source_root.clone());
    }
    for root in roots {
        let Ok(root) = root.canonicalize() else {
            continue;
        };
        let Ok(relative) = resolved.strip_prefix(&root) else {
            continue;
        };
        let components = relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name.to_owned()),
                _ => Err(()),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ApiError::forbidden("Task output path is not inside shared storage."))?;
        if components.is_empty() {
            continue;
        }
        return openat_regular_file(&root, &components)
            .map_err(|_| ApiError::not_found("Task output is not available."));
    }
    Err(ApiError::forbidden(
        "Task output is outside configured shared storage.",
    ))
}

fn openat_regular_file(root: &Path, components: &[std::ffi::OsString]) -> std::io::Result<File> {
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    for component in &components[..components.len() - 1] {
        let name = std::ffi::CString::new(component.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    let final_name = std::ffi::CString::new(components.last().unwrap().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            final_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(file)
}

struct WebControlClient {
    stream: UnixStream,
    hello: ControllerHello,
}

impl WebControlClient {
    fn connect(binding: &ServiceBinding) -> Result<Self, ApiError> {
        binding.prepare_endpoint_dir().map_err(|error| {
            ApiError::unavailable(format!("Controller IPC unavailable: {error}"))
        })?;
        let mut stream = UnixStream::connect(binding.endpoint_path()).map_err(|error| {
            ApiError::unavailable(format!("Controller IPC unavailable: {error}"))
        })?;
        stream
            .set_read_timeout(Some(IPC_TIMEOUT))
            .and_then(|_| stream.set_write_timeout(Some(IPC_TIMEOUT)))
            .map_err(|error| {
                ApiError::unavailable(format!("Controller IPC unavailable: {error}"))
            })?;
        if peer_uid(&stream).map_err(|error| ApiError::unavailable(error.to_string()))?
            != binding.uid()
        {
            return Err(ApiError::unavailable(
                "Controller IPC peer identity did not match.",
            ));
        }
        write_frame(
            &mut stream,
            &ClientHello {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                binding_digest: binding.binding_digest().into(),
                namespace: binding.namespace().into(),
                uid: binding.uid(),
                build_id: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                capabilities: vec![
                    "status.v1".into(),
                    "monitor.v1".into(),
                    "jobs.v1".into(),
                    "web.v1".into(),
                ],
            },
        )
        .map_err(|error| {
            ApiError::unavailable(format!("Controller IPC handshake failed: {error}"))
        })?;
        let response: HelloResponse = read_frame(&mut stream)
            .map_err(|error| {
                ApiError::unavailable(format!("Controller IPC handshake failed: {error}"))
            })?
            .ok_or_else(|| ApiError::unavailable("Controller closed during IPC handshake."))?;
        let hello = match response {
            HelloResponse::Accepted(hello) => hello,
            HelloResponse::Rejected(error) => return Err(ApiError::unavailable(error.message)),
        };
        if hello.protocol_version != CONTROL_PROTOCOL_VERSION
            || hello.binding_digest != binding.binding_digest()
            || hello.namespace != binding.namespace()
            || hello.uid != binding.uid()
        {
            return Err(ApiError::unavailable(
                "Controller IPC binding did not match.",
            ));
        }
        Ok(Self { stream, hello })
    }

    fn hello(&self) -> &ControllerHello {
        &self.hello
    }

    fn request(&mut self, command: ControlCommand) -> Result<ControlPayload, ApiError> {
        let request_id = RequestId(Id128::random());
        write_frame(
            &mut self.stream,
            &ControlRequest {
                request_id,
                expected_generation: Some(self.hello.config_generation),
                command,
            },
        )
        .map_err(|error| ApiError::unavailable(format!("Controller request failed: {error}")))?;
        let response: ControlResponse = read_frame(&mut self.stream)
            .map_err(|error| ApiError::unavailable(format!("Controller response failed: {error}")))?
            .ok_or_else(|| ApiError::unavailable("Controller closed before replying."))?;
        if response.request_id != request_id {
            return Err(ApiError::unavailable(
                "Controller response did not match the request.",
            ));
        }
        response.result.map_err(|error| {
            let status = match error.code {
                ControlErrorCode::Busy => StatusCode::TOO_MANY_REQUESTS,
                ControlErrorCode::StaleGeneration => StatusCode::CONFLICT,
                ControlErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_REQUEST,
            };
            ApiError::new(status, error.message)
        })
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }
    fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }
    fn too_many(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, message)
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }
    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, message)
    }
    fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod blocker_tests {
    use super::*;
    #[test]
    fn slow_initializer_cannot_hold_the_startup_timeout_path() {
        let (release, wait) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = wait.recv();
        });
        let started = Instant::now();
        finish_web_thread(worker, Duration::ZERO);
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
    }
    #[test]
    fn timed_out_nfs_read_retains_its_slot_and_does_not_hold_runtime_shutdown() {
        let runtime = TokioRuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let slots = Arc::new(AtomicUsize::new(MAX_LOG_READS - 1));
        let (release, wait) = mpsc::channel();
        runtime.block_on(async {
            let result =
                isolated_log_read(Arc::clone(&slots), Duration::from_millis(20), move || {
                    wait.recv().unwrap();
                    Ok(())
                })
                .await;
            assert!(result.is_err());
            assert_eq!(slots.load(Ordering::Acquire), MAX_LOG_READS);
            assert!(
                isolated_log_read(Arc::clone(&slots), Duration::from_secs(1), || Ok(()))
                    .await
                    .is_err()
            );
        });
        let started = Instant::now();
        drop(runtime);
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while slots.load(Ordering::Acquire) == MAX_LOG_READS && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(slots.load(Ordering::Acquire), MAX_LOG_READS - 1);
    }
}
