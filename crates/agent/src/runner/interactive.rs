//! Per-job PTY and attachment socket for interactive jobs.

use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use macluster_protocol::{
    identifiers::{Id128, StartToken},
    types::{JobMode, JobState, RuntimePhase},
};

use crate::{AgentError, AgentRecord};

const ATTACH_MAGIC: &[u8; 5] = b"MPTY2";
const ATTACH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_PENDING_BYTES: usize = 1024 * 1024;
const EVENT_INPUT: u8 = 1;
const EVENT_RESIZE: u8 = 2;

pub(super) fn serve_attach_stdio<R, W>(
    input: &mut R,
    output: &mut W,
    state_dir: &Path,
    node_id: &str,
    job_id: u64,
    token: StartToken,
) -> Result<(), AgentError>
where
    R: Read + AsRawFd,
    W: Write + AsRawFd,
{
    let record =
        crate::wait_for_active_execution(state_dir, job_id, token, Duration::from_secs(15))?;
    if record.terminal() {
        return Err(AgentError::State(
            "interactive task has already finished".into(),
        ));
    }
    if record.node_id != node_id {
        return Err(AgentError::State(
            "interactive attachment node does not match the active task".into(),
        ));
    }
    if record.spec.mode != JobMode::Interactive {
        return Err(AgentError::State(
            "job does not have an interactive PTY".into(),
        ));
    }
    let input_fd = input.as_raw_fd();
    let output_fd = output.as_raw_fd();
    if unsafe { libc::isatty(input_fd) } != 1 || unsafe { libc::isatty(output_fd) } != 1 {
        return Err(AgentError::State(
            "interactive attachment requires a terminal".into(),
        ));
    }
    let _terminal = TerminalModeGuard::enter(input_fd)?;
    let initial_window = terminal_window(input_fd)?;
    let mut stream = connect_attach(state_dir, job_id, token, initial_window)?;
    stream.set_nonblocking(false)?;
    let mut last_window = Some(initial_window);
    let mut input_open = true;
    loop {
        let window = terminal_window(input_fd)?;
        if last_window != Some(window) {
            send_resize(&mut stream, window.0, window.1)?;
            last_window = Some(window);
        }

        let mut descriptors = [
            libc::pollfd {
                fd: if input_open { input_fd } else { -1 },
                events: if input_open {
                    libc::POLLIN | libc::POLLHUP | libc::POLLERR
                } else {
                    0
                },
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
        ];
        let polled = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, 100) };
        if polled == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        // Some PTYs surface a closed master as EIO without a POLLHUP event, so
        // inspect nonblocking stdin after every poll cycle.
        if input_open {
            let mut input_bytes = [0_u8; 16 * 1024];
            match input.read(&mut input_bytes) {
                Ok(0) => {
                    stream.shutdown(std::net::Shutdown::Write)?;
                    input_open = false;
                }
                Ok(count) => send_input(&mut stream, &input_bytes[..count])?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    stream.shutdown(std::net::Shutdown::Write)?;
                    input_open = false;
                }
                Err(error) => return Err(error.into()),
            }
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            let mut output_bytes = [0_u8; 16 * 1024];
            match stream.read(&mut output_bytes) {
                Ok(0) => break,
                Ok(count) => {
                    write_terminal_output(output, &output_bytes[..count])?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn write_terminal_output<W: Write + AsRawFd>(output: &mut W, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match output.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write interactive terminal output",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_terminal_writable(output.as_raw_fd())?;
            }
            Err(error) => return Err(error),
        }
    }

    loop {
        match output.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_terminal_writable(output.as_raw_fd())?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn wait_for_terminal_writable(fd: i32) -> io::Result<()> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    loop {
        descriptor.revents = 0;
        let ready = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if ready == -1 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if descriptor.revents & libc::POLLOUT != 0 {
            return Ok(());
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "interactive terminal output is closed",
            ));
        }
    }
}

fn connect_attach(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    initial_window: (u16, u16),
) -> Result<UnixStream, AgentError> {
    let socket_path = state_dir
        .join("jobs")
        .join(job_id.to_string())
        .join("pty.sock");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stream = loop {
        match UnixStream::connect(&socket_path) {
            Ok(stream) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(AgentError::State(format!(
                        "interactive PTY socket did not become ready: {error}"
                    )));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.write_all(ATTACH_MAGIC)?;
    stream.write_all(&job_id.to_be_bytes())?;
    stream.write_all(&initial_window.0.to_be_bytes())?;
    stream.write_all(&initial_window.1.to_be_bytes())?;
    stream.write_all(token.to_string().as_bytes())?;
    let mut response = [0_u8; 1];
    stream.read_exact(&mut response)?;
    match response[0] {
        0 => Ok(stream),
        1 => Err(AgentError::State(
            "interactive PTY attachment was rejected".into(),
        )),
        _ => Err(AgentError::State(
            "interactive PTY returned an invalid attach response".into(),
        )),
    }
}

fn send_input(stream: &mut UnixStream, input: &[u8]) -> io::Result<()> {
    stream.write_all(&[EVENT_INPUT])?;
    stream.write_all(&(input.len() as u32).to_be_bytes())?;
    stream.write_all(input)
}

fn send_resize(stream: &mut UnixStream, rows: u16, cols: u16) -> io::Result<()> {
    stream.write_all(&[
        EVENT_RESIZE,
        cols.to_be_bytes()[0],
        cols.to_be_bytes()[1],
        rows.to_be_bytes()[0],
        rows.to_be_bytes()[1],
    ])
}

fn terminal_window(fd: i32) -> io::Result<(u16, u16)> {
    let mut window = unsafe { std::mem::zeroed::<libc::winsize>() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut window) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((window.ws_row, window.ws_col))
}

struct TerminalModeGuard {
    fd: i32,
    original: libc::termios,
    original_flags: i32,
}

impl TerminalModeGuard {
    fn enter(fd: i32) -> io::Result<Self> {
        let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if original_flags == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } == -1 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, &original);
            }
            return Err(error);
        }
        Ok(Self {
            fd,
            original,
            original_flags,
        })
    }
}

impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            libc::fcntl(self.fd, libc::F_SETFL, self.original_flags);
        }
    }
}

pub(super) fn run_authorized(
    state_dir: &Path,
    job_id: u64,
    token: StartToken,
    mut record: AgentRecord,
) -> Result<(), AgentError> {
    let shared_root = PathBuf::from(&record.shared_root).canonicalize()?;
    if super::verbose_output_conflict(
        &record,
        &shared_root,
        &[
            Path::new(&record.spec.stdout_path),
            Path::new(&record.spec.stderr_path),
        ],
    )? {
        return super::fail_record(state_dir, record, super::RESERVED_VERBOSE_OUTPUT_ERROR);
    }
    let output_roots = super::permitted_output_roots(&record, &shared_root)?;
    let local_dir = state_dir.join("jobs").join(job_id.to_string());
    fs::create_dir_all(&local_dir)?;
    fs::set_permissions(&local_dir, fs::Permissions::from_mode(0o700))?;
    let socket_path = local_dir.join("pty.sock");
    let stdout_local = local_dir.join("stdout.log");
    let stderr_local = local_dir.join("stderr.log");
    let stdout_path = super::resolve_output(&record.spec.stdout_path, job_id, &output_roots)?;
    let stderr_path = super::resolve_output(&record.spec.stderr_path, job_id, &output_roots)?;
    if super::verbose_output_conflict(&record, &shared_root, &[&stdout_path, &stderr_path])? {
        return super::fail_record(state_dir, record, super::RESERVED_VERBOSE_OUTPUT_ERROR);
    }
    if stdout_path == stderr_path {
        return super::fail_record(
            state_dir,
            record,
            "stdout and stderr resolve to the same path",
        );
    }
    if stdout_path.exists() || stderr_path.exists() {
        return super::fail_record(state_dir, record, "output path already exists");
    }

    let verbose_logs = record
        .spec
        .env
        .get(macluster_protocol::types::VERBOSE_TASK_LOG_ENV)
        .is_some_and(|value| value == "1");
    let mut stdout_log = if verbose_logs {
        None
    } else {
        Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&stdout_local)?,
        )
    };
    let stderr_log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stderr_local)?;
    drop(stderr_log);

    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;

    // Do not start user code before the authorized terminal has attached. This
    // prevents short commands from exiting before msub receives their output.
    let (mut attachment, initial_window) =
        match wait_for_attachment(&listener, job_id, token, state_dir)? {
            Some(attachment) => attachment,
            None => {
                let _ = fs::remove_file(&socket_path);
                let _ = fs::remove_file(&stdout_local);
                let _ = fs::remove_file(&stderr_local);
                // The task never started, so there is no output to sync. A
                // cancellation in wait_for_attachment() may have finalized
                // the record and marked logs pending before reaching here.
                let mut record = crate::active_record(state_dir, job_id, token)?;
                record.log_sync_pending = false;
                crate::write_active(state_dir, record)?;
                return Ok(());
            }
        };
    attachment.set_nonblocking(true)?;

    let (mut master, slave) = create_pty_with_size(initial_window.0, initial_window.1)?;
    let task_command = build_interactive_command(state_dir, job_id, &record)?;
    let gate_path = local_dir.join(format!(".task-gate-{}", Id128::random()));
    let mut command = super::gated_task_command(task_command, &gate_path);
    super::configure_task_environment(&mut command, job_id, &record)?;
    command
        .current_dir(&record.spec.cwd)
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // `setsid` gives the task a process group of its own. The slave is already
    // installed as all three standard streams when it becomes the controlling
    // terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let message = format!("\r\nmacluster: could not start interactive task: {error}\r\n");
            let _ = attachment.write_all(message.as_bytes());
            let _ = fs::remove_file(&socket_path);
            return super::fail_record(
                state_dir,
                record,
                &format!("could not start interactive task: {error}"),
            );
        }
    };
    let child_pid = child.id();
    let mut log_session = if verbose_logs {
        match super::task_logs::TaskLogSession::start_pty(
            &local_dir,
            record.controller.controller_uuid.to_string(),
            record.share_uuid.clone(),
            job_id,
            token,
        ) {
            Ok(session) => Some(session),
            Err(error) => {
                super::signal_group(child_pid, libc::SIGKILL);
                let _ = child.wait();
                let _ = fs::remove_file(&socket_path);
                return super::fail_record(
                    state_dir,
                    record,
                    &format!("could not start verbose PTY logging: {error}"),
                );
            }
        }
    } else {
        None
    };
    let Some(child_start_id) = crate::wait_for_process_start_identity(child_pid) else {
        super::signal_group(child_pid, libc::SIGKILL);
        let _ = child.wait();
        if let Some(session) = log_session.take() {
            let _ = session.finish();
        }
        let _ = fs::remove_file(&socket_path);
        return super::fail_record(
            state_dir,
            record,
            "could not verify interactive task process identity",
        );
    };
    record.child_pid = Some(child_pid);
    record.child_start_id = Some(child_start_id);
    record.phase = RuntimePhase::Running;
    if let Err(error) = crate::write_active(state_dir, record.clone()) {
        super::signal_group(child_pid, libc::SIGKILL);
        let _ = child.wait();
        if let Some(session) = log_session.take() {
            let _ = session.finish();
        }
        let _ = fs::remove_file(&socket_path);
        return Err(error);
    }
    if let Err(error) = super::release_task_gate(&gate_path) {
        super::signal_group(child_pid, libc::SIGKILL);
        let _ = child.wait();
        if let Some(session) = log_session.take() {
            let _ = session.finish();
        }
        let _ = fs::remove_file(&gate_path);
        let _ = fs::remove_file(&socket_path);
        return super::fail_record(
            state_dir,
            record,
            &format!("could not release interactive task start gate: {error}"),
        );
    }

    let result = supervise_pty(
        state_dir,
        &mut child,
        &mut master,
        &mut attachment,
        stdout_log.as_mut(),
        log_session.as_mut(),
        job_id,
        token,
        child_pid,
        record.spec.walltime_secs,
    );
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            super::signal_group(child_pid, libc::SIGTERM);
            let began = Instant::now();
            while child.try_wait()?.is_none() && began.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(25));
            }
            if child.try_wait()?.is_none() {
                super::signal_group(child_pid, libc::SIGKILL);
                let _ = child.wait();
            }
            TaskResult {
                state: JobState::Failed,
                exit_code: child.try_wait()?.and_then(|status| status.code()),
                reason: Some(format!("interactive PTY runner failed: {error}")),
            }
        }
    };
    let mut result = result;
    if let Some(session) = log_session.take() {
        match session.finish() {
            Ok(completion) => {
                if let Some(reason) = completion.raw_capture_failed {
                    result.state = JobState::Failed;
                    result.reason = Some(format!("raw PTY log capture failed: {reason}"));
                }
                if let Some(reason) = completion.annotation_failed {
                    eprintln!("macluster-agent: enhanced task log failed: {reason}");
                }
            }
            Err(error) => {
                eprintln!("macluster-agent: could not seal enhanced PTY logs: {error}");
            }
        }
    }
    crate::finalize_active(
        state_dir,
        job_id,
        token,
        result.state,
        result.exit_code,
        result.reason,
    )?;
    let _ = fs::remove_file(&socket_path);
    Ok(())
}

struct TaskResult {
    state: JobState,
    exit_code: Option<i32>,
    reason: Option<String>,
}

fn wait_for_attachment(
    listener: &UnixListener,
    job_id: u64,
    token: StartToken,
    state_dir: &Path,
) -> Result<Option<(UnixStream, (u16, u16))>, AgentError> {
    loop {
        let record = crate::active_record(state_dir, job_id, token)?;
        if record.terminal() {
            return Ok(None);
        }
        if let Some(cause) = record.termination_cause {
            crate::finalize_active(state_dir, job_id, token, cause, None, record.end_reason)?;
            return Ok(None);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // On macOS, an accepted socket can inherit the listener's
                // nonblocking mode. Normalize it before the timed handshake.
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(ATTACH_HANDSHAKE_TIMEOUT))?;
                let mut handshake = [0_u8; 53];
                let accepted = stream.read_exact(&mut handshake).is_ok()
                    && &handshake[..5] == ATTACH_MAGIC
                    && u64::from_be_bytes(handshake[5..13].try_into().expect("fixed field"))
                        == job_id
                    && &handshake[17..] == token.to_string().as_bytes();
                if accepted {
                    let rows =
                        u16::from_be_bytes(handshake[13..15].try_into().expect("fixed field"));
                    let cols =
                        u16::from_be_bytes(handshake[15..17].try_into().expect("fixed field"));
                    stream.write_all(&[0])?;
                    stream.set_read_timeout(None)?;
                    return Ok(Some((stream, (rows, cols))));
                }
                let _ = stream.write_all(&[1]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
fn create_pty() -> io::Result<(File, File)> {
    create_pty_with_size(24, 80)
}

fn create_pty_with_size(rows: u16, cols: u16) -> io::Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    let mut window = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty writes two fresh descriptors to the provided pointers.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut window,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openpty returned uniquely owned descriptors.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: successful openpty returned uniquely owned descriptors.
    let slave = unsafe { File::from_raw_fd(slave) };
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok((master, slave))
}

fn build_interactive_command(
    state_dir: &Path,
    job_id: u64,
    record: &AgentRecord,
) -> Result<Command, AgentError> {
    if record.spec.snapshot.is_some() {
        super::build_task_command(&crate::local_script_path(state_dir, job_id))
    } else {
        let shell = login_shell();
        let mut command = Command::new(&shell);
        match shell.file_name().and_then(|name| name.to_str()) {
            Some("zsh") => {
                command.args(["-f", "-i"]);
            }
            Some("bash") => {
                command.args(["--noprofile", "--norc", "-i"]);
            }
            Some("fish") => {
                command.args(["--no-config", "-i"]);
            }
            Some("csh" | "tcsh") => {
                command.args(["-f", "-i"]);
            }
            _ => {
                command.arg("-i");
            }
        }
        Ok(command)
    }
}

fn login_shell() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    let passwd = unsafe { libc::getpwuid(uid) };
    if !passwd.is_null() {
        let shell = unsafe { (*passwd).pw_shell };
        if !shell.is_null() {
            let value = unsafe { std::ffi::CStr::from_ptr(shell) }.to_string_lossy();
            if value.starts_with('/') && Path::new(value.as_ref()).is_file() {
                return PathBuf::from(value.as_ref());
            }
        }
    }
    PathBuf::from("/bin/zsh")
}

fn supervise_pty(
    state_dir: &Path,
    child: &mut Child,
    master: &mut File,
    attachment: &mut UnixStream,
    mut output_log: Option<&mut File>,
    mut log_session: Option<&mut super::task_logs::TaskLogSession>,
    job_id: u64,
    token: StartToken,
    pgid: u32,
    walltime: Option<u64>,
) -> Result<TaskResult, AgentError> {
    let start = super::continuous_time_ns();
    let timeout = walltime.map(|seconds| u128::from(seconds).saturating_mul(1_000_000_000));
    let mut termination: Option<(JobState, String, Instant)> = None;
    let mut input_buffer = Vec::new();
    let mut pending_input = VecDeque::new();
    let mut pending_output = VecDeque::new();
    let mut child_status = None;
    let mut pty_eof = false;
    let mut attachment_open = true;
    let mut kill_started = false;
    let mut next_sample = Instant::now();
    let mut last_output_at = next_sample;
    let mut last_heartbeat_at = next_sample;
    let mut observed_output_bytes = 0;
    if let Some(session) = log_session.as_deref_mut() {
        session.initialize_sample(pgid);
        next_sample += Duration::from_secs(5);
    }

    loop {
        if let Some(session) = log_session.as_deref_mut() {
            let now = Instant::now();
            let output_bytes = session.output_bytes();
            if output_bytes != observed_output_bytes {
                observed_output_bytes = output_bytes;
                last_output_at = now;
            }
            if now >= next_sample {
                session.sample(pgid);
                next_sample = now + Duration::from_secs(5);
            }
            if now.duration_since(last_output_at) >= Duration::from_secs(5)
                && now.duration_since(last_heartbeat_at) >= Duration::from_secs(5)
            {
                session.heartbeat();
                last_heartbeat_at = now;
            }
        }
        let record = crate::active_record(state_dir, job_id, token)?;
        if termination.is_none() {
            if let Some(cause) = record.termination_cause {
                let reason = record
                    .end_reason
                    .clone()
                    .unwrap_or_else(|| "interactive task termination requested".into());
                termination = Some((cause, reason, Instant::now()));
                super::signal_group(
                    pgid,
                    if cause == JobState::Cancelled && record.force_cancel {
                        libc::SIGKILL
                    } else {
                        libc::SIGTERM
                    },
                );
            } else if timeout
                .is_some_and(|timeout| super::continuous_time_ns().saturating_sub(start) >= timeout)
            {
                crate::mark_termination_cause(
                    state_dir,
                    job_id,
                    token,
                    JobState::Timeout,
                    "walltime limit reached",
                )?;
                termination = Some((
                    JobState::Timeout,
                    "walltime limit reached".into(),
                    Instant::now(),
                ));
                super::signal_group(pgid, libc::SIGTERM);
            }
        }
        if let Some((state, reason, began)) = termination.as_ref() {
            if *state == JobState::Cancelled && record.force_cancel {
                super::signal_group(pgid, libc::SIGKILL);
                kill_started = true;
            } else if reason == "interactive attachment closed"
                && began.elapsed() >= Duration::from_secs(2)
            {
                super::signal_group(pgid, libc::SIGKILL);
                kill_started = true;
            } else if reason == "interactive attachment closed"
                && began.elapsed() >= Duration::from_secs(1)
            {
                super::signal_group(pgid, libc::SIGTERM);
            } else if began.elapsed() >= Duration::from_secs(30) {
                super::signal_group(pgid, libc::SIGKILL);
                kill_started = true;
            }
            let _ = reason;
        }

        if child_status.is_none() {
            child_status = child.try_wait()?;
            if child_status.is_some() && termination.is_none() && super::group_exists(pgid) {
                let reason = "interactive task exited while background descendants remained; descendant processes were terminated";
                super::terminate_group(pgid, Instant::now());
                termination = Some((JobState::Failed, reason.into(), Instant::now()));
            }
        }

        if attachment_open {
            let mut fds = [
                libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: if pty_eof || pending_output.len() >= MAX_PENDING_BYTES {
                        0
                    } else {
                        libc::POLLIN | libc::POLLHUP | libc::POLLERR
                    },
                    revents: 0,
                },
                libc::pollfd {
                    fd: attachment.as_raw_fd(),
                    events: libc::POLLIN
                        | libc::POLLHUP
                        | libc::POLLERR
                        | if pending_output.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                    revents: 0,
                },
            ];
            let polled = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 100) };
            if polled == -1 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
            if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                read_pty_output(
                    master,
                    output_log.as_deref_mut(),
                    log_session.as_deref_mut(),
                    &mut pending_output,
                    &mut pty_eof,
                    attachment_open,
                )?;
            }
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                match read_attachment_events(
                    attachment,
                    master,
                    &mut input_buffer,
                    &mut pending_input,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        attachment_open = false;
                        if termination.is_none() && child_status.is_none() {
                            crate::mark_termination_cause(
                                state_dir,
                                job_id,
                                token,
                                JobState::Cancelled,
                                "interactive attachment closed",
                            )?;
                            termination = Some((
                                JobState::Cancelled,
                                "interactive attachment closed".into(),
                                Instant::now(),
                            ));
                            pending_output.clear();
                            super::signal_group(pgid, libc::SIGHUP);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        attachment_open = false;
                        if termination.is_none() && child_status.is_none() {
                            crate::mark_termination_cause(
                                state_dir,
                                job_id,
                                token,
                                JobState::Cancelled,
                                "interactive attachment sent an invalid terminal event",
                            )?;
                            termination = Some((
                                JobState::Cancelled,
                                "interactive attachment sent an invalid terminal event".into(),
                                Instant::now(),
                            ));
                            pending_output.clear();
                            super::signal_group(pgid, libc::SIGHUP);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if attachment_open && fds[1].revents & libc::POLLOUT != 0 {
                flush_output(attachment, &mut pending_output)?;
            }
        } else {
            let mut fds = [libc::pollfd {
                fd: master.as_raw_fd(),
                events: if pty_eof || pending_output.len() >= MAX_PENDING_BYTES {
                    0
                } else {
                    libc::POLLIN | libc::POLLHUP | libc::POLLERR
                },
                revents: 0,
            }];
            let polled = unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) };
            if polled == -1 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
            if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                read_pty_output(
                    master,
                    output_log.as_deref_mut(),
                    log_session.as_deref_mut(),
                    &mut pending_output,
                    &mut pty_eof,
                    false,
                )?;
            }
        }

        flush_input(master, &mut pending_input)?;
        if let Some(status) = child_status
            && pty_eof
            && (pending_output.is_empty() || !attachment_open)
        {
            if let Some((state, reason, _)) = termination {
                return Ok(TaskResult {
                    state,
                    exit_code: status.code(),
                    reason: Some(reason),
                });
            }
            return Ok(if status.success() {
                TaskResult {
                    state: JobState::Completed,
                    exit_code: status.code(),
                    reason: None,
                }
            } else {
                TaskResult {
                    state: JobState::Failed,
                    exit_code: status.code(),
                    reason: Some(super::format_exit(status)),
                }
            });
        }
        if kill_started && child_status.is_none() {
            child_status = Some(child.wait()?);
        }
    }
}

fn read_pty_output(
    master: &mut File,
    mut output_log: Option<&mut File>,
    mut log_session: Option<&mut super::task_logs::TaskLogSession>,
    pending: &mut VecDeque<u8>,
    pty_eof: &mut bool,
    deliver_to_attachment: bool,
) -> io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => {
                *pty_eof = true;
                return Ok(());
            }
            Ok(count) => {
                if let Some(session) = log_session.as_deref_mut() {
                    session.append_pty_output(&buffer[..count])?;
                } else if let Some(output_log) = output_log.as_deref_mut() {
                    output_log.write_all(&buffer[..count])?;
                } else {
                    return Err(io::Error::other("interactive output logger is unavailable"));
                }
                if deliver_to_attachment {
                    pending.extend(&buffer[..count]);
                }
                if deliver_to_attachment && pending.len() >= MAX_PENDING_BYTES {
                    return Ok(());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            // macOS reports EIO when the PTY slave has been closed.
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                *pty_eof = true;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn read_attachment_events(
    attachment: &mut UnixStream,
    master: &mut File,
    buffered: &mut Vec<u8>,
    pending_input: &mut VecDeque<u8>,
) -> io::Result<bool> {
    let mut data = [0_u8; 16 * 1024];
    match attachment.read(&mut data) {
        Ok(0) => return Ok(false),
        Ok(count) => buffered.extend_from_slice(&data[..count]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok(true),
        Err(error) => return Err(error),
    }
    let mut consumed = 0;
    loop {
        let available = &buffered[consumed..];
        let Some(kind) = available.first().copied() else {
            break;
        };
        match kind {
            EVENT_INPUT => {
                if available.len() < 5 {
                    break;
                }
                let len =
                    u32::from_be_bytes(available[1..5].try_into().expect("fixed field")) as usize;
                if len > MAX_EVENT_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "terminal input event is too large",
                    ));
                }
                if available.len() < 5 + len {
                    break;
                }
                pending_input.extend(&available[5..5 + len]);
                consumed += 5 + len;
            }
            EVENT_RESIZE => {
                if available.len() < 5 {
                    break;
                }
                let cols = u16::from_be_bytes([available[1], available[2]]);
                let rows = u16::from_be_bytes([available[3], available[4]]);
                set_window_size(master.as_raw_fd(), rows, cols)?;
                consumed += 5;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown terminal event",
                ));
            }
        }
    }
    if consumed > 0 {
        buffered.drain(..consumed);
    }
    if buffered.len() > MAX_EVENT_BYTES + 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete terminal event is too large",
        ));
    }
    Ok(true)
}

fn flush_input(master: &mut File, pending: &mut VecDeque<u8>) -> io::Result<()> {
    while !pending.is_empty() {
        let (first, second) = pending.as_slices();
        let slice = if first.is_empty() { second } else { first };
        match master.write(slice) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "PTY write returned 0",
                ));
            }
            Ok(count) => {
                pending.drain(..count);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn flush_output(attachment: &mut UnixStream, pending: &mut VecDeque<u8>) -> io::Result<()> {
    while !pending.is_empty() {
        let (first, second) = pending.as_slices();
        let slice = if first.is_empty() { second } else { first };
        match attachment.write(slice) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned 0",
                ));
            }
            Ok(count) => {
                pending.drain(..count);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn set_window_size(fd: i32, rows: u16, cols: u16) -> io::Result<()> {
    let window = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &window) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::run;
    use macluster_protocol::{
        identifiers::{ControllerUuid, Id128, QueueName},
        types::{ControllerEpoch, JobMode, JobSpec, JobState, RuntimePhase, SnapshotRef},
    };
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        os::fd::AsRawFd,
        os::unix::net::UnixStream,
        path::PathBuf,
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    fn ready_interactive_state(
        script: Option<&str>,
        walltime: Option<u64>,
    ) -> (PathBuf, PathBuf, StartToken) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Keep the nested Unix-domain socket path below macOS SUN_LEN.
        let root = interactive_test_root(nonce);
        let state_dir = root.join("agent");
        let shared = root.join("shared");
        let job_dir = state_dir.join("jobs/1");
        fs::create_dir_all(&job_dir).unwrap();
        fs::create_dir_all(shared.join("projects")).unwrap();
        fs::write(
            shared.join(".macluster-share-id"),
            "00000000-0000-4000-8000-000000000001\n",
        )
        .unwrap();
        if let Some(script) = script {
            fs::write(job_dir.join("script.sh"), script).unwrap();
        }
        let shared = shared.canonicalize().unwrap();
        let token = StartToken(Id128::random());
        let spec = JobSpec {
            storage_namespace: None,
            queue: QueueName::new("mini01").unwrap(),
            node: None,
            name: "interactive-test".into(),
            cwd: shared.join("projects").to_string_lossy().into_owned(),
            stdout_path: shared
                .join("jobs/%j/stdout.log")
                .to_string_lossy()
                .into_owned(),
            stderr_path: shared
                .join("jobs/%j/stderr.log")
                .to_string_lossy()
                .into_owned(),
            walltime_secs: walltime,
            env: BTreeMap::new(),
            mode: JobMode::Interactive,
            snapshot: script.map(|script| SnapshotRef {
                sha256: "a".repeat(64),
                size_bytes: script.len() as u64,
            }),
        };
        let record = AgentRecord {
            controller: ControllerEpoch {
                controller_uuid: ControllerUuid(Id128::random()),
                epoch: 1,
            },
            start_token: token,
            job_id: 1,
            node_id: "mini01-a".into(),
            shared_root: shared.to_string_lossy().into_owned(),
            tool_paths: Vec::new(),
            named_shares: Vec::new(),
            spec,
            phase: RuntimePhase::Launching,
            authorized: true,
            runner_pid: Some(std::process::id()),
            runner_start_id: crate::process_start_identity(std::process::id()),
            child_pid: None,
            child_start_id: None,
            task_start_gated: true,
            share_uuid: Some("00000000-0000-4000-8000-000000000001".into()),
            storage_node_id: Some("mini01-a".into()),
            storage_host: Some("127.0.0.1".into()),
            storage_source_root: Some(shared.to_string_lossy().into_owned()),
            terminal_state: None,
            exit_code: None,
            end_reason: None,
            termination_cause: None,
            cancel_requested: false,
            force_cancel: false,
            boot_id: "boot".into(),
            log_sync_pending: false,
            log_sync_retry_after_unix_ms: None,
            started_unix_ms: 1,
        };
        let store = crate::AgentStore {
            controller: Some(record.controller),
            active: Some(record),
            tombstones: Vec::new(),
            log_sync_shutdown: None,
            ..Default::default()
        };
        crate::write_store(&state_dir, &store).unwrap();
        (root, state_dir, token)
    }

    fn interactive_test_root(nonce: u128) -> PathBuf {
        PathBuf::from("/tmp").join(format!(
            "mci-{}-{nonce:x}-{}",
            std::process::id(),
            Id128::random()
        ))
    }

    #[test]
    fn interactive_test_roots_are_unique_even_with_the_same_timestamp() {
        assert_ne!(interactive_test_root(123), interactive_test_root(123));
    }

    fn attach_socket(state_dir: &Path, job_id: u64, token: StartToken) -> UnixStream {
        let (stream, response) = attach_socket_with_window(state_dir, job_id, token, 24, 80);
        assert_eq!(response, [0], "attachment was rejected");
        stream
    }

    fn attach_socket_with_window(
        state_dir: &Path,
        job_id: u64,
        token: StartToken,
        rows: u16,
        cols: u16,
    ) -> (UnixStream, [u8; 1]) {
        let socket = state_dir
            .join("jobs")
            .join(job_id.to_string())
            .join("pty.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match UnixStream::connect(&socket) {
                Ok(mut stream) => {
                    stream.write_all(ATTACH_MAGIC).unwrap();
                    stream.write_all(&job_id.to_be_bytes()).unwrap();
                    stream.write_all(&rows.to_be_bytes()).unwrap();
                    stream.write_all(&cols.to_be_bytes()).unwrap();
                    stream.write_all(token.to_string().as_bytes()).unwrap();
                    let mut response = [0_u8; 1];
                    stream.read_exact(&mut response).unwrap();
                    return (stream, response);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    assert!(Instant::now() < deadline, "PTY socket was not created");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("could not connect to PTY socket: {error}"),
            }
        }
    }

    fn send_input(stream: &mut UnixStream, input: &[u8]) {
        stream.write_all(&[1]).unwrap();
        stream
            .write_all(&(input.len() as u32).to_be_bytes())
            .unwrap();
        stream.write_all(input).unwrap();
    }

    fn run_in_thread(state_dir: PathBuf, token: StartToken) -> thread::JoinHandle<()> {
        thread::spawn(move || run(&state_dir, 1, token).unwrap())
    }

    #[test]
    fn interactive_task_path_keeps_shared_tools_and_excludes_unshared_host_tools() {
        let (root, state_dir, token) = ready_interactive_state(
            Some("#!/bin/bash\nprintf '%s\\n' \"$PATH\"\nexit 0\n"),
            None,
        );
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.spec.env.insert(
            "PATH".into(),
            "/shared/tools/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/login/tools/bin"
                .into(),
        );
        record.tool_paths = vec!["/shared/tools".into(), "/shared/tools/bin".into()];
        crate::write_store(&state_dir, &store).unwrap();

        let runner = run_in_thread(state_dir.clone(), token);
        let mut attachment = attach_socket(&state_dir, 1, token);
        let mut output = Vec::new();
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();

        let path = String::from_utf8_lossy(&output);
        let path = path.trim();
        let entries: Vec<_> = path.split(':').collect();
        assert!(entries.contains(&"/shared/tools/bin"), "{path}");
        assert!(!entries.contains(&"/opt/homebrew/bin"), "{path}");
        assert!(!entries.contains(&"/usr/local/bin"), "{path}");
        assert!(!entries.contains(&"/login/tools/bin"), "{path}");
        let shared_root = fs::canonicalize(root.join("shared")).unwrap();
        assert!(
            path.split(':')
                .any(|entry| entry == shared_root.to_string_lossy()),
            "primary shared root is missing from task PATH: {path}"
        );
        assert!(
            path.split(':')
                .any(|entry| entry == shared_root.join("bin").to_string_lossy()),
            "primary shared bin directory is missing from task PATH: {path}"
        );
        let share_bin = entries
            .iter()
            .position(|entry| *entry == "/shared/tools/bin")
            .unwrap();
        let system_bin = entries
            .iter()
            .position(|entry| *entry == "/usr/bin")
            .unwrap();
        assert!(share_bin < system_bin, "{path}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interactive_shell_does_not_reintroduce_compute_homebrew_from_startup_files() {
        if super::login_shell()
            .file_name()
            .is_none_or(|name| name != "zsh")
        {
            return;
        }
        let (root, state_dir, token) = ready_interactive_state(None, None);
        let shell_config = root.join("compute-shell-config");
        fs::create_dir_all(&shell_config).unwrap();
        fs::write(
            shell_config.join(".zshrc"),
            "export PATH=/compute/homebrew/bin\n",
        )
        .unwrap();

        let shared_root = fs::canonicalize(root.join("shared")).unwrap();
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.spec.env.insert(
            "PATH".into(),
            format!("{}:/usr/bin:/bin", shared_root.join("bin").display()),
        );
        record.spec.env.insert(
            "ZDOTDIR".into(),
            shell_config.to_string_lossy().into_owned(),
        );
        crate::write_store(&state_dir, &store).unwrap();

        let runner = run_in_thread(state_dir.clone(), token);
        let mut attachment = attach_socket(&state_dir, 1, token);
        send_input(
            &mut attachment,
            b"printf '__TASK_PATH__=%s\\n' \"$PATH\"; exit 0\n",
        );
        let mut output = Vec::new();
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();
        let output = String::from_utf8_lossy(&output);

        assert!(output.contains(&format!(
            "__TASK_PATH__={}",
            shared_root.join("bin").display()
        )));
        assert!(!output.contains("/compute/homebrew/bin"), "{output}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn activated_nested_shared_mamba_environment_keeps_python_priority() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mamba_root = root.join("mamba");
        let base_bin = mamba_root.join("bin");
        let activated_bin = mamba_root.join("envs/analysis/bin");
        fs::create_dir_all(&base_bin).unwrap();
        fs::create_dir_all(&activated_bin).unwrap();
        let base_python = base_bin.join("python");
        let activated_python = activated_bin.join("python");
        fs::write(&base_python, "#!/bin/sh\necho BASE\n").unwrap();
        fs::write(&activated_python, "#!/bin/sh\necho JXFU\n").unwrap();
        fs::set_permissions(&base_python, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&activated_python, fs::Permissions::from_mode(0o755)).unwrap();

        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.spec.env.insert(
            "PATH".into(),
            format!("{}:/usr/bin:/bin", activated_bin.display()),
        );
        record.tool_paths = vec![
            mamba_root.to_string_lossy().into_owned(),
            base_bin.to_string_lossy().into_owned(),
        ];
        let path = super::super::task_path(record);
        crate::write_store(&state_dir, &store).unwrap();

        let output = Command::new("/bin/sh")
            .args(["-c", "python"])
            .env("PATH", path)
            .output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "JXFU\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn task_path_prefers_active_nested_virtualenv() {
        let (fixture_root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        let software_root = Path::new(&record.shared_root).join("software");
        let venv_bin = software_root.join("envs/analysis/bin");
        record.spec.env.insert(
            "PATH".into(),
            format!(
                "{}:{}:/usr/bin:/bin",
                venv_bin.display(),
                software_root.join("bin").display()
            ),
        );
        record.tool_paths = vec![
            software_root.to_string_lossy().into_owned(),
            software_root.join("bin").to_string_lossy().into_owned(),
        ];

        let path = super::super::task_path(record);

        assert_eq!(
            path.split(':').next(),
            Some(venv_bin.to_string_lossy().as_ref())
        );
        assert!(path.contains(&software_root.join("bin").to_string_lossy().to_string()));
        fs::remove_dir_all(fixture_root).unwrap();
    }

    #[test]
    fn task_path_prefers_active_conda_prefix() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        let mamba_root = Path::new(&record.shared_root).join("mamba");
        let active_bin = mamba_root.join("envs/analysis/bin");
        record.spec.env.insert(
            "PATH".into(),
            format!(
                "{}:{}:/usr/bin:/bin",
                active_bin.display(),
                mamba_root.join("bin").display()
            ),
        );
        record.tool_paths = vec![
            mamba_root.to_string_lossy().into_owned(),
            mamba_root.join("bin").to_string_lossy().into_owned(),
        ];

        let path = super::super::task_path(record);

        assert_eq!(
            path.split(':').next(),
            Some(active_bin.to_string_lossy().as_ref())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn task_path_respects_explicit_path_override() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record
            .spec
            .env
            .insert("PATH".into(), "/usr/bin:/bin".into());
        record.spec.env.insert(
            macluster_protocol::types::EXPLICIT_TASK_PATH_ENV.into(),
            "1".into(),
        );
        record.tool_paths = vec!["/shared/mamba".into(), "/shared/mamba/bin".into()];

        let path = super::super::task_path(record);

        assert_eq!(path, "/usr/bin:/bin");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn task_path_never_falls_back_to_compute_local_tools() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        record.spec.env.insert(
            "PATH".into(),
            "/login-only/bin:/opt/homebrew/bin:/usr/bin:/bin".into(),
        );
        record.tool_paths = vec!["/shared/mamba".into(), "/shared/mamba/bin".into()];

        let path = super::super::task_path(record);

        assert!(!path.contains("/login-only/bin"), "{path}");
        assert!(!path.contains("/opt/homebrew/bin"), "{path}");
        assert!(path.split(':').any(|entry| entry == "/usr/bin"), "{path}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cargo_target_cache_reuses_same_cluster_project_environment() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_ref().unwrap();

        let first = super::super::cargo_target_directory(record).unwrap();
        let second = super::super::cargo_target_directory(record).unwrap();

        assert_eq!(first, second);
        assert!(
            first.starts_with(
                std::env::temp_dir()
                    .canonicalize()
                    .unwrap()
                    .join("macluster/cargo-target")
            )
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cargo_target_cache_separates_cluster_project_environment() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();
        let original = super::super::cargo_target_directory(record).unwrap();
        let original_cwd = record.spec.cwd.clone();

        let other_project = root.join("shared/other-project");
        fs::create_dir_all(&other_project).unwrap();
        record.spec.cwd = other_project.to_string_lossy().into_owned();
        let project = super::super::cargo_target_directory(record).unwrap();
        assert_ne!(original, project);

        record.spec.cwd = original_cwd;
        record.spec.env.insert(
            macluster_protocol::types::ACTIVE_ENV_PREFIX_ENV.into(),
            "/shared/envs/other".into(),
        );
        let environment = super::super::cargo_target_directory(record).unwrap();
        assert_ne!(original, environment);

        record
            .spec
            .env
            .remove(macluster_protocol::types::ACTIVE_ENV_PREFIX_ENV);
        record.spec.storage_namespace = Some(macluster_protocol::identifiers::Id128::random());
        let cluster = super::super::cargo_target_directory(record).unwrap();
        assert_ne!(original, cluster);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cargo_target_cache_preserves_explicit_overrides() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();

        for value in ["target", "/custom/cargo-target"] {
            record
                .spec
                .env
                .insert("CARGO_TARGET_DIR".into(), value.into());
            assert_eq!(
                super::super::cargo_target_directory(record).unwrap(),
                PathBuf::from(value)
            );
            assert!(!super::super::cargo_target_is_managed(record));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compiler_caches_are_node_local_reusable_and_toolchain_scoped() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();

        let ccache =
            super::super::compiler_cache_directory(record, "CCACHE_DIR", "ccache").unwrap();
        let same_ccache =
            super::super::compiler_cache_directory(record, "CCACHE_DIR", "ccache").unwrap();
        let sccache =
            super::super::compiler_cache_directory(record, "SCCACHE_DIR", "sccache").unwrap();
        assert_eq!(ccache, same_ccache);
        assert_ne!(ccache, sccache);
        assert!(ccache.starts_with(std::env::temp_dir().canonicalize().unwrap()));

        record
            .spec
            .env
            .insert("CC".into(), "/shared/toolchain/bin/clang".into());
        let changed_toolchain =
            super::super::compiler_cache_directory(record, "CCACHE_DIR", "ccache").unwrap();
        assert_ne!(ccache, changed_toolchain);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn compiler_cache_directories_preserve_explicit_overrides() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();

        for value in ["cache", "/custom/cache"] {
            record.spec.env.insert("CCACHE_DIR".into(), value.into());
            assert_eq!(
                super::super::compiler_cache_directory(record, "CCACHE_DIR", "ccache").unwrap(),
                PathBuf::from(value)
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cargo_home_uses_a_private_node_cache_when_not_shared() {
        let (root, state_dir, _) = ready_interactive_state(None, None);
        let mut store = crate::read_store(&state_dir).unwrap();
        let record = store.active.as_mut().unwrap();

        let cargo_home = super::super::cargo_home_directory(record).unwrap();
        assert!(super::super::cargo_home_is_managed(record));
        assert!(
            cargo_home.starts_with(
                std::env::temp_dir()
                    .canonicalize()
                    .unwrap()
                    .join("macluster/cargo-home")
            )
        );

        record
            .spec
            .env
            .insert("CARGO_HOME".into(), "registry-cache".into());
        assert_eq!(
            super::super::cargo_home_directory(record).unwrap(),
            PathBuf::from("registry-cache")
        );
        assert!(!super::super::cargo_home_is_managed(record));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_pty_shell_accepts_input_and_streams_output() {
        let (root, state_dir, token) = ready_interactive_state(None, None);
        let runner = run_in_thread(state_dir.clone(), token);
        let mut attachment = attach_socket(&state_dir, 1, token);
        send_input(&mut attachment, b"echo INTERACTIVE_PTY_MARKER; exit 0\n");
        let mut output = Vec::new();
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("INTERACTIVE_PTY_MARKER"), "{output}");
        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Completed));
        assert!(record.log_sync_pending);
        crate::runner::publish_logs_for_test(&state_dir, record).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("shared/jobs/1/stdout.log")).unwrap(),
            output
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn initial_terminal_size_is_applied_before_interactive_command_starts() {
        let (root, state_dir, token) = ready_interactive_state(Some("stty size\nexit 0\n"), None);
        let runner = run_in_thread(state_dir.clone(), token);
        let (mut attachment, response) = attach_socket_with_window(&state_dir, 1, token, 33, 91);
        if response != [0] {
            drop(attachment);
            crate::mark_termination_cause(
                &state_dir,
                1,
                token,
                JobState::Cancelled,
                "test attach rejected",
            )
            .unwrap();
            runner.join().unwrap();
            fs::remove_dir_all(&root).unwrap();
            panic!("initial-size attach handshake was rejected: {response:?}");
        }
        let mut output = Vec::new();
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();
        assert!(
            String::from_utf8_lossy(&output).contains("33 91"),
            "command did not start with the attached terminal size: {}",
            String::from_utf8_lossy(&output)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attach_accepts_handshake_split_by_a_brief_scheduler_delay() {
        let (root, state_dir, token) =
            ready_interactive_state(Some("read -r value\necho VALUE:$value\nexit 0\n"), None);
        let runner = run_in_thread(state_dir.clone(), token);
        let socket = state_dir.join("jobs/1/pty.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut slow = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    assert!(Instant::now() < deadline, "PTY socket was not created");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("could not connect to PTY socket: {error}"),
            }
        };
        let mut handshake = Vec::with_capacity(53);
        handshake.extend_from_slice(ATTACH_MAGIC);
        handshake.extend_from_slice(&1_u64.to_be_bytes());
        handshake.extend_from_slice(&24_u16.to_be_bytes());
        handshake.extend_from_slice(&80_u16.to_be_bytes());
        handshake.extend_from_slice(token.to_string().as_bytes());
        slow.write_all(&handshake[..17]).unwrap();
        thread::sleep(Duration::from_millis(300));
        let sent_remaining = slow.write_all(&handshake[17..]).is_ok();
        let mut response = [1_u8; 1];
        let read_response = slow.read_exact(&mut response).is_ok();
        let accepted = sent_remaining && read_response && response == [0];

        let mut output = Vec::new();
        if accepted {
            send_input(&mut slow, b"go\n");
            slow.read_to_end(&mut output).unwrap();
        } else {
            drop(slow);
            let mut attachment = attach_socket(&state_dir, 1, token);
            send_input(&mut attachment, b"go\n");
            attachment.read_to_end(&mut output).unwrap();
        }
        runner.join().unwrap();
        let output = String::from_utf8_lossy(&output);
        fs::remove_dir_all(root).unwrap();
        assert!(
            accepted,
            "attach rejected a valid delayed handshake (sent={sent_remaining}, read={read_response}, response={response:?})"
        );
        assert!(output.contains("VALUE:go"), "{output}");
    }

    #[test]
    fn attach_rejects_wrong_start_token() {
        let (root, state_dir, token) = ready_interactive_state(None, None);
        let runner = run_in_thread(state_dir.clone(), token);
        let socket = state_dir.join("jobs/1/pty.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut wrong = loop {
            match UnixStream::connect(&socket) {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        || error.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    assert!(Instant::now() < deadline, "PTY socket was not created");
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("could not connect to PTY socket: {error}"),
            }
        };
        let mut handshake = Vec::with_capacity(53);
        handshake.extend_from_slice(ATTACH_MAGIC);
        handshake.extend_from_slice(&1_u64.to_be_bytes());
        handshake.extend_from_slice(&24_u16.to_be_bytes());
        handshake.extend_from_slice(&80_u16.to_be_bytes());
        handshake.extend_from_slice(StartToken(Id128::random()).to_string().as_bytes());
        wrong.write_all(&handshake).unwrap();
        let mut response = [0_u8; 1];
        wrong.read_exact(&mut response).unwrap();
        assert_eq!(response, [1], "wrong start token must be rejected");
        drop(wrong);

        let mut attachment = attach_socket(&state_dir, 1, token);
        send_input(&mut attachment, b"exit 0\n");
        let mut output = Vec::new();
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn closing_attach_terminates_interactive_child_and_finalizes_job() {
        let (root, state_dir, token) = ready_interactive_state(None, None);
        let runner = run_in_thread(state_dir.clone(), token);
        let mut attachment = attach_socket(&state_dir, 1, token);
        send_input(&mut attachment, b"exec /bin/sleep 60\n");
        thread::sleep(Duration::from_millis(150));
        drop(attachment);
        assert!(
            runner.join().is_ok(),
            "runner did not reap the child after the attachment closed"
        );
        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Cancelled));
        assert!(
            record
                .end_reason
                .as_deref()
                .unwrap_or_default()
                .contains("attach")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interactive_command_exit_code_is_recorded() {
        let (root, state_dir, token) =
            ready_interactive_state(Some("read -r input\necho COMMAND:$input\nexit 23\n"), None);
        let runner = run_in_thread(state_dir.clone(), token);
        let mut attachment = attach_socket(&state_dir, 1, token);
        send_input(&mut attachment, b"go\n");
        let mut output = Vec::new();
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();
        assert!(String::from_utf8_lossy(&output).contains("COMMAND:go"));
        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Failed));
        assert_eq!(record.exit_code, Some(23));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interactive_walltime_expires_and_finalizes_timeout() {
        let (root, state_dir, token) =
            ready_interactive_state(Some("exec /bin/sleep 60\n"), Some(1));
        let runner = run_in_thread(state_dir.clone(), token);
        let attachment = attach_socket(&state_dir, 1, token);
        let mut output = Vec::new();
        let mut attachment = attachment;
        attachment.read_to_end(&mut output).unwrap();
        runner.join().unwrap();
        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Timeout));
        fs::remove_dir_all(root).unwrap();
    }

    fn read_until(master: &mut File, output: &mut Vec<u8>, pattern: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !output
            .windows(pattern.len())
            .any(|window| window == pattern)
        {
            assert!(
                Instant::now() < deadline,
                "terminal output missing {pattern:?}; received {:?}",
                String::from_utf8_lossy(output)
            );
            let mut descriptor = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if ready == -1 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("terminal poll failed: {error}");
            }
            if ready == 0 {
                continue;
            }
            let mut buffer = [0_u8; 2048];
            match master.read(&mut buffer) {
                Ok(0) => panic!("terminal closed before output {pattern:?}"),
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    panic!("terminal closed before output {pattern:?}");
                }
                Err(error) => panic!("terminal read failed: {error}"),
            }
        }
    }

    #[test]
    fn attach_forwards_initial_terminal_size_and_later_resize() {
        let (root, state_dir, token) =
            ready_interactive_state(Some("stty size\nread -r go\nstty size\n"), None);
        let (mut terminal_master, terminal_slave) = create_pty().unwrap();
        set_window_size(terminal_master.as_raw_fd(), 33, 91).unwrap();
        let runner = run_in_thread(state_dir.clone(), token);
        let attach_state = state_dir.clone();
        let attach = thread::spawn(move || {
            let mut input = terminal_slave.try_clone().unwrap();
            let mut output = terminal_slave;
            crate::serve_attach_stdio(&mut input, &mut output, &attach_state, "mini01-a", 1, token)
                .unwrap();
        });
        let mut output = Vec::new();
        read_until(&mut terminal_master, &mut output, b"33 91");
        set_window_size(terminal_master.as_raw_fd(), 52, 133).unwrap();
        thread::sleep(Duration::from_millis(250));
        terminal_master.write_all(b"go\n").unwrap();
        read_until(&mut terminal_master, &mut output, b"52 133");
        runner.join().unwrap();
        attach.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attach_retries_terminal_output_after_would_block() {
        struct WouldBlockOnce {
            file: File,
            writes: u8,
        }

        impl AsRawFd for WouldBlockOnce {
            fn as_raw_fd(&self) -> i32 {
                self.file.as_raw_fd()
            }
        }

        impl Write for WouldBlockOnce {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                match self.writes {
                    0 => {
                        self.writes = 1;
                        self.file.write(&bytes[..bytes.len().min(8)])
                    }
                    1 => {
                        self.writes = 2;
                        Err(std::io::ErrorKind::WouldBlock.into())
                    }
                    _ => self.file.write(bytes),
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.file.flush()
            }
        }

        let (root, state_dir, token) =
            ready_interactive_state(Some("printf 'BACKPRESSURE_MARKER\\n'\n"), None);
        let (mut terminal_master, terminal_slave) = create_pty().unwrap();
        let runner = run_in_thread(state_dir.clone(), token);
        let attach_state = state_dir.clone();
        let attach = thread::spawn(move || {
            let mut input = terminal_slave.try_clone().unwrap();
            let mut output = WouldBlockOnce {
                file: terminal_slave,
                writes: 0,
            };
            crate::serve_attach_stdio(&mut input, &mut output, &attach_state, "mini01-a", 1, token)
        });

        let mut output = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !output
            .windows(b"BACKPRESSURE_MARKER".len())
            .any(|window| window == b"BACKPRESSURE_MARKER")
            && Instant::now() < deadline
        {
            let mut descriptor = libc::pollfd {
                fd: terminal_master.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
            if ready <= 0 {
                continue;
            }
            let mut buffer = [0_u8; 2048];
            match terminal_master.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => output.extend_from_slice(&buffer[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("terminal read failed: {error}"),
            }
        }

        let attach_result = attach.join().unwrap();
        runner.join().unwrap();
        assert!(
            attach_result.is_ok(),
            "transient terminal backpressure must not abort attachment: {attach_result:?}"
        );
        assert!(
            output
                .windows(b"BACKPRESSURE_MARKER".len())
                .any(|window| window == b"BACKPRESSURE_MARKER"),
            "interactive output was truncated: {:?}",
            String::from_utf8_lossy(&output)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attach_waits_until_start_job_persists_the_active_record() {
        let (root, state_dir, token) =
            ready_interactive_state(Some("echo ATTACH_AFTER_START_MARKER; exit 0\n"), None);
        let state_path = state_dir.join("agent-state.json");
        let store: crate::AgentStore = serde_json::from_slice(&fs::read(&state_path).unwrap())
            .expect("read prepared agent state");
        fs::remove_file(&state_path).unwrap();

        let (mut terminal_master, terminal_slave) = create_pty().unwrap();
        let attach_state = state_dir.clone();
        let attach = thread::spawn(move || {
            let mut input = terminal_slave.try_clone().unwrap();
            let mut output = terminal_slave;
            crate::serve_attach_stdio(&mut input, &mut output, &attach_state, "mini01-a", 1, token)
        });
        thread::sleep(Duration::from_millis(50));
        assert!(
            !attach.is_finished(),
            "attach should wait while the controller is still starting the job"
        );

        {
            let _lock = crate::StateLock::acquire(&state_dir).unwrap();
            crate::write_store(&state_dir, &store).unwrap();
        }
        let runner = run_in_thread(state_dir.clone(), token);
        let mut output = Vec::new();
        read_until(
            &mut terminal_master,
            &mut output,
            b"ATTACH_AFTER_START_MARKER",
        );

        runner.join().unwrap();
        attach.join().unwrap().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_before_attach_does_not_leave_logs_pending() {
        let (root, state_dir, token) = ready_interactive_state(Some("echo never-started\n"), None);
        let runner = run_in_thread(state_dir.clone(), token);
        let socket = state_dir.join("jobs/1/pty.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "PTY socket was not created");
            thread::sleep(Duration::from_millis(10));
        }

        crate::mark_termination_cause(
            &state_dir,
            1,
            token,
            JobState::Cancelled,
            "cancelled before attachment",
        )
        .unwrap();
        runner.join().unwrap();

        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Cancelled));
        assert!(!record.log_sync_pending);
        assert!(!state_dir.join("jobs/1/stdout.log").exists());
        assert!(!state_dir.join("jobs/1/stderr.log").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn eof_on_attach_helper_closes_interactive_child_session() {
        let (root, state_dir, token) = ready_interactive_state(Some("exec /bin/sleep 60\n"), None);
        let (terminal_master, terminal_slave) = create_pty().unwrap();
        let runner = run_in_thread(state_dir.clone(), token);
        let attach_state = state_dir.clone();
        let attach = thread::spawn(move || {
            struct EofInput(File);
            impl Read for EofInput {
                fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                    Ok(0)
                }
            }
            impl AsRawFd for EofInput {
                fn as_raw_fd(&self) -> i32 {
                    self.0.as_raw_fd()
                }
            }
            let mut input = EofInput(terminal_slave.try_clone().unwrap());
            let mut output = terminal_slave;
            crate::serve_attach_stdio(&mut input, &mut output, &attach_state, "mini01-a", 1, token)
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while crate::active_record(&state_dir, 1, token)
            .unwrap()
            .child_pid
            .is_none()
        {
            assert!(Instant::now() < deadline, "interactive child did not start");
            thread::sleep(Duration::from_millis(20));
        }
        runner.join().unwrap();
        attach.join().unwrap();
        drop(terminal_master);
        let record = crate::active_record(&state_dir, 1, token).unwrap();
        assert_eq!(record.terminal_state, Some(JobState::Cancelled));
        fs::remove_dir_all(root).unwrap();
    }
}
