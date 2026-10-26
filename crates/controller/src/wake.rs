use std::{
    fs,
    hash::{Hash, Hasher},
    io,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixDatagram,
    },
    path::{Path, PathBuf},
    time::Duration,
};

const MAX_SOCKET_PATH_BYTES: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum WakeError {
    #[error("controller wake socket path is too long: {0}")]
    PathTooLong(PathBuf),
    #[error("controller wake socket I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub struct ControllerWake {
    socket: UnixDatagram,
    path: PathBuf,
}

impl ControllerWake {
    /// Bind the wake socket after acquiring the controller instance lock.
    /// A leftover socket can then only belong to a dead controller process.
    pub fn bind(state_dir: &Path) -> Result<Self, WakeError> {
        fs::create_dir_all(state_dir)?;
        let path = wake_socket_path(state_dir)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&path)?,
            Ok(_) => {
                return Err(WakeError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to replace non-socket {}", path.display()),
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let socket = UnixDatagram::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, path })
    }

    /// Wait for a coalesced notification or the caller's periodic fallback.
    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&self.socket),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        if result == 0 || descriptor.revents & libc::POLLIN == 0 {
            return Ok(false);
        }

        let mut received = false;
        let mut bytes = [0_u8; 64];
        loop {
            match self.socket.recv(&mut bytes) {
                Ok(_) => received = true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(received)
    }
}

impl Drop for ControllerWake {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn notify_controller(state_dir: &Path) -> Result<(), WakeError> {
    let path = wake_socket_path(state_dir)?;
    let socket = UnixDatagram::unbound()?;
    socket.set_nonblocking(true)?;
    match socket.send_to(b"w", &path) {
        Ok(1) => Ok(()),
        Ok(_) => Err(WakeError::Io(io::Error::new(
            io::ErrorKind::WriteZero,
            "controller wake datagram was not sent",
        ))),
        Err(error) => Err(error.into()),
    }
}

fn wake_socket_path(state_dir: &Path) -> Result<PathBuf, WakeError> {
    let canonical = state_dir.canonicalize()?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical.as_os_str().as_encoded_bytes().hash(&mut hasher);
    let path = std::env::temp_dir().join(format!(
        "mcw-{:x}-{:x}.sock",
        unsafe { libc::getuid() },
        hasher.finish()
    ));
    check_path_length(&path)?;
    Ok(path)
}

fn check_path_length(path: &Path) -> Result<(), WakeError> {
    if path.as_os_str().as_encoded_bytes().len() >= MAX_SOCKET_PATH_BYTES {
        return Err(WakeError::PathTooLong(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ControllerWake, WakeError, notify_controller};
    use std::{
        fs, io,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

    struct TempState(PathBuf);

    impl TempState {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "macluster-wake-{}-{}",
                std::process::id(),
                NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn absent_socket_is_a_best_effort_delivery_error() {
        let root = TempState::new();

        let error = notify_controller(root.path()).unwrap_err();

        assert!(
            matches!(error, WakeError::Io(ref error) if error.kind() == io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn duplicate_notifications_are_drained_as_one_wake_event() {
        let root = TempState::new();
        let wake = ControllerWake::bind(root.path()).unwrap();

        for _ in 0..20 {
            notify_controller(root.path()).unwrap();
        }

        assert!(wake.wait(Duration::ZERO).unwrap());
        assert!(!wake.wait(Duration::ZERO).unwrap());
    }

    #[test]
    fn full_datagram_queue_returns_would_block_and_recovers_after_drain() {
        let root = TempState::new();
        let wake = ControllerWake::bind(root.path()).unwrap();
        let mut reached_capacity = false;
        for _ in 0..100_000 {
            match notify_controller(root.path()) {
                Ok(()) => {}
                Err(WakeError::Io(error))
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    reached_capacity = true;
                    break;
                }
                Err(error) => panic!("unexpected notification error: {error}"),
            }
        }
        assert!(reached_capacity, "socket send queue did not reach capacity");

        assert!(wake.wait(Duration::ZERO).unwrap());
        notify_controller(root.path()).unwrap();
        assert!(wake.wait(Duration::ZERO).unwrap());
    }

    #[test]
    fn bind_refuses_to_replace_a_non_socket_wake_path() {
        let root = TempState::new();
        let path = super::wake_socket_path(root.path()).unwrap();
        std::fs::write(&path, b"preserve").unwrap();

        let error = ControllerWake::bind(root.path()).unwrap_err();

        assert!(
            matches!(error, WakeError::Io(ref error) if error.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(std::fs::read(path).unwrap(), b"preserve");
    }
}
