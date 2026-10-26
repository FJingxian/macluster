use std::io;

pub struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

impl RawModeGuard {
    pub fn enter() -> io::Result<Self> {
        Self::enter_fd(libc::STDIN_FILENO)
    }

    fn enter_fd(fd: i32) -> io::Result<Self> {
        if unsafe { libc::isatty(fd) } != 1 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "interactive submission requires a terminal",
            ));
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
        Ok(Self { fd, original })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

#[cfg(test)]
mod tests {
    use super::RawModeGuard;
    use std::{
        fs::File,
        os::fd::{AsRawFd, FromRawFd},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    fn pty_pair() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        let mut window = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut window,
                )
            },
            0
        );
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    }

    fn attributes(fd: i32) -> libc::termios {
        let mut attributes = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(unsafe { libc::tcgetattr(fd, &mut attributes) }, 0);
        attributes
    }

    fn assert_same_terminal_mode(actual: &libc::termios, expected: &libc::termios) {
        assert_eq!(actual.c_iflag, expected.c_iflag);
        assert_eq!(actual.c_oflag, expected.c_oflag);
        assert_eq!(actual.c_cflag, expected.c_cflag);
        // Darwin marks detached PTYs with transient PENDIN/EXTPROC flags and
        // can normalize ICANON during close. The end-to-end msub PTY test
        // checks the complete lflag on the active terminal session.
        let stable_lflags = libc::ECHO | libc::ISIG;
        assert_eq!(
            actual.c_lflag & stable_lflags,
            expected.c_lflag & stable_lflags
        );
        assert_eq!(actual.c_cc, expected.c_cc);
    }

    fn assert_restored_in_child(mode: &str) {
        let (_master, slave) = pty_pair();
        let before = attributes(slave.as_raw_fd());
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ready_file =
            std::env::temp_dir().join(format!("mcr-raw-{}-{nonce}", std::process::id()));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "terminal::tests::raw_mode_child_helper"])
            .env("MCLUSTER_RAW_MODE_TEST", mode)
            .env("MCLUSTER_RAW_MODE_READY", &ready_file)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready_file.exists() {
            assert!(Instant::now() < deadline, "raw mode helper did not finish");
            thread::sleep(Duration::from_millis(10));
        }
        // Inspect the terminal while the helper remains alive and its test
        // harness has not written anything that could alter PTY state flags.
        assert_same_terminal_mode(&attributes(slave.as_raw_fd()), &before);
        let status = child.wait().unwrap();
        let _ = std::fs::remove_file(ready_file);
        assert!(status.success(), "raw mode helper exited with {status}");
    }

    #[test]
    fn raw_mode_is_restored_after_normal_return() {
        assert_restored_in_child("normal");
    }

    #[test]
    fn raw_mode_is_restored_after_attach_error() {
        assert_restored_in_child("attach-error");
    }

    #[test]
    fn raw_mode_child_helper() {
        let Ok(mode) = std::env::var("MCLUSTER_RAW_MODE_TEST") else {
            return;
        };
        match mode.as_str() {
            "normal" => {
                let guard = RawModeGuard::enter().unwrap();
                drop(guard);
            }
            "attach-error" => {
                let result: Result<(), &'static str> = (|| {
                    let _guard = RawModeGuard::enter().unwrap();
                    Err("attach failed")
                })();
                assert_eq!(result, Err("attach failed"));
            }
            _ => panic!("unknown raw mode helper action: {mode}"),
        }
        let ready_file = std::env::var_os("MCLUSTER_RAW_MODE_READY").unwrap();
        std::fs::write(ready_file, b"ready").unwrap();
        thread::sleep(Duration::from_millis(500));
    }
}
