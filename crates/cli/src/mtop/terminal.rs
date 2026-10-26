use std::{
    io::{self, Stdout},
    sync::atomic::{AtomicBool, Ordering},
};

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);

pub struct TerminalGuard {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
    restored: bool,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide) {
            let _ = disable_raw_mode();
            return Err(error);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
                let _ = disable_raw_mode();
                return Err(error);
            }
        };
        TERMINAL_ACTIVE.store(true, Ordering::SeqCst);
        Ok(Self {
            terminal: Some(terminal),
            restored: false,
        })
    }

    pub fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        self.terminal
            .as_mut()
            .expect("terminal guard has not been restored")
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        TERMINAL_ACTIVE.store(false, Ordering::SeqCst);
        let mut first_error = None;
        if let Some(mut terminal) = self.terminal.take() {
            if let Err(error) = terminal.show_cursor() {
                first_error = Some(error);
            }
            if let Err(error) = execute!(
                terminal.backend_mut(),
                LeaveAlternateScreen,
                crossterm::cursor::Show
            ) && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        if let Err(error) = disable_raw_mode()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Restore terminal modes before the default panic hook writes its diagnostic.
pub fn install_panic_restore_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if TERMINAL_ACTIVE.swap(false, Ordering::SeqCst) {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
        }
        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::TerminalGuard;

    #[test]
    fn dropping_an_unentered_guard_is_safe() {
        let guard = TerminalGuard {
            terminal: None,
            restored: false,
        };
        drop(guard);
    }
}
