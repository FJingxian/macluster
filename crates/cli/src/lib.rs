//! User-facing command parsing and display helpers.

mod app;
pub mod arguments;
mod init;
mod mtop;
mod node_admin;
mod ssh_bootstrap;
mod terminal;

/// Run a command using an explicit invocation name and argument list. The
/// invocation name may be `msub`, `mjob`, `mqueue`, `mkill`, `mtop`, or `mnode`.
pub fn run_with(program: &str, args: &[String]) -> i32 {
    match app::run(program, args) {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("macluster: {message}");
            code
        }
    }
}
