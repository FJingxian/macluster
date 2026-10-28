//! User-facing command parsing and display helpers.

mod app;
pub mod arguments;
mod control_client;
mod embedded_power;
mod init;
mod mtop;
mod nfs_recovery;
mod node_admin;
pub mod service;
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
