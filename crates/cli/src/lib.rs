//! User-facing command parsing and display helpers.

mod app;
pub mod arguments;
mod client_access;
pub mod client_context;
pub mod client_join;
pub mod client_profile;
pub mod client_storage;
mod control_client;
pub mod discovery;
mod embedded_power;
mod init;
mod job_resources;
mod mtop;
mod nfs_recovery;
mod node_admin;
mod remote_admin;
mod remote_transport;
pub mod service;
mod ssh_bootstrap;
mod terminal;
mod update_signing;

/// Run a command using an explicit invocation name and argument list. The
/// invocation name may be `msub`, `mjob`, `mqueue`, `mkill`, `mtop`, `mnode`, or `mfans`.
pub fn run_with(program: &str, args: &[String]) -> i32 {
    match app::run(program, args) {
        Ok(()) => 0,
        Err((code, message)) => {
            eprintln!("macluster: {message}");
            code
        }
    }
}
