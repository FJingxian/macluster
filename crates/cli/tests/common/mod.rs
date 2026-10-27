use std::process::Command;

pub fn macluster_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_macluster"));
    command.env("MACLUSTER_DISABLE_SERVICE_AUTOSTART", "1");
    command
}
