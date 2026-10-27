use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
    process::Command,
    sync::OnceLock,
};

use macluster_core::config::NodeConfig;
use macluster_protocol::framing::sha256_hex;

static CONTROL_ROOT: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Reuse authenticated OpenSSH connections for mtop metric and process queries.
/// If a private control-socket directory cannot be established, SSH falls back
/// to its normal one-command-per-connection behavior.
pub(super) fn add_control_args(node: &NodeConfig, command: &mut Command) {
    let Some(root) = control_root() else {
        return;
    };
    let identity = node
        .ssh_identity_file
        .as_deref()
        .unwrap_or("default-identity");
    // Do not share a connection between different Macs that reuse the same IP.
    let identity = format!("{identity}\0{}", node.machine_uuid.as_deref().unwrap_or(""));
    let Ok(identity_hash) = sha256_hex(identity.as_bytes()) else {
        return;
    };
    let control_path = root.join(format!("{}-%C", &identity_hash[..16]));
    command
        .arg("-oControlMaster=auto")
        .arg("-oControlPersist=10")
        .arg(format!("-oControlPath={}", control_path.display()));
}

fn control_root() -> Option<&'static PathBuf> {
    CONTROL_ROOT
        .get_or_init(|| {
            let uid = unsafe { libc::getuid() };
            let root = PathBuf::from(format!("/tmp/macluster-mtop-{uid}"));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return None,
            }

            let metadata = fs::symlink_metadata(&root).ok()?;
            if !metadata.is_dir() || metadata.uid() != uid {
                return None;
            }
            if metadata.permissions().mode() & 0o777 != 0o700 {
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).ok()?;
            }
            Some(root)
        })
        .as_ref()
}
