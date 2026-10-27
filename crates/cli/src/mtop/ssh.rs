//! mtop adapter to the controller's cluster-scoped OpenSSH connection pool.

use std::process::Command;

use macluster_controller::ssh::{ConnectionKey, SshPool};
use macluster_core::config::NodeConfig;

pub(super) fn add_control_args(
    namespace: &str,
    node_id: &str,
    node: &NodeConfig,
    command: &mut Command,
) {
    let pool = SshPool::new(namespace);
    let Ok(key) = ConnectionKey::for_node(namespace, node_id, node) else {
        return;
    };
    // If the private runtime directory cannot be established safely, keep
    // monitoring functional with an ordinary one-command SSH connection.
    let _ = pool.append_args(&key, command);
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use macluster_controller::ssh::{ConnectionKey, SshPool};
    use macluster_core::config::{NodeConfig, Transport};

    use super::add_control_args;

    #[test]
    fn mtop_uses_the_same_cluster_control_path_as_controller_transport() {
        let node = NodeConfig {
            host: "192.0.2.50".into(),
            transport: Transport::Ssh,
            remote_binary: "/usr/local/bin/macluster".into(),
            ssh_user: Some("worker".into()),
            ssh_port: Some(22),
            ssh_identity_file: None,
            remote_config: None,
            machine_uuid: Some("00000000-0000-4000-8000-000000000050".into()),
            execution_uid: Some(501),
        };
        let namespace = "mtop-control-path-test";
        let mut mtop_command = Command::new("ssh");
        add_control_args(namespace, "worker-a", &node, &mut mtop_command);
        let mtop_path = mtop_command
            .get_args()
            .find_map(|arg| {
                arg.to_string_lossy()
                    .strip_prefix("-oControlPath=")
                    .map(str::to_owned)
            })
            .unwrap();

        let pool = SshPool::new(namespace);
        let key = ConnectionKey::for_node(namespace, "worker-a", &node).unwrap();
        let mut controller_command = Command::new("ssh");
        pool.append_args(&key, &mut controller_command).unwrap();
        let controller_path = controller_command
            .get_args()
            .find_map(|arg| {
                arg.to_string_lossy()
                    .strip_prefix("-oControlPath=")
                    .map(str::to_owned)
            })
            .unwrap();
        assert_eq!(mtop_path, controller_path);
        if let Some(root) = std::path::Path::new(&mtop_path).parent() {
            let _ = fs::remove_dir_all(root);
        }
    }
}
