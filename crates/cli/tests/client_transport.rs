use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn remote_interactive_submission_rejects_non_tty_before_ssh() {
    let home = std::env::temp_dir().join(format!(
        "macluster-client-tty-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let profiles = home.join("Library/Application Support/macluster/clients");
    fs::create_dir_all(&profiles).unwrap();
    let profile = profiles.join("f779bcf5-ea85-5caa-9579-74b395f3cce5.json");
    fs::write(
        &profile,
        r#"{
  "version": 1,
  "cluster_uuid": "f779bcf5-ea85-5caa-9579-74b395f3cce5",
  "cluster_name": "home-cluster",
  "binding_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "namespace": "f779bcf5-ea85-5caa-9579-74b395f3cce5",
  "descriptor_generation": 1,
  "controller_host": "192.0.2.1",
  "controller_user": "cluster",
  "controller_port": 22,
  "known_hosts_path": "/tmp/known_hosts",
  "identity_file": "/tmp/id_ed25519",
  "remote_uid": 501,
  "remote_binary": "/opt/homebrew/bin/macluster",
  "remote_config": "/tmp/config.toml",
  "remote_state_dir": "/tmp/state",
  "mounts_enabled": false,
  "nfs_client_id": "client-test",
  "nfs_client_ip": "192.0.2.10",
  "last_used_unix_ms": 1,
  "descriptor": null,
  "mounted_descriptor": null
}"#,
    )
    .unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_macluster"))
        .args(["msub", "-Is", "pwd"])
        .env("HOME", &home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run remote interactive submission without a TTY");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires terminal stdin and stdout"),
        "{stderr}"
    );
    assert!(!stderr.contains("known_hosts"), "{stderr}");
    assert!(!stderr.contains("Permission denied"), "{stderr}");
    fs::remove_dir_all(home).unwrap();
}
