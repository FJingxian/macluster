use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_macluster"))
        .args(args)
        .output()
        .expect("run macluster help");
    assert!(
        output.status.success(),
        "help command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "help command wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("help is UTF-8")
}

fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

#[test]
fn short_help_for_long_commands_is_a_quick_reference() {
    for (args, maximum_words) in [
        (&["msub", "-h"][..], 100),
        (&["mnode", "-h"][..], 120),
        (&["--init", "-h"][..], 60),
        (&["mjob", "-h"][..], 50),
        (&["mqueue", "-h"][..], 60),
        (&["mtop", "-h"][..], 60),
        (&["mkill", "-h"][..], 50),
        (&["mfans", "-h"][..], 70),
        (&["controller", "-h"][..], 90),
    ] {
        let output = help(args);
        assert!(output.contains("Usage"), "{} has no usage line", args[0]);
        assert!(
            word_count(&output) <= maximum_words,
            "{} -h is too long ({} words)",
            args[0],
            word_count(&output)
        );
    }
}

#[test]
fn long_help_keeps_operational_details_for_reference() {
    let submit = help(&["msub", "--help"]);
    assert!(submit.contains("VIRTUAL_ENV"));
    assert!(submit.contains("Ctrl-C"));
    assert!(submit.contains("500 ms"), "{submit}");
    assert!(
        submit.contains("5 seconds while output is quiet"),
        "{submit}"
    );
    assert!(submit.contains("RSS snapshot"), "{submit}");

    let node = help(&["mnode", "--help"]);
    assert!(node.contains("mnode --scan"), "{node}");
    assert!(node.contains("searches only the subnet attached"), "{node}");
    assert!(node.contains("host fingerprint"));
    assert!(node.contains("host-key verification"));

    let init = help(&["--init", "--help"]);
    assert!(init.contains("Shared data files are preserved"));
    assert!(init.contains("--force"));

    let job = help(&["mjob", "--help"]);
    assert!(job.contains("five-second intervals"));
    assert!(job.contains("baseline"));
}

#[test]
fn main_help_is_a_compact_module_index() {
    let output = help(&["--help"]);
    for section in ["Usage", "Modes", "Options", "Modules"] {
        assert!(output.contains(section), "missing {section}: {output}");
    }
    for command in ["msub", "mjob", "mqueue", "mnode", "mtop", "mfans"] {
        assert!(output.contains(command), "missing {command}: {output}");
    }
    assert!(output.contains("queue (mqueue)"), "{output}");
    assert!(
        output.contains("macluster <MODULE> [-h|--help]"),
        "{output}"
    );
    assert!(output.contains("macluster --init"), "{output}");
    assert!(output.contains("macluster --join"), "{output}");
    assert!(output.contains("macluster --clusters"), "{output}");
    assert!(
        output.contains("macluster [--cluster NAME|UUID] --leave"),
        "{output}"
    );
    assert!(output.contains("macluster --web [IP[:PORT]]"), "{output}");
    assert!(!output.contains("macluster controller"), "{output}");
}

#[test]
fn top_level_init_and_web_shortcuts_have_help() {
    assert!(help(&["--init", "--help"]).contains("FIRST SETUP"));
    assert!(help(&["--join", "--help"]).contains("multi-entry cluster"));
    assert!(help(&["--clusters", "--help"]).contains("Lists each"));
    assert!(help(&["--leave", "--help"]).contains("--cluster NAME|UUID"));
    let web = help(&["--web", "--help"]);
    assert!(web.contains("127.0.0.1[:PORT]"), "{web}");
    assert!(web.contains("local-only"), "{web}");
}

#[test]
fn detailed_help_has_clear_examples_and_section_headings() {
    for (args, headings) in [
        (
            &["msub", "--help"][..],
            &["OPTIONS", "EXAMPLES", "WORKING DIRECTORY", "ENVIRONMENT"][..],
        ),
        (
            &["mnode", "--help"][..],
            &["ADD NODES", "SHARES", "REMOVE NODES", "EXAMPLES"][..],
        ),
        (
            &["mjob", "--help"][..],
            &["OPTIONS", "EXAMPLES", "METRICS", "STORAGE"][..],
        ),
    ] {
        let output = help(args);
        for heading in headings {
            assert!(
                output.contains(heading),
                "{} is missing {heading}: {output}",
                args[0]
            );
        }
    }
}

#[test]
fn smb_help_and_docs_describe_one_prompt_migration_and_secret_boundaries() {
    let node = help(&["mnode", "--help"]);
    assert!(node.contains("--smb-user ACCOUNT"), "{node}");
    assert!(node.contains("--update-credential"), "{node}");
    assert!(node.contains("root-only credential vault"), "{node}");
    assert!(node.contains("root-only node copy"), "{node}");
    assert!(node.contains("mount_smbfs"), "{node}");

    let english = include_str!("../../../README.md");
    let chinese = include_str!("../../../doc/README.zh-CN.md");
    let skill = include_str!("../../../skills/macluster/SKILL.md");
    for document in [english, chinese, skill] {
        assert!(
            document.contains("--smb-user")
                && document.contains("--update-credential")
                && (document.contains("SMB session")
                    || document.contains("credential vault")
                    || document.contains("vault")),
            "SMB credential documentation is incomplete"
        );
    }
    assert!(english.contains("root-only credential vault"));
    assert!(english.contains("root-only node"));
    assert!(english.contains("node copy"));
    assert!(english.contains("same URI"));
    assert!(chinese.contains("root 专用 vault"));
    assert!(chinese.contains("root-only 节点凭据"));
    assert!(chinese.contains("相同 URI"));
    assert!(!english.contains("password in config"));
}

#[test]
fn clusters_lists_joined_login_client_profiles() {
    let home = std::env::temp_dir().join(format!(
        "macluster-client-list-{}-{}",
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
  "descriptor": null
}"#,
    )
    .unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_macluster"))
        .arg("--clusters")
        .env("HOME", &home)
        .output()
        .expect("list joined clusters");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("home-cluster"), "{stdout}");
    assert!(stdout.contains("cluster@192.0.2.1:22"), "{stdout}");
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn internal_smb_master_cluster_uuid_is_not_parsed_as_a_login_profile() {
    let output = Command::new(env!("CARGO_BIN_EXE_macluster"))
        .args([
            "internal",
            "smb-master",
            "delete",
            "--cluster-uuid",
            "not-a-uuid",
            "--server-id",
            "nas-01",
            "--server",
            "192.0.2.20",
            "--account",
            "smb-user",
        ])
        .output()
        .expect("run internal SMB master command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--cluster selects a joined login-client profile"),
        "{stderr}"
    );
    assert!(stderr.contains("canonical UUID"), "{stderr}");
}
