mod common;

use common::macluster_command;
use macluster_controller::transport::run_child_bounded;
use macluster_core::storage::Storage;
use macluster_protocol::{
    framing::{read_frame, write_frame},
    identifiers::{ControllerUuid, Id128, RequestId, StartToken},
    types::{
        ControllerEpoch, JobSpec, JobState, Operation, PROTOCOL_VERSION, Request, Response,
        ResponseBody,
    },
};
use std::{
    fs,
    io::Cursor,
    os::unix::fs::PermissionsExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

fn agent(config: &Path, state: &Path, operation: Operation) -> ResponseBody {
    let mut command = macluster_command();
    command
        .arg("--config")
        .arg(config)
        .arg("--state-dir")
        .arg(state)
        .args(["internal", "agent-stdio", "--node", "worker"]);
    let mut input = Vec::new();
    write_frame(
        &mut input,
        &Request {
            protocol_version: PROTOCOL_VERSION,
            request_id: RequestId::random(),
            operation,
        },
    )
    .unwrap();
    let output = run_child_bounded(command, Some(input), Duration::from_secs(3)).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    read_frame::<_, Response>(&mut Cursor::new(output.stdout))
        .unwrap()
        .unwrap()
        .result
        .unwrap()
}

fn execute_namespaced_job(config: &Path, state: &Path, spec: JobSpec) {
    let controller = ControllerEpoch {
        controller_uuid: ControllerUuid(Id128::random()),
        epoch: 1,
    };
    let token = StartToken(Id128::random());
    assert!(matches!(
        agent(
            config,
            state,
            Operation::StartJob {
                controller,
                start_token: token,
                job_id: 1,
                spec: spec.clone()
            }
        ),
        ResponseBody::Started(_)
    ));
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let ResponseBody::Execution(status) = agent(config, state, Operation::Status) else {
            panic!("expected execution");
        };
        if let Some(terminal) = status.terminal_state {
            assert_eq!(terminal, JobState::Completed, "{:?}", status.end_reason);
            if !status.log_sync_pending {
                break;
            }
        }
        assert!(Instant::now() < deadline, "namespaced job did not finish");
        thread::sleep(Duration::from_millis(30));
    }
    // A lost main record plus an idempotent Start retry must restore the
    // terminal receipt, rather than execute the command a second time.
    fs::remove_file(state.join("agent-state.json")).unwrap();
    assert!(matches!(
        agent(
            config,
            state,
            Operation::StartJob {
                controller,
                start_token: token,
                job_id: 1,
                spec
            }
        ),
        ResponseBody::Started(_)
    ));
    let ResponseBody::Execution(status) = agent(config, state, Operation::Status) else {
        panic!("expected receipt status");
    };
    assert_eq!(status.terminal_state, Some(JobState::Completed));
}

#[test]
fn fresh_controller_can_reuse_shared_storage_without_colliding_with_old_job_one() {
    let root = std::env::temp_dir().join(format!("macluster-reset-namespace-{}", Id128::random()));
    let shared = root.join("shared");
    fs::create_dir_all(&shared).unwrap();
    let shared = shared.canonicalize().unwrap();
    let project = root.join("JanusX");
    fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();
    let mamba_env = root.join("mamba/envs/analysis");
    fs::create_dir_all(&mamba_env).unwrap();
    let mamba_env = mamba_env.canonicalize().unwrap();
    let project_uuid = Id128::random().to_string();
    let mamba_uuid = Id128::random().to_string();
    fs::write(project.join(".macluster-share-id"), &project_uuid).unwrap();
    fs::write(mamba_env.join(".macluster-share-id"), &mamba_uuid).unwrap();
    fs::write(project.join("pyproject.toml"), "[project]\nname='smoke'\n").unwrap();
    let mamba_bin = mamba_env.join("bin");
    fs::create_dir_all(&mamba_bin).unwrap();
    let fake_python = mamba_bin.join("python3");
    fs::write(
        &fake_python,
        "#!/bin/sh\nprintf 'Python shared-env 3.13\\n'\nprintf 'CONDA_PREFIX=%s\\n' \"${CONDA_PREFIX:-unset}\"\nprintf 'CONDA_DEFAULT_ENV=%s\\n' \"${CONDA_DEFAULT_ENV:-unset}\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&fake_python).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_python, permissions).unwrap();
    let old = Id128::random().to_string();
    let new = Id128::random().to_string();
    for (name, namespace, script) in [
        ("old", &old, "printf old"),
        (
            "new",
            &new,
            "/bin/pwd > executed-cwd.txt; /bin/ls > listed-files.txt; python3 --version > python-version.txt; printf new",
        ),
    ] {
        let config = root.join(format!("{name}.toml"));
        let state = root.join(name);
        fs::write(&config, format!(
            "[cluster]\nname=\"{name}\"\ndefault_queue=\"q\"\nshared_root=\"{}\"\nshare_uuid=\"{namespace}\"\nstorage_server=\"worker\"\nprotocol_version=1\n[queues.q]\nnodes=[\"worker\"]\nscheduler=\"fifo\"\n[nodes.worker]\nhost=\"192.0.2.1\"\ntransport=\"ssh\"\n", shared.display()
        )).unwrap();
        let mut config_text = fs::read_to_string(&config).unwrap();
        config_text.push_str(&format!("\n[shares.janusx]\nserver=\"worker\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"{project_uuid}\"\n", project.display(), project.display()));
        config_text.push_str(&format!("\n[shares.analysis]\nserver=\"worker\"\nsource_root=\"{}\"\nmount_root=\"{}\"\nshare_uuid=\"{mamba_uuid}\"\n", mamba_env.display(), mamba_env.display()));
        fs::write(&config, config_text).unwrap();
        let mut submit_command = macluster_command();
        submit_command
            .arg("--config")
            .arg(&config)
            .arg("--state-dir")
            .arg(&state)
            .args(["msub", "--wrap", script])
            .current_dir(&project);
        if name == "new" {
            // Simulate an unactivated login shell: mamba is mounted as a
            // named share, so the agent must add its bin directory itself.
            submit_command
                .env("PATH", "/usr/bin:/bin")
                .env("CONDA_PREFIX", &mamba_env)
                .env("CONDA_DEFAULT_ENV", "analysis");
        }
        let submit = submit_command.output().unwrap();
        assert!(
            submit.status.success(),
            "{}",
            String::from_utf8_lossy(&submit.stderr)
        );
        let publish = macluster_command()
            .arg("--state-dir")
            .arg(&state)
            .args([
                "internal",
                "publish-snapshot",
                "--job-id",
                "1",
                "--shared-root",
            ])
            .arg(&shared)
            .output()
            .unwrap();
        assert!(
            publish.status.success(),
            "fresh job 1 conflicts with retained files: {}",
            String::from_utf8_lossy(&publish.stderr)
        );
        let job = Storage::open(&state).unwrap().get_job(1).unwrap().unwrap();
        assert_eq!(
            Path::new(&job.spec.stdout_path),
            shared.join("jobs").join(namespace).join("%j/stdout.log")
        );
        assert!(
            shared
                .join("jobs")
                .join(namespace)
                .join("1/script.sh")
                .exists()
        );
        if name == "old" {
            fs::write(
                shared.join("jobs").join(namespace).join("1/stdout.log"),
                name,
            )
            .unwrap();
        } else {
            fs::write(shared.join(".macluster-share-id"), namespace).unwrap();
            let mut task_spec = job.spec;
            task_spec.stdout_path = project.join("task.stdout").to_string_lossy().into_owned();
            task_spec.stderr_path = project.join("task.stderr").to_string_lossy().into_owned();
            execute_namespaced_job(&config, &root.join("new-agent"), task_spec);
        }
    }
    assert_eq!(
        fs::read_to_string(shared.join("jobs").join(&old).join("1/stdout.log")).unwrap(),
        "old"
    );
    assert_eq!(
        fs::read_to_string(project.join("task.stdout")).unwrap(),
        "new"
    );
    assert_eq!(fs::read_to_string(project.join("task.stderr")).unwrap(), "");
    assert!(
        fs::read_to_string(project.join("listed-files.txt"))
            .unwrap()
            .lines()
            .any(|line| line == "pyproject.toml")
    );
    assert_eq!(
        fs::read_to_string(project.join("python-version.txt")).unwrap(),
        format!(
            "Python shared-env 3.13\nCONDA_PREFIX={}\nCONDA_DEFAULT_ENV=analysis\n",
            mamba_env.display()
        )
    );
    assert_eq!(
        Path::new(
            fs::read_to_string(project.join("executed-cwd.txt"))
                .unwrap()
                .trim()
        ),
        project
    );
    fs::remove_dir_all(root).unwrap();
}
