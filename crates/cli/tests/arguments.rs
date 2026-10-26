use std::path::Path;

use macluster_cli::arguments::{
    CliError, SubmitOptions, merge_submit_options, parse_script_declarations, parse_submit_args,
};

#[test]
fn submission_parses_queue_node_parallel_settings_and_time() {
    let options = parse_submit_args([
        "-q",
        "mini01",
        "--node",
        "mini01-a",
        "-J",
        "analysis",
        "-t",
        "27:03:09",
        "-o",
        "jobs/%j.out",
        "-e",
        "jobs/%j.err",
        "--env",
        "PATH=/opt/bin",
        "job.sh",
    ])
    .unwrap();

    assert_eq!(options.queue.unwrap().as_str(), "mini01");
    assert_eq!(options.node.unwrap().as_str(), "mini01-a");
    assert_eq!(options.name.as_deref(), Some("analysis"));
    assert_eq!(options.walltime_secs, Some(97_389));
    assert_eq!(
        options.stdout_path.as_deref(),
        Some(Path::new("jobs/%j.out"))
    );
    assert_eq!(options.env["PATH"], "/opt/bin");
    assert_eq!(options.script.as_deref(), Some(Path::new("job.sh")));
}

#[test]
fn verbose_task_logging_is_opt_in() {
    let ordinary = parse_submit_args(["echo", "done"]).unwrap();
    assert!(!ordinary.verbose);

    let short = parse_submit_args(["-v", "echo", "done"]).unwrap();
    assert!(short.verbose);

    let long = parse_submit_args(["--verbose", "job.sh"]).unwrap();
    assert!(long.verbose);
}

#[test]
fn core_and_memory_request_flags_are_rejected_explicitly() {
    assert!(matches!(
        parse_submit_args(["-q", "mini01", "-n", "4", "job.sh"]),
        Err(CliError::UnsupportedResourceFlag(ref flag)) if flag == "-n"
    ));
    assert!(matches!(
        parse_submit_args(["-q", "mini01", "--memory", "4G", "job.sh"]),
        Err(CliError::UnsupportedResourceFlag(ref flag)) if flag == "--memory"
    ));
}

#[test]
fn invalid_time_environment_and_duplicate_script_are_rejected() {
    assert!(matches!(
        parse_submit_args(["-q", "mini01", "-t", "2:60:00", "job.sh"]),
        Err(CliError::InvalidValue(_))
    ));
    assert!(matches!(
        parse_submit_args(["-q", "mini01", "--env", "MCLUSTER_CPUS=8", "job.sh"]),
        Err(CliError::ReservedEnvironment(_))
    ));
    assert!(matches!(
        parse_submit_args(["-q", "mini01", "--wrap", "echo hi", "job.sh"]),
        Err(CliError::ConflictingInputs)
    ));
}

#[test]
fn script_declarations_are_literal_and_command_line_wins() {
    let declarations = parse_script_declarations("#MSUB -n 2\n").unwrap_err();
    assert!(
        matches!(declarations, CliError::UnsupportedResourceFlag(_)),
        "unexpected error: {declarations:?}"
    );

    let declarations = parse_script_declarations(
        "#SBATCH -q ignored\n#MSUB -q mini01 -J 'run $HOME'\n\n#!/bin/bash\necho ok\n#MSUB -q ignored-late\n",
    )
    .unwrap();
    assert_eq!(declarations.queue.as_ref().unwrap().as_str(), "mini01");
    assert_eq!(declarations.name.as_deref(), Some("run $HOME"));

    let cli = SubmitOptions {
        queue: Some("mini02".parse().unwrap()),
        ..SubmitOptions::default()
    };
    let merged = merge_submit_options(declarations, cli);
    assert_eq!(merged.queue.unwrap().as_str(), "mini02");
}

#[test]
fn request_id_alone_replays_a_cached_submission() {
    let options =
        parse_submit_args(["--request-id", "00000000-0000-4000-8000-000000000001"]).unwrap();
    assert!(options.script.is_none());
    assert!(options.wrap.is_none());
    assert_eq!(
        options.request_id.unwrap().to_string(),
        "00000000-0000-4000-8000-000000000001"
    );
}

#[test]
fn parse_interactive_flag_with_no_command() {
    let options = parse_submit_args(["-Is", "-q", "mini01"]).unwrap();
    assert!(options.interactive);
    assert!(options.script.is_none());
    assert!(options.wrap.is_none());
}

#[test]
fn parse_interactive_flag_with_command() {
    let options = parse_submit_args(["-Is", "-q", "mini01", "python -i"]).unwrap();
    assert!(options.interactive);
    assert_eq!(options.script.as_deref(), Some(Path::new("python -i")));
}

#[test]
fn interactive_flag_preserves_queue_and_node_options() {
    let options = parse_submit_args(["-Is", "-q", "mini01", "--node", "mini01-a"]).unwrap();
    assert!(options.interactive);
    assert_eq!(options.queue.as_ref().unwrap().as_str(), "mini01");
    assert_eq!(options.node.as_ref().unwrap().as_str(), "mini01-a");
}

#[test]
fn unquoted_command_keeps_trailing_flags_as_arguments() {
    let options = parse_submit_args([
        "-Is",
        "-q",
        "mini01",
        "pip",
        "install",
        ".",
        "--break-system-packages",
    ])
    .unwrap();

    assert!(options.interactive);
    assert_eq!(options.queue.as_ref().unwrap().as_str(), "mini01");
    assert_eq!(
        options.wrap.as_deref(),
        Some("'pip' 'install' '.' '--break-system-packages'")
    );
    assert!(options.script.is_none());
}

#[test]
fn quoted_inline_command_preserves_shell_syntax() {
    let options = parse_submit_args(["-Is", "pip install . > log"]).unwrap();

    // A single argv element is the established raw shell-expression form.
    assert_eq!(
        options.script.as_deref(),
        Some(Path::new("pip install . > log"))
    );
    assert!(options.wrap.is_none());
}

#[test]
fn argv_command_shell_quotes_empty_space_and_single_quote_arguments() {
    let options = parse_submit_args(["printf", "%s\\n", "", "two words", "it's", "x; rm"]).unwrap();

    assert_eq!(
        options.wrap.as_deref(),
        Some("'printf' '%s\\n' '' 'two words' 'it'\\''s' 'x; rm'")
    );
}
