use std::process::Command;

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
        (&["init", "-h"][..], 60),
        (&["mjob", "-h"][..], 50),
    ] {
        let output = help(args);
        assert!(output.contains("Usage:"), "{} has no usage line", args[0]);
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

    let node = help(&["mnode", "--help"]);
    assert!(node.contains("host fingerprint"));
    assert!(node.contains("host-key verification"));

    let init = help(&["init", "--help"]);
    assert!(init.contains("Shared data files are preserved"));
    assert!(init.contains("--force"));

    let job = help(&["mjob", "--help"]);
    assert!(job.contains("five-second intervals"));
    assert!(job.contains("baseline"));
}
