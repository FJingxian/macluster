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
    assert!(node.contains("host fingerprint"));
    assert!(node.contains("host-key verification"));

    let init = help(&["init", "--help"]);
    assert!(init.contains("Shared data files are preserved"));
    assert!(init.contains("--force"));

    let job = help(&["mjob", "--help"]);
    assert!(job.contains("five-second intervals"));
    assert!(job.contains("baseline"));
}

#[test]
fn main_help_is_a_command_index_with_examples() {
    let output = help(&["--help"]);
    for section in ["COMMANDS", "GLOBAL OPTIONS", "EXAMPLES"] {
        assert!(output.contains(section), "missing {section}: {output}");
    }
    for command in ["msub", "mjob", "mqueue", "mnode", "mtop", "mfans"] {
        assert!(output.contains(command), "missing {command}: {output}");
    }
    assert!(output.contains("queue (mqueue)"), "{output}");
    assert!(output.contains("macluster --init"), "{output}");
    assert!(
        output.contains("macluster --web [127.0.0.1[:PORT]]"),
        "{output}"
    );
    assert!(!output.contains("macluster controller"), "{output}");
}

#[test]
fn top_level_init_and_web_shortcuts_have_help() {
    assert!(help(&["--init", "--help"]).contains("FIRST SETUP"));
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
