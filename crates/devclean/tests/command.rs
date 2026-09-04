use devclean::command::{CommandRunner, CommandSpec, CommandStatus};
use std::time::Duration;

fn spec(script: &str) -> CommandSpec {
    CommandSpec {
        executable: "/bin/sh".into(),
        args: vec!["-c".into(), script.into()],
        cwd: "/tmp".into(),
        timeout: Duration::from_millis(500),
        output_limit: 16,
    }
}

#[test]
fn command_has_minimal_environment_and_bounded_output() {
    unsafe {
        std::env::set_var("DEVCLEAN_SECRET_TEST", "secret");
    }
    let result = CommandRunner
        .run(&spec(
            "printf '%s' \"${DEVCLEAN_SECRET_TEST-unset}\"; printf '12345678901234567890'",
        ))
        .unwrap();
    assert_eq!(result.status, CommandStatus::OutputTruncated);
    assert!(!String::from_utf8_lossy(&result.stdout).contains("secret"));
}

#[test]
fn timeout_kills_the_process_group_and_stderr_is_not_returned() {
    let mut command = spec("printf 'sensitive' >&2; sleep 2");
    command.timeout = Duration::from_millis(30);
    let result = CommandRunner.run(&command).unwrap();
    assert_eq!(result.status, CommandStatus::TimedOut);
    assert!(result.stderr_was_present);
}

#[test]
fn relative_executable_is_rejected() {
    let mut command = spec("true");
    command.executable = "sh".into();
    assert!(CommandRunner.run(&command).is_err());
}

#[test]
fn symlink_and_unapproved_absolute_executables_are_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("sh");
    std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
    let mut command = spec("true");
    command.executable = camino::Utf8PathBuf::from_path_buf(link).unwrap();
    assert!(CommandRunner.run(&command).is_err());
}

#[test]
fn null_stdin_and_fixed_locale_are_observable() {
    let result = CommandRunner
        .run(&spec(
            "read x || true; printf '%s:%s' \"${LC_ALL}\" \"${x-empty}\"",
        ))
        .unwrap();
    assert_eq!(String::from_utf8(result.stdout).unwrap(), "C:");
}

#[test]
fn timeout_kills_descendants() {
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("survived");
    let mut command = spec(&format!(
        "(sleep 0.2; touch '{}') & sleep 2",
        marker.display()
    ));
    command.timeout = Duration::from_millis(30);
    assert_eq!(
        CommandRunner.run(&command).unwrap().status,
        CommandStatus::TimedOut
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists());
}

#[test]
fn infinite_output_is_bounded_and_terminated() {
    let mut command = spec("while :; do printf x; done");
    command.timeout = Duration::from_millis(30);
    command.output_limit = 8;
    let result = CommandRunner.run(&command).unwrap();
    assert_eq!(result.status, CommandStatus::OutputTruncated);
    assert_eq!(result.stdout.len(), 8);
}
