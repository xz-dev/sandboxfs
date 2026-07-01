mod common;

use std::fs;
use std::time::Duration;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

use common::{RunningSession, sandboxfs_cmd_for};

#[test]
fn help_exposes_run_but_not_create_or_list() {
    std::process::Command::cargo_bin("sandboxfs")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("create").not())
        .stdout(predicate::str::contains("list").not());
}

#[test]
fn control_command_fails_without_foreground_session() {
    let temp = TempDir::new().unwrap();
    sandboxfs_cmd_for(&temp.path().join("run"), &temp.path().join("logs"))
        .args(["missing", "mount"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sandboxfs run missing"));
}

#[test]
fn mount_hide_umount_monitor_and_destroy_use_isolated_runtime() {
    let mut session = RunningSession::start("demo_cli");
    let local = session.temp.path().join("local");
    fs::create_dir_all(&local).unwrap();
    fs::write(local.join("a"), "hi").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();

    session
        .sandbox_cmd()
        .arg("mount")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "{} on /data",
            local.canonicalize().unwrap().display()
        )));

    session
        .sandbox_cmd()
        .args(["hide", "/data/a"])
        .assert()
        .success();

    session
        .sandbox_cmd()
        .arg("monitor")
        .assert()
        .success()
        .stdout(predicate::str::contains("] id="))
        .stdout(predicate::str::contains("mount local="))
        .stdout(predicate::str::contains("path=/data"))
        .stdout(predicate::str::contains("hide path=/data/a"));

    session
        .sandbox_cmd()
        .args(["umount", "/data"])
        .assert()
        .success();

    session.sandbox_cmd().arg("destroy").assert().success();
    assert!(session.wait_for_exit(Duration::from_secs(5)).success());
}

#[test]
fn protection_rule_commands_log_outcomes_and_list_sorted_filters_without_logging() {
    let session = RunningSession::start("demo_cli_protection");

    session
        .sandbox_cmd()
        .args(["protect-write", "/b"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-read", "/a"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-write", "/a"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-read", "/a"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["unprotect-read", "/missing"])
        .assert()
        .success();

    session
        .sandbox_cmd()
        .arg("list-protection")
        .assert()
        .success()
        .stdout("READ /a\nWRITE /a\nWRITE /b\n");
    session
        .sandbox_cmd()
        .args(["list-protection", "--read"])
        .assert()
        .success()
        .stdout("READ /a\n");
    session
        .sandbox_cmd()
        .args(["list-protection", "--write"])
        .assert()
        .success()
        .stdout("WRITE /a\nWRITE /b\n");
    session
        .sandbox_cmd()
        .args(["list-protection", "--read", "--write"])
        .assert()
        .success()
        .stdout("READ /a\nWRITE /a\nWRITE /b\n");

    let log_path = session.log_dir().join(format!("{}.log", session.name));
    let log_before_list = fs::read_to_string(&log_path).unwrap();
    session
        .sandbox_cmd()
        .arg("list-protection")
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&log_path).unwrap(), log_before_list);

    assert!(log_before_list.contains("protect kind=WRITE pattern=/b result=added"));
    assert!(log_before_list.contains("protect kind=READ pattern=/a result=added"));
    assert!(log_before_list.contains("protect kind=WRITE pattern=/a result=added"));
    assert!(log_before_list.contains("protect kind=READ pattern=/a result=already-present"));
    assert!(log_before_list.contains("unprotect kind=READ pattern=/missing result=not-present"));
}

#[test]
fn trusted_metadata_command_failure_preserves_underlying_metadata() {
    let session = RunningSession::start("demo_cli_trusted_failure");
    let local = session.temp.path().join("local");
    fs::create_dir_all(&local).unwrap();
    fs::write(local.join("file"), "hi").unwrap();
    let before = fs::metadata(local.join("file")).unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();

    session
        .sandbox_cmd()
        .args(["chmod", "444", "/missing"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("No such file")
                .or(predicate::str::contains("No such file or directory")),
        );

    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let after = fs::metadata(local.join("file")).unwrap();
    assert_eq!(
        after.permissions().mode() & 0o777,
        before.permissions().mode() & 0o777
    );
    assert_eq!(after.uid(), before.uid());
    assert_eq!(after.gid(), before.gid());

    session
        .sandbox_cmd()
        .arg("metadata")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}
