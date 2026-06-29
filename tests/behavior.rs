mod common;

use std::fs;
use std::time::Duration;

use assert_cmd::prelude::*;
use predicates::prelude::*;

use common::{RunningSession, wait_until};

#[test]
fn scenario_mappings_and_hide_rules_are_listed_and_logged() {
    let session = RunningSession::start("demo_behavior_overlay");
    let old = session.temp.path().join("old");
    let new = session.temp.path().join("new");
    fs::create_dir_all(&old).unwrap();
    fs::create_dir_all(&new).unwrap();

    session
        .sandbox_cmd()
        .args(["mount", old.to_str().unwrap(), "/app"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["hide", "/app/cache"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["mount", new.to_str().unwrap(), "/app"])
        .assert()
        .success();

    session
        .sandbox_cmd()
        .arg("mount")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "{} on /app",
            old.canonicalize().unwrap().display()
        )))
        .stdout(predicate::str::contains("hide /app/cache"))
        .stdout(predicate::str::contains(format!(
            "{} on /app",
            new.canonicalize().unwrap().display()
        )));

    session
        .sandbox_cmd()
        .arg("monitor")
        .assert()
        .success()
        .stdout(predicate::str::contains("] id="))
        .stdout(predicate::str::contains("mount local="))
        .stdout(predicate::str::contains("hide path=/app/cache"));
}

#[test]
fn scenario_destroy_removes_log_and_socket_state() {
    let mut session = RunningSession::start_with_existing_log("demo_behavior_destroy", "stale\n");
    let local = session.temp.path().join("local");
    fs::create_dir_all(&local).unwrap();
    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();

    let log_path = session.log_dir().join("demo_behavior_destroy.log");
    assert!(log_path.exists());
    assert!(!fs::read_to_string(&log_path).unwrap().contains("stale"));
    assert!(session.socket_path().exists());

    session.sandbox_cmd().arg("destroy").assert().success();
    assert!(session.wait_for_exit(Duration::from_secs(5)).success());
    assert!(wait_until(Duration::from_secs(2), || !session
        .socket_path()
        .exists()));
    assert!(!log_path.exists());
}

#[test]
fn scenario_wrong_detach_reports_user_facing_error_without_attach() {
    let session = RunningSession::start("demo_behavior_detach_error");
    let wrong = session.temp.path().join("wrong");
    fs::create_dir_all(&wrong).unwrap();

    session
        .sandbox_cmd()
        .args(["detach", wrong.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not attached"));
}
