use std::fs;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

struct RunningSession {
    temp: TempDir,
    name: String,
    child: Option<Child>,
}

impl RunningSession {
    fn start(name: &str) -> Self {
        let temp = TempDir::new().unwrap();
        let runtime = temp.path().join("run");
        let child = Command::cargo_bin("sandboxfs")
            .unwrap()
            .arg("run")
            .arg(name)
            .env("SANDBOXFS_RUNTIME_DIR", &runtime)
            .env_remove("SANDBOXFS_SOCKET")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_socket(&runtime.join(format!("{name}.sock")));
        Self {
            temp,
            name: name.to_string(),
            child: Some(child),
        }
    }

    fn runtime(&self) -> std::path::PathBuf {
        self.temp.path().join("run")
    }

    fn sandbox_cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("sandboxfs").unwrap();
        cmd.env("SANDBOXFS_RUNTIME_DIR", self.runtime())
            .env_remove("SANDBOXFS_SOCKET")
            .arg(&self.name);
        cmd
    }
}

impl Drop for RunningSession {
    fn drop(&mut self) {
        let already_exited = self
            .child
            .as_mut()
            .and_then(|child| child.try_wait().ok())
            .flatten()
            .is_some();
        if already_exited || self.child.is_none() {
            return;
        }

        let _ = self.sandbox_cmd().arg("destroy").status();
        let start = Instant::now();
        let child = self.child.as_mut().unwrap();
        loop {
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            if start.elapsed() > Duration::from_secs(5) {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn wait_for_socket(path: &std::path::Path) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("socket did not appear: {}", path.display());
}

#[test]
fn help_exposes_run_but_not_create_or_list() {
    Command::cargo_bin("sandboxfs")
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
    Command::cargo_bin("sandboxfs")
        .unwrap()
        .env("SANDBOXFS_RUNTIME_DIR", temp.path().join("run"))
        .env_remove("SANDBOXFS_SOCKET")
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
        .stdout(predicate::str::contains("add"))
        .stdout(predicate::str::contains("hide /data/a"));

    session
        .sandbox_cmd()
        .args(["umount", "/data"])
        .assert()
        .success();

    session.sandbox_cmd().arg("destroy").assert().success();

    let start = Instant::now();
    let child = session.child.as_mut().unwrap();
    loop {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success());
                break;
            }
            None if start.elapsed() > Duration::from_secs(5) => {
                child.kill().unwrap();
                panic!("run process did not exit after destroy");
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
}
