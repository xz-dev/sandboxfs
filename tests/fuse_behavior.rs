mod common;

use std::fs;
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;

use common::{RunningSession, wait_until};

fn require_fuse() {
    if std::env::var_os("SANDBOXFS_RUN_FUSE_TESTS").is_none() {
        eprintln!("set SANDBOXFS_RUN_FUSE_TESTS=1 to run real FUSE tests");
        return;
    }
    assert!(
        std::path::Path::new("/dev/fuse").exists(),
        "/dev/fuse is required"
    );
    assert!(
        std::process::Command::new("fusermount3")
            .arg("--version")
            .status()
            .is_ok(),
        "fusermount3 is required"
    );
}

fn fuse_enabled() -> bool {
    std::env::var_os("SANDBOXFS_RUN_FUSE_TESTS").is_some()
}

#[test]
#[ignore]
fn attach_read_and_read_only_write_error() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_read");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(
        fs::read_to_string(mountpoint.join("data/file")).unwrap(),
        "hello"
    );
    let err = fs::write(mountpoint.join("data/file"), "new").unwrap_err();
    assert!(matches!(
        err.raw_os_error(),
        Some(libc::EROFS | libc::EACCES | libc::EPERM)
    ));
    assert_eq!(fs::read_to_string(local.join("file")).unwrap(), "hello");
}

#[test]
#[ignore]
fn trusted_chmod_preserves_underlying_mode() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_trusted");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["chmod", "444", "/data/file"])
        .assert()
        .success();

    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(local.join("file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    assert_eq!(
        fs::metadata(mountpoint.join("data/file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
}

#[test]
#[ignore]
fn direct_chmod_pending_can_be_allowed_denied_or_do_nothing() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_pending");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let mut child = std::process::Command::new("chmod")
        .args(["444", mountpoint.join("data/file").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("mode=0444"))
            .unwrap_or(false)
    }));
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    let id = pending.split_whitespace().next().unwrap().to_string();
    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    assert!(wait_child(&mut child).success());

    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(mountpoint.join("data/file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );

    let mut child = std::process::Command::new("chmod")
        .args(["555", mountpoint.join("data/file").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("mode=0555"))
            .unwrap_or(false)
    }));
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    let id = pending.split_whitespace().next().unwrap().to_string();
    session
        .sandbox_cmd()
        .args(["allow", "--do-nothing", &id])
        .assert()
        .success();
    assert!(wait_child(&mut child).success());
    assert_eq!(
        fs::metadata(mountpoint.join("data/file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );

    let mut child = std::process::Command::new("chmod")
        .args(["600", mountpoint.join("data/file").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("mode=0600"))
            .unwrap_or(false)
    }));
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    let id = pending.split_whitespace().next().unwrap().to_string();
    session.sandbox_cmd().args(["deny", &id]).assert().success();
    assert!(!wait_child(&mut child).success());
}

fn wait_child(child: &mut std::process::Child) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            let _ = child.wait().unwrap();
            return status;
        }
        if start.elapsed() > Duration::from_secs(5) {
            child.kill().unwrap();
            let _ = child.wait().unwrap();
            panic!("child did not finish");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
