mod common;

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::prelude::*;

use common::{RunningSession, sandboxfs_cmd_for, wait_until};

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

fn require_stress() {
    if std::env::var_os("SANDBOXFS_RUN_STRESS_TESTS").is_none() {
        eprintln!("set SANDBOXFS_RUN_STRESS_TESTS=1 to run FUSE stress tests");
    }
}

fn stress_enabled() -> bool {
    std::env::var_os("SANDBOXFS_RUN_STRESS_TESTS").is_some()
}

fn require_command(name: &str) {
    assert!(
        std::process::Command::new(name)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok(),
        "{name} is required"
    );
}

fn session_log(session: &RunningSession) -> String {
    fs::read_to_string(session.log_dir().join(format!("{}.log", session.name))).unwrap()
}

fn wait_for_log_line(session: &RunningSession, parts: &[&str]) -> String {
    let mut log = String::new();
    assert!(
        wait_until(Duration::from_secs(3), || {
            log = session_log(session);
            log.lines()
                .any(|line| parts.iter().all(|part| line.contains(part)))
        }),
        "log did not contain line with {parts:?}:\n{log}"
    );
    log
}

fn assert_log_line_contains(log: &str, parts: &[&str]) {
    assert!(
        log.lines()
            .any(|line| parts.iter().all(|part| line.contains(part))),
        "log did not contain line with {parts:?}:\n{log}"
    );
}

fn lsattr_flags(path: &Path) -> String {
    let output = std::process::Command::new("lsattr")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "lsattr failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    stdout
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("lsattr produced no flags for {}", path.display()))
        .to_string()
}

fn assert_immutable_visible(path: &Path) {
    let flags = lsattr_flags(path);
    assert!(flags.contains('i'), "expected immutable flag in {flags}");
}

fn assert_not_immutable_visible(path: &Path) {
    let flags = lsattr_flags(path);
    assert!(!flags.contains('i'), "unexpected immutable flag in {flags}");
}

fn pending_ids(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(ToString::to_string)
        .collect()
}

#[test]
#[ignore]
fn attach_and_detach_log_lifecycle_events() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_attach_detach_log");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&mountpoint).unwrap();

    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();
    let log = wait_for_log_line(&session, &[" id=", " attach ", " attach=", "mountpoint="]);
    let attach_id = log
        .lines()
        .find_map(|line| {
            if line.contains(" attach ") && line.contains("mountpoint=") {
                line.split_whitespace()
                    .find_map(|part| part.strip_prefix("attach="))
            } else {
                None
            }
        })
        .expect("attach id in log")
        .to_string();

    session
        .sandbox_cmd()
        .args(["detach", mountpoint.to_str().unwrap()])
        .assert()
        .success();
    let log = wait_for_log_line(
        &session,
        &[" id=", " detach ", &format!("attach={attach_id}")],
    );
    assert_log_line_contains(&log, &[" detach ", &format!("attach={attach_id}")]);
    assert!(
        !log.lines()
            .any(|line| line.contains(" detach ")
                && line.contains(&mountpoint.display().to_string()))
    );
}

#[test]
#[ignore]
fn attach_readlink_passthrough() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_readlink");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    std::os::unix::fs::symlink("target-file", local.join("link")).unwrap();

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

    let metadata = fs::symlink_metadata(mountpoint.join("data/link")).unwrap();
    assert!(metadata.file_type().is_symlink());
    assert_eq!(
        fs::read_link(mountpoint.join("data/link")).unwrap(),
        Path::new("target-file")
    );
}

#[test]
#[ignore]
fn attach_reports_backing_statfs() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_statfs");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();

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

    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let path = std::ffi::CString::new(mountpoint.join("data").to_str().unwrap()).unwrap();
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    assert_eq!(result, 0);
    let stat = unsafe { stat.assume_init() };
    assert!(stat.f_bsize > 0);
    assert!(stat.f_namemax > 0);
}

#[test]
#[ignore]
fn access_uses_sandbox_visible_mode() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_access");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("script"), "#!/bin/sh\n").unwrap();

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
        .args(["chmod", "644", "/data/script"])
        .assert()
        .success();

    let path = std::ffi::CString::new(mountpoint.join("data/script").to_str().unwrap()).unwrap();
    let result = unsafe { libc::access(path.as_ptr(), libc::X_OK) };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EACCES)
    );

    session
        .sandbox_cmd()
        .args(["chmod", "755", "/data/script"])
        .assert()
        .success();
    let result = unsafe { libc::access(path.as_ptr(), libc::X_OK) };
    assert_eq!(result, 0);
}

#[test]
#[ignore]
fn fsync_read_handle_succeeds() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_fsync");
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

    let file = fs::File::open(mountpoint.join("data/file")).unwrap();
    file.sync_all().unwrap();
    file.sync_data().unwrap();
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
fn trusted_chattr_preserves_underlying_flags() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    require_command("lsattr");
    require_command("chattr");
    let session = RunningSession::start("demo_fuse_trusted_chattr");
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

    let host_flags_before = lsattr_flags(&local.join("file"));
    assert_not_immutable_visible(&mountpoint.join("data/file"));

    session
        .sandbox_cmd()
        .args(["chattr", "+i", "/data/file"])
        .assert()
        .success();

    assert_immutable_visible(&mountpoint.join("data/file"));
    assert_eq!(lsattr_flags(&local.join("file")), host_flags_before);

    let log = session_log(&session);
    assert_log_line_contains(
        &log,
        &[" id=", " trusted ", "path=/data/file CHATTR flags=0x10"],
    );
}

#[test]
#[ignore]
fn trusted_chown_preserves_underlying_owner_and_logs() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("trusted chown FUSE test requires root");
        return;
    }
    require_command("chown");
    let session = RunningSession::start("demo_fuse_trusted_chown");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    let underlying_before = fs::metadata(local.join("file")).unwrap();

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
        .args(["chown", "1234:2345", "/data/file"])
        .assert()
        .success();

    use std::os::unix::fs::MetadataExt;
    let mount_metadata = fs::metadata(mountpoint.join("data/file")).unwrap();
    assert_eq!(mount_metadata.uid(), 1234);
    assert_eq!(mount_metadata.gid(), 2345);
    let underlying_after = fs::metadata(local.join("file")).unwrap();
    assert_eq!(underlying_after.uid(), underlying_before.uid());
    assert_eq!(underlying_after.gid(), underlying_before.gid());

    let log = session_log(&session);
    assert_log_line_contains(
        &log,
        &[
            " id=",
            " trusted ",
            "path=/data/file SETATTR uid=1234 gid=2345",
        ],
    );
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
fn direct_chattr_pending_can_be_allowed() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    require_command("lsattr");
    require_command("chattr");
    let session = RunningSession::start("demo_fuse_direct_chattr");
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

    let mut child = std::process::Command::new("chattr")
        .args(["+i", mountpoint.join("data/file").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("CHATTR flags=0x10"))
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

    let host_flags_before = lsattr_flags(&local.join("file"));
    assert_immutable_visible(&mountpoint.join("data/file"));
    assert_eq!(lsattr_flags(&local.join("file")), host_flags_before);

    let mut child = std::process::Command::new("chattr")
        .args(["-i", mountpoint.join("data/file").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("CHATTR flags=0x0"))
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

    assert_not_immutable_visible(&mountpoint.join("data/file"));
    assert_eq!(lsattr_flags(&local.join("file")), host_flags_before);
}

#[test]
#[ignore]
fn stress_multiple_pending_viewers_do_not_consume_request() {
    require_fuse();
    require_stress();
    if !fuse_enabled() || !stress_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_stress_pending_viewers");
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
    let id = pending_ids(&pending).into_iter().next().unwrap();
    assert!(pending.contains(&format!("{id} path=/data/file SETATTR mode=0444")));

    let runtime = session.runtime();
    let log_dir = session.log_dir();
    let name = session.name.clone();
    let mut viewers = Vec::new();
    for _ in 0..16 {
        let runtime = runtime.clone();
        let log_dir = log_dir.clone();
        let name = name.clone();
        let id = id.clone();
        viewers.push(std::thread::spawn(move || {
            let output = sandboxfs_cmd_for(&runtime, &log_dir)
                .args([name.as_str(), "allow"])
                .output()
                .unwrap();
            assert!(output.status.success());
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains(&format!("{id} path=/data/file SETATTR mode=0444")));
        }));
    }
    for viewer in viewers {
        viewer.join().unwrap();
    }

    let pending_after_viewers =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    assert!(pending_after_viewers.contains(&format!("{id} path=/data/file SETATTR mode=0444")));

    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    assert!(wait_child(&mut child).success());
    session
        .sandbox_cmd()
        .arg("allow")
        .assert()
        .success()
        .stdout(predicates::str::is_empty());

    let log = session_log(&session);
    assert_eq!(
        log.matches("pending path=/data/file SETATTR mode=0444")
            .count(),
        1
    );
    assert_log_line_contains(&log, &["decision", &format!("request={id}"), "ALLOW"]);
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
