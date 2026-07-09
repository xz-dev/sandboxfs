mod common;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime};

use assert_cmd::prelude::*;

use common::{RunningSession, gatefs_cmd_for, wait_until};

fn require_fuse() {
    if std::env::var_os("GATEFS_RUN_FUSE_TESTS").is_none() {
        eprintln!("set GATEFS_RUN_FUSE_TESTS=1 to run real FUSE tests");
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
    std::env::var_os("GATEFS_RUN_FUSE_TESTS").is_some()
}

fn require_stress() {
    if std::env::var_os("GATEFS_RUN_STRESS_TESTS").is_none() {
        eprintln!("set GATEFS_RUN_STRESS_TESTS=1 to run FUSE stress tests");
    }
}

fn stress_enabled() -> bool {
    std::env::var_os("GATEFS_RUN_STRESS_TESTS").is_some()
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

fn wait_for_pending(session: &RunningSession, expected: &str) -> String {
    let mut observed = String::new();
    assert!(
        wait_until(Duration::from_secs(3), || {
            let Ok(out) = session.sandbox_cmd().arg("allow").output() else {
                return false;
            };
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = stdout.lines().find(|line| line.contains(expected)) {
                observed = line
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                return !observed.is_empty();
            }
            false
        }),
        "pending operation was not observed: {expected}"
    );
    observed
}

fn assert_no_pending(session: &RunningSession) {
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    assert!(
        pending.trim().is_empty(),
        "unexpected pending requests: {pending}"
    );
}

fn c_string_path(path: &Path) -> std::ffi::CString {
    c_string(path.as_os_str())
}

fn c_string(value: &OsStr) -> std::ffi::CString {
    std::ffi::CString::new(value.as_bytes()).unwrap()
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    let path = c_string_path(path);
    let name = c_string(OsStr::new(name));
    let result = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn get_xattr(path: &Path, name: &str) -> std::io::Result<Vec<u8>> {
    let path = c_string_path(path);
    let name = c_string(OsStr::new(name));
    let size = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut value = vec![0; size as usize];
    let read = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    value.truncate(read as usize);
    Ok(value)
}

fn get_xattr_with_buffer(path: &Path, name: &str) -> std::io::Result<Vec<u8>> {
    let path = c_string_path(path);
    let name = c_string(OsStr::new(name));
    let mut value = vec![0; 1024];
    let read = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    value.truncate(read as usize);
    Ok(value)
}

fn list_xattr(path: &Path) -> std::io::Result<Vec<u8>> {
    let path = c_string_path(path);
    let size = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut names = vec![0; size as usize];
    let read = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    names.truncate(read as usize);
    Ok(names)
}

fn list_xattr_with_buffer(path: &Path) -> std::io::Result<Vec<u8>> {
    let path = c_string_path(path);
    let mut names = vec![0; 1024];
    let read = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    names.truncate(read as usize);
    Ok(names)
}

fn remove_xattr(path: &Path, name: &str) -> std::io::Result<()> {
    let path = c_string_path(path);
    let name = c_string(OsStr::new(name));
    let result = unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
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
fn attach_xattr_bypass() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    set_xattr(&local.join("file"), "user.before", b"one").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-metadata", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(
        get_xattr(&mountpoint.join("data/file"), "user.before").unwrap(),
        b"one"
    );
    let names = list_xattr(&mountpoint.join("data/file")).unwrap();
    assert!(
        names
            .windows(b"user.before\0".len())
            .any(|window| window == b"user.before\0")
    );

    set_xattr(&mountpoint.join("data/file"), "user.after", b"two").unwrap();
    assert_eq!(
        get_xattr(&local.join("file"), "user.after").unwrap(),
        b"two"
    );
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    assert!(
        pending.trim().is_empty(),
        "unexpected pending xattr request: {pending}"
    );

    remove_xattr(&mountpoint.join("data/file"), "user.after").unwrap();
    let err = get_xattr(&local.join("file"), "user.after").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));
}

#[test]
#[ignore]
fn unprotected_xattr_write_forwards_to_backing_filesystem() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_unprotected_forward");
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

    set_xattr(&mountpoint.join("data/file"), "user.unprotected", b"value").unwrap();
    assert_eq!(
        get_xattr(&local.join("file"), "user.unprotected").unwrap(),
        b"value"
    );
    remove_xattr(&mountpoint.join("data/file"), "user.unprotected").unwrap();
    let err = get_xattr(&local.join("file"), "user.unprotected").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));
}

fn protected_getxattr_is_gated_by_policy(protection_command: &str, session_name: &str) {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start(session_name);
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    set_xattr(&local.join("file"), "user.gated_read", b"value").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args([protection_command, "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || get_xattr_with_buffer(&path, "user.gated_read")
    });
    let id = wait_for_pending(&session, "GETXATTR name=user.gated_read");
    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    assert_eq!(child.join().unwrap().unwrap(), b"value");
}

#[test]
#[ignore]
fn protected_getxattr_is_gated_by_read_policy() {
    protected_getxattr_is_gated_by_policy("protect-read", "demo_fuse_xattr_read_gate");
}

#[test]
#[ignore]
fn protected_getxattr_is_gated_by_xattr_policy() {
    protected_getxattr_is_gated_by_policy("protect-xattr", "demo_fuse_xattr_getxattr_gate");
}

#[test]
#[ignore]
fn protected_listxattr_is_gated_by_read_policy() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_list_read_gate");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    set_xattr(&local.join("file"), "user.gated_list", b"value").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-read", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || list_xattr_with_buffer(&path)
    });
    let id = wait_for_pending(&session, "LISTXATTR");
    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    let names = child.join().unwrap().unwrap();
    assert!(
        names
            .windows(b"user.gated_list\0".len())
            .any(|window| window == b"user.gated_list\0")
    );
}

#[test]
#[ignore]
fn read_bypass_does_not_release_xattr_protected_getxattr() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_read_bypass_boundary");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    set_xattr(&local.join("file"), "user.xattr_protected", b"value").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-xattr", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-read", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || get_xattr_with_buffer(&path, "user.xattr_protected")
    });
    let id = wait_for_pending(&session, "GETXATTR name=user.xattr_protected");
    session.sandbox_cmd().args(["deny", &id]).assert().success();
    assert_eq!(
        child.join().unwrap().unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
}

#[test]
#[ignore]
fn xattr_bypass_releases_read_protected_getxattr() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_read_xattr_bypass");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    set_xattr(&local.join("file"), "user.allowed_read", b"value").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-read", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-xattr", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(
        get_xattr_with_buffer(&mountpoint.join("data/file"), "user.allowed_read").unwrap(),
        b"value"
    );
    assert_no_pending(&session);
}

#[test]
#[ignore]
fn attach_xattr_bypass_does_not_follow_symlink_inode() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_symlink");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("target"), "hello").unwrap();
    std::os::unix::fs::symlink("target", local.join("link")).unwrap();
    set_xattr(&local.join("target"), "user.target", b"target-value").unwrap();

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

    let err = get_xattr(&mountpoint.join("data/link"), "user.target").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));
}

fn protected_xattr_write_is_gated_by_policy(protection_command: &str, session_name: &str) {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start(session_name);
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
        .args([protection_command, "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || set_xattr(&path, "user.gated", b"value")
    });
    let id = wait_for_pending(&session, "SETXATTR name=user.gated");
    assert!(get_xattr(&local.join("file"), "user.gated").is_err());
    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    child.join().unwrap().unwrap();
    assert_eq!(
        get_xattr(&local.join("file"), "user.gated").unwrap(),
        b"value"
    );

    let log = session_log(&session);
    assert_log_line_contains(&log, &[" pending ", "SETXATTR name=user.gated"]);
    assert_log_line_contains(&log, &["decision", &format!("request={id}"), "ALLOW"]);
}

#[test]
#[ignore]
fn protected_xattr_write_is_gated_by_xattr_policy() {
    protected_xattr_write_is_gated_by_policy("protect-xattr", "demo_fuse_xattr_specific_gate");
}

#[test]
#[ignore]
fn protected_xattr_write_is_gated_by_metadata_policy() {
    protected_xattr_write_is_gated_by_policy("protect-metadata", "demo_fuse_xattr_metadata_gate");
}

#[test]
#[ignore]
fn protected_xattr_write_is_gated_by_write_policy() {
    protected_xattr_write_is_gated_by_policy("protect-write", "demo_fuse_xattr_write_gate");
}

#[test]
#[ignore]
fn metadata_bypass_does_not_release_xattr_protected_xattr() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_metadata_bypass");
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
        .args(["protect-xattr", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-metadata", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || set_xattr(&path, "user.xattr_protected", b"value")
    });
    let id = wait_for_pending(&session, "SETXATTR name=user.xattr_protected");
    session.sandbox_cmd().args(["deny", &id]).assert().success();
    assert_eq!(
        child.join().unwrap().unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
}

#[test]
#[ignore]
fn write_bypass_does_not_release_xattr_protected_xattr() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_write_bypass_boundary");
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
        .args(["protect-xattr", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || set_xattr(&path, "user.xattr_protected", b"value")
    });
    let id = wait_for_pending(&session, "SETXATTR name=user.xattr_protected");
    session.sandbox_cmd().args(["deny", &id]).assert().success();
    assert_eq!(
        child.join().unwrap().unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
}

#[test]
#[ignore]
fn write_bypass_does_not_release_metadata_protected_xattr() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_write_bypass_metadata_boundary");
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
        .args(["protect-metadata", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || set_xattr(&path, "user.metadata_protected", b"value")
    });
    let id = wait_for_pending(&session, "SETXATTR name=user.metadata_protected");
    session.sandbox_cmd().args(["deny", &id]).assert().success();
    assert_eq!(
        child.join().unwrap().unwrap_err().raw_os_error(),
        Some(libc::EACCES)
    );
}

#[test]
#[ignore]
fn xattr_bypass_releases_metadata_protected_xattr_but_not_chmod() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_xattr_specific_bypass");
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
        .args(["protect-metadata", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-xattr", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    set_xattr(&mountpoint.join("data/file"), "user.allowed", b"value").unwrap();
    assert_eq!(
        get_xattr(&local.join("file"), "user.allowed").unwrap(),
        b"value"
    );
    assert_no_pending(&session);

    let chmod_path = mountpoint.join("data/file");
    let mut child = std::process::Command::new("chmod")
        .arg("600")
        .arg(&chmod_path)
        .spawn()
        .unwrap();
    let pending_id = wait_for_pending(&session, "SETATTR mode=0600");
    session
        .sandbox_cmd()
        .args(["deny", pending_id.as_str()])
        .assert()
        .success();
    assert!(!child.wait().unwrap().success());
}

fn protected_removexattr_write_is_gated_by_policy(protection_command: &str, session_name: &str) {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start(session_name);
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello").unwrap();
    set_xattr(&local.join("file"), "user.gated_remove", b"value").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args([protection_command, "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let child = std::thread::spawn({
        let path = mountpoint.join("data/file");
        move || remove_xattr(&path, "user.gated_remove")
    });
    let id = wait_for_pending(&session, "REMOVEXATTR name=user.gated_remove");
    assert_eq!(
        get_xattr(&local.join("file"), "user.gated_remove").unwrap(),
        b"value"
    );
    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    child.join().unwrap().unwrap();
    let err = get_xattr(&local.join("file"), "user.gated_remove").unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::ENODATA));

    let log = session_log(&session);
    assert_log_line_contains(&log, &[" pending ", "REMOVEXATTR name=user.gated_remove"]);
    assert_log_line_contains(&log, &["decision", &format!("request={id}"), "ALLOW"]);
}

#[test]
#[ignore]
fn protected_removexattr_write_is_gated_by_xattr_policy() {
    protected_removexattr_write_is_gated_by_policy(
        "protect-xattr",
        "demo_fuse_removexattr_specific_gate",
    );
}

#[test]
#[ignore]
fn protected_removexattr_write_is_gated_by_metadata_policy() {
    protected_removexattr_write_is_gated_by_policy(
        "protect-metadata",
        "demo_fuse_removexattr_metadata_gate",
    );
}

#[test]
#[ignore]
fn attach_readlink_bypass() {
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
fn attach_read_and_unprotected_write_succeeds() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_read_write_default");
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
    fs::write(mountpoint.join("data/file"), "new").unwrap();
    assert_eq!(fs::read_to_string(local.join("file")).unwrap(), "new");
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
fn direct_touch_pending_can_be_allowed_without_host_mutation() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_direct_touch");
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
        .args(["protect-metadata", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();
    let mut child = std::process::Command::new("touch")
        .env("TZ", "UTC")
        .args([
            "-d",
            "2001-02-03 04:05:06 UTC",
            mountpoint.join("data/file").to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("mtime=<set>"))
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

    let mount_metadata = fs::metadata(mountpoint.join("data/file")).unwrap();
    assert_eq!(
        mount_metadata
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        981173106
    );
    assert_eq!(
        fs::metadata(local.join("file"))
            .unwrap()
            .modified()
            .unwrap(),
        underlying_before.modified().unwrap()
    );
    let log = session_log(&session);
    assert_log_line_contains(
        &log,
        &[" pending ", "path=/data/file SETATTR", "mtime=<set>"],
    );
    assert_log_line_contains(&log, &["decision", &format!("request={id}"), "ALLOW"]);
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
        .args(["protect-metadata", "/data/**"])
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
            let output = gatefs_cmd_for(&runtime, &log_dir)
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
fn bypass_write_allows_matching_write_effects_without_pending() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_bypass_write_effects");
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
        .args(["protect-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    fs::write(mountpoint.join("data/file"), "created through bypass").unwrap();
    assert_eq!(
        fs::read_to_string(local.join("file")).unwrap(),
        "created through bypass"
    );
    fs::write(mountpoint.join("data/file"), "updated through bypass").unwrap();
    assert_eq!(
        fs::read_to_string(local.join("file")).unwrap(),
        "updated through bypass"
    );
    fs::remove_file(mountpoint.join("data/file")).unwrap();
    assert!(!local.join("file").exists());
    session
        .sandbox_cmd()
        .arg("allow")
        .assert()
        .success()
        .stdout(predicates::str::is_empty());
}

#[test]
#[ignore]
fn append_open_writes_at_end_even_with_zero_offset() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_append_flag");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "base").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-write", "/data/file"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("printf plus >> \"$1\"")
        .arg("sh")
        .arg(mountpoint.join("data/file"))
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(fs::read_to_string(local.join("file")).unwrap(), "baseplus");
}

#[test]
#[ignore]
fn create_exclusive_fails_when_target_exists() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_create_exclusive");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "existing").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-write", "/data/file"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg("set -C; : > \"$1\"")
        .arg("sh")
        .arg(mountpoint.join("data/file"))
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(fs::read_to_string(local.join("file")).unwrap(), "existing");
}

#[test]
#[ignore]
fn protected_mknod_fifo_allow_forwards_to_backing_filesystem() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    require_command("mkfifo");
    let session = RunningSession::start("demo_fuse_mknod_fifo");
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
        .args(["protect-write", "/data/fifo"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let mut child = std::process::Command::new("mkfifo")
        .arg(mountpoint.join("data/fifo"))
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("WRITE mknod"))
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
    assert!(
        fs::symlink_metadata(local.join("fifo"))
            .unwrap()
            .file_type()
            .is_fifo()
    );
    assert_log_line_contains(
        &session_log(&session),
        &[" pending ", "path=/data/fifo WRITE mknod"],
    );
}

#[test]
#[ignore]
fn protected_symlink_write_allow_executes_host_mutation() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_symlink_write");
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
        .args(["protect-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let mut child = std::process::Command::new("ln")
        .args(["-s", "file", mountpoint.join("data/link").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("WRITE symlink"))
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
    assert_eq!(
        fs::read_link(local.join("link")).unwrap(),
        Path::new("file")
    );

    let log = session_log(&session);
    assert_log_line_contains(&log, &[" pending ", "path=/data/link WRITE symlink"]);
    assert_log_line_contains(&log, &["decision", &format!("request={id}"), "ALLOW"]);
}

#[test]
#[ignore]
fn metadata_protection_blocks_truncate_even_when_write_is_bypassed() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_truncate_metadata_precedence");
    let local = session.temp.path().join("local");
    let mountpoint = session.temp.path().join("mnt");
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&mountpoint).unwrap();
    fs::write(local.join("file"), "hello world").unwrap();

    session
        .sandbox_cmd()
        .args(["mount", local.to_str().unwrap(), "/data"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["bypass-write", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-metadata", "/data/**"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let mut child = std::process::Command::new("truncate")
        .args(["-s", "5", mountpoint.join("data/file").to_str().unwrap()])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).contains("METADATA truncate"))
            .unwrap_or(false)
    }));
    assert_eq!(
        fs::read_to_string(local.join("file")).unwrap(),
        "hello world"
    );
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    let id = pending.split_whitespace().next().unwrap().to_string();
    session
        .sandbox_cmd()
        .args(["allow", &id])
        .assert()
        .success();
    assert!(wait_child(&mut child).success());
    assert_eq!(fs::read_to_string(local.join("file")).unwrap(), "hello");
}

#[test]
#[ignore]
fn protected_hardlink_cleans_up_sibling_pending_after_deny() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_hardlink_deny_cleanup");
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
        .args(["protect-metadata", "/data/file"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-write", "/data/hard"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let mut child = std::process::Command::new("ln")
        .args([
            mountpoint.join("data/file").to_str().unwrap(),
            mountpoint.join("data/hard").to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| pending_ids(&String::from_utf8_lossy(&out.stdout)).len() == 2)
            .unwrap_or(false)
    }));
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    let ids = pending_ids(&pending);
    session
        .sandbox_cmd()
        .args(["deny", &ids[0]])
        .assert()
        .success();
    assert!(!wait_child(&mut child).success());
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| out.stdout.is_empty())
            .unwrap_or(false)
    }));
    assert!(!local.join("hard").exists());
}

#[test]
#[ignore]
fn protected_hardlink_requires_source_metadata_and_destination_write_effects() {
    require_fuse();
    if !fuse_enabled() {
        return;
    }
    let session = RunningSession::start("demo_fuse_hardlink_effects");
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
        .args(["protect-metadata", "/data/file"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["protect-write", "/data/hard"])
        .assert()
        .success();
    session
        .sandbox_cmd()
        .args(["attach", mountpoint.to_str().unwrap()])
        .assert()
        .success();

    let mut child = std::process::Command::new("ln")
        .args([
            mountpoint.join("data/file").to_str().unwrap(),
            mountpoint.join("data/hard").to_str().unwrap(),
        ])
        .spawn()
        .unwrap();
    assert!(wait_until(Duration::from_secs(3), || {
        session
            .sandbox_cmd()
            .arg("allow")
            .output()
            .map(|out| {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains("METADATA link") && stdout.contains("WRITE link")
            })
            .unwrap_or(false)
    }));
    let pending =
        String::from_utf8(session.sandbox_cmd().arg("allow").output().unwrap().stdout).unwrap();
    let ids = pending_ids(&pending);
    assert_eq!(
        ids.len(),
        2,
        "expected source metadata and destination write pending requests: {pending}"
    );
    for id in &ids {
        session.sandbox_cmd().args(["allow", id]).assert().success();
    }
    assert!(wait_child(&mut child).success());
    assert!(local.join("hard").exists());
    assert_eq!(fs::metadata(local.join("file")).unwrap().nlink(), 2);

    let log = session_log(&session);
    assert_log_line_contains(&log, &[" pending ", "path=/data/file METADATA link"]);
    assert_log_line_contains(&log, &[" pending ", "path=/data/hard WRITE link"]);
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
        .args(["protect-metadata", "/data/**"])
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
