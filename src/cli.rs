//! Command-line interface implementation.

use std::ffi::{CString, OsString};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

use clap::{ArgAction, Parser, Subcommand};

use crate::ipc::{self, Request, Response};
use crate::path::{SandboxPath, rewrite_sandbox_path_arg};
use crate::runtime::RuntimePaths;
use crate::session;
use crate::state::{ProtectionKind, ProtectionRule, TrustedPathScope};
use crate::{Error, Result};

#[derive(Debug, Parser)]
#[command(
    name = "sandboxfs",
    version,
    about = "Foreground, in-memory overlay sandbox filesystem"
)]
pub struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Debug, Subcommand)]
enum TopCommand {
    /// Run a named sandbox session in the foreground.
    Run { name: String },
    #[command(external_subcommand)]
    Sandbox(Vec<OsString>),
}

#[derive(Debug, Parser)]
struct SandboxCli {
    name: String,
    #[command(subcommand)]
    command: SandboxCommand,
}

#[derive(Debug, Subcommand)]
enum SandboxCommand {
    /// Stop the foreground sandbox session.
    Destroy,
    Attach {
        mountpoint: String,
    },
    Detach {
        mountpoint: String,
    },
    Mount {
        local: Option<String>,
        on_fs: Option<String>,
    },
    Umount {
        on_fs: String,
    },
    Hide {
        on_fs: String,
    },
    ProtectRead {
        pattern: String,
    },
    ProtectWrite {
        pattern: String,
    },
    UnprotectRead {
        pattern: String,
    },
    UnprotectWrite {
        pattern: String,
    },
    ListProtection {
        #[arg(long, action = ArgAction::SetTrue)]
        read: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        write: bool,
    },
    Chmod {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Chown {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Chattr {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Allow {
        #[arg(long, action = ArgAction::SetTrue)]
        do_nothing: bool,
        id: Option<u64>,
    },
    Deny {
        id: u64,
    },
    Monitor {
        #[arg(short = 'f', long, action = ArgAction::SetTrue)]
        follow: bool,
    },
    Metadata,
}

pub fn main_entry() -> Result<i32> {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> Result<i32> {
    let runtime = RuntimePaths::discover()?;
    match cli.command {
        TopCommand::Run { name } => {
            session::serve_session(runtime, name)?;
            Ok(0)
        }
        TopCommand::Sandbox(args) => {
            let mut argv = vec![OsString::from("sandboxfs")];
            argv.extend(args);
            let sandbox =
                SandboxCli::try_parse_from(argv).map_err(|err| Error::msg(err.to_string()))?;
            run_sandbox(&runtime, sandbox)
        }
    }
}

fn run_sandbox(runtime: &RuntimePaths, cli: SandboxCli) -> Result<i32> {
    let name = cli.name;
    match cli.command {
        SandboxCommand::Destroy => print_response(send(
            runtime,
            &name,
            &Request::Shutdown { name: name.clone() },
        )?),
        SandboxCommand::Attach { mountpoint } => print_response(send(
            runtime,
            &name,
            &Request::Attach {
                name: name.clone(),
                mountpoint,
                temporary: false,
            },
        )?),
        SandboxCommand::Detach { mountpoint } => print_response(send(
            runtime,
            &name,
            &Request::Detach {
                name: name.clone(),
                mountpoint,
            },
        )?),
        SandboxCommand::Mount {
            local: None,
            on_fs: None,
        } => print_response(send(
            runtime,
            &name,
            &Request::ListMounts { name: name.clone() },
        )?),
        SandboxCommand::Mount {
            local: Some(local),
            on_fs: Some(on_fs),
        } => {
            let on_fs = SandboxPath::new(on_fs)?;
            print_response(send(
                runtime,
                &name,
                &Request::Mount {
                    name: name.clone(),
                    local,
                    on_fs,
                },
            )?)
        }
        SandboxCommand::Mount { .. } => Err(Error::msg(
            "mount expects either no arguments or <local> <on_fs>",
        )),
        SandboxCommand::Umount { on_fs } => print_response(send(
            runtime,
            &name,
            &Request::Umount {
                name: name.clone(),
                on_fs: SandboxPath::new(on_fs)?,
            },
        )?),
        SandboxCommand::Hide { on_fs } => print_response(send(
            runtime,
            &name,
            &Request::Hide {
                name: name.clone(),
                on_fs: SandboxPath::new(on_fs)?,
            },
        )?),
        SandboxCommand::ProtectRead { pattern } => protect(
            runtime,
            &name,
            ProtectionKind::Read,
            SandboxPath::new(pattern)?,
        ),
        SandboxCommand::ProtectWrite { pattern } => protect(
            runtime,
            &name,
            ProtectionKind::Write,
            SandboxPath::new(pattern)?,
        ),
        SandboxCommand::UnprotectRead { pattern } => unprotect(
            runtime,
            &name,
            ProtectionKind::Read,
            SandboxPath::new(pattern)?,
        ),
        SandboxCommand::UnprotectWrite { pattern } => unprotect(
            runtime,
            &name,
            ProtectionKind::Write,
            SandboxPath::new(pattern)?,
        ),
        SandboxCommand::ListProtection { read, write } => print_response(send(
            runtime,
            &name,
            &Request::ListProtection {
                name: name.clone(),
                include_read: read,
                include_write: write,
            },
        )?),
        SandboxCommand::Chmod { args } => run_trusted_command(runtime, &name, "chmod", args),
        SandboxCommand::Chown { args } => run_trusted_command(runtime, &name, "chown", args),
        SandboxCommand::Chattr { args } => run_trusted_command(runtime, &name, "chattr", args),
        SandboxCommand::Allow {
            do_nothing: false,
            id: None,
        } => print_response(send(
            runtime,
            &name,
            &Request::Pending { name: name.clone() },
        )?),
        SandboxCommand::Allow {
            do_nothing: true,
            id: None,
        } => Err(Error::msg("allow --do-nothing requires an operation id")),
        SandboxCommand::Allow {
            do_nothing,
            id: Some(id),
        } => print_response(send(
            runtime,
            &name,
            &Request::Allow {
                name: name.clone(),
                id,
                do_nothing,
            },
        )?),
        SandboxCommand::Deny { id } => print_response(send(
            runtime,
            &name,
            &Request::Deny {
                name: name.clone(),
                id,
            },
        )?),
        SandboxCommand::Monitor { follow } => monitor(runtime, &name, follow),
        SandboxCommand::Metadata => print_response(send(
            runtime,
            &name,
            &Request::Metadata { name: name.clone() },
        )?),
    }
}

fn protect(
    runtime: &RuntimePaths,
    name: &str,
    kind: ProtectionKind,
    pattern: SandboxPath,
) -> Result<i32> {
    print_response(send(
        runtime,
        name,
        &Request::Protect {
            name: name.to_string(),
            kind,
            pattern,
        },
    )?)
}

fn unprotect(
    runtime: &RuntimePaths,
    name: &str,
    kind: ProtectionKind,
    pattern: SandboxPath,
) -> Result<i32> {
    print_response(send(
        runtime,
        name,
        &Request::Unprotect {
            name: name.to_string(),
            kind,
            pattern,
        },
    )?)
}

fn send(runtime: &RuntimePaths, name: &str, request: &Request) -> Result<Response> {
    ipc::send(&runtime.socket_path(name), request).map_err(|error| {
        Error::msg(format!(
            "could not contact sandbox session {name}; is `sandboxfs run {name}` running? ({error})"
        ))
    })
}

fn print_response(response: Response) -> Result<i32> {
    match response {
        Response::Ok => Ok(0),
        Response::Text { text } => {
            if !text.is_empty() {
                println!("{text}");
            }
            Ok(0)
        }
        Response::Pending { items } => {
            let text = format_pending_items(&items);
            if !text.is_empty() {
                println!("{text}");
            }
            Ok(0)
        }
        Response::ProtectionRules { items } => {
            let text = format_protection_rules(&items);
            if !text.is_empty() {
                println!("{text}");
            }
            Ok(0)
        }
        Response::Trusted { .. } => Ok(0),
        Response::Error { message } => Err(Error::msg(message)),
    }
}

fn format_pending_items(items: &[crate::state::PendingMetadataRequest]) -> String {
    items
        .iter()
        .map(|item| format!("{} {}", item.id, item.description))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_protection_rules(items: &[ProtectionRule]) -> String {
    items
        .iter()
        .map(|item| format!("{} {}", item.kind, item.pattern))
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_trusted_command(
    runtime: &RuntimePaths,
    name: &str,
    command_name: &str,
    args: Vec<String>,
) -> Result<i32> {
    if args.is_empty() {
        return Err(Error::msg(format!("{command_name} requires arguments")));
    }
    let rewritten = rewrite_command_path_args(command_name, &args)?;
    let command_c = CString::new(command_name).map_err(|_| Error::msg("command contains NUL"))?;
    let mut argv_storage = Vec::with_capacity(rewritten.args.len() + 1);
    argv_storage.push(command_c.clone());
    for arg in &rewritten.args {
        argv_storage
            .push(CString::new(arg.as_str()).map_err(|_| Error::msg("argument contains NUL"))?);
    }
    let mut argv_ptrs: Vec<*const libc::c_char> =
        argv_storage.iter().map(|arg| arg.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let op_id = monotonic_id();
    let mountpoint = runtime.tmp_mount_dir(name, op_id);
    fs::create_dir_all(&mountpoint)?;
    let begin = match send(
        runtime,
        name,
        &Request::BeginTrustedOperation {
            name: name.to_string(),
            command: command_name.to_string(),
            mountpoint: mountpoint.display().to_string(),
            paths: rewritten.paths.clone(),
        },
    ) {
        Ok(response) => response,
        Err(error) => {
            let _ = fs::remove_dir(&mountpoint);
            return Err(error);
        }
    };
    let (token, actual_mountpoint) = match begin {
        Response::Trusted {
            token, mountpoint, ..
        } => (token, PathBuf::from(mountpoint)),
        Response::Error { message } => {
            let _ = fs::remove_dir(&mountpoint);
            return Err(Error::msg(message));
        }
        other => {
            let _ = fs::remove_dir(&mountpoint);
            return Err(Error::msg(format!(
                "unexpected session response: {other:?}"
            )));
        }
    };

    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        cleanup_trusted_lossy(runtime, name, &token);
        return Err(std::io::Error::last_os_error().into());
    }
    let read_raw_fd = fds[0];
    let write_raw_fd = fds[1];
    let cwd_c = match CString::new(actual_mountpoint.as_os_str().as_bytes()) {
        Ok(cwd) => cwd,
        Err(_) => {
            close_fd(read_raw_fd);
            close_fd(write_raw_fd);
            cleanup_trusted_lossy(runtime, name, &token);
            return Err(Error::msg("mountpoint contains NUL"));
        }
    };

    // Avoid a race where the child reaches FUSE before the session has registered
    // its pid as trusted. std::process::Command cannot be used here because its
    // spawn path waits for exec and would deadlock if pre-exec blocked.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        close_fd(read_raw_fd);
        close_fd(write_raw_fd);
        cleanup_trusted_lossy(runtime, name, &token);
        return Err(std::io::Error::last_os_error().into());
    }
    if child_pid == 0 {
        unsafe {
            let _ = libc::close(write_raw_fd);
            let mut byte = [0u8; 1];
            if libc::read(read_raw_fd, byte.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(126);
            }
            let _ = libc::close(read_raw_fd);
            if libc::chdir(cwd_c.as_ptr()) != 0 {
                libc::_exit(125);
            }
            libc::execvp(command_c.as_ptr(), argv_ptrs.as_ptr());
            libc::_exit(127);
        }
    }

    close_fd(read_raw_fd);
    let register_result = match send(
        runtime,
        name,
        &Request::RegisterTrustedPid {
            token: token.clone(),
            pid: child_pid as u32,
            uid: unsafe { libc::geteuid() },
        },
    ) {
        Ok(response) => response,
        Err(error) => {
            kill_release_wait(child_pid, write_raw_fd);
            cleanup_trusted_lossy(runtime, name, &token);
            return Err(error);
        }
    };
    match register_result {
        Response::Ok => {}
        Response::Error { message } => {
            kill_release_wait(child_pid, write_raw_fd);
            cleanup_trusted_lossy(runtime, name, &token);
            return Err(Error::msg(message));
        }
        other => {
            kill_release_wait(child_pid, write_raw_fd);
            cleanup_trusted_lossy(runtime, name, &token);
            return Err(Error::msg(format!(
                "unexpected session response: {other:?}"
            )));
        }
    }
    if unsafe { libc::write(write_raw_fd, [1u8].as_ptr().cast(), 1) } != 1 {
        let error = std::io::Error::last_os_error();
        close_fd(write_raw_fd);
        let mut status = 0;
        unsafe {
            libc::waitpid(child_pid, &mut status, 0);
        }
        cleanup_trusted_lossy(runtime, name, &token);
        return Err(error.into());
    }
    close_fd(write_raw_fd);
    let mut status = 0;
    if unsafe { libc::waitpid(child_pid, &mut status, 0) } < 0 {
        cleanup_trusted_lossy(runtime, name, &token);
        return Err(std::io::Error::last_os_error().into());
    }
    cleanup_trusted(runtime, name, &token)?;
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(1)
    }
}

fn kill_release_wait(pid: libc::pid_t, write_fd: libc::c_int) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let _ = libc::write(write_fd, [1u8].as_ptr().cast(), 1);
        close_fd(write_fd);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }
}

fn close_fd(fd: libc::c_int) {
    unsafe {
        libc::close(fd);
    }
}

fn cleanup_trusted(runtime: &RuntimePaths, name: &str, token: &str) -> Result<()> {
    match send(
        runtime,
        name,
        &Request::EndTrustedOperation {
            token: token.to_string(),
        },
    )? {
        Response::Ok => Ok(()),
        Response::Error { message } => Err(Error::msg(message)),
        other => Err(Error::msg(format!(
            "unexpected session response: {other:?}"
        ))),
    }
}

fn cleanup_trusted_lossy(runtime: &RuntimePaths, name: &str, token: &str) {
    let _ = cleanup_trusted(runtime, name, token);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RewrittenCommand {
    args: Vec<String>,
    paths: Vec<TrustedPathScope>,
}

fn rewrite_command_path_args(command: &str, args: &[String]) -> Result<RewrittenCommand> {
    match command {
        "chmod" => rewrite_chmod_args(args),
        "chown" => rewrite_chown_args(args),
        "chattr" => rewrite_chattr_args(args),
        _ => rewrite_all_args(args),
    }
}

fn rewrite_chmod_args(args: &[String]) -> Result<RewrittenCommand> {
    if args.len() < 2 {
        return Err(Error::msg("chmod requires mode and path"));
    }
    let mut out = args.to_vec();
    let recursive = chmod_is_recursive(args);
    let mut paths = Vec::new();
    let mut mode_seen = false;
    for item in &mut out {
        if item == "--" {
            continue;
        }
        if item.starts_with("--reference") {
            return Err(Error::msg(
                "chmod --reference is not supported by sandboxfs path rewriting",
            ));
        }
        if item.starts_with('-') && !mode_seen {
            continue;
        }
        if !mode_seen {
            mode_seen = true;
            continue;
        }
        rewrite_path_operand(item, recursive, &mut paths)?;
    }
    Ok(RewrittenCommand { args: out, paths })
}

fn rewrite_chown_args(args: &[String]) -> Result<RewrittenCommand> {
    if args.len() < 2 {
        return Err(Error::msg("chown requires owner and path"));
    }
    let mut out = args.to_vec();
    let recursive = chown_is_recursive(args);
    let mut paths = Vec::new();
    let mut owner_seen = false;
    for item in &mut out {
        if item == "--" {
            continue;
        }
        if item.starts_with("--reference") || item.starts_with("--from") {
            return Err(Error::msg(
                "chown --reference/--from is not supported by sandboxfs path rewriting",
            ));
        }
        if item.starts_with('-') && !owner_seen {
            continue;
        }
        if !owner_seen {
            owner_seen = true;
            continue;
        }
        rewrite_path_operand(item, recursive, &mut paths)?;
    }
    Ok(RewrittenCommand { args: out, paths })
}

fn rewrite_chattr_args(args: &[String]) -> Result<RewrittenCommand> {
    if args.len() < 2 {
        return Err(Error::msg("chattr requires flags and path"));
    }
    let mut out = args.to_vec();
    let recursive = chattr_is_recursive(args);
    let mut paths = Vec::new();
    let mut flags_seen = false;
    for item in &mut out {
        if item == "--" {
            continue;
        }
        if item.starts_with('-') && !item.starts_with("--") && !flags_seen {
            flags_seen = true;
            continue;
        }
        if item.starts_with('+') || item.starts_with('-') || item.starts_with('=') {
            flags_seen = true;
            continue;
        }
        if !flags_seen {
            flags_seen = true;
            continue;
        }
        rewrite_path_operand(item, recursive, &mut paths)?;
    }
    Ok(RewrittenCommand { args: out, paths })
}

fn rewrite_all_args(args: &[String]) -> Result<RewrittenCommand> {
    let mut out = args.to_vec();
    let mut paths = Vec::new();
    for item in &mut out {
        rewrite_path_operand(item, false, &mut paths)?;
    }
    Ok(RewrittenCommand { args: out, paths })
}

fn rewrite_path_operand(
    item: &mut String,
    recursive: bool,
    paths: &mut Vec<TrustedPathScope>,
) -> Result<()> {
    reject_parent_dir_operand(item)?;
    paths.push(TrustedPathScope {
        path: SandboxPath::new(item.as_str())?,
        recursive,
    });
    *item = rewrite_sandbox_path_arg(item);
    Ok(())
}

fn reject_parent_dir_operand(item: &str) -> Result<()> {
    if Path::new(item)
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::msg(
            "metadata command paths containing '..' are not supported by sandboxfs path rewriting",
        ));
    }
    Ok(())
}

fn chmod_is_recursive(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--recursive"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('R'))
    })
}

fn chown_is_recursive(args: &[String]) -> bool {
    chmod_is_recursive(args)
}

fn chattr_is_recursive(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "-R"
            || arg == "--recursive"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('R'))
    })
}

const MONITOR_TAIL_LINES: usize = 10;

fn monitor(runtime: &RuntimePaths, name: &str, follow: bool) -> Result<i32> {
    let response = send(
        runtime,
        name,
        &Request::LogPath {
            name: name.to_string(),
        },
    )?;
    let path = match response {
        Response::Text { text } => PathBuf::from(text),
        Response::Error { message } => return Err(Error::msg(message)),
        other => {
            return Err(Error::msg(format!(
                "unexpected session response: {other:?}"
            )));
        }
    };
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err.into()),
    };
    print!("{}", tail_lines(&data, MONITOR_TAIL_LINES));
    std::io::stdout().flush()?;
    if !follow {
        return Ok(0);
    }
    let mut file = fs::OpenOptions::new().read(true).open(&path)?;
    let mut pos = file.metadata()?.len();
    loop {
        file.seek(SeekFrom::Start(pos))?;
        let mut buf = String::new();
        let n = file.read_to_string(&mut buf)?;
        if n > 0 {
            print!("{buf}");
            std::io::stdout().flush()?;
            pos += n as u64;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn tail_lines(data: &str, line_count: usize) -> &str {
    if line_count == 0 {
        return "";
    }
    let mut newline_count = 0usize;
    for (idx, byte) in data.bytes().enumerate().rev() {
        if byte == b'\n' {
            newline_count += 1;
            if newline_count > line_count {
                return &data[idx + 1..];
            }
        }
    }
    data
}

fn monotonic_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chmod_rewrites_only_path_arguments() {
        let rewritten = rewrite_chmod_args(&["-R".into(), "444".into(), "/a/b".into()]).unwrap();
        assert_eq!(rewritten.args, vec!["-R", "444", "./a/b"]);
        assert_eq!(
            rewritten.paths,
            vec![TrustedPathScope {
                path: SandboxPath::new("/a/b").unwrap(),
                recursive: true,
            }]
        );
    }

    #[test]
    fn chown_rewrites_only_path_arguments() {
        let rewritten = rewrite_chown_args(&["root:root".into(), "/a/b".into()]).unwrap();
        assert_eq!(rewritten.args, vec!["root:root", "./a/b"]);
        assert_eq!(
            rewritten.paths,
            vec![TrustedPathScope {
                path: SandboxPath::new("/a/b").unwrap(),
                recursive: false,
            }]
        );
    }

    #[test]
    fn path_rewriting_rejects_parent_components() {
        let error = rewrite_chmod_args(&["444".into(), "../host".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("'..'"));
    }

    #[test]
    fn monitor_tails_last_lines() {
        let data = "one\ntwo\nthree\nfour\n";
        assert_eq!(tail_lines(data, 2), "three\nfour\n");
        assert_eq!(tail_lines(data, 10), data);
        assert_eq!(tail_lines(data, 0), "");
    }

    #[test]
    fn pending_response_lines_use_operation_descriptions() {
        let items = vec![
            crate::state::PendingMetadataRequest {
                id: 7,
                sandbox: "demo".to_string(),
                operation: crate::state::MetadataOperation::Chmod {
                    path: SandboxPath::new("/data/file").unwrap(),
                    mode: 0o444,
                },
                kinds: vec![crate::state::PendingOperationKind::Mode],
                pid: 123,
                uid: 1000,
                gid: 1000,
                description: "path=/data/file SETATTR mode=0444".to_string(),
            },
            crate::state::PendingMetadataRequest {
                id: 8,
                sandbox: "demo".to_string(),
                operation: crate::state::MetadataOperation::Chattr {
                    path: SandboxPath::new("/data/file").unwrap(),
                    flags: crate::state::FS_IMMUTABLE_FL,
                },
                kinds: vec![crate::state::PendingOperationKind::Flags],
                pid: 123,
                uid: 1000,
                gid: 1000,
                description: "path=/data/file CHATTR flags=0x10".to_string(),
            },
        ];

        assert_eq!(
            format_pending_items(&items),
            "7 path=/data/file SETATTR mode=0444\n8 path=/data/file CHATTR flags=0x10"
        );
    }
}
