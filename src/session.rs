//! Foreground sandbox session server and state machine.

use std::fs;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use fuser::{Config, MountOption};

use crate::fs::SandboxFs;
use crate::ipc::{self, Request, Response};
use crate::log;
use crate::path::SandboxPath;
use crate::runtime::RuntimePaths;
use crate::state::{
    AttachMount, PendingDecision, PendingRequest, ProtectionKind, Sandbox, SandboxRegistry,
    TrustedOperation, TrustedPathScope,
};
use crate::{Error, Result};

#[derive(Debug)]
pub struct MountedSession {
    pub sandbox: String,
    pub mountpoint: PathBuf,
    pub temporary: bool,
    pub session: fuser::BackgroundSession,
}

#[derive(Debug)]
pub struct SessionState {
    pub registry: Arc<Mutex<SandboxRegistry>>,
    pub runtime: RuntimePaths,
    pub mounts: Mutex<Vec<MountedSession>>,
    pub log_writer: log::LogWriterHandle,
    _log_writer: Option<log::LogWriter>,
}

impl SessionState {
    pub fn new(runtime: RuntimePaths) -> Self {
        let log_writer = log::LogWriter::new();
        let log_writer_handle = log_writer.handle();
        Self::with_log_writer(runtime, log_writer_handle, Some(log_writer))
    }

    fn with_log_writer(
        runtime: RuntimePaths,
        log_writer: log::LogWriterHandle,
        owned_log_writer: Option<log::LogWriter>,
    ) -> Self {
        Self {
            registry: Arc::new(Mutex::new(SandboxRegistry::new())),
            runtime,
            mounts: Mutex::new(Vec::new()),
            log_writer,
            _log_writer: owned_log_writer,
        }
    }

    pub fn new_session(runtime: RuntimePaths, name: &str) -> Result<Self> {
        let state = Self::new(runtime);
        state.create_initial(name)?;
        Ok(state)
    }

    fn create_initial(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let log_path = self.runtime.sandbox_log_path(name);
        self.log_writer.reset(&log_path)?;
        let mut registry = self.registry.lock().unwrap();
        registry
            .sandboxes
            .insert(name.to_string(), Sandbox::new(name, log_path));
        Ok(())
    }

    pub fn handle(&self, request: Request) -> Response {
        match self.handle_result(request) {
            Ok(response) => response,
            Err(error) => Response::Error {
                message: error.to_string(),
            },
        }
    }

    fn handle_result(&self, request: Request) -> Result<Response> {
        match request {
            Request::Ping => Ok(Response::Ok),
            Request::Shutdown { name } => self.destroy(&name),
            Request::Attach {
                name,
                mountpoint,
                temporary,
            } => self.attach(&name, PathBuf::from(mountpoint), temporary),
            Request::Detach { name, mountpoint } => self.detach(&name, Path::new(&mountpoint)),
            Request::Mount { name, local, on_fs } => {
                self.mount_layer(&name, PathBuf::from(local), on_fs)
            }
            Request::Umount { name, on_fs } => self.umount_layer(&name, &on_fs),
            Request::Hide { name, on_fs } => self.hide(&name, on_fs),
            Request::Protect {
                name,
                kind,
                pattern,
            } => self.protect(&name, kind, pattern),
            Request::Unprotect {
                name,
                kind,
                pattern,
            } => self.unprotect(&name, kind, pattern),
            Request::ListProtection {
                name,
                include_read,
                include_write,
            } => self.list_protection(&name, include_read, include_write),
            Request::ListMounts { name } => self.list_mounts(&name),
            Request::Metadata { name } => self.metadata(&name),
            Request::BeginTrustedOperation {
                name,
                command,
                mountpoint,
                paths,
            } => self.begin_trusted(&name, &command, PathBuf::from(mountpoint), paths),
            Request::RegisterTrustedPid { token, pid, uid } => {
                self.register_trusted_pid(&token, pid, uid)
            }
            Request::EndTrustedOperation { token } => self.end_trusted(&token),
            Request::Pending { name } => self.pending(&name),
            Request::Allow {
                name,
                id,
                do_nothing,
            } => self.allow(&name, id, do_nothing),
            Request::Deny { name, id } => self.deny(&name, id),
            Request::LogPath { name } => self.log_path(&name),
        }
    }

    pub fn destroy(&self, name: &str) -> Result<Response> {
        let (mountpoints, waiters) = {
            let mut registry = self.registry.lock().unwrap();
            let Some(sandbox) = registry.sandboxes.get(name) else {
                return Err(Error::msg(format!("sandbox not found: {name}")));
            };
            let mountpoints: Vec<PathBuf> = sandbox.attaches.keys().cloned().collect();
            let removed_pending: Vec<u64> = registry
                .pending_requests_for_sandbox(name)
                .into_iter()
                .map(|pending| pending.id())
                .collect();
            let mut waiters = Vec::new();
            for id in removed_pending {
                registry.remove_any_pending_request(id);
                if let Some(waiter) = registry.pending_waiters.remove(&id) {
                    waiters.push(waiter);
                }
            }
            registry
                .trusted
                .retain(|_, trusted| trusted.sandbox != name);
            (mountpoints, waiters)
        };
        for waiter in waiters {
            let (lock, cvar) = &*waiter;
            *lock.lock().unwrap() = Some(PendingDecision::Deny);
            cvar.notify_all();
        }
        for mountpoint in mountpoints {
            self.detach(name, &mountpoint)?;
        }
        let mut registry = self.registry.lock().unwrap();
        let Some(sandbox) = registry.sandboxes.remove(name) else {
            return Ok(Response::Ok);
        };
        self.log_writer.remove(&sandbox.log_path)?;
        Ok(Response::Ok)
    }

    fn attach(&self, name: &str, mountpoint: PathBuf, temporary: bool) -> Result<Response> {
        let mountpoint = canonicalize_existing_dir(&mountpoint)?;
        {
            let registry = self.registry.lock().unwrap();
            if !registry.sandboxes.contains_key(name) {
                return Err(Error::msg(format!("sandbox not found: {name}")));
            }
            for (other_name, sandbox) in &registry.sandboxes {
                if sandbox.attaches.contains_key(&mountpoint) {
                    if other_name == name {
                        return Err(Error::msg(format!(
                            "mountpoint already attached: {}",
                            mountpoint.display()
                        )));
                    }
                    return Err(Error::msg(format!(
                        "mountpoint already used by sandbox {other_name}: {}",
                        mountpoint.display()
                    )));
                }
            }
        }

        let fs = SandboxFs::new(
            name.to_string(),
            Arc::clone(&self.registry),
            self.log_writer.clone(),
        );
        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::FSName(format!("sandboxfs:{name}")),
            MountOption::Subtype("sandboxfs".to_string()),
            MountOption::RW,
        ];
        let session = fuser::spawn_mount2(fs, &mountpoint, &config)?;
        self.mounts.lock().unwrap().push(MountedSession {
            sandbox: name.to_string(),
            mountpoint: mountpoint.clone(),
            temporary,
            session,
        });
        let mut registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        sandbox.attaches.insert(
            mountpoint.clone(),
            AttachMount {
                mountpoint: mountpoint.clone(),
                temporary,
                active: true,
            },
        );
        Ok(Response::Ok)
    }

    fn detach(&self, name: &str, mountpoint: &Path) -> Result<Response> {
        let mountpoint = canonicalize_maybe_existing(mountpoint)?;
        {
            let registry = self.registry.lock().unwrap();
            let sandbox = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
            if !sandbox.attaches.contains_key(&mountpoint) {
                return Err(Error::msg(format!(
                    "mountpoint is not attached to sandbox {name}: {}",
                    mountpoint.display()
                )));
            }
        }

        let session = {
            let mut mounts = self.mounts.lock().unwrap();
            let idx = mounts
                .iter()
                .position(|mounted| mounted.sandbox == name && mounted.mountpoint == mountpoint)
                .ok_or_else(|| {
                    Error::msg(format!("mount session not found: {}", mountpoint.display()))
                })?;
            mounts.remove(idx)
        };
        session.session.umount_and_join()?;
        let mut registry = self.registry.lock().unwrap();
        if let Some(sandbox) = registry.sandboxes.get_mut(name) {
            sandbox.attaches.remove(&mountpoint);
        }
        Ok(Response::Ok)
    }

    fn mount_layer(&self, name: &str, local: PathBuf, on_fs: SandboxPath) -> Result<Response> {
        let local = fs::canonicalize(&local)?;
        if !local.exists() {
            return Err(Error::msg(format!(
                "local path does not exist: {}",
                local.display()
            )));
        }
        let mut registry = self.registry.lock().unwrap();
        let id = registry.next_operation_id();
        let sandbox = registry
            .sandboxes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        sandbox.add_layer(local.clone(), on_fs.clone());
        self.log_writer.append(
            &sandbox.log_path,
            log::format_log_line(id, &format!("mount local={} path={on_fs}", local.display())),
        )?;
        Ok(Response::Ok)
    }

    fn umount_layer(&self, name: &str, on_fs: &SandboxPath) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let id = registry.next_operation_id();
        let sandbox = registry
            .sandboxes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        if !sandbox.remove_layer(on_fs) {
            return Err(Error::msg(format!("no mount at {on_fs}")));
        }
        self.log_writer.append(
            &sandbox.log_path,
            log::format_log_line(id, &format!("umount path={on_fs}")),
        )?;
        Ok(Response::Ok)
    }

    fn hide(&self, name: &str, on_fs: SandboxPath) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let id = registry.next_operation_id();
        let sandbox = registry
            .sandboxes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        sandbox.add_hide(on_fs.clone());
        self.log_writer.append(
            &sandbox.log_path,
            log::format_log_line(id, &format!("hide path={on_fs}")),
        )?;
        Ok(Response::Ok)
    }

    fn protect(&self, name: &str, kind: ProtectionKind, pattern: SandboxPath) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let id = registry.next_operation_id();
        let sandbox = registry
            .sandboxes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        let result = sandbox.protect(kind, pattern.clone());
        self.log_writer.append(
            &sandbox.log_path,
            log::format_log_line(
                id,
                &format!(
                    "protect kind={kind} pattern={pattern} result={}",
                    result.log_name()
                ),
            ),
        )?;
        Ok(Response::Ok)
    }

    fn unprotect(
        &self,
        name: &str,
        kind: ProtectionKind,
        pattern: SandboxPath,
    ) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let id = registry.next_operation_id();
        let sandbox = registry
            .sandboxes
            .get_mut(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        let result = sandbox.unprotect(kind, &pattern);
        self.log_writer.append(
            &sandbox.log_path,
            log::format_log_line(
                id,
                &format!(
                    "unprotect kind={kind} pattern={pattern} result={}",
                    result.log_name()
                ),
            ),
        )?;
        Ok(Response::Ok)
    }

    fn list_protection(
        &self,
        name: &str,
        include_read: bool,
        include_write: bool,
    ) -> Result<Response> {
        let registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        Ok(Response::ProtectionRules {
            items: sandbox.protection_rules(include_read, include_write),
        })
    }

    fn list_mounts(&self, name: &str) -> Result<Response> {
        let registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        let mut lines = Vec::new();
        for layer in &sandbox.layers {
            lines.push(format!("{} on {}", layer.local.display(), layer.on_fs));
        }
        for hide in &sandbox.hides {
            lines.push(format!("hide {}", hide.path));
        }
        Ok(Response::Text {
            text: lines.join("\n"),
        })
    }

    fn metadata(&self, name: &str) -> Result<Response> {
        let registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        let lines: Vec<String> = sandbox
            .metadata_differences()
            .into_iter()
            .map(|p| p.to_string())
            .collect();
        Ok(Response::Text {
            text: lines.join("\n"),
        })
    }

    fn begin_trusted(
        &self,
        name: &str,
        command: &str,
        requested_mountpoint: PathBuf,
        paths: Vec<TrustedPathScope>,
    ) -> Result<Response> {
        let operation_id = {
            let mut registry = self.registry.lock().unwrap();
            if !registry.sandboxes.contains_key(name) {
                return Err(Error::msg(format!("sandbox not found: {name}")));
            }
            registry.next_operation_id()
        };
        fs::create_dir_all(&requested_mountpoint)?;
        self.attach(name, requested_mountpoint.clone(), true)?;
        let token = format!("{name}-{operation_id}-{}", std::process::id());
        let mut registry = self.registry.lock().unwrap();
        registry.trusted.insert(
            token.clone(),
            TrustedOperation {
                id: operation_id,
                sandbox: name.to_string(),
                token: token.clone(),
                pid: None,
                uid: None,
                mountpoint: requested_mountpoint.clone(),
                command: command.to_string(),
                paths,
            },
        );
        Ok(Response::Trusted {
            token,
            operation_id,
            mountpoint: requested_mountpoint.display().to_string(),
        })
    }

    fn register_trusted_pid(&self, token: &str, pid: u32, uid: u32) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let trusted = registry
            .trusted
            .get_mut(token)
            .ok_or_else(|| Error::msg(format!("trusted operation not found: {token}")))?;
        trusted.pid = Some(pid);
        trusted.uid = Some(uid);
        Ok(Response::Ok)
    }

    fn end_trusted(&self, token: &str) -> Result<Response> {
        let trusted = self.registry.lock().unwrap().trusted.remove(token);
        if let Some(trusted) = trusted {
            self.detach(&trusted.sandbox, &trusted.mountpoint)?;
            fs::remove_dir(&trusted.mountpoint)?;
            Ok(Response::Ok)
        } else {
            Err(Error::msg(format!("trusted operation not found: {token}")))
        }
    }

    fn pending(&self, name: &str) -> Result<Response> {
        let registry = self.registry.lock().unwrap();
        if !registry.sandboxes.contains_key(name) {
            return Err(Error::msg(format!("sandbox not found: {name}")));
        }
        let items = registry.pending_requests_for_sandbox(name);
        Ok(Response::Pending { items })
    }

    fn allow(&self, name: &str, id: u64, do_nothing: bool) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let pending = registry
            .remove_any_pending_request(id)
            .ok_or_else(|| Error::msg(format!("pending operation not found: {id}")))?;
        if pending.sandbox() != name {
            registry.insert_any_pending_request(pending);
            return Err(Error::msg(format!(
                "pending operation {id} does not belong to sandbox {name}"
            )));
        }
        let decision_id = registry.next_operation_id();
        let waiter = registry.pending_waiters.remove(&id);
        let log_path = registry
            .sandboxes
            .get(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
            .log_path
            .clone();
        if waiter.is_none()
            && !do_nothing
            && let PendingRequest::Metadata(pending) = &pending
        {
            let sandbox = registry
                .sandboxes
                .get_mut(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
            sandbox.apply_metadata_override(&pending.operation)?;
        }
        let log_result = self.log_writer.append(
            &log_path,
            log::format_log_line(
                decision_id,
                &format!(
                    "decision request={id} {}",
                    if do_nothing {
                        "ALLOW_DO_NOTHING"
                    } else {
                        "ALLOW"
                    }
                ),
            ),
        );
        notify_pending_waiter(
            waiter,
            if do_nothing {
                PendingDecision::DoNothing
            } else {
                PendingDecision::Apply
            },
        );
        log_result?;
        Ok(Response::Ok)
    }

    fn deny(&self, name: &str, id: u64) -> Result<Response> {
        let mut registry = self.registry.lock().unwrap();
        let pending = registry
            .remove_any_pending_request(id)
            .ok_or_else(|| Error::msg(format!("pending operation not found: {id}")))?;
        if pending.sandbox() != name {
            registry.insert_any_pending_request(pending);
            return Err(Error::msg(format!(
                "pending operation {id} does not belong to sandbox {name}"
            )));
        }
        let decision_id = registry.next_operation_id();
        let log_path = registry
            .sandboxes
            .get(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
            .log_path
            .clone();
        let waiter = registry.pending_waiters.remove(&id);
        let log_result = self.log_writer.append(
            &log_path,
            log::format_log_line(decision_id, &format!("decision request={id} DENY")),
        );
        notify_pending_waiter(waiter, PendingDecision::Deny);
        log_result?;
        Ok(Response::Ok)
    }

    fn log_path(&self, name: &str) -> Result<Response> {
        let registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get(name)
            .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
        Ok(Response::Text {
            text: sandbox.log_path.display().to_string(),
        })
    }
}

pub fn serve_session(runtime: RuntimePaths, name: String) -> Result<()> {
    let socket = runtime.socket_path(&name);
    if let Some(parent) = socket.parent() {
        fs::create_dir_all(parent)?;
    }
    prepare_socket_path(&socket)?;
    let listener = UnixListener::bind(&socket)?;
    listener.set_nonblocking(true)?;
    let state = match SessionState::new_session(runtime.clone(), &name) {
        Ok(state) => Arc::new(state),
        Err(error) => {
            let _ = fs::remove_file(&socket);
            return Err(error);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    install_signal_handlers(Arc::clone(&stop))?;

    println!("sandboxfs {name} running");
    println!("socket: {}", socket.display());
    println!("log:    {}", runtime.sandbox_log_path(&name).display());
    println!("press Ctrl-C or run `sandboxfs {name} destroy` to stop");

    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    let request = match ipc::read_request(&stream) {
                        Ok(request) => request,
                        Err(error) => {
                            let _ = ipc::write_response(
                                stream,
                                &Response::Error {
                                    message: error.to_string(),
                                },
                            );
                            return;
                        }
                    };
                    let is_shutdown = matches!(request, Request::Shutdown { .. });
                    let response = state.handle(request);
                    let _ = ipc::write_response(stream, &response);
                    if is_shutdown && matches!(response, Response::Ok) {
                        stop.store(true, Ordering::SeqCst);
                    }
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(err.into()),
        }
    }

    let cleanup_result = state.destroy(&name);
    match cleanup_result {
        Ok(_) | Err(Error::Message(_)) => {}
        Err(error) => return Err(error),
    }
    let _ = fs::remove_file(socket);
    Ok(())
}

static SIGNAL_HANDLERS: OnceLock<Vec<signal_hook::iterator::Handle>> = OnceLock::new();

fn install_signal_handlers(stop: Arc<AtomicBool>) -> Result<()> {
    if SIGNAL_HANDLERS.get().is_some() {
        return Ok(());
    }
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ])?;
    let handle = signals.handle();
    thread::spawn(move || {
        for _ in signals.forever() {
            stop.store(true, Ordering::SeqCst);
        }
    });
    let _ = SIGNAL_HANDLERS.set(vec![handle]);
    Ok(())
}

fn prepare_socket_path(socket: &Path) -> Result<()> {
    match ipc::send(socket, &Request::Ping) {
        Ok(_) => {
            return Err(Error::msg(format!(
                "sandbox session socket is already active: {}",
                socket.display()
            )));
        }
        Err(_) if socket.exists() => match fs::remove_file(socket) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        },
        Err(_) => {}
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return Err(Error::msg(format!("invalid sandbox name: {name}")));
    }
    Ok(())
}

fn notify_pending_waiter(waiter: Option<crate::state::PendingWaiter>, decision: PendingDecision) {
    if let Some(waiter) = waiter {
        let (lock, cvar) = &*waiter;
        *lock.lock().unwrap() = Some(decision);
        cvar.notify_all();
    }
}

fn canonicalize_existing_dir(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(Error::msg(format!(
            "mountpoint is not a directory: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn canonicalize_maybe_existing(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        Ok(fs::canonicalize(path)?)
    } else if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn new_session_contains_named_sandbox() {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let session = SessionState::new_session(runtime, "a").unwrap();
        assert!(session.registry.lock().unwrap().sandboxes.contains_key("a"));
    }

    #[test]
    fn detach_unknown_mountpoint_fails() {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let session = SessionState::new_session(runtime, "a").unwrap();
        match session.handle(Request::Detach {
            name: "a".into(),
            mountpoint: temp.path().join("m").display().to_string(),
        }) {
            Response::Error { .. } => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn destroy_unknown_sandbox_fails() {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let session = SessionState::new_session(runtime, "a").unwrap();
        match session.handle(Request::Shutdown { name: "b".into() }) {
            Response::Error { message } => assert!(message.contains("sandbox not found")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allow_notifies_waiter_even_if_decision_log_fails() {
        let (session, waiter) = session_with_stopped_writer_and_pending_request();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: true,
        }) {
            Response::Error { message } => assert!(message.contains("log writer stopped")),
            other => panic!("unexpected {other:?}"),
        }

        assert_waiter_decision(&waiter, PendingDecision::DoNothing);
        assert_no_pending_request(&session);
    }

    #[test]
    fn deny_notifies_waiter_even_if_decision_log_fails() {
        let (session, waiter) = session_with_stopped_writer_and_pending_request();

        match session.handle(Request::Deny {
            name: "a".to_string(),
            id: 1,
        }) {
            Response::Error { message } => assert!(message.contains("log writer stopped")),
            other => panic!("unexpected {other:?}"),
        }

        assert_waiter_decision(&waiter, PendingDecision::Deny);
        assert_no_pending_request(&session);
    }

    #[test]
    fn allow_logs_fresh_decision_id_and_request_id() {
        let (_temp, session, _writer, waiter) = session_with_pending_request_and_writer();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 ALLOW"));
        assert_waiter_decision(&waiter, PendingDecision::Apply);
    }

    #[test]
    fn allow_do_nothing_logs_fresh_decision_id_and_request_id() {
        let (_temp, session, _writer, waiter) = session_with_pending_request_and_writer();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: true,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 ALLOW_DO_NOTHING"));
        assert_waiter_decision(&waiter, PendingDecision::DoNothing);
    }

    #[test]
    fn deny_logs_fresh_decision_id_and_request_id() {
        let (_temp, session, _writer, waiter) = session_with_pending_request_and_writer();

        match session.handle(Request::Deny {
            name: "a".to_string(),
            id: 1,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 DENY"));
        assert_waiter_decision(&waiter, PendingDecision::Deny);
    }

    #[test]
    fn pending_lists_metadata_and_read_write_requests_sorted_by_id() {
        let (_temp, session, writer, _waiter) = session_with_pending_request_and_writer();
        {
            let mut registry = session.registry.lock().unwrap();
            registry.insert_pending_read_write_request(crate::state::PendingReadWriteRequest::new(
                3,
                "a".to_string(),
                crate::state::ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/file").unwrap(),
                },
                123,
                1000,
                1000,
            ));
        }

        match session.handle(Request::Pending {
            name: "a".to_string(),
        }) {
            Response::Pending { items } => {
                assert_eq!(
                    items
                        .iter()
                        .map(crate::state::PendingRequest::id)
                        .collect::<Vec<_>>(),
                    vec![1, 3]
                );
                assert!(matches!(
                    items[0],
                    crate::state::PendingRequest::Metadata(_)
                ));
                assert!(matches!(
                    items[1],
                    crate::state::PendingRequest::ReadWrite(_)
                ));
                assert_eq!(items[1].description(), "path=/data/file READ file");
            }
            other => panic!("unexpected {other:?}"),
        }

        writer.shutdown().unwrap();
    }

    #[test]
    fn allow_logs_and_notifies_read_write_request() {
        let (_temp, session, _writer, waiter) =
            session_with_pending_read_write_request_and_writer();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 ALLOW"));
        assert_waiter_decision(&waiter, PendingDecision::Apply);
        assert_no_pending_read_write_request(&session);
    }

    #[test]
    fn allow_do_nothing_logs_and_notifies_read_write_request() {
        let (_temp, session, _writer, waiter) =
            session_with_pending_read_write_request_and_writer();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: true,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 ALLOW_DO_NOTHING"));
        assert_waiter_decision(&waiter, PendingDecision::DoNothing);
        assert_no_pending_read_write_request(&session);
    }

    #[test]
    fn deny_logs_and_notifies_read_write_request() {
        let (_temp, session, _writer, waiter) =
            session_with_pending_read_write_request_and_writer();

        match session.handle(Request::Deny {
            name: "a".to_string(),
            id: 1,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 DENY"));
        assert_waiter_decision(&waiter, PendingDecision::Deny);
        assert_no_pending_read_write_request(&session);
    }

    #[test]
    fn concurrent_pending_views_do_not_consume_request() {
        let (_temp, session, writer, waiter) = session_with_pending_request_and_writer();
        let session = Arc::new(session);
        let mut viewers = Vec::new();
        for _ in 0..24 {
            let session = Arc::clone(&session);
            viewers.push(thread::spawn(move || {
                match session.handle(Request::Pending {
                    name: "a".to_string(),
                }) {
                    Response::Pending { items } => {
                        assert_eq!(items.len(), 1);
                        assert_eq!(items[0].id(), 1);
                        assert_eq!(items[0].description(), "path=/data/file SETATTR mode=0444");
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }));
        }
        for viewer in viewers {
            viewer.join().unwrap();
        }

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_waiter_decision(&waiter, PendingDecision::Apply);
        assert_no_pending_request(&session);
        drop(session);
        writer.shutdown().unwrap();
    }

    #[test]
    fn destroy_cleans_pending_indexes_and_notifies_waiters() {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();
        let waiters: Vec<_> = (1..=3)
            .map(|_| Arc::new((Mutex::new(None), std::sync::Condvar::new())))
            .collect();
        {
            let mut registry = session.registry.lock().unwrap();
            for (id, (operation, kinds)) in [
                (
                    1,
                    (
                        crate::state::MetadataOperation::Chmod {
                            path: SandboxPath::new("/data/file").unwrap(),
                            mode: 0o444,
                        },
                        vec![crate::state::PendingOperationKind::Mode],
                    ),
                ),
                (
                    2,
                    (
                        crate::state::MetadataOperation::Chown {
                            path: SandboxPath::new("/data/file").unwrap(),
                            uid: Some(1000),
                            gid: None,
                        },
                        vec![crate::state::PendingOperationKind::Uid],
                    ),
                ),
                (
                    3,
                    (
                        crate::state::MetadataOperation::Chattr {
                            path: SandboxPath::new("/data/file").unwrap(),
                            flags: crate::state::FS_IMMUTABLE_FL,
                        },
                        vec![crate::state::PendingOperationKind::Flags],
                    ),
                ),
            ] {
                registry.insert_pending_request(crate::state::PendingMetadataRequest {
                    id,
                    sandbox: "a".to_string(),
                    description: operation.event_body(),
                    operation,
                    kinds,
                    pid: 123,
                    uid: 1000,
                    gid: 1000,
                });
                registry
                    .pending_waiters
                    .insert(id, Arc::clone(&waiters[(id - 1) as usize]));
            }
        }

        match session.handle(Request::Shutdown {
            name: "a".to_string(),
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        for waiter in &waiters {
            assert_waiter_decision(waiter, PendingDecision::Deny);
        }
        let registry = session.registry.lock().unwrap();
        assert!(registry.pending.is_empty());
        assert!(registry.pending_waiters.is_empty());
        assert!(registry.pending_index.is_empty());
    }

    #[test]
    fn allow_applies_without_waiter_and_logs_decision() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("file"), "data").unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().join("run"), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();
        session
            .mount_layer(
                "a",
                temp.path().to_path_buf(),
                SandboxPath::new("/data").unwrap(),
            )
            .unwrap();
        {
            let mut registry = session.registry.lock().unwrap();
            registry.insert_pending_request(crate::state::PendingMetadataRequest {
                id: 2,
                sandbox: "a".to_string(),
                operation: crate::state::MetadataOperation::Chmod {
                    path: SandboxPath::new("/data/file").unwrap(),
                    mode: 0o444,
                },
                kinds: vec![crate::state::PendingOperationKind::Mode],
                pid: 123,
                uid: 1000,
                gid: 1000,
                description: "path=/data/file SETATTR mode=0444".to_string(),
            });
            registry.next_operation_id = 3;
        }

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 2,
            do_nothing: false,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let registry = session.registry.lock().unwrap();
        let sandbox = registry.sandboxes.get("a").unwrap();
        let override_ = sandbox
            .metadata
            .get(&SandboxPath::new("/data/file").unwrap())
            .unwrap();
        assert_eq!(override_.mode, Some(0o444));
        assert!(!registry.pending.contains_key(&2));
        assert!(
            log::read_log(&session.runtime.sandbox_log_path("a"))
                .unwrap()
                .contains("decision request=2 ALLOW")
        );
    }

    #[test]
    fn allow_do_nothing_without_waiter_does_not_apply_override() {
        let temp = TempDir::new().unwrap();
        std::fs::write(temp.path().join("file"), "data").unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().join("run"), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();
        session
            .mount_layer(
                "a",
                temp.path().to_path_buf(),
                SandboxPath::new("/data").unwrap(),
            )
            .unwrap();
        {
            let mut registry = session.registry.lock().unwrap();
            registry.insert_pending_request(crate::state::PendingMetadataRequest {
                id: 2,
                sandbox: "a".to_string(),
                operation: crate::state::MetadataOperation::Chmod {
                    path: SandboxPath::new("/data/file").unwrap(),
                    mode: 0o444,
                },
                kinds: vec![crate::state::PendingOperationKind::Mode],
                pid: 123,
                uid: 1000,
                gid: 1000,
                description: "path=/data/file SETATTR mode=0444".to_string(),
            });
            registry.next_operation_id = 3;
        }

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 2,
            do_nothing: true,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let registry = session.registry.lock().unwrap();
        assert!(
            !registry
                .sandboxes
                .get("a")
                .unwrap()
                .metadata
                .contains_key(&SandboxPath::new("/data/file").unwrap())
        );
        assert!(!registry.pending.contains_key(&2));
        assert!(
            log::read_log(&session.runtime.sandbox_log_path("a"))
                .unwrap()
                .contains("decision request=2 ALLOW_DO_NOTHING")
        );
    }

    fn session_with_stopped_writer_and_pending_request()
    -> (SessionState, crate::state::PendingWaiter) {
        let (_temp, session, writer, waiter) = session_with_pending_request_and_writer();
        writer.shutdown().unwrap();
        (session, waiter)
    }

    fn session_with_pending_request_and_writer() -> (
        TempDir,
        SessionState,
        log::LogWriter,
        crate::state::PendingWaiter,
    ) {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();

        let waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        {
            let mut registry = session.registry.lock().unwrap();
            registry.next_operation_id = 2;
            registry.insert_pending_request(crate::state::PendingMetadataRequest {
                id: 1,
                sandbox: "a".to_string(),
                operation: crate::state::MetadataOperation::Chmod {
                    path: SandboxPath::new("/data/file").unwrap(),
                    mode: 0o444,
                },
                kinds: vec![crate::state::PendingOperationKind::Mode],
                pid: 123,
                uid: 1000,
                gid: 1000,
                description: "path=/data/file SETATTR mode=0444".to_string(),
            });
            registry.pending_waiters.insert(1, Arc::clone(&waiter));
        }
        (temp, session, writer, waiter)
    }

    fn session_with_pending_read_write_request_and_writer() -> (
        TempDir,
        SessionState,
        log::LogWriter,
        crate::state::PendingWaiter,
    ) {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();

        let waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        {
            let mut registry = session.registry.lock().unwrap();
            registry.next_operation_id = 2;
            registry.insert_pending_read_write_request(crate::state::PendingReadWriteRequest::new(
                1,
                "a".to_string(),
                crate::state::ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/file").unwrap(),
                },
                123,
                1000,
                1000,
            ));
            registry.pending_waiters.insert(1, Arc::clone(&waiter));
        }
        (temp, session, writer, waiter)
    }

    fn assert_waiter_decision(waiter: &crate::state::PendingWaiter, decision: PendingDecision) {
        let (lock, _cvar) = &**waiter;
        assert_eq!(*lock.lock().unwrap(), Some(decision));
    }

    fn assert_no_pending_request(session: &SessionState) {
        let registry = session.registry.lock().unwrap();
        assert!(!registry.pending.contains_key(&1));
        assert!(!registry.pending_waiters.contains_key(&1));
    }

    fn assert_no_pending_read_write_request(session: &SessionState) {
        let registry = session.registry.lock().unwrap();
        assert!(!registry.pending_read_write.contains_key(&1));
        assert!(!registry.pending_waiters.contains_key(&1));
    }
}
