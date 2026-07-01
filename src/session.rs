//! Foreground sandbox session server and state machine.

use std::fs;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use fuser::{Config, MountOption};

use crate::fs::SandboxFs;
use crate::ipc::{self, Request, Response};
use crate::log;
use crate::path::SandboxPath;
use crate::process_info::{ProcessInfoProvider, SysinfoProcessInfoProvider};
use crate::runtime::RuntimePaths;
use crate::state::{
    AttachMount, PendingDecision, PendingRequest, PendingWaiter, ProtectionKind,
    ReadWriteAccessGrant, ReadWriteGrantLifetime, ReadWriteGrantLifetimeRequest,
    ReadWriteGrantOptions, ReadWriteGrantSubject, Sandbox, SandboxRegistry, TrustedOperation,
    TrustedPathScope, duration_expires_at, grant_pattern_matches,
};
use crate::{Error, Result};

#[derive(Debug)]
pub struct MountedSession {
    pub sandbox: String,
    pub attach_id: u64,
    pub mountpoint: PathBuf,
    pub temporary: bool,
    pub session: fuser::BackgroundSession,
}

struct CanceledPending {
    id: u64,
    event_id: u64,
    attach_id: Option<u64>,
    waiter: Option<PendingWaiter>,
}

#[derive(Debug)]
struct ReleasedReadWritePending {
    id: u64,
    attach_id: Option<u64>,
    release_event_id: Option<u64>,
    waiter: Option<PendingWaiter>,
}

#[derive(Debug)]
struct GrantAllowOutcome {
    decision_id: u64,
    grant_event_id: Option<u64>,
    consumed_event_id: Option<u64>,
    log_path: PathBuf,
    request_id: u64,
    request_attach_id: Option<u64>,
    released: Vec<ReleasedReadWritePending>,
    grant: Option<ReadWriteAccessGrant>,
    warning: Option<String>,
    downgraded: bool,
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
                grant,
            } => self.allow(&name, id, do_nothing, grant),
            Request::Deny { name, id } => self.deny(&name, id),
            Request::Cancel { name, id } => self.cancel(&name, id, "explicit"),
            Request::CancelAll { name, mountpoint } => {
                self.cancel_all(&name, mountpoint.as_deref())
            }
            Request::LogPath { name } => self.log_path(&name),
        }
    }

    pub fn destroy(&self, name: &str) -> Result<Response> {
        let mountpoints = {
            let mut registry = self.registry.lock().unwrap();
            let Some(sandbox) = registry.sandboxes.get(name) else {
                return Err(Error::msg(format!("sandbox not found: {name}")));
            };
            let mountpoints: Vec<PathBuf> = sandbox.attaches.keys().cloned().collect();
            registry
                .trusted
                .retain(|_, trusted| trusted.sandbox != name);
            mountpoints
        };
        let _ = self.cancel_all(name, None);
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

        let (attach_id, attach_event_id, log_path) = {
            let mut registry = self.registry.lock().unwrap();
            let attach_id = registry.next_operation_id();
            let attach_event_id = registry.next_operation_id();
            let log_path = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
                .log_path
                .clone();
            (attach_id, attach_event_id, log_path)
        };
        let fs = SandboxFs::new_with_attach_id(
            name.to_string(),
            Some(attach_id),
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
            attach_id,
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
                id: attach_id,
                mountpoint: mountpoint.clone(),
                temporary,
                active: true,
            },
        );
        self.log_writer.append(
            &log_path,
            log::format_log_line(
                attach_event_id,
                &format!(
                    "attach attach={attach_id} mountpoint={}",
                    mountpoint.display()
                ),
            ),
        )?;
        Ok(Response::Ok)
    }

    fn detach(&self, name: &str, mountpoint: &Path) -> Result<Response> {
        let mountpoint = canonicalize_maybe_existing(mountpoint)?;
        let (attach_id, log_path) = {
            let registry = self.registry.lock().unwrap();
            let sandbox = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
            let Some(attach) = sandbox.attaches.get(&mountpoint) else {
                return Err(Error::msg(format!(
                    "mountpoint is not attached to sandbox {name}: {}",
                    mountpoint.display()
                )));
            };
            (attach.id, sandbox.log_path.clone())
        };
        let _ = self.cancel_attached_view(name, attach_id, "detach");

        let session = {
            let mut mounts = self.mounts.lock().unwrap();
            let idx = mounts
                .iter()
                .position(|mounted| {
                    mounted.sandbox == name
                        && mounted.attach_id == attach_id
                        && mounted.mountpoint == mountpoint
                })
                .ok_or_else(|| {
                    Error::msg(format!("mount session not found: {}", mountpoint.display()))
                })?;
            mounts.remove(idx)
        };
        session.session.umount_and_join()?;
        let detach_event_id = {
            let mut registry = self.registry.lock().unwrap();
            let detach_event_id = registry.next_operation_id();
            if let Some(sandbox) = registry.sandboxes.get_mut(name) {
                sandbox.attaches.remove(&mountpoint);
            }
            detach_event_id
        };
        self.log_writer.append(
            &log_path,
            log::format_log_line(detach_event_id, &format!("detach attach={attach_id}")),
        )?;
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

    fn allow(
        &self,
        name: &str,
        id: u64,
        do_nothing: bool,
        grant: Option<ReadWriteGrantOptions>,
    ) -> Result<Response> {
        if do_nothing && grant.is_some() {
            return Err(Error::msg(
                "allow --do-nothing cannot be combined with read/write grant options",
            ));
        }
        if let Some(grant) = grant {
            return self.allow_read_write_grant(name, id, grant);
        }

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
        let attach_field = pending
            .attach_id()
            .map(|id| format!(" attach={id}"))
            .unwrap_or_default();
        let log_result = self.log_writer.append(
            &log_path,
            log::format_log_line(
                decision_id,
                &format!(
                    "decision request={id}{attach_field} {}",
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

    fn allow_read_write_grant(
        &self,
        name: &str,
        id: u64,
        options: ReadWriteGrantOptions,
    ) -> Result<Response> {
        if matches!(
            options.lifetime,
            ReadWriteGrantLifetimeRequest::Duration { seconds: 0 }
        ) {
            return Err(Error::msg("duration must be greater than zero"));
        }
        let process_provider = SysinfoProcessInfoProvider;
        let now = SystemTime::now();
        let outcome = (|| -> Result<GrantAllowOutcome> {
            let mut registry = self.registry.lock().unwrap();
            let selected = registry
                .remove_any_pending_request(id)
                .ok_or_else(|| Error::msg(format!("pending operation not found: {id}")))?;
            if selected.sandbox() != name {
                registry.insert_any_pending_request(selected);
                return Err(Error::msg(format!(
                    "pending operation {id} does not belong to sandbox {name}"
                )));
            }
            let PendingRequest::ReadWrite(mut selected) = selected else {
                registry.insert_any_pending_request(selected);
                return Err(Error::msg(
                    "read/write grant options can only be used with read/write pending requests",
                ));
            };
            let log_path = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
                .log_path
                .clone();
            let decision_id = registry.next_operation_id();
            let mut selected_waiter = registry.pending_waiters.remove(&id);
            let request_attach_id = selected.attach_id;
            let grant_path = options.path.unwrap_or_else(|| selected.path.clone());
            if !grant_pattern_matches(&grant_path, &selected.path) {
                let message = format!(
                    "read/write grant path {grant_path} does not match pending path {}",
                    selected.path
                );
                registry.insert_pending_read_write_request(selected);
                if let Some(waiter) = selected_waiter {
                    registry.pending_waiters.insert(id, waiter);
                }
                return Err(Error::msg(message));
            }
            let mut warning = None;
            let mut downgraded = false;
            let selected_identity = selected.process_identity;
            let exact_identity =
                || selected_identity.or_else(|| process_provider.identity_for_pid(selected.pid));
            let subject = if options.tree {
                match process_provider.process_tree_for_pid(selected.pid) {
                    Some(identities) if !identities.is_empty() => {
                        let requester_identity = selected.process_identity.or_else(|| {
                            identities
                                .iter()
                                .find(|identity| identity.pid == selected.pid)
                                .copied()
                        });
                        match requester_identity {
                            Some(identity) if identities.contains(&identity) => {
                                selected.process_identity.get_or_insert(identity);
                                Some(ReadWriteGrantSubject::ProcessTree { identities })
                            }
                            Some(identity) => {
                                selected.process_identity.get_or_insert(identity);
                                warning = Some(format!(
                                    "process tree unavailable for pid {}; using exact requester grant",
                                    selected.pid
                                ));
                                Some(ReadWriteGrantSubject::Exact { identity })
                            }
                            None => match exact_identity() {
                                Some(identity) => {
                                    selected.process_identity.get_or_insert(identity);
                                    warning = Some(format!(
                                        "process tree unavailable for pid {}; using exact requester grant",
                                        selected.pid
                                    ));
                                    Some(ReadWriteGrantSubject::Exact { identity })
                                }
                                None => {
                                    warning = Some(format!(
                                        "requester identity unavailable for pid {}; released current request without creating grant",
                                        selected.pid
                                    ));
                                    downgraded = true;
                                    None
                                }
                            },
                        }
                    }
                    _ => match exact_identity() {
                        Some(identity) => {
                            selected.process_identity.get_or_insert(identity);
                            warning = Some(format!(
                                "process tree unavailable for pid {}; using exact requester grant",
                                selected.pid
                            ));
                            Some(ReadWriteGrantSubject::Exact { identity })
                        }
                        None => {
                            warning = Some(format!(
                                "requester identity unavailable for pid {}; released current request without creating grant",
                                selected.pid
                            ));
                            downgraded = true;
                            None
                        }
                    },
                }
            } else {
                match exact_identity() {
                    Some(identity) => {
                        selected.process_identity.get_or_insert(identity);
                        Some(ReadWriteGrantSubject::Exact { identity })
                    }
                    None => {
                        warning = Some(format!(
                            "requester identity unavailable for pid {}; released current request without creating grant",
                            selected.pid
                        ));
                        downgraded = true;
                        None
                    }
                }
            };
            let Some(subject) = subject else {
                return Ok(GrantAllowOutcome {
                    decision_id,
                    grant_event_id: None,
                    consumed_event_id: None,
                    log_path,
                    request_id: id,
                    request_attach_id,
                    released: vec![ReleasedReadWritePending {
                        id,
                        attach_id: request_attach_id,
                        release_event_id: None,
                        waiter: selected_waiter.take(),
                    }],
                    grant: None,
                    warning,
                    downgraded,
                });
            };
            let lifetime = match options.lifetime {
                ReadWriteGrantLifetimeRequest::OneShot => ReadWriteGrantLifetime::OneShot,
                ReadWriteGrantLifetimeRequest::Duration { seconds } => {
                    let duration = Duration::from_secs(seconds);
                    ReadWriteGrantLifetime::Duration {
                        expires_at_epoch_ms: duration_expires_at(now, duration),
                    }
                }
            };
            let grant_id = registry.next_operation_id();
            let grant_event_id = registry.next_operation_id();
            let grant = ReadWriteAccessGrant {
                id: grant_id,
                sandbox: name.to_string(),
                kind: selected.kind,
                path_pattern: grant_path,
                subject,
                lifetime,
                created_at_epoch_ms: crate::state::epoch_millis(now),
            };
            let selected_matches_grant = grant.matches_request(&selected, now);
            let matching_ids = registry.matching_pending_read_write_ids_for_grant(&grant, now);
            let mut released = Vec::new();
            let mut selected_released = false;
            let consumed_event_id = match grant.lifetime {
                ReadWriteGrantLifetime::OneShot => {
                    let earliest = matching_ids
                        .iter()
                        .copied()
                        .chain(selected_matches_grant.then_some(id))
                        .min();
                    if let Some(release_id) = earliest {
                        if release_id == id {
                            selected_released = true;
                            released.push(ReleasedReadWritePending {
                                id,
                                attach_id: request_attach_id,
                                release_event_id: None,
                                waiter: selected_waiter.take(),
                            });
                        } else if let Some(request) =
                            registry.remove_pending_read_write_request(release_id)
                        {
                            let release_event_id = registry.next_operation_id();
                            released.push(ReleasedReadWritePending {
                                id: release_id,
                                attach_id: request.attach_id,
                                release_event_id: Some(release_event_id),
                                waiter: registry.pending_waiters.remove(&release_id),
                            });
                        }
                        Some(registry.next_operation_id())
                    } else {
                        registry.insert_read_write_grant(grant.clone());
                        None
                    }
                }
                ReadWriteGrantLifetime::Duration { .. } => {
                    if selected_matches_grant {
                        selected_released = true;
                        released.push(ReleasedReadWritePending {
                            id,
                            attach_id: request_attach_id,
                            release_event_id: None,
                            waiter: selected_waiter.take(),
                        });
                    }
                    for release_id in matching_ids {
                        if let Some(request) =
                            registry.remove_pending_read_write_request(release_id)
                        {
                            let release_event_id = registry.next_operation_id();
                            released.push(ReleasedReadWritePending {
                                id: release_id,
                                attach_id: request.attach_id,
                                release_event_id: Some(release_event_id),
                                waiter: registry.pending_waiters.remove(&release_id),
                            });
                        }
                    }
                    registry.insert_read_write_grant(grant.clone());
                    None
                }
            };
            if !selected_released {
                registry.insert_pending_read_write_request(selected);
                if let Some(waiter) = selected_waiter {
                    registry.pending_waiters.insert(id, waiter);
                }
            }
            Ok(GrantAllowOutcome {
                decision_id,
                grant_event_id: Some(grant_event_id),
                consumed_event_id,
                log_path,
                request_id: id,
                request_attach_id,
                released,
                grant: Some(grant),
                warning,
                downgraded,
            })
        })()?;

        let response = self.finish_read_write_grant_allow(outcome)?;
        Ok(response)
    }

    fn finish_read_write_grant_allow(&self, outcome: GrantAllowOutcome) -> Result<Response> {
        let selected_attach = format_attach_field(outcome.request_attach_id);
        let mut decision_body = format!(
            "decision request={}{} ALLOW",
            outcome.request_id, selected_attach
        );
        if outcome.downgraded {
            decision_body.push_str(" downgraded=grantless");
        }
        if let Some(warning) = &outcome.warning {
            decision_body.push_str(&format!(" warning={}", quote_log_value(warning)));
        }
        let mut log_result = self.log_writer.append(
            &outcome.log_path,
            log::format_log_line(outcome.decision_id, &decision_body),
        );

        if let (Some(event_id), Some(grant)) = (outcome.grant_event_id, outcome.grant.as_ref()) {
            let grant_result = self.log_writer.append(
                &outcome.log_path,
                log::format_log_line(event_id, &format_grant_created_body(grant)),
            );
            if log_result.is_ok() && grant_result.is_err() {
                log_result = grant_result;
            }
        }
        if let (Some(event_id), Some(grant)) = (outcome.consumed_event_id, outcome.grant.as_ref()) {
            let consumed_result = self.log_writer.append(
                &outcome.log_path,
                log::format_log_line(event_id, &format_grant_consumed_body(grant.id)),
            );
            if log_result.is_ok() && consumed_result.is_err() {
                log_result = consumed_result;
            }
        }

        for released in outcome.released {
            if let Some(event_id) = released.release_event_id {
                let attach_field = format_attach_field(released.attach_id);
                let release_result = self.log_writer.append(
                    &outcome.log_path,
                    log::format_log_line(
                        event_id,
                        &format!(
                            "grant-release request={}{} decision={}",
                            released.id, attach_field, outcome.request_id
                        ),
                    ),
                );
                if log_result.is_ok() && release_result.is_err() {
                    log_result = release_result;
                }
            }
            notify_pending_waiter(released.waiter, PendingDecision::Apply);
        }
        log_result?;
        if let Some(warning) = outcome.warning {
            Ok(Response::Warning { message: warning })
        } else {
            Ok(Response::Ok)
        }
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
        let attach_field = pending
            .attach_id()
            .map(|id| format!(" attach={id}"))
            .unwrap_or_default();
        let log_result = self.log_writer.append(
            &log_path,
            log::format_log_line(
                decision_id,
                &format!("decision request={id}{attach_field} DENY"),
            ),
        );
        notify_pending_waiter(waiter, PendingDecision::Deny);
        log_result?;
        Ok(Response::Ok)
    }

    fn cancel(&self, name: &str, id: u64, reason: &str) -> Result<Response> {
        let (event_id, log_path, waiter, attach_id) = {
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
            let attach_id = pending.attach_id();
            let event_id = registry.next_operation_id();
            let log_path = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
                .log_path
                .clone();
            let waiter = registry.pending_waiters.remove(&id);
            (event_id, log_path, waiter, attach_id)
        };
        let attach_field = attach_id
            .map(|id| format!(" attach={id}"))
            .unwrap_or_default();
        let log_result = self.log_writer.append(
            &log_path,
            log::format_log_line(
                event_id,
                &format!("cancel request={id}{attach_field} reason={reason}"),
            ),
        );
        notify_pending_waiter(waiter, PendingDecision::Cancel);
        log_result?;
        Ok(Response::Ok)
    }

    fn cancel_all(&self, name: &str, mountpoint: Option<&str>) -> Result<Response> {
        if let Some(mountpoint) = mountpoint {
            let mountpoint = canonicalize_maybe_existing(Path::new(mountpoint))?;
            let attach_id = {
                let registry = self.registry.lock().unwrap();
                let sandbox = registry
                    .sandboxes
                    .get(name)
                    .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?;
                let Some(attach) = sandbox.attaches.get(&mountpoint) else {
                    return Err(Error::msg(format!(
                        "mountpoint is not attached to sandbox {name}: {}",
                        mountpoint.display()
                    )));
                };
                attach.id
            };
            return self.cancel_attached_view(name, attach_id, "cancel-all");
        }

        let (scope_event_id, log_path, canceled) = {
            let mut registry = self.registry.lock().unwrap();
            let log_path = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
                .log_path
                .clone();
            let ids: Vec<u64> = registry
                .pending_requests_for_sandbox(name)
                .into_iter()
                .map(|pending| pending.id())
                .collect();
            let scope_event_id = registry.next_operation_id();
            let mut canceled = Vec::new();
            for id in ids {
                let attach_id = registry
                    .remove_any_pending_request(id)
                    .and_then(|pending| pending.attach_id());
                let waiter = registry.pending_waiters.remove(&id);
                let event_id = registry.next_operation_id();
                canceled.push(CanceledPending {
                    id,
                    event_id,
                    attach_id,
                    waiter,
                });
            }
            (scope_event_id, log_path, canceled)
        };
        self.finish_cancel_scope(
            scope_event_id,
            log_path,
            canceled,
            "sandbox",
            None,
            "cancel-all",
        )
    }

    fn cancel_attached_view(&self, name: &str, attach_id: u64, reason: &str) -> Result<Response> {
        let (scope_event_id, log_path, canceled) = {
            let mut registry = self.registry.lock().unwrap();
            let log_path = registry
                .sandboxes
                .get(name)
                .ok_or_else(|| Error::msg(format!("sandbox not found: {name}")))?
                .log_path
                .clone();
            let ids: Vec<u64> = registry
                .pending_requests_for_sandbox(name)
                .into_iter()
                .filter(|pending| pending.attach_id() == Some(attach_id))
                .map(|pending| pending.id())
                .collect();
            let scope_event_id = registry.next_operation_id();
            let mut canceled = Vec::new();
            for id in ids {
                registry.remove_any_pending_request(id);
                let waiter = registry.pending_waiters.remove(&id);
                let event_id = registry.next_operation_id();
                canceled.push(CanceledPending {
                    id,
                    event_id,
                    attach_id: Some(attach_id),
                    waiter,
                });
            }
            (scope_event_id, log_path, canceled)
        };
        self.finish_cancel_scope(
            scope_event_id,
            log_path,
            canceled,
            "attached-view",
            Some(attach_id),
            reason,
        )
    }

    fn finish_cancel_scope(
        &self,
        scope_event_id: u64,
        log_path: PathBuf,
        canceled: Vec<CanceledPending>,
        scope: &str,
        attach_id: Option<u64>,
        reason: &str,
    ) -> Result<Response> {
        let attach_field = attach_id
            .map(|id| format!(" attach={id}"))
            .unwrap_or_default();
        let mut log_result = self.log_writer.append(
            &log_path,
            log::format_log_line(
                scope_event_id,
                &format!(
                    "cancel{attach_field} scope={scope} reason={reason} count={}",
                    canceled.len()
                ),
            ),
        );
        for item in &canceled {
            let item_attach_field = item
                .attach_id
                .map(|id| format!(" attach={id}"))
                .unwrap_or_default();
            let item_result = self.log_writer.append(
                &log_path,
                log::format_log_line(
                    item.event_id,
                    &format!(
                        "cancel request={}{} reason={reason}",
                        item.id, item_attach_field
                    ),
                ),
            );
            if log_result.is_ok() && item_result.is_err() {
                log_result = item_result;
            }
        }
        for item in canceled {
            notify_pending_waiter(item.waiter, PendingDecision::Cancel);
        }
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

fn format_attach_field(attach_id: Option<u64>) -> String {
    attach_id
        .map(|id| format!(" attach={id}"))
        .unwrap_or_default()
}

fn quote_log_value(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn format_grant_created_body(grant: &ReadWriteAccessGrant) -> String {
    let mut body = format!(
        "grant-created grant={} kind={} path={} subject={} subject_count={} lifetime={}",
        grant.id,
        grant.kind,
        grant.path_pattern,
        grant.subject.log_name(),
        grant.subject.len(),
        grant.lifetime.log_name()
    );
    if let ReadWriteGrantLifetime::Duration {
        expires_at_epoch_ms,
    } = grant.lifetime
    {
        body.push_str(&format!(" expires_at_epoch_ms={expires_at_epoch_ms}"));
    }
    body
}

fn format_grant_consumed_body(grant_id: u64) -> String {
    format!("grant-consumed grant={grant_id} lifetime=one-shot")
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
            grant: None,
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
            grant: None,
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
            grant: None,
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
            grant: None,
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
            grant: None,
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
    fn grant_options_reject_metadata_requests_without_consuming_them() {
        let (_temp, session, writer, waiter) = session_with_pending_request_and_writer();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
            grant: Some(ReadWriteGrantOptions {
                path: None,
                lifetime: ReadWriteGrantLifetimeRequest::OneShot,
                tree: false,
            }),
        }) {
            Response::Error { message } => assert!(message.contains("read/write grant options")),
            other => panic!("unexpected {other:?}"),
        }

        assert_eq!(*waiter.0.lock().unwrap(), None);
        assert!(session.registry.lock().unwrap().pending.contains_key(&1));
        writer.shutdown().unwrap();
    }

    #[test]
    fn read_write_one_shot_grant_consumes_selected_when_it_is_earliest_match() {
        let (_temp, session, _writer, waiter) =
            session_with_pending_read_write_request_and_writer();

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
            grant: Some(ReadWriteGrantOptions {
                path: None,
                lifetime: ReadWriteGrantLifetimeRequest::OneShot,
                tree: false,
            }),
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 decision request=1 ALLOW"));
        assert!(data.contains(" grant-created grant=3 kind=READ path=/data/file subject=exact subject_count=1 lifetime=one-shot"));
        assert!(data.contains(" grant-consumed grant=3 lifetime=one-shot"));
        assert_waiter_decision(&waiter, PendingDecision::Apply);
        let registry = session.registry.lock().unwrap();
        assert!(registry.pending_read_write.is_empty());
        assert!(registry.read_write_grants.is_empty());
    }

    #[test]
    fn read_write_reusable_grant_downgrades_without_requester_identity() {
        let (_temp, session, _writer, waiter) =
            session_with_pending_read_write_request_and_writer();
        {
            let mut registry = session.registry.lock().unwrap();
            let pending = registry.pending_read_write.get_mut(&1).unwrap();
            pending.pid = u32::MAX;
            pending.process_identity = None;
        }

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
            grant: Some(ReadWriteGrantOptions {
                path: None,
                lifetime: ReadWriteGrantLifetimeRequest::Duration { seconds: 60 },
                tree: false,
            }),
        }) {
            Response::Warning { message } => {
                assert!(message.contains("requester identity unavailable"));
            }
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains("decision request=1 ALLOW downgraded=grantless"));
        assert!(data.contains("requester identity unavailable"));
        assert_waiter_decision(&waiter, PendingDecision::Apply);
        let registry = session.registry.lock().unwrap();
        assert!(registry.pending_read_write.is_empty());
        assert!(registry.read_write_grants.is_empty());
    }

    #[test]
    fn read_write_one_shot_grant_releases_earliest_matching_pending_request_only() {
        let (_temp, session, _writer, first_waiter) =
            session_with_pending_read_write_request_and_writer();
        let second_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        {
            let mut registry = session.registry.lock().unwrap();
            let identity = SysinfoProcessInfoProvider
                .identity_for_pid(std::process::id())
                .unwrap();
            registry
                .pending_read_write
                .get_mut(&1)
                .unwrap()
                .process_identity = Some(identity);
            registry.insert_pending_read_write_request(
                crate::state::PendingReadWriteRequest::new(
                    2,
                    "a".to_string(),
                    crate::state::ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/file").unwrap(),
                    },
                    std::process::id(),
                    1000,
                    1000,
                )
                .with_process_identity(Some(identity)),
            );
            registry
                .pending_waiters
                .insert(2, Arc::clone(&second_waiter));
            registry.next_operation_id = 3;
        }

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 2,
            do_nothing: false,
            grant: Some(ReadWriteGrantOptions {
                path: None,
                lifetime: ReadWriteGrantLifetimeRequest::OneShot,
                tree: false,
            }),
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        assert_waiter_decision(&first_waiter, PendingDecision::Apply);
        assert_eq!(*second_waiter.0.lock().unwrap(), None);
        let registry = session.registry.lock().unwrap();
        assert!(!registry.pending_read_write.contains_key(&1));
        assert!(registry.pending_read_write.contains_key(&2));
        assert!(registry.read_write_grants.is_empty());
    }

    #[test]
    fn read_write_duration_grant_releases_all_matching_pending_requests_and_persists() {
        let (_temp, session, _writer, first_waiter) =
            session_with_pending_read_write_request_and_writer();
        let second_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        {
            let mut registry = session.registry.lock().unwrap();
            let identity = SysinfoProcessInfoProvider
                .identity_for_pid(std::process::id())
                .unwrap();
            registry
                .pending_read_write
                .get_mut(&1)
                .unwrap()
                .process_identity = Some(identity);
            registry.insert_pending_read_write_request(
                crate::state::PendingReadWriteRequest::new(
                    2,
                    "a".to_string(),
                    crate::state::ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/other").unwrap(),
                    },
                    std::process::id(),
                    1000,
                    1000,
                )
                .with_process_identity(Some(identity)),
            );
            registry
                .pending_waiters
                .insert(2, Arc::clone(&second_waiter));
            registry.next_operation_id = 3;
        }

        match session.handle(Request::Allow {
            name: "a".to_string(),
            id: 1,
            do_nothing: false,
            grant: Some(ReadWriteGrantOptions {
                path: Some(SandboxPath::new("/data/**").unwrap()),
                lifetime: ReadWriteGrantLifetimeRequest::Duration { seconds: 60 },
                tree: false,
            }),
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        assert_waiter_decision(&first_waiter, PendingDecision::Apply);
        assert_waiter_decision(&second_waiter, PendingDecision::Apply);
        let registry = session.registry.lock().unwrap();
        assert!(registry.pending_read_write.is_empty());
        assert_eq!(registry.read_write_grants.len(), 1);
        assert!(matches!(
            registry.read_write_grants.values().next().unwrap().lifetime,
            ReadWriteGrantLifetime::Duration { .. }
        ));
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
    fn cancel_logs_and_notifies_metadata_request() {
        let (_temp, session, _writer, waiter) = session_with_pending_request_and_writer();

        match session.handle(Request::Cancel {
            name: "a".to_string(),
            id: 1,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 cancel request=1 reason=explicit"));
        assert_waiter_decision(&waiter, PendingDecision::Cancel);
        assert_no_pending_request(&session);
    }

    #[test]
    fn cancel_logs_and_notifies_read_write_request() {
        let (_temp, session, _writer, waiter) =
            session_with_pending_read_write_request_and_writer();

        match session.handle(Request::Cancel {
            name: "a".to_string(),
            id: 1,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=2 cancel request=1 reason=explicit"));
        assert_waiter_decision(&waiter, PendingDecision::Cancel);
        assert_no_pending_read_write_request(&session);
    }

    #[test]
    fn cancel_all_logs_and_notifies_metadata_and_read_write_requests() {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();
        let metadata_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        let read_write_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        {
            let mut registry = session.registry.lock().unwrap();
            registry.insert_pending_request(crate::state::PendingMetadataRequest {
                id: 1,
                sandbox: "a".to_string(),
                attach_id: None,
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
            registry.insert_pending_read_write_request(crate::state::PendingReadWriteRequest::new(
                2,
                "a".to_string(),
                crate::state::ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/secret").unwrap(),
                },
                124,
                1000,
                1000,
            ));
            registry
                .pending_waiters
                .insert(1, Arc::clone(&metadata_waiter));
            registry
                .pending_waiters
                .insert(2, Arc::clone(&read_write_waiter));
            registry.next_operation_id = 3;
        }

        match session.handle(Request::CancelAll {
            name: "a".to_string(),
            mountpoint: None,
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(data.contains(" id=3 cancel scope=sandbox reason=cancel-all count=2"));
        assert!(data.contains(" id=4 cancel request=1 reason=cancel-all"));
        assert!(data.contains(" id=5 cancel request=2 reason=cancel-all"));
        assert_waiter_decision(&metadata_waiter, PendingDecision::Cancel);
        assert_waiter_decision(&read_write_waiter, PendingDecision::Cancel);
        let registry = session.registry.lock().unwrap();
        assert!(registry.pending.is_empty());
        assert!(registry.pending_read_write.is_empty());
        assert!(registry.pending_waiters.is_empty());
        assert!(registry.pending_index.is_empty());
    }

    #[test]
    fn cancel_all_mountpoint_scope_cancels_only_matching_attach_requests() {
        let temp = TempDir::new().unwrap();
        let mountpoint = temp.path().join("mnt");
        fs::create_dir(&mountpoint).unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        let writer = log::LogWriter::new();
        let writer_handle = writer.handle();
        let session = SessionState::with_log_writer(runtime, writer_handle, None);
        session.create_initial("a").unwrap();
        let matching_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        let other_attach_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        let no_attach_waiter: crate::state::PendingWaiter =
            Arc::new((Mutex::new(None), std::sync::Condvar::new()));
        {
            let mut registry = session.registry.lock().unwrap();
            let sandbox = registry.sandboxes.get_mut("a").unwrap();
            sandbox.attaches.insert(
                mountpoint.clone(),
                AttachMount {
                    id: 7,
                    mountpoint: mountpoint.clone(),
                    temporary: false,
                    active: true,
                },
            );
            registry.insert_pending_request(crate::state::PendingMetadataRequest {
                id: 1,
                sandbox: "a".to_string(),
                attach_id: Some(7),
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
            registry.insert_pending_read_write_request(
                crate::state::PendingReadWriteRequest::new_with_attach_path(
                    2,
                    "a".to_string(),
                    Some(8),
                    crate::state::ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/other").unwrap(),
                    },
                    SandboxPath::new("/data/other").unwrap(),
                    crate::state::RequesterIdentity {
                        pid: 124,
                        uid: 1000,
                        gid: 1000,
                    },
                ),
            );
            registry.insert_pending_read_write_request(crate::state::PendingReadWriteRequest::new(
                3,
                "a".to_string(),
                crate::state::ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/no-attach").unwrap(),
                },
                125,
                1000,
                1000,
            ));
            registry
                .pending_waiters
                .insert(1, Arc::clone(&matching_waiter));
            registry
                .pending_waiters
                .insert(2, Arc::clone(&other_attach_waiter));
            registry
                .pending_waiters
                .insert(3, Arc::clone(&no_attach_waiter));
            registry.next_operation_id = 9;
        }

        match session.handle(Request::CancelAll {
            name: "a".to_string(),
            mountpoint: Some(mountpoint.display().to_string()),
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        let data = log::read_log(&session.runtime.sandbox_log_path("a")).unwrap();
        assert!(
            data.contains(" id=9 cancel attach=7 scope=attached-view reason=cancel-all count=1")
        );
        assert!(data.contains(" id=10 cancel request=1 attach=7 reason=cancel-all"));
        assert_waiter_decision(&matching_waiter, PendingDecision::Cancel);
        assert_eq!(*other_attach_waiter.0.lock().unwrap(), None);
        assert_eq!(*no_attach_waiter.0.lock().unwrap(), None);
        let registry = session.registry.lock().unwrap();
        assert!(!registry.pending.contains_key(&1));
        assert!(registry.pending_read_write.contains_key(&2));
        assert!(registry.pending_read_write.contains_key(&3));
        assert!(!registry.pending_waiters.contains_key(&1));
        assert!(registry.pending_waiters.contains_key(&2));
        assert!(registry.pending_waiters.contains_key(&3));
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
            grant: None,
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
        let waiters: Vec<_> = (1..=4)
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
                    attach_id: None,
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
            registry.insert_pending_read_write_request(crate::state::PendingReadWriteRequest::new(
                4,
                "a".to_string(),
                crate::state::ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/file").unwrap(),
                },
                123,
                1000,
                1000,
            ));
            registry.pending_waiters.insert(4, Arc::clone(&waiters[3]));
        }

        match session.handle(Request::Shutdown {
            name: "a".to_string(),
        }) {
            Response::Ok => {}
            other => panic!("unexpected {other:?}"),
        }

        for waiter in &waiters {
            assert_waiter_decision(waiter, PendingDecision::Cancel);
        }
        let registry = session.registry.lock().unwrap();
        assert!(registry.pending.is_empty());
        assert!(registry.pending_read_write.is_empty());
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
                attach_id: None,
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
            grant: None,
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
                attach_id: None,
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
            grant: None,
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
                attach_id: None,
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
            let process_identity = SysinfoProcessInfoProvider
                .identity_for_pid(std::process::id())
                .unwrap();
            registry.insert_pending_read_write_request(
                crate::state::PendingReadWriteRequest::new(
                    1,
                    "a".to_string(),
                    crate::state::ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/file").unwrap(),
                    },
                    std::process::id(),
                    1000,
                    1000,
                )
                .with_process_identity(Some(process_identity)),
            );
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
