//! fuser filesystem implementation for sandboxfs.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::SystemTime;

use fuser::{
    AccessFlags, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation,
    INodeNo, OpenAccMode, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyIoctl, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
};

use crate::hostfs;
use crate::log;
use crate::path::SandboxPath;
use crate::process_info::{ProcessInfoProvider, SysinfoProcessInfoProvider};
use crate::state::{
    FS_IMMUTABLE_FL, GrantMatchOutcome, MetadataOperation, PendingDecision, PendingMetadataRequest,
    PendingReadWriteRequest, PendingWaiter, ReadWriteOperation,
    RequesterIdentity as RequestIdentity, ResolvedPath, SandboxRegistry, TTL, apply_override,
    mode_to_kind, stable_ino, virtual_dir_attr,
};

const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_GETFLAGS_INT: u32 = 0x8004_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
const FS_IOC_SETFLAGS_INT: u32 = 0x4004_6602;
const FS_IOC_FSGETXATTR: u32 = 0x801c_581f;
const FS_IOC_FSSETXATTR: u32 = 0x401c_5820;
const FSXATTR_SIZE: usize = 28;
const FS_APPEND_FL: u32 = 0x0000_0020;
const FS_SYNC_FL: u32 = 0x0000_0008;
const FS_NOATIME_FL: u32 = 0x0000_0080;
const FS_NODUMP_FL: u32 = 0x0000_0040;
const FS_PROJINHERIT_FL: u32 = 0x2000_0000;
const FS_XFLAG_IMMUTABLE: u32 = 0x0000_0008;
const FS_XFLAG_APPEND: u32 = 0x0000_0010;
const FS_XFLAG_SYNC: u32 = 0x0000_0020;
const FS_XFLAG_NOATIME: u32 = 0x0000_0040;
const FS_XFLAG_NODUMP: u32 = 0x0000_0080;
const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
const FS_SUPPORTED_XFLAGS: u32 = FS_XFLAG_IMMUTABLE
    | FS_XFLAG_APPEND
    | FS_XFLAG_SYNC
    | FS_XFLAG_NOATIME
    | FS_XFLAG_NODUMP
    | FS_XFLAG_PROJINHERIT;

#[derive(Debug, Clone)]
pub struct SandboxFs {
    pub sandbox_name: String,
    pub attach_id: Option<u64>,
    pub registry: Arc<Mutex<SandboxRegistry>>,
    log_writer: log::LogWriterHandle,
    inodes: Arc<Mutex<HashMap<u64, SandboxPath>>>,
    handles: Arc<Mutex<HashMap<u64, HandleInfo>>>,
    next_handle: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone)]
struct HandleInfo {
    local_path: PathBuf,
    sandbox_path: SandboxPath,
}

struct PendingMetadataOutcome {
    unchanged_attr: FileAttr,
    path: SandboxPath,
    operation: MetadataOperation,
    waiter: PendingWaiter,
}

enum MetadataOutcome {
    Applied(FileAttr),
    Pending(PendingMetadataOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadWriteDecision {
    Proceed,
    Denied,
    Canceled,
}

impl RequestIdentity {
    fn from_request(req: &Request) -> Self {
        Self {
            pid: req.pid(),
            uid: req.uid(),
            gid: req.gid(),
        }
    }
}

impl SandboxFs {
    pub fn new(
        sandbox_name: impl Into<String>,
        registry: Arc<Mutex<SandboxRegistry>>,
        log_writer: log::LogWriterHandle,
    ) -> Self {
        Self::new_with_attach_id(sandbox_name, None, registry, log_writer)
    }

    pub fn new_with_attach_id(
        sandbox_name: impl Into<String>,
        attach_id: Option<u64>,
        registry: Arc<Mutex<SandboxRegistry>>,
        log_writer: log::LogWriterHandle,
    ) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(1, SandboxPath::root());
        Self {
            sandbox_name: sandbox_name.into(),
            attach_id,
            registry,
            log_writer,
            inodes: Arc::new(Mutex::new(inodes)),
            handles: Arc::new(Mutex::new(HashMap::new())),
            next_handle: Arc::new(Mutex::new(1)),
        }
    }

    fn remember(&self, path: &SandboxPath) -> INodeNo {
        let ino = stable_ino(path);
        self.inodes.lock().unwrap().insert(ino.0, path.clone());
        ino
    }

    fn path_for_ino(&self, ino: INodeNo) -> Option<SandboxPath> {
        self.inodes.lock().unwrap().get(&ino.0).cloned()
    }

    fn attr_for_path(&self, path: &SandboxPath) -> std::result::Result<FileAttr, Errno> {
        let registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get(&self.sandbox_name)
            .ok_or(Errno::ENOENT)?;
        let Some(resolved) = sandbox.resolve(path) else {
            return Err(Errno::ENOENT);
        };
        let mut attr = match resolved {
            ResolvedPath::VirtualDir { .. } => virtual_dir_attr(path),
            ResolvedPath::Real { local_path, .. } => {
                real_attr(path, &local_path).map_err(io_to_errno)?
            }
        };
        attr.ino = self.remember(path);
        Ok(apply_override(attr, sandbox.metadata.get(path)))
    }

    fn path_child(&self, parent: INodeNo, name: &OsStr) -> std::result::Result<SandboxPath, Errno> {
        if name.as_bytes() == b"." {
            return self.path_for_ino(parent).ok_or(Errno::ENOENT);
        }
        let parent_path = self.path_for_ino(parent).ok_or(Errno::ENOENT)?;
        parent_path.join(Path::new(name)).map_err(|_| Errno::EINVAL)
    }

    fn is_trusted_operation(
        registry: &SandboxRegistry,
        sandbox_name: &str,
        pid: u32,
        uid: u32,
        path: &SandboxPath,
    ) -> bool {
        registry.trusted.values().any(|op| {
            op.sandbox == sandbox_name
                && op.pid == Some(pid)
                && op.uid == Some(uid)
                && op.paths.iter().any(|scope| {
                    if scope.recursive {
                        path.starts_with(&scope.path)
                    } else {
                        path == &scope.path
                    }
                })
        })
    }

    #[cfg(test)]
    fn create_pending_or_apply_for_identity(
        &self,
        identity: RequestIdentity,
        path: SandboxPath,
        operation: MetadataOperation,
    ) -> std::result::Result<FileAttr, Errno> {
        match self.begin_metadata_request(identity, path, operation)? {
            MetadataOutcome::Applied(attr) => Ok(attr),
            MetadataOutcome::Pending(pending) => self.finish_pending_attr(pending),
        }
    }

    fn begin_metadata_request(
        &self,
        identity: RequestIdentity,
        path: SandboxPath,
        operation: MetadataOperation,
    ) -> std::result::Result<MetadataOutcome, Errno> {
        let unchanged_attr = self.attr_for_path(&path)?;
        let mut registry = self.registry.lock().unwrap();
        let trusted = Self::is_trusted_operation(
            &registry,
            &self.sandbox_name,
            identity.pid,
            identity.uid,
            &path,
        );
        if trusted {
            let log_path = {
                let sandbox = registry
                    .sandboxes
                    .get(&self.sandbox_name)
                    .ok_or(Errno::ENOENT)?;
                if sandbox.resolve(operation.path()).is_none() {
                    return Err(Errno::ENOTSUP);
                }
                sandbox.log_path.clone()
            };
            let id = registry.next_operation_id();
            let trusted_id = registry
                .trusted
                .values()
                .find(|op| {
                    op.sandbox == self.sandbox_name
                        && op.pid == Some(identity.pid)
                        && op.uid == Some(identity.uid)
                        && op.paths.iter().any(|scope| {
                            if scope.recursive {
                                path.starts_with(&scope.path)
                            } else {
                                path == scope.path
                            }
                        })
                })
                .map(|op| op.id);
            let body = if let Some(trusted_id) = trusted_id {
                format!("trusted trusted={trusted_id} {}", operation.event_body())
            } else {
                format!("trusted {}", operation.event_body())
            };
            self.log_writer
                .append(&log_path, log::format_log_line(id, &body))
                .map_err(|_| Errno::EIO)?;
            let sandbox = registry
                .sandboxes
                .get_mut(&self.sandbox_name)
                .ok_or(Errno::ENOENT)?;
            sandbox
                .apply_metadata_override(&operation)
                .map_err(|_| Errno::ENOTSUP)?;
            drop(registry);
            return self.attr_for_path(&path).map(MetadataOutcome::Applied);
        }

        let description = operation.event_body();
        let kinds = operation.pending_kinds();
        if kinds.is_empty() {
            return Ok(MetadataOutcome::Applied(unchanged_attr));
        }
        let log_path = registry
            .sandboxes
            .get(&self.sandbox_name)
            .map(|s| s.log_path.clone())
            .ok_or(Errno::ENOENT)?;
        let waiter: PendingWaiter = Arc::new((Mutex::new(None), Condvar::new()));
        let mut superseded_waiters = Vec::new();
        let mut log_failed = false;

        let replacement_ids: Vec<u64> = operation
            .pending_keys(&self.sandbox_name)
            .into_iter()
            .filter_map(|key| registry.pending_index.remove(&key))
            .collect();
        let mut unique_replacement_ids = Vec::new();
        for id in replacement_ids {
            if !unique_replacement_ids.contains(&id) {
                unique_replacement_ids.push(id);
            }
        }
        for old_id in unique_replacement_ids {
            if let Some(old_request) = registry.remove_pending_request(old_id) {
                let decision_id = registry.next_operation_id();
                let attach_field = format_attach_field(old_request.attach_id);
                if self
                    .log_writer
                    .append(
                        &log_path,
                        log::format_log_line(
                            decision_id,
                            &format!(
                                "decision request={old_id}{attach_field} DENY reason=superseded"
                            ),
                        ),
                    )
                    .is_err()
                {
                    log_failed = true;
                }
                superseded_waiters.push(registry.pending_waiters.remove(&old_id));
            }
        }

        let id = registry.next_operation_id();
        if self
            .log_writer
            .append(
                &log_path,
                log::format_log_line(
                    id,
                    &format!(
                        "pending{} {description}",
                        format_attach_field(self.attach_id)
                    ),
                ),
            )
            .is_err()
        {
            log_failed = true;
        }
        for waiter in superseded_waiters {
            notify_waiter(waiter, PendingDecision::Deny);
        }
        if log_failed {
            return Err(Errno::EIO);
        }

        let request = PendingMetadataRequest {
            id,
            sandbox: self.sandbox_name.clone(),
            attach_id: self.attach_id,
            operation: operation.clone(),
            kinds,
            pid: identity.pid,
            uid: identity.uid,
            gid: identity.gid,
            description: description.clone(),
        };
        registry.insert_pending_request(request);
        registry.pending_waiters.insert(id, Arc::clone(&waiter));
        drop(registry);

        Ok(MetadataOutcome::Pending(PendingMetadataOutcome {
            unchanged_attr,
            path,
            operation,
            waiter,
        }))
    }

    fn authorize_read_write(
        &self,
        identity: RequestIdentity,
        operation: ReadWriteOperation,
    ) -> std::result::Result<ReadWriteDecision, Errno> {
        let kind = operation.kind();
        let description = operation.event_body();
        let mut registry = self.registry.lock().unwrap();
        let Some(sandbox) = registry.sandboxes.get(&self.sandbox_name) else {
            return Err(Errno::ENOENT);
        };
        let Some(protected_path) = operation
            .protection_paths()
            .into_iter()
            .find(|path| sandbox.is_protected(kind, path))
            .cloned()
        else {
            return Ok(ReadWriteDecision::Proceed);
        };
        let log_path = sandbox.log_path.clone();
        let process_identity = SysinfoProcessInfoProvider.identity_for_pid(identity.pid);
        let now = SystemTime::now();
        let expired_events: Vec<(u64, u64)> = registry
            .prune_expired_read_write_grants_for_sandbox(&self.sandbox_name, now)
            .into_iter()
            .map(|grant| (registry.next_operation_id(), grant.id))
            .collect();
        match registry.match_read_write_grant_for_intent(
            &self.sandbox_name,
            kind,
            &protected_path,
            process_identity,
            now,
        ) {
            GrantMatchOutcome::Matched { grant_id, consumed } => {
                let consumed_event_id = consumed.then(|| registry.next_operation_id());
                drop(registry);
                for (event_id, grant_id) in expired_events {
                    let _ = self.log_writer.append(
                        &log_path,
                        log::format_log_line(
                            event_id,
                            &format!("grant-expired grant={grant_id} lifetime=duration"),
                        ),
                    );
                }
                if let Some(event_id) = consumed_event_id {
                    let _ = self.log_writer.append(
                        &log_path,
                        log::format_log_line(
                            event_id,
                            &format!("grant-consumed grant={grant_id} lifetime=one-shot"),
                        ),
                    );
                }
                return Ok(ReadWriteDecision::Proceed);
            }
            GrantMatchOutcome::NotMatched => {}
        }
        for (event_id, grant_id) in expired_events {
            let _ = self.log_writer.append(
                &log_path,
                log::format_log_line(
                    event_id,
                    &format!("grant-expired grant={grant_id} lifetime=duration"),
                ),
            );
        }
        let waiter: PendingWaiter = Arc::new((Mutex::new(None), Condvar::new()));
        let id = registry.next_operation_id();
        self.log_writer
            .append(
                &log_path,
                log::format_log_line(
                    id,
                    &format!(
                        "pending{} {description}",
                        format_attach_field(self.attach_id)
                    ),
                ),
            )
            .map_err(|_| Errno::EIO)?;
        registry.insert_pending_read_write_request(
            PendingReadWriteRequest::new_with_attach_path(
                id,
                self.sandbox_name.clone(),
                self.attach_id,
                operation,
                protected_path,
                identity,
            )
            .with_process_identity(process_identity),
        );
        registry.pending_waiters.insert(id, Arc::clone(&waiter));
        drop(registry);

        match wait_for_decision(&waiter) {
            PendingDecision::Apply | PendingDecision::DoNothing => Ok(ReadWriteDecision::Proceed),
            PendingDecision::Deny => Ok(ReadWriteDecision::Denied),
            PendingDecision::Cancel => Ok(ReadWriteDecision::Canceled),
        }
    }

    fn finish_pending_attr(
        &self,
        pending: PendingMetadataOutcome,
    ) -> std::result::Result<FileAttr, Errno> {
        match wait_for_decision(&pending.waiter) {
            PendingDecision::Apply => {
                self.apply_pending_operation(&pending.operation)?;
                self.attr_for_path(&pending.path)
            }
            PendingDecision::DoNothing => Ok(pending.unchanged_attr),
            PendingDecision::Deny => Err(Errno::EPERM),
            PendingDecision::Cancel => Err(Errno::ECANCELED),
        }
    }

    fn apply_pending_operation(
        &self,
        operation: &MetadataOperation,
    ) -> std::result::Result<(), Errno> {
        let mut registry = self.registry.lock().unwrap();
        let sandbox = registry
            .sandboxes
            .get_mut(&self.sandbox_name)
            .ok_or(Errno::ENOENT)?;
        sandbox
            .apply_metadata_override(operation)
            .map_err(|_| Errno::ENOTSUP)
    }

    fn spawn_attr_waiter(&self, pending: PendingMetadataOutcome, reply: ReplyAttr) {
        let fs = self.clone();
        std::thread::spawn(move || match fs.finish_pending_attr(pending) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => reply.error(err),
        });
    }

    fn spawn_ioctl_waiter(&self, pending: PendingMetadataOutcome, reply: ReplyIoctl) {
        let fs = self.clone();
        std::thread::spawn(move || match wait_for_decision(&pending.waiter) {
            PendingDecision::Apply => match fs.apply_pending_operation(&pending.operation) {
                Ok(()) => reply.ioctl(0, &[]),
                Err(err) => reply.error(err),
            },
            PendingDecision::DoNothing => reply.ioctl(0, &[]),
            PendingDecision::Deny => reply.error(Errno::EPERM),
            PendingDecision::Cancel => reply.error(Errno::ECANCELED),
        });
    }
}

fn flags_to_xflags(flags: u32) -> u32 {
    let mut xflags = 0;
    if flags & FS_IMMUTABLE_FL != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if flags & FS_APPEND_FL != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    if flags & FS_SYNC_FL != 0 {
        xflags |= FS_XFLAG_SYNC;
    }
    if flags & FS_NOATIME_FL != 0 {
        xflags |= FS_XFLAG_NOATIME;
    }
    if flags & FS_NODUMP_FL != 0 {
        xflags |= FS_XFLAG_NODUMP;
    }
    if flags & FS_PROJINHERIT_FL != 0 {
        xflags |= FS_XFLAG_PROJINHERIT;
    }
    xflags
}

fn xflags_to_flags(xflags: u32) -> std::result::Result<u32, Errno> {
    if xflags & !FS_SUPPORTED_XFLAGS != 0 {
        return Err(Errno::ENOTSUP);
    }
    let mut flags = 0;
    if xflags & FS_XFLAG_IMMUTABLE != 0 {
        flags |= FS_IMMUTABLE_FL;
    }
    if xflags & FS_XFLAG_APPEND != 0 {
        flags |= FS_APPEND_FL;
    }
    if xflags & FS_XFLAG_SYNC != 0 {
        flags |= FS_SYNC_FL;
    }
    if xflags & FS_XFLAG_NOATIME != 0 {
        flags |= FS_NOATIME_FL;
    }
    if xflags & FS_XFLAG_NODUMP != 0 {
        flags |= FS_NODUMP_FL;
    }
    if xflags & FS_XFLAG_PROJINHERIT != 0 {
        flags |= FS_PROJINHERIT_FL;
    }
    Ok(flags)
}

fn encode_fsxattr(flags: u32) -> [u8; FSXATTR_SIZE] {
    let mut data = [0u8; FSXATTR_SIZE];
    data[..4].copy_from_slice(&flags_to_xflags(flags).to_ne_bytes());
    data
}

fn decode_fsxattr_flags(data: &[u8]) -> std::result::Result<u32, Errno> {
    if data.len() < FSXATTR_SIZE {
        return Err(Errno::EINVAL);
    }
    if data[4..FSXATTR_SIZE].iter().any(|byte| *byte != 0) {
        return Err(Errno::ENOTSUP);
    }
    let xflags = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    xflags_to_flags(xflags)
}

impl Filesystem for SandboxFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let Ok(path) = self.path_child(parent, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.attr_for_path(&path) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(err) => reply.error(err),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.attr_for_path(&path) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(err) => reply.error(err),
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let registry = self.registry.lock().unwrap();
        let Some(sandbox) = registry.sandboxes.get(&self.sandbox_name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match sandbox.resolve(&path) {
            Some(ResolvedPath::Real { local_path, .. }) => match hostfs::read_link(&local_path) {
                Ok(target) => reply.data(target.as_os_str().as_bytes()),
                Err(err) => reply.error(io_to_errno(err)),
            },
            Some(ResolvedPath::VirtualDir { .. }) => reply.error(Errno::EINVAL),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn statfs(&self, _req: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let path = self.path_for_ino(ino).unwrap_or_else(SandboxPath::root);
        let registry = self.registry.lock().unwrap();
        let Some(sandbox) = registry.sandboxes.get(&self.sandbox_name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let local_path = match sandbox.resolve(&path) {
            Some(ResolvedPath::Real { local_path, .. }) => local_path,
            Some(ResolvedPath::VirtualDir { .. }) => sandbox
                .layers
                .last()
                .map(|layer| layer.local.clone())
                .unwrap_or_else(|| PathBuf::from("/")),
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        };
        match hostfs::statfs(&local_path) {
            Ok(stat) => reply.statfs(
                stat.blocks,
                stat.bfree,
                stat.bavail,
                stat.files,
                stat.ffree,
                stat.bsize,
                stat.namelen,
                stat.frsize,
            ),
            Err(err) => reply.error(io_to_errno(err)),
        }
    }

    fn access(&self, req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.attr_for_path(&path) {
            Ok(attr) if check_access(&attr, req.uid(), req.gid(), mask) => reply.ok(),
            Ok(_) => reply.error(Errno::EACCES),
            Err(err) => reply.error(err),
        }
    }

    fn readdir(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(dir) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::ReadDirectory { path: dir.clone() },
        ) {
            Ok(ReadWriteDecision::Proceed) => {}
            Ok(ReadWriteDecision::Denied) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(ReadWriteDecision::Canceled) => {
                reply.error(Errno::ECANCELED);
                return;
            }
            Err(err) => {
                reply.error(err);
                return;
            }
        }
        let entries = {
            let registry = self.registry.lock().unwrap();
            let Some(sandbox) = registry.sandboxes.get(&self.sandbox_name) else {
                reply.error(Errno::ENOENT);
                return;
            };
            match sandbox.children(&dir) {
                Ok(children) => children,
                Err(_) => {
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
        };

        let mut all: Vec<(u64, FileType, OsString)> = Vec::new();
        all.push((ino.0, FileType::Directory, OsString::from(".")));
        let parent_ino = dir.parent().map(|p| stable_ino(&p).0).unwrap_or(ino.0);
        all.push((parent_ino, FileType::Directory, OsString::from("..")));
        for (name, resolved) in entries {
            let path = match resolved {
                ResolvedPath::Real { sandbox_path, .. }
                | ResolvedPath::VirtualDir { sandbox_path } => sandbox_path,
            };
            let kind = self
                .attr_for_path(&path)
                .map(|a| a.kind)
                .unwrap_or(FileType::RegularFile);
            all.push((self.remember(&path).0, kind, OsString::from(name)));
        }

        for (idx, (entry_ino, kind, name)) in all.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(entry_ino), (idx + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            match self.authorize_read_write(
                RequestIdentity::from_request(req),
                ReadWriteOperation::OpenWrite { path },
            ) {
                Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
                Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
                Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
                Err(err) => reply.error(err),
            }
            return;
        }
        let registry = self.registry.lock().unwrap();
        let Some(sandbox) = registry.sandboxes.get(&self.sandbox_name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match sandbox.resolve(&path) {
            Some(ResolvedPath::Real { local_path, .. }) if local_path.is_file() => {
                let mut next = self.next_handle.lock().unwrap();
                let fh = *next;
                *next += 1;
                self.handles.lock().unwrap().insert(
                    fh,
                    HandleInfo {
                        local_path,
                        sandbox_path: path.clone(),
                    },
                );
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Some(ResolvedPath::VirtualDir { .. }) => reply.error(Errno::EISDIR),
            Some(_) => reply.error(Errno::EACCES),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let Some(handle) = self.handles.lock().unwrap().get(&fh.0).cloned() else {
            reply.error(Errno::EBADF);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::ReadFile {
                path: handle.sandbox_path,
            },
        ) {
            Ok(ReadWriteDecision::Proceed) => {}
            Ok(ReadWriteDecision::Denied) => {
                reply.error(Errno::EACCES);
                return;
            }
            Ok(ReadWriteDecision::Canceled) => {
                reply.error(Errno::ECANCELED);
                return;
            }
            Err(err) => {
                reply.error(err);
                return;
            }
        }
        let mut file = match File::open(handle.local_path) {
            Ok(file) => file,
            Err(err) => {
                reply.error(io_to_errno(err));
                return;
            }
        };
        if let Err(err) = file.seek(SeekFrom::Start(offset)) {
            reply.error(io_to_errno(err));
            return;
        }
        let mut buf = vec![0; size as usize];
        match file.read(&mut buf) {
            Ok(n) => reply.data(&buf[..n]),
            Err(err) => reply.error(io_to_errno(err)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: fuser::LockOwner,
        reply: ReplyEmpty,
    ) {
        if self.handles.lock().unwrap().contains_key(&fh.0) {
            reply.ok();
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.handles.lock().unwrap().remove(&fh.0);
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.handles.lock().unwrap().contains_key(&fh.0) {
            reply.ok();
        } else {
            reply.error(Errno::EBADF);
        }
    }

    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if size.is_some() {
            match self.authorize_read_write(
                RequestIdentity::from_request(req),
                ReadWriteOperation::Truncate { path },
            ) {
                Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
                Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
                Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
                Err(err) => reply.error(err),
            }
            return;
        }
        let operation = MetadataOperation::SetAttr {
            path: path.clone(),
            mode: mode.map(|m| (m & 0o7777) as u16),
            uid,
            gid,
            flags: flags.map(|f| f.bits()),
        };
        match self.begin_metadata_request(RequestIdentity::from_request(req), path, operation) {
            Ok(MetadataOutcome::Applied(attr)) => reply.attr(&TTL, &attr),
            Ok(MetadataOutcome::Pending(pending)) => self.spawn_attr_waiter(pending, reply),
            Err(err) => reply.error(err),
        }
    }

    fn ioctl(
        &self,
        req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: fuser::IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        _out_size: u32,
        reply: ReplyIoctl,
    ) {
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match cmd {
            FS_IOC_GETFLAGS | FS_IOC_GETFLAGS_INT => match self.attr_for_path(&path) {
                Ok(attr) => reply.ioctl(0, &attr.flags.to_ne_bytes()),
                Err(err) => reply.error(err),
            },
            FS_IOC_FSGETXATTR => match self.attr_for_path(&path) {
                Ok(attr) => reply.ioctl(0, &encode_fsxattr(attr.flags)),
                Err(err) => reply.error(err),
            },
            FS_IOC_SETFLAGS | FS_IOC_SETFLAGS_INT => {
                if in_data.len() < 4 {
                    reply.error(Errno::EINVAL);
                    return;
                }
                let flags = u32::from_ne_bytes([in_data[0], in_data[1], in_data[2], in_data[3]]);
                let operation = MetadataOperation::Chattr {
                    path: path.clone(),
                    flags,
                };
                match self.begin_metadata_request(
                    RequestIdentity::from_request(req),
                    path,
                    operation,
                ) {
                    Ok(MetadataOutcome::Applied(_)) => reply.ioctl(0, &[]),
                    Ok(MetadataOutcome::Pending(pending)) => {
                        self.spawn_ioctl_waiter(pending, reply)
                    }
                    Err(err) => reply.error(err),
                }
            }
            FS_IOC_FSSETXATTR => {
                let flags = match decode_fsxattr_flags(in_data) {
                    Ok(flags) => flags,
                    Err(err) => {
                        reply.error(err);
                        return;
                    }
                };
                let operation = MetadataOperation::Chattr {
                    path: path.clone(),
                    flags,
                };
                match self.begin_metadata_request(
                    RequestIdentity::from_request(req),
                    path,
                    operation,
                ) {
                    Ok(MetadataOutcome::Applied(_)) => reply.ioctl(0, &[]),
                    Ok(MetadataOutcome::Pending(pending)) => {
                        self.spawn_ioctl_waiter(pending, reply)
                    }
                    Err(err) => reply.error(err),
                }
            }
            _ => reply.error(Errno::ENOTSUP),
        }
    }

    fn write(
        &self,
        req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        let Some(handle) = self.handles.lock().unwrap().get(&fh.0).cloned() else {
            reply.error(Errno::EBADF);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::WriteFile {
                path: handle.sandbox_path,
            },
        ) {
            Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
            Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
            Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
            Err(err) => reply.error(err),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Ok(path) = self.path_child(parent, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::Create { path },
        ) {
            Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
            Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
            Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
            Err(err) => reply.error(err),
        }
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Ok(path) = self.path_child(parent, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::Mkdir { path },
        ) {
            Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
            Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
            Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
            Err(err) => reply.error(err),
        }
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Ok(path) = self.path_child(parent, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::Unlink { path },
        ) {
            Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
            Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
            Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
            Err(err) => reply.error(err),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Ok(path) = self.path_child(parent, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::Rmdir { path },
        ) {
            Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
            Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
            Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
            Err(err) => reply.error(err),
        }
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        let Ok(from) = self.path_child(parent, name) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Ok(to) = self.path_child(newparent, newname) else {
            reply.error(Errno::ENOENT);
            return;
        };
        match self.authorize_read_write(
            RequestIdentity::from_request(req),
            ReadWriteOperation::Rename { from, to },
        ) {
            Ok(ReadWriteDecision::Proceed) => reply.error(Errno::EROFS),
            Ok(ReadWriteDecision::Denied) => reply.error(Errno::EACCES),
            Ok(ReadWriteDecision::Canceled) => reply.error(Errno::ECANCELED),
            Err(err) => reply.error(err),
        }
    }
}

fn format_attach_field(attach_id: Option<u64>) -> String {
    attach_id
        .map(|id| format!(" attach={id}"))
        .unwrap_or_default()
}

fn check_access(attr: &FileAttr, uid: u32, gid: u32, mask: AccessFlags) -> bool {
    if mask.is_empty() {
        return true;
    }
    let perm = u32::from(attr.perm);
    let shift = if uid == 0 {
        6
    } else if uid == attr.uid {
        6
    } else if gid == attr.gid {
        3
    } else {
        0
    };
    if mask.contains(AccessFlags::R_OK) && ((perm >> shift) & 0o4 == 0) {
        return false;
    }
    if mask.contains(AccessFlags::W_OK) && ((perm >> shift) & 0o2 == 0) {
        return false;
    }
    if mask.contains(AccessFlags::X_OK)
        && (if uid == 0 {
            perm & 0o111 == 0
        } else {
            (perm >> shift) & 0o1 == 0
        })
    {
        return false;
    }
    true
}

fn wait_for_decision(waiter: &PendingWaiter) -> PendingDecision {
    let (lock, cvar) = &**waiter;
    let mut decision = lock.lock().unwrap();
    while decision.is_none() {
        decision = cvar.wait(decision).unwrap();
    }
    decision.unwrap()
}

fn notify_waiter(waiter: Option<PendingWaiter>, decision: PendingDecision) {
    if let Some(waiter) = waiter {
        let (lock, cvar) = &*waiter;
        *lock.lock().unwrap() = Some(decision);
        cvar.notify_all();
    }
}

fn real_attr(path: &SandboxPath, local_path: &Path) -> std::io::Result<FileAttr> {
    let meta = std::fs::symlink_metadata(local_path)?;
    let mode = meta.mode();
    Ok(FileAttr {
        ino: stable_ino(path),
        size: meta.size(),
        blocks: meta.blocks(),
        atime: system_time(meta.atime(), meta.atime_nsec()),
        mtime: system_time(meta.mtime(), meta.mtime_nsec()),
        ctime: system_time(meta.ctime(), meta.ctime_nsec()),
        crtime: SystemTime::UNIX_EPOCH,
        kind: mode_to_kind(mode, meta.file_type()),
        perm: (mode & 0o7777) as u16,
        nlink: meta.nlink() as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        rdev: meta.rdev() as u32,
        blksize: meta.blksize() as u32,
        flags: 0,
    })
}

fn system_time(sec: i64, nsec: i64) -> SystemTime {
    if sec >= 0 {
        SystemTime::UNIX_EPOCH + std::time::Duration::new(sec as u64, nsec as u32)
    } else {
        SystemTime::UNIX_EPOCH
    }
}

fn io_to_errno(err: std::io::Error) -> Errno {
    match err.raw_os_error().unwrap_or(libc::EIO) {
        libc::EPERM => Errno::EPERM,
        libc::ENOENT => Errno::ENOENT,
        libc::EIO => Errno::EIO,
        libc::EBADF => Errno::EBADF,
        libc::EACCES => Errno::EACCES,
        libc::EEXIST => Errno::EEXIST,
        libc::ENOTDIR => Errno::ENOTDIR,
        libc::EISDIR => Errno::EISDIR,
        libc::EINVAL => Errno::EINVAL,
        libc::EROFS => Errno::EROFS,
        libc::ENOSYS => Errno::ENOSYS,
        libc::ENOTSUP => Errno::ENOTSUP,
        _ => Errno::EIO,
    }
}

trait OsStrBytes {
    fn as_bytes(&self) -> &[u8];
}

impl OsStrBytes for OsStr {
    fn as_bytes(&self) -> &[u8] {
        use std::os::unix::ffi::OsStrExt;
        OsStrExt::as_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use crate::state::{
        ProtectionKind, ReadWriteAccessGrant, ReadWriteGrantLifetime, ReadWriteGrantSubject,
        ReadWriteOperation, Sandbox, TrustedOperation, TrustedPathScope, epoch_millis,
    };

    fn registry_with_file(temp: &TempDir, log_path: PathBuf) -> Arc<Mutex<SandboxRegistry>> {
        let local = temp.path().join("local");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(local.join("file"), "hello").unwrap();
        std::fs::set_permissions(local.join("file"), std::fs::Permissions::from_mode(0o644))
            .unwrap();

        let mut sandbox = Sandbox::new("demo", log_path);
        sandbox.add_layer(local, SandboxPath::new("/data").unwrap());

        let registry = Arc::new(Mutex::new(SandboxRegistry::new()));
        registry
            .lock()
            .unwrap()
            .sandboxes
            .insert("demo".to_string(), sandbox);
        registry
    }

    fn wait_for_pending(registry: &Arc<Mutex<SandboxRegistry>>) -> u64 {
        let start = Instant::now();
        loop {
            if let Some(id) = registry.lock().unwrap().pending.keys().next().copied() {
                return id;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "pending operation did not appear"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_pending_read_write(registry: &Arc<Mutex<SandboxRegistry>>) -> u64 {
        let start = Instant::now();
        loop {
            if let Some(id) = registry
                .lock()
                .unwrap()
                .pending_read_write
                .keys()
                .next()
                .copied()
            {
                return id;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "pending read/write operation did not appear"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_pending_read_write_count(registry: &Arc<Mutex<SandboxRegistry>>, expected: usize) {
        let start = Instant::now();
        loop {
            if registry.lock().unwrap().pending_read_write.len() == expected {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "pending read/write count did not reach {expected}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn resolve_pending_read_write(
        registry: &Arc<Mutex<SandboxRegistry>>,
        id: u64,
        decision: PendingDecision,
    ) {
        let waiter = {
            let mut registry = registry.lock().unwrap();
            registry.remove_pending_read_write_request(id);
            registry.pending_waiters.remove(&id).unwrap()
        };
        let (lock, cvar) = &*waiter;
        *lock.lock().unwrap() = Some(decision);
        cvar.notify_all();
    }

    #[test]
    fn fsxattr_conversion_maps_common_inode_flags() {
        let flags = FS_IMMUTABLE_FL
            | FS_APPEND_FL
            | FS_SYNC_FL
            | FS_NOATIME_FL
            | FS_NODUMP_FL
            | FS_PROJINHERIT_FL;
        let xflags = flags_to_xflags(flags);
        assert_eq!(xflags & FS_XFLAG_IMMUTABLE, FS_XFLAG_IMMUTABLE);
        assert_eq!(xflags & FS_XFLAG_APPEND, FS_XFLAG_APPEND);
        assert_eq!(xflags & FS_XFLAG_SYNC, FS_XFLAG_SYNC);
        assert_eq!(xflags & FS_XFLAG_NOATIME, FS_XFLAG_NOATIME);
        assert_eq!(xflags & FS_XFLAG_NODUMP, FS_XFLAG_NODUMP);
        assert_eq!(xflags & FS_XFLAG_PROJINHERIT, FS_XFLAG_PROJINHERIT);
        assert_eq!(xflags_to_flags(xflags).unwrap(), flags);
        assert_eq!(flags_to_xflags(0x1), 0);
        assert_eq!(i32::from(xflags_to_flags(0x1).unwrap_err()), libc::ENOTSUP);
        assert_eq!(decode_fsxattr_flags(&encode_fsxattr(flags)).unwrap(), flags);
        let mut fsxattr_with_project_id = encode_fsxattr(FS_IMMUTABLE_FL);
        fsxattr_with_project_id[12..16].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(
            i32::from(decode_fsxattr_flags(&fsxattr_with_project_id).unwrap_err()),
            libc::ENOTSUP
        );
        assert_eq!(
            &encode_fsxattr(FS_IMMUTABLE_FL)[..4],
            &FS_XFLAG_IMMUTABLE.to_ne_bytes()
        );
    }

    #[test]
    fn protected_read_file_waits_for_decision_and_then_reads() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        {
            let mut registry = registry.lock().unwrap();
            registry.sandboxes.get_mut("demo").unwrap().protect(
                ProtectionKind::Read,
                SandboxPath::new("/data/file").unwrap(),
            );
        }
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let worker = {
            let fs = fs.clone();
            thread::spawn(move || {
                fs.authorize_read_write(
                    RequestIdentity {
                        pid: 123,
                        uid: 1000,
                        gid: 1000,
                    },
                    ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/file").unwrap(),
                    },
                )
            })
        };

        let id = wait_for_pending_read_write(&registry);
        {
            let registry = registry.lock().unwrap();
            let pending = registry.pending_read_write.get(&id).unwrap();
            assert_eq!(pending.kind, ProtectionKind::Read);
            assert_eq!(pending.path, SandboxPath::new("/data/file").unwrap());
            assert_eq!(pending.description, "path=/data/file READ file");
        }
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains(&format!(" id={id} pending path=/data/file READ file")));

        resolve_pending_read_write(&registry, id, PendingDecision::Apply);
        assert_eq!(worker.join().unwrap().unwrap(), ReadWriteDecision::Proceed);
        writer.shutdown().unwrap();
    }

    #[test]
    fn protected_read_matching_duration_grant_proceeds_without_pending_request() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let identity = SysinfoProcessInfoProvider
            .identity_for_pid(std::process::id())
            .unwrap();
        {
            let mut registry = registry.lock().unwrap();
            registry
                .sandboxes
                .get_mut("demo")
                .unwrap()
                .protect(ProtectionKind::Read, SandboxPath::new("/data/**").unwrap());
            registry.insert_read_write_grant(ReadWriteAccessGrant {
                id: 42,
                sandbox: "demo".to_string(),
                kind: ProtectionKind::Read,
                path_pattern: SandboxPath::new("/data/**").unwrap(),
                subject: ReadWriteGrantSubject::Exact { identity },
                lifetime: ReadWriteGrantLifetime::Duration {
                    expires_at_epoch_ms: epoch_millis(SystemTime::now() + Duration::from_secs(60)),
                },
                created_at_epoch_ms: epoch_millis(SystemTime::now()),
            });
        }
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let decision = fs
            .authorize_read_write(
                RequestIdentity {
                    pid: std::process::id(),
                    uid: 1000,
                    gid: 1000,
                },
                ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/file").unwrap(),
                },
            )
            .unwrap();

        assert_eq!(decision, ReadWriteDecision::Proceed);
        assert!(registry.lock().unwrap().pending_read_write.is_empty());
        assert!(log::read_log(&log_path).unwrap_or_default().is_empty());
        writer.shutdown().unwrap();
    }

    #[test]
    fn protected_read_matching_one_shot_grant_is_consumed() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let identity = SysinfoProcessInfoProvider
            .identity_for_pid(std::process::id())
            .unwrap();
        {
            let mut registry = registry.lock().unwrap();
            registry.sandboxes.get_mut("demo").unwrap().protect(
                ProtectionKind::Read,
                SandboxPath::new("/data/file").unwrap(),
            );
            registry.insert_read_write_grant(ReadWriteAccessGrant {
                id: 42,
                sandbox: "demo".to_string(),
                kind: ProtectionKind::Read,
                path_pattern: SandboxPath::new("/data/file").unwrap(),
                subject: ReadWriteGrantSubject::Exact { identity },
                lifetime: ReadWriteGrantLifetime::OneShot,
                created_at_epoch_ms: epoch_millis(SystemTime::now()),
            });
        }
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let decision = fs
            .authorize_read_write(
                RequestIdentity {
                    pid: std::process::id(),
                    uid: 1000,
                    gid: 1000,
                },
                ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/file").unwrap(),
                },
            )
            .unwrap();

        assert_eq!(decision, ReadWriteDecision::Proceed);
        assert!(registry.lock().unwrap().pending_read_write.is_empty());
        assert!(registry.lock().unwrap().read_write_grants.is_empty());
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains("grant-consumed grant=42 lifetime=one-shot"));
        writer.shutdown().unwrap();
    }

    #[test]
    fn protected_read_expired_duration_grant_is_pruned_and_request_queues() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let identity = SysinfoProcessInfoProvider
            .identity_for_pid(std::process::id())
            .unwrap();
        {
            let mut registry = registry.lock().unwrap();
            registry.sandboxes.get_mut("demo").unwrap().protect(
                ProtectionKind::Read,
                SandboxPath::new("/data/file").unwrap(),
            );
            registry.insert_read_write_grant(ReadWriteAccessGrant {
                id: 42,
                sandbox: "demo".to_string(),
                kind: ProtectionKind::Read,
                path_pattern: SandboxPath::new("/data/file").unwrap(),
                subject: ReadWriteGrantSubject::Exact { identity },
                lifetime: ReadWriteGrantLifetime::Duration {
                    expires_at_epoch_ms: 0,
                },
                created_at_epoch_ms: epoch_millis(SystemTime::now()),
            });
            registry.next_operation_id = 50;
        }
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let worker = {
            let fs = fs.clone();
            thread::spawn(move || {
                fs.authorize_read_write(
                    RequestIdentity {
                        pid: std::process::id(),
                        uid: 1000,
                        gid: 1000,
                    },
                    ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/file").unwrap(),
                    },
                )
            })
        };

        let id = wait_for_pending_read_write(&registry);
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains(" id=50 grant-expired grant=42 lifetime=duration"));
        assert!(data.contains(&format!(" id={id} pending path=/data/file READ file")));
        resolve_pending_read_write(&registry, id, PendingDecision::Apply);
        assert_eq!(worker.join().unwrap().unwrap(), ReadWriteDecision::Proceed);
        assert!(registry.lock().unwrap().read_write_grants.is_empty());
        writer.shutdown().unwrap();
    }

    #[test]
    fn protected_read_deny_returns_denied_decision() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path);
        registry
            .lock()
            .unwrap()
            .sandboxes
            .get_mut("demo")
            .unwrap()
            .protect(
                ProtectionKind::Read,
                SandboxPath::new("/data/file").unwrap(),
            );
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let worker = {
            let fs = fs.clone();
            thread::spawn(move || {
                fs.authorize_read_write(
                    RequestIdentity {
                        pid: 123,
                        uid: 1000,
                        gid: 1000,
                    },
                    ReadWriteOperation::ReadFile {
                        path: SandboxPath::new("/data/file").unwrap(),
                    },
                )
            })
        };

        let id = wait_for_pending_read_write(&registry);
        resolve_pending_read_write(&registry, id, PendingDecision::Deny);
        assert_eq!(worker.join().unwrap().unwrap(), ReadWriteDecision::Denied);
        writer.shutdown().unwrap();
    }

    #[test]
    fn unprotected_read_write_operation_does_not_create_pending_request() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path);
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let decision = fs
            .authorize_read_write(
                RequestIdentity {
                    pid: 123,
                    uid: 1000,
                    gid: 1000,
                },
                ReadWriteOperation::ReadFile {
                    path: SandboxPath::new("/data/file").unwrap(),
                },
            )
            .unwrap();

        assert_eq!(decision, ReadWriteDecision::Proceed);
        assert!(registry.lock().unwrap().pending_read_write.is_empty());
        writer.shutdown().unwrap();
    }

    #[test]
    fn protected_write_do_nothing_continues_to_existing_read_only_behavior() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path);
        registry
            .lock()
            .unwrap()
            .sandboxes
            .get_mut("demo")
            .unwrap()
            .protect(
                ProtectionKind::Write,
                SandboxPath::new("/data/file").unwrap(),
            );
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let worker = {
            let fs = fs.clone();
            thread::spawn(move || {
                fs.authorize_read_write(
                    RequestIdentity {
                        pid: 123,
                        uid: 1000,
                        gid: 1000,
                    },
                    ReadWriteOperation::WriteFile {
                        path: SandboxPath::new("/data/file").unwrap(),
                    },
                )
            })
        };

        let id = wait_for_pending_read_write(&registry);
        resolve_pending_read_write(&registry, id, PendingDecision::DoNothing);
        assert_eq!(worker.join().unwrap().unwrap(), ReadWriteDecision::Proceed);
        writer.shutdown().unwrap();
    }

    #[test]
    fn protected_rename_queues_when_either_side_is_protected() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path);
        registry
            .lock()
            .unwrap()
            .sandboxes
            .get_mut("demo")
            .unwrap()
            .protect(
                ProtectionKind::Write,
                SandboxPath::new("/data/new").unwrap(),
            );
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let worker = {
            let fs = fs.clone();
            thread::spawn(move || {
                fs.authorize_read_write(
                    RequestIdentity {
                        pid: 123,
                        uid: 1000,
                        gid: 1000,
                    },
                    ReadWriteOperation::Rename {
                        from: SandboxPath::new("/data/old").unwrap(),
                        to: SandboxPath::new("/data/new").unwrap(),
                    },
                )
            })
        };

        let id = wait_for_pending_read_write(&registry);
        {
            let registry = registry.lock().unwrap();
            let pending = registry.pending_read_write.get(&id).unwrap();
            assert_eq!(pending.path, SandboxPath::new("/data/new").unwrap());
            assert_eq!(
                pending.description,
                "path=/data/old WRITE rename to=/data/new"
            );
        }
        resolve_pending_read_write(&registry, id, PendingDecision::Apply);
        assert_eq!(worker.join().unwrap().unwrap(), ReadWriteDecision::Proceed);
        writer.shutdown().unwrap();
    }

    #[test]
    fn concurrent_protected_reads_queue_independently() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path);
        registry
            .lock()
            .unwrap()
            .sandboxes
            .get_mut("demo")
            .unwrap()
            .protect(
                ProtectionKind::Read,
                SandboxPath::new("/data/file").unwrap(),
            );
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());

        let workers: Vec<_> = (0..3)
            .map(|pid| {
                let fs = fs.clone();
                thread::spawn(move || {
                    fs.authorize_read_write(
                        RequestIdentity {
                            pid,
                            uid: 1000,
                            gid: 1000,
                        },
                        ReadWriteOperation::ReadFile {
                            path: SandboxPath::new("/data/file").unwrap(),
                        },
                    )
                })
            })
            .collect();

        wait_for_pending_read_write_count(&registry, 3);
        let ids = registry
            .lock()
            .unwrap()
            .pending_read_write
            .keys()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 3);
        for id in ids {
            resolve_pending_read_write(&registry, id, PendingDecision::Apply);
        }
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), ReadWriteDecision::Proceed);
        }
        writer.shutdown().unwrap();
    }

    #[test]
    fn untrusted_metadata_request_logs_pending_event() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());
        let path = SandboxPath::new("/data/file").unwrap();

        let worker = {
            let fs = fs.clone();
            let path = path.clone();
            thread::spawn(move || {
                fs.create_pending_or_apply_for_identity(
                    RequestIdentity {
                        pid: 123,
                        uid: 1000,
                        gid: 1000,
                    },
                    path.clone(),
                    MetadataOperation::Chmod { path, mode: 0o444 },
                )
            })
        };

        let id = wait_for_pending(&registry);
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains(&format!(
            " id={id} pending path=/data/file SETATTR mode=0444"
        )));

        let waiter = {
            let mut registry = registry.lock().unwrap();
            registry.remove_pending_request(id);
            registry.pending_waiters.remove(&id).unwrap()
        };
        let (lock, cvar) = &*waiter;
        *lock.lock().unwrap() = Some(PendingDecision::DoNothing);
        cvar.notify_all();

        let attr = worker.join().unwrap().unwrap();
        assert_eq!(attr.perm, 0o644);
        writer.shutdown().unwrap();
    }

    #[test]
    fn trusted_metadata_request_logs_trusted_event_without_host_mutation() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        {
            let mut registry = registry.lock().unwrap();
            registry.trusted.insert(
                "token".to_string(),
                TrustedOperation {
                    id: 42,
                    sandbox: "demo".to_string(),
                    token: "token".to_string(),
                    pid: Some(123),
                    uid: Some(1000),
                    mountpoint: temp.path().join("mnt"),
                    command: "chmod".to_string(),
                    paths: vec![TrustedPathScope {
                        path: SandboxPath::new("/data/file").unwrap(),
                        recursive: false,
                    }],
                },
            );
        }
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());
        let path = SandboxPath::new("/data/file").unwrap();

        let attr = fs
            .create_pending_or_apply_for_identity(
                RequestIdentity {
                    pid: 123,
                    uid: 1000,
                    gid: 1000,
                },
                path.clone(),
                MetadataOperation::Chmod { path, mode: 0o444 },
            )
            .unwrap();

        assert_eq!(attr.perm, 0o444);
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains(" id=1 trusted trusted=42 path=/data/file SETATTR mode=0444"));
        assert_eq!(
            std::fs::metadata(temp.path().join("local/file"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        writer.shutdown().unwrap();
    }

    #[test]
    fn same_path_same_kind_replaces_and_denies_old_request() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());
        let identity = RequestIdentity {
            pid: 123,
            uid: 1000,
            gid: 1000,
        };
        let path = SandboxPath::new("/data/file").unwrap();

        let first = fs
            .begin_metadata_request(
                identity,
                path.clone(),
                MetadataOperation::Chmod {
                    path: path.clone(),
                    mode: 0o444,
                },
            )
            .unwrap();
        let first = match first {
            MetadataOutcome::Pending(pending) => pending,
            MetadataOutcome::Applied(_) => panic!("expected pending request"),
        };
        let second = fs
            .begin_metadata_request(
                identity,
                path.clone(),
                MetadataOperation::Chmod { path, mode: 0o600 },
            )
            .unwrap();
        let second = match second {
            MetadataOutcome::Pending(pending) => pending,
            MetadataOutcome::Applied(_) => panic!("expected pending request"),
        };

        assert_eq!(*first.waiter.0.lock().unwrap(), Some(PendingDecision::Deny));
        assert_eq!(
            registry
                .lock()
                .unwrap()
                .pending
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(*second.waiter.0.lock().unwrap(), None);
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains(" id=1 pending path=/data/file SETATTR mode=0444"));
        assert!(data.contains(" id=2 decision request=1 DENY reason=superseded"));
        assert!(data.contains(" id=3 pending path=/data/file SETATTR mode=0600"));
        writer.shutdown().unwrap();
    }

    #[test]
    fn same_path_different_kinds_remain_pending_independently() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());
        let identity = RequestIdentity {
            pid: 123,
            uid: 1000,
            gid: 1000,
        };
        let path = SandboxPath::new("/data/file").unwrap();

        let uid_request = fs
            .begin_metadata_request(
                identity,
                path.clone(),
                MetadataOperation::SetAttr {
                    path: path.clone(),
                    mode: None,
                    uid: Some(2000),
                    gid: None,
                    flags: None,
                },
            )
            .unwrap();
        let gid_request = fs
            .begin_metadata_request(
                identity,
                path.clone(),
                MetadataOperation::SetAttr {
                    path,
                    mode: None,
                    uid: None,
                    gid: Some(3000),
                    flags: None,
                },
            )
            .unwrap();

        let uid_request = match uid_request {
            MetadataOutcome::Pending(pending) => pending,
            MetadataOutcome::Applied(_) => panic!("expected pending request"),
        };
        let gid_request = match gid_request {
            MetadataOutcome::Pending(pending) => pending,
            MetadataOutcome::Applied(_) => panic!("expected pending request"),
        };
        assert_eq!(*uid_request.waiter.0.lock().unwrap(), None);
        assert_eq!(*gid_request.waiter.0.lock().unwrap(), None);
        let pending_ids = registry
            .lock()
            .unwrap()
            .pending
            .keys()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(pending_ids, vec![1, 2]);
        let data = log::read_log(&log_path).unwrap();
        assert!(data.contains(" id=1 pending path=/data/file SETATTR uid=2000"));
        assert!(data.contains(" id=2 pending path=/data/file SETATTR gid=3000"));
        assert!(!data.contains("reason=superseded"));
        writer.shutdown().unwrap();
    }

    #[test]
    fn concurrent_same_kind_replacement_leaves_one_pending_per_path_kind() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path.clone());
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", Arc::clone(&registry), writer.handle());
        let path = SandboxPath::new("/data/file").unwrap();

        let mut threads = Vec::new();
        for offset in 0..10 {
            let fs = fs.clone();
            let path = path.clone();
            threads.push(thread::spawn(move || {
                let mode = 0o400 + offset;
                match fs
                    .begin_metadata_request(
                        RequestIdentity {
                            pid: mode,
                            uid: 1000,
                            gid: 1000,
                        },
                        path.clone(),
                        MetadataOperation::Chmod {
                            path,
                            mode: mode as u16,
                        },
                    )
                    .unwrap()
                {
                    MetadataOutcome::Pending(pending) => pending,
                    MetadataOutcome::Applied(_) => panic!("expected pending request"),
                }
            }));
        }

        let pending_outcomes: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let registry = registry.lock().unwrap();
        assert_eq!(registry.pending.len(), 1);
        assert_eq!(registry.pending_index.len(), 1);
        let remaining_operation = registry
            .pending
            .values()
            .next()
            .unwrap()
            .operation
            .event_body();
        drop(registry);

        let mut still_pending = 0;
        let mut denied = 0;
        for pending in &pending_outcomes {
            match *pending.waiter.0.lock().unwrap() {
                Some(PendingDecision::Deny) => denied += 1,
                None => {
                    still_pending += 1;
                    assert_eq!(pending.operation.event_body(), remaining_operation);
                }
                other => panic!("unexpected waiter decision: {other:?}"),
            }
        }
        assert_eq!(still_pending, 1);
        assert_eq!(denied, 9);

        let data = log::read_log(&log_path).unwrap();
        assert_eq!(
            data.matches(" pending path=/data/file SETATTR mode=")
                .count(),
            10
        );
        assert_eq!(data.matches(" DENY reason=superseded").count(), 9);
        writer.shutdown().unwrap();
    }

    #[test]
    fn pending_metadata_request_does_not_block_unrelated_lookup() {
        let temp = TempDir::new().unwrap();
        let log_path = temp.path().join("logs/demo.log");
        let registry = registry_with_file(&temp, log_path);
        std::fs::write(temp.path().join("local/other"), "world").unwrap();
        let writer = log::LogWriter::new();
        let fs = SandboxFs::new("demo", registry, writer.handle());
        let path = SandboxPath::new("/data/file").unwrap();

        let outcome = fs
            .begin_metadata_request(
                RequestIdentity {
                    pid: 123,
                    uid: 1000,
                    gid: 1000,
                },
                path.clone(),
                MetadataOperation::Chmod { path, mode: 0o444 },
            )
            .unwrap();
        assert!(matches!(outcome, MetadataOutcome::Pending(_)));

        let unrelated = fs
            .attr_for_path(&SandboxPath::new("/data/other").unwrap())
            .unwrap();
        assert_eq!(unrelated.perm, 0o644);
        writer.shutdown().unwrap();
    }
}
