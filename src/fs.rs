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
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    OpenAccMode, OpenFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyIoctl, ReplyOpen, ReplyWrite, Request,
};

use crate::log;
use crate::path::SandboxPath;
use crate::state::{
    MetadataOperation, PendingDecision, PendingWaiter, ResolvedPath, SandboxRegistry, TTL,
    apply_override, mode_to_kind, stable_ino, virtual_dir_attr,
};

const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;

#[derive(Debug, Clone)]
pub struct SandboxFs {
    pub sandbox_name: String,
    pub registry: Arc<Mutex<SandboxRegistry>>,
    log_writer: log::LogWriterHandle,
    inodes: Arc<Mutex<HashMap<u64, SandboxPath>>>,
    handles: Arc<Mutex<HashMap<u64, PathBuf>>>,
    next_handle: Arc<Mutex<u64>>,
}

#[derive(Debug, Clone, Copy)]
struct RequestIdentity {
    pid: u32,
    uid: u32,
    gid: u32,
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
        let mut inodes = HashMap::new();
        inodes.insert(1, SandboxPath::root());
        Self {
            sandbox_name: sandbox_name.into(),
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

    fn create_pending_or_apply(
        &self,
        req: &Request,
        path: SandboxPath,
        operation: MetadataOperation,
    ) -> std::result::Result<FileAttr, Errno> {
        self.create_pending_or_apply_for_identity(
            RequestIdentity::from_request(req),
            path,
            operation,
        )
    }

    fn create_pending_or_apply_for_identity(
        &self,
        identity: RequestIdentity,
        path: SandboxPath,
        operation: MetadataOperation,
    ) -> std::result::Result<FileAttr, Errno> {
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
            return self.attr_for_path(&path);
        }

        let id = registry.next_operation_id();
        let description = operation.event_body();
        let log_path = registry
            .sandboxes
            .get(&self.sandbox_name)
            .map(|s| s.log_path.clone())
            .ok_or(Errno::ENOENT)?;
        let waiter: PendingWaiter = Arc::new((Mutex::new(None), Condvar::new()));
        self.log_writer
            .append(
                &log_path,
                log::format_log_line(id, &format!("pending {description}")),
            )
            .map_err(|_| Errno::EIO)?;
        registry.pending.insert(
            id,
            crate::state::PendingMetadataRequest {
                id,
                sandbox: self.sandbox_name.clone(),
                operation: operation.clone(),
                pid: identity.pid,
                uid: identity.uid,
                gid: identity.gid,
                description: description.clone(),
            },
        );
        registry.pending_waiters.insert(id, Arc::clone(&waiter));
        drop(registry);

        let (lock, cvar) = &*waiter;
        let mut decision = lock.lock().unwrap();
        while decision.is_none() {
            decision = cvar.wait(decision).unwrap();
        }
        match decision.unwrap() {
            PendingDecision::Apply => {
                let mut registry = self.registry.lock().unwrap();
                let sandbox = registry
                    .sandboxes
                    .get_mut(&self.sandbox_name)
                    .ok_or(Errno::ENOENT)?;
                sandbox
                    .apply_metadata_override(&operation)
                    .map_err(|_| Errno::ENOTSUP)?;
                drop(registry);
                self.attr_for_path(&path)
            }
            PendingDecision::DoNothing => Ok(unchanged_attr),
            PendingDecision::Deny => Err(Errno::EPERM),
        }
    }
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

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let Some(dir) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
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

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if flags.acc_mode() != OpenAccMode::O_RDONLY {
            reply.error(Errno::EROFS);
            return;
        }
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
            Some(ResolvedPath::Real { local_path, .. }) if local_path.is_file() => {
                let mut next = self.next_handle.lock().unwrap();
                let fh = *next;
                *next += 1;
                self.handles.lock().unwrap().insert(fh, local_path);
                reply.opened(FileHandle(fh), FopenFlags::empty());
            }
            Some(ResolvedPath::VirtualDir { .. }) => reply.error(Errno::EISDIR),
            Some(_) => reply.error(Errno::EACCES),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyData,
    ) {
        let Some(path) = self.handles.lock().unwrap().get(&fh.0).cloned() else {
            reply.error(Errno::EBADF);
            return;
        };
        let mut file = match File::open(path) {
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
        if size.is_some() {
            reply.error(Errno::EROFS);
            return;
        }
        let Some(path) = self.path_for_ino(ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let operation = MetadataOperation::SetAttr {
            path: path.clone(),
            mode: mode.map(|m| (m & 0o7777) as u16),
            uid,
            gid,
            flags: flags.map(|f| f.bits()),
        };
        match self.create_pending_or_apply(req, path, operation) {
            Ok(attr) => reply.attr(&TTL, &attr),
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
        if cmd == FS_IOC_GETFLAGS {
            match self.attr_for_path(&path) {
                Ok(attr) => reply.ioctl(0, &u64::from(attr.flags).to_ne_bytes()),
                Err(err) => reply.error(err),
            }
            return;
        }
        if cmd == FS_IOC_SETFLAGS {
            if in_data.len() < 4 {
                reply.error(Errno::EINVAL);
                return;
            }
            let flags = u32::from_ne_bytes([in_data[0], in_data[1], in_data[2], in_data[3]]);
            let operation = MetadataOperation::Chattr {
                path: path.clone(),
                flags,
            };
            match self.create_pending_or_apply(req, path, operation) {
                Ok(_) => reply.ioctl(0, &[]),
                Err(err) => reply.error(err),
            }
            return;
        }
        reply.error(Errno::ENOTSUP);
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        _data: &[u8],
        _write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: ReplyWrite,
    ) {
        reply.error(Errno::EROFS);
    }

    fn create(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        reply.error(Errno::EROFS);
    }

    fn mkdir(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        reply.error(Errno::EROFS);
    }

    fn unlink(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::EROFS);
    }

    fn rmdir(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::EROFS);
    }

    fn rename(
        &self,
        _req: &Request,
        _parent: INodeNo,
        _name: &OsStr,
        _newparent: INodeNo,
        _newname: &OsStr,
        _flags: fuser::RenameFlags,
        reply: ReplyEmpty,
    ) {
        reply.error(Errno::EROFS);
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

    use crate::state::{Sandbox, TrustedOperation, TrustedPathScope};

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
            registry.pending.remove(&id);
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
}
