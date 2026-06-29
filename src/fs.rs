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
    inodes: Arc<Mutex<HashMap<u64, SandboxPath>>>,
    handles: Arc<Mutex<HashMap<u64, PathBuf>>>,
    next_handle: Arc<Mutex<u64>>,
}

impl SandboxFs {
    pub fn new(sandbox_name: impl Into<String>, registry: Arc<Mutex<SandboxRegistry>>) -> Self {
        let mut inodes = HashMap::new();
        inodes.insert(1, SandboxPath::root());
        Self {
            sandbox_name: sandbox_name.into(),
            registry,
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

    fn is_trusted_pid(registry: &SandboxRegistry, sandbox_name: &str, pid: u32) -> bool {
        registry
            .trusted
            .values()
            .any(|op| op.sandbox == sandbox_name && op.pid == Some(pid))
    }

    fn create_pending_or_apply(
        &self,
        req: &Request,
        path: SandboxPath,
        operation: MetadataOperation,
    ) -> std::result::Result<FileAttr, Errno> {
        let mut registry = self.registry.lock().unwrap();
        let trusted = Self::is_trusted_pid(&registry, &self.sandbox_name, req.pid());
        if trusted {
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
        let description = operation.description();
        let log_path = registry
            .sandboxes
            .get(&self.sandbox_name)
            .map(|s| s.log_path.clone())
            .ok_or(Errno::ENOENT)?;
        let waiter: PendingWaiter = Arc::new((Mutex::new(None), Condvar::new()));
        registry.pending.insert(
            id,
            crate::state::PendingMetadataRequest {
                id,
                sandbox: self.sandbox_name.clone(),
                operation: operation.clone(),
                pid: req.pid(),
                uid: req.uid(),
                gid: req.gid(),
                description: description.clone(),
            },
        );
        registry.pending_waiters.insert(id, Arc::clone(&waiter));
        let _ = log::append_log(&log_path, format!("{id} {description}"));
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
            PendingDecision::DoNothing => self.attr_for_path(&path),
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
