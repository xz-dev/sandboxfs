//! In-memory sandbox data model and overlay resolution.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType, INodeNo};
use serde::{Deserialize, Serialize};

use crate::path::SandboxPath;
use crate::{Error, Result};

pub const ROOT_INO: u64 = 1;
pub const FIRST_DYNAMIC_INO: u64 = 2;
pub const VIRTUAL_DIR_MODE: u16 = 0o555;
pub const TTL: Duration = Duration::from_secs(1);
pub const FS_IMMUTABLE_FL: u32 = 0x0000_0010;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountLayer {
    pub id: u64,
    pub local: PathBuf,
    pub on_fs: SandboxPath,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HideRule {
    pub id: u64,
    pub path: SandboxPath,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataOverride {
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub flags: Option<u32>,
}

impl MetadataOverride {
    pub fn is_empty(&self) -> bool {
        self.mode.is_none() && self.uid.is_none() && self.gid.is_none() && self.flags.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetadataOperation {
    Chmod {
        path: SandboxPath,
        mode: u16,
    },
    Chown {
        path: SandboxPath,
        uid: Option<u32>,
        gid: Option<u32>,
    },
    Chattr {
        path: SandboxPath,
        flags: u32,
    },
    SetAttr {
        path: SandboxPath,
        mode: Option<u16>,
        uid: Option<u32>,
        gid: Option<u32>,
        flags: Option<u32>,
    },
}

impl MetadataOperation {
    pub fn path(&self) -> &SandboxPath {
        match self {
            Self::Chmod { path, .. }
            | Self::Chown { path, .. }
            | Self::Chattr { path, .. }
            | Self::SetAttr { path, .. } => path,
        }
    }

    pub fn description(&self) -> String {
        self.event_body()
    }

    pub fn event_body(&self) -> String {
        match self {
            Self::Chmod { path, mode } => format!("path={path} SETATTR mode={mode:04o}"),
            Self::Chown { path, uid, gid } => format_setattr_body(path, None, *uid, *gid, None),
            Self::Chattr { path, flags } => format!("path={path} CHATTR flags=0x{flags:x}"),
            Self::SetAttr {
                path,
                mode,
                uid,
                gid,
                flags,
            } => format_setattr_body(path, *mode, *uid, *gid, *flags),
        }
    }

    pub fn shell_hint(&self) -> String {
        match self {
            Self::Chmod { path, mode } => format!("chmod {:o} {}", mode, path),
            Self::Chown { path, uid, gid } => format_chown_shell_hint(path, *uid, *gid),
            Self::Chattr { path, flags } => format!("chattr flags=0x{flags:x} {path}"),
            Self::SetAttr {
                path,
                mode,
                uid,
                gid,
                flags,
            } => match (mode, uid, gid, flags) {
                (Some(mode), None, None, None) => format!("chmod {:o} {}", mode, path),
                (None, Some(uid), None, None) => format_chown_shell_hint(path, Some(*uid), None),
                (None, None, Some(gid), None) => format_chown_shell_hint(path, None, Some(*gid)),
                (None, Some(uid), Some(gid), None) => {
                    format_chown_shell_hint(path, Some(*uid), Some(*gid))
                }
                (None, None, None, Some(flags)) => format!("chattr flags=0x{flags:x} {path}"),
                _ => self.event_body(),
            },
        }
    }
}

fn format_setattr_body(
    path: &SandboxPath,
    mode: Option<u16>,
    uid: Option<u32>,
    gid: Option<u32>,
    flags: Option<u32>,
) -> String {
    let mut fields = Vec::new();
    if let Some(mode) = mode {
        fields.push(format!("mode={mode:04o}"));
    }
    if let Some(uid) = uid {
        fields.push(format!("uid={uid}"));
    }
    if let Some(gid) = gid {
        fields.push(format!("gid={gid}"));
    }
    if let Some(flags) = flags {
        fields.push(format!("flags=0x{flags:x}"));
    }
    if fields.is_empty() {
        fields.push("unchanged".to_string());
    }
    format!("path={path} SETATTR {}", fields.join(" "))
}

fn format_chown_shell_hint(path: &SandboxPath, uid: Option<u32>, gid: Option<u32>) -> String {
    match (uid, gid) {
        (Some(uid), Some(gid)) => format!("chown {uid}:{gid} {path}"),
        (Some(uid), None) => format!("chown {uid} {path}"),
        (None, Some(gid)) => format!("chown :{gid} {path}"),
        (None, None) => format!("chown unchanged {path}"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMetadataRequest {
    pub id: u64,
    pub sandbox: String,
    pub operation: MetadataOperation,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDecision {
    Apply,
    DoNothing,
    Deny,
}

pub type PendingWaiter = Arc<(Mutex<Option<PendingDecision>>, Condvar)>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedPathScope {
    pub path: SandboxPath,
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedOperation {
    pub id: u64,
    pub sandbox: String,
    pub token: String,
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub mountpoint: PathBuf,
    pub command: String,
    pub paths: Vec<TrustedPathScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachMount {
    pub mountpoint: PathBuf,
    pub temporary: bool,
    #[serde(skip)]
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPath {
    Real {
        local_path: PathBuf,
        layer_id: u64,
        sandbox_path: SandboxPath,
    },
    VirtualDir {
        sandbox_path: SandboxPath,
    },
}

#[derive(Debug, Clone)]
pub struct Sandbox {
    pub name: String,
    pub layers: Vec<MountLayer>,
    pub hides: Vec<HideRule>,
    pub metadata: BTreeMap<SandboxPath, MetadataOverride>,
    pub attaches: BTreeMap<PathBuf, AttachMount>,
    pub next_layer_id: u64,
    pub next_hide_id: u64,
    pub log_path: PathBuf,
}

impl Sandbox {
    pub fn new(name: impl Into<String>, log_path: PathBuf) -> Self {
        Self {
            name: name.into(),
            layers: Vec::new(),
            hides: Vec::new(),
            metadata: BTreeMap::new(),
            attaches: BTreeMap::new(),
            next_layer_id: 1,
            next_hide_id: 1,
            log_path,
        }
    }

    fn next_overlay_order(&mut self) -> u64 {
        let id = self.next_layer_id.max(self.next_hide_id);
        self.next_layer_id = id + 1;
        self.next_hide_id = id + 1;
        id
    }

    pub fn add_layer(&mut self, local: impl Into<PathBuf>, on_fs: SandboxPath) -> u64 {
        let id = self.next_overlay_order();
        self.layers.push(MountLayer {
            id,
            local: local.into(),
            on_fs,
        });
        id
    }

    pub fn remove_layer(&mut self, on_fs: &SandboxPath) -> bool {
        if let Some(index) = self.layers.iter().rposition(|layer| &layer.on_fs == on_fs) {
            self.layers.remove(index);
            true
        } else {
            false
        }
    }

    pub fn add_hide(&mut self, path: SandboxPath) -> u64 {
        let id = self.next_overlay_order();
        self.hides.push(HideRule { id, path });
        id
    }

    pub fn is_hidden(&self, path: &SandboxPath) -> bool {
        let newest_covering_layer = self
            .layers
            .iter()
            .filter(|layer| path.starts_with(&layer.on_fs))
            .map(|layer| layer.id)
            .max()
            .unwrap_or(0);
        self.hides
            .iter()
            .any(|hide| path.starts_with(&hide.path) && hide.id > newest_covering_layer)
    }

    pub fn resolve(&self, path: &SandboxPath) -> Option<ResolvedPath> {
        if self.is_hidden(path) {
            return None;
        }
        for layer in self.layers.iter().rev() {
            if path.starts_with(&layer.on_fs) {
                let rest = path.strip_prefix(&layer.on_fs).ok()?;
                return Some(ResolvedPath::Real {
                    local_path: layer.local.join(rest),
                    layer_id: layer.id,
                    sandbox_path: path.clone(),
                });
            }
        }
        if self.is_virtual_dir(path) {
            Some(ResolvedPath::VirtualDir {
                sandbox_path: path.clone(),
            })
        } else {
            None
        }
    }

    pub fn is_virtual_dir(&self, path: &SandboxPath) -> bool {
        if path.as_path() == Path::new("/") {
            return true;
        }
        self.layers
            .iter()
            .any(|layer| layer.on_fs.starts_with(path) && &layer.on_fs != path)
    }

    pub fn children(&self, dir: &SandboxPath) -> Result<BTreeMap<String, ResolvedPath>> {
        if self.is_hidden(dir) {
            return Err(Error::msg(format!("{dir} is hidden")));
        }
        let mut children = BTreeMap::new();
        let mut covered_by_layer = false;

        for layer in &self.layers {
            if layer.on_fs == *dir || dir.starts_with(&layer.on_fs) {
                covered_by_layer = true;
            }
            if layer.on_fs.starts_with(dir) && &layer.on_fs != dir {
                let rest = layer.on_fs.strip_prefix(dir)?;
                if let Some(first) = rest.components().next() {
                    let name = first.as_os_str().to_string_lossy().into_owned();
                    let child = dir.join(&name)?;
                    if !self.is_hidden(&child) {
                        children.insert(
                            name,
                            ResolvedPath::VirtualDir {
                                sandbox_path: child,
                            },
                        );
                    }
                }
            }
        }

        if let Some(ResolvedPath::Real { local_path, .. }) = self.resolve(dir) {
            if local_path.is_dir() {
                for entry in std::fs::read_dir(&local_path)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let child = dir.join(&name)?;
                    if !self.is_hidden(&child)
                        && let Some(resolved) = self.resolve(&child)
                    {
                        children.insert(name, resolved);
                    }
                }
            }
        } else if !covered_by_layer && !self.is_virtual_dir(dir) {
            return Err(Error::msg(format!("{dir} does not exist")));
        }

        Ok(children)
    }

    pub fn apply_metadata_override(&mut self, op: &MetadataOperation) -> Result<()> {
        let path = op.path().clone();
        if self.resolve(&path).is_none() {
            return Err(Error::msg(format!("path not found: {path}")));
        }
        let entry = self.metadata.entry(path).or_default();
        match op {
            MetadataOperation::Chmod { mode, .. } => entry.mode = Some(*mode),
            MetadataOperation::Chown { uid, gid, .. } => {
                if let Some(uid) = uid {
                    entry.uid = Some(*uid);
                }
                if let Some(gid) = gid {
                    entry.gid = Some(*gid);
                }
            }
            MetadataOperation::Chattr { flags, .. } => entry.flags = Some(*flags),
            MetadataOperation::SetAttr {
                mode,
                uid,
                gid,
                flags,
                ..
            } => {
                if let Some(mode) = mode {
                    entry.mode = Some(*mode);
                }
                if let Some(uid) = uid {
                    entry.uid = Some(*uid);
                }
                if let Some(gid) = gid {
                    entry.gid = Some(*gid);
                }
                if let Some(flags) = flags {
                    entry.flags = Some(*flags);
                }
            }
        }
        Ok(())
    }

    pub fn metadata_differences(&self) -> Vec<SandboxPath> {
        self.metadata
            .iter()
            .filter_map(|(path, value)| {
                if value.is_empty() {
                    None
                } else {
                    Some(path.clone())
                }
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct SandboxRegistry {
    pub sandboxes: HashMap<String, Sandbox>,
    pub pending: BTreeMap<u64, PendingMetadataRequest>,
    pub pending_waiters: HashMap<u64, PendingWaiter>,
    pub trusted: HashMap<String, TrustedOperation>,
    pub next_operation_id: u64,
}

impl SandboxRegistry {
    pub fn new() -> Self {
        Self {
            next_operation_id: 1,
            ..Self::default()
        }
    }

    pub fn next_operation_id(&mut self) -> u64 {
        let id = self.next_operation_id;
        self.next_operation_id += 1;
        id
    }

    pub fn attach_index(&self) -> HashSet<PathBuf> {
        self.sandboxes
            .values()
            .flat_map(|sandbox| sandbox.attaches.keys().cloned())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub kind: FileType,
    pub ino: u64,
}

pub fn stable_ino(path: &SandboxPath) -> INodeNo {
    if path.as_path() == Path::new("/") {
        return INodeNo(ROOT_INO);
    }
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in path.as_str().as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    INodeNo(FIRST_DYNAMIC_INO + (hash & 0x000f_ffff_ffff_ffff))
}

pub fn mode_to_kind(mode: u32, metadata_file_type: std::fs::FileType) -> FileType {
    if metadata_file_type.is_dir() {
        FileType::Directory
    } else if metadata_file_type.is_symlink() {
        FileType::Symlink
    } else if metadata_file_type.is_file() {
        FileType::RegularFile
    } else {
        match mode & libc::S_IFMT {
            libc::S_IFDIR => FileType::Directory,
            libc::S_IFLNK => FileType::Symlink,
            libc::S_IFREG => FileType::RegularFile,
            libc::S_IFIFO => FileType::NamedPipe,
            libc::S_IFSOCK => FileType::Socket,
            libc::S_IFCHR => FileType::CharDevice,
            libc::S_IFBLK => FileType::BlockDevice,
            _ => FileType::RegularFile,
        }
    }
}

pub fn virtual_dir_attr(path: &SandboxPath) -> FileAttr {
    let now = SystemTime::UNIX_EPOCH;
    FileAttr {
        ino: stable_ino(path),
        size: 0,
        blocks: 0,
        atime: now,
        mtime: now,
        ctime: now,
        crtime: now,
        kind: FileType::Directory,
        perm: VIRTUAL_DIR_MODE,
        nlink: 2,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        rdev: 0,
        blksize: 4096,
        flags: FS_IMMUTABLE_FL,
    }
}

#[allow(clippy::cast_possible_truncation)]
pub fn apply_override(mut attr: FileAttr, override_: Option<&MetadataOverride>) -> FileAttr {
    if let Some(override_) = override_ {
        if let Some(mode) = override_.mode {
            attr.perm = mode;
        }
        if let Some(uid) = override_.uid {
            attr.uid = uid;
        }
        if let Some(gid) = override_.gid {
            attr.gid = gid;
        }
        if let Some(flags) = override_.flags {
            attr.flags = flags;
        }
    }
    attr
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn later_layers_override_earlier_layers() {
        let t1 = TempDir::new().unwrap();
        let t2 = TempDir::new().unwrap();
        std::fs::write(t1.path().join("x"), "one").unwrap();
        std::fs::write(t2.path().join("x"), "two").unwrap();
        let mut s = Sandbox::new("s", t1.path().join("s.log"));
        s.add_layer(t1.path(), SandboxPath::new("/a").unwrap());
        s.add_layer(t2.path(), SandboxPath::new("/a").unwrap());
        match s.resolve(&SandboxPath::new("/a/x").unwrap()).unwrap() {
            ResolvedPath::Real { local_path, .. } => {
                assert_eq!(std::fs::read_to_string(local_path).unwrap(), "two")
            }
            _ => panic!("expected real"),
        }
    }

    #[test]
    fn hide_is_overridden_by_newer_layer() {
        let t1 = TempDir::new().unwrap();
        let t2 = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", t1.path().join("s.log"));
        s.add_layer(t1.path(), SandboxPath::new("/a").unwrap());
        s.add_hide(SandboxPath::new("/a").unwrap());
        assert!(s.resolve(&SandboxPath::new("/a").unwrap()).is_none());
        s.add_layer(t2.path(), SandboxPath::new("/a").unwrap());
        assert!(s.resolve(&SandboxPath::new("/a").unwrap()).is_some());
    }

    #[test]
    fn virtual_dirs_exist_for_missing_intermediate_mount_dirs() {
        let t1 = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", t1.path().join("s.log"));
        s.add_layer(t1.path(), SandboxPath::new("/a/b/c").unwrap());
        assert!(matches!(
            s.resolve(&SandboxPath::new("/a").unwrap()),
            Some(ResolvedPath::VirtualDir { .. })
        ));
        assert!(matches!(
            s.resolve(&SandboxPath::new("/a/b").unwrap()),
            Some(ResolvedPath::VirtualDir { .. })
        ));
    }

    #[test]
    fn metadata_override_tracks_differences() {
        let t1 = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", t1.path().join("s.log"));
        s.add_layer(t1.path(), SandboxPath::new("/a").unwrap());
        s.apply_metadata_override(&MetadataOperation::Chmod {
            path: SandboxPath::new("/a").unwrap(),
            mode: 0o444,
        })
        .unwrap();
        assert_eq!(
            s.metadata_differences(),
            vec![SandboxPath::new("/a").unwrap()]
        );
    }
}
