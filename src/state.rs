//! In-memory sandbox data model and overlay resolution.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionKind {
    Read,
    Write,
}

impl ProtectionKind {
    pub fn log_name(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

impl std::fmt::Display for ProtectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.log_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionRule {
    pub kind: ProtectionKind,
    pub pattern: SandboxPath,
}

impl ProtectionRule {
    pub fn matches(&self, path: &SandboxPath) -> bool {
        protected_pattern_matches(&self.pattern, path)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionRuleResult {
    Added,
    AlreadyPresent,
    Removed,
    NotPresent,
}

impl ProtectionRuleResult {
    pub fn log_name(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::AlreadyPresent => "already-present",
            Self::Removed => "removed",
            Self::NotPresent => "not-present",
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingOperationKind {
    Mode,
    Uid,
    Gid,
    Flags,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingOperationKey {
    pub sandbox: String,
    pub path: SandboxPath,
    pub kind: PendingOperationKind,
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

    pub fn pending_kinds(&self) -> Vec<PendingOperationKind> {
        let mut kinds = Vec::new();
        match self {
            Self::Chmod { .. } => kinds.push(PendingOperationKind::Mode),
            Self::Chown { uid, gid, .. } => {
                if uid.is_some() {
                    kinds.push(PendingOperationKind::Uid);
                }
                if gid.is_some() {
                    kinds.push(PendingOperationKind::Gid);
                }
            }
            Self::Chattr { .. } => kinds.push(PendingOperationKind::Flags),
            Self::SetAttr {
                mode,
                uid,
                gid,
                flags,
                ..
            } => {
                if mode.is_some() {
                    kinds.push(PendingOperationKind::Mode);
                }
                if uid.is_some() {
                    kinds.push(PendingOperationKind::Uid);
                }
                if gid.is_some() {
                    kinds.push(PendingOperationKind::Gid);
                }
                if flags.is_some() {
                    kinds.push(PendingOperationKind::Flags);
                }
            }
        }
        kinds
    }

    pub fn pending_keys(&self, sandbox: &str) -> Vec<PendingOperationKey> {
        self.pending_kinds()
            .into_iter()
            .map(|kind| PendingOperationKey {
                sandbox: sandbox.to_string(),
                path: self.path().clone(),
                kind,
            })
            .collect()
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
    pub kinds: Vec<PendingOperationKind>,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub description: String,
}

impl PendingMetadataRequest {
    pub fn keys(&self) -> Vec<PendingOperationKey> {
        self.kinds
            .iter()
            .copied()
            .map(|kind| PendingOperationKey {
                sandbox: self.sandbox.clone(),
                path: self.operation.path().clone(),
                kind,
            })
            .collect()
    }
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
    pub protection_rules: Vec<ProtectionRule>,
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
            protection_rules: Vec::new(),
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

    pub fn protect(&mut self, kind: ProtectionKind, pattern: SandboxPath) -> ProtectionRuleResult {
        if self
            .protection_rules
            .iter()
            .any(|rule| rule.kind == kind && rule.pattern == pattern)
        {
            return ProtectionRuleResult::AlreadyPresent;
        }
        self.protection_rules.push(ProtectionRule { kind, pattern });
        ProtectionRuleResult::Added
    }

    pub fn unprotect(
        &mut self,
        kind: ProtectionKind,
        pattern: &SandboxPath,
    ) -> ProtectionRuleResult {
        let Some(index) = self
            .protection_rules
            .iter()
            .position(|rule| rule.kind == kind && &rule.pattern == pattern)
        else {
            return ProtectionRuleResult::NotPresent;
        };
        self.protection_rules.remove(index);
        ProtectionRuleResult::Removed
    }

    pub fn protection_rules(&self, include_read: bool, include_write: bool) -> Vec<ProtectionRule> {
        let include_all = !include_read && !include_write;
        let include_read = include_read || include_all;
        let include_write = include_write || include_all;
        let mut rules: Vec<ProtectionRule> = self
            .protection_rules
            .iter()
            .filter(|rule| match rule.kind {
                ProtectionKind::Read => include_read,
                ProtectionKind::Write => include_write,
            })
            .cloned()
            .collect();
        rules.sort_by(|left, right| {
            left.pattern
                .cmp(&right.pattern)
                .then_with(|| left.kind.cmp(&right.kind))
        });
        rules
    }

    pub fn is_protected(&self, kind: ProtectionKind, path: &SandboxPath) -> bool {
        self.protection_rules
            .iter()
            .any(|rule| rule.kind == kind && rule.matches(path))
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
    pub pending_index: BTreeMap<PendingOperationKey, u64>,
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

    pub fn insert_pending_request(&mut self, request: PendingMetadataRequest) {
        for key in request.keys() {
            self.pending_index.insert(key, request.id);
        }
        self.pending.insert(request.id, request);
    }

    pub fn remove_pending_request(&mut self, id: u64) -> Option<PendingMetadataRequest> {
        let request = self.pending.remove(&id)?;
        for key in request.keys() {
            if self.pending_index.get(&key) == Some(&id) {
                self.pending_index.remove(&key);
            }
        }
        Some(request)
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

fn protected_pattern_matches(pattern: &SandboxPath, path: &SandboxPath) -> bool {
    let pattern_components = sandbox_path_components(pattern);
    let path_components = sandbox_path_components(path);
    if matches_pattern_components(&pattern_components, &path_components) {
        return true;
    }
    if matches!(
        pattern_components.last().map(String::as_str),
        Some("*") | Some("**")
    ) && pattern_components[..pattern_components.len() - 1] == path_components[..]
    {
        return true;
    }
    false
}

fn sandbox_path_components(path: &SandboxPath) -> Vec<String> {
    path.as_path()
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect()
}

fn matches_pattern_components(pattern: &[String], path: &[String]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        Some((head, rest)) if head == "**" => {
            (0..=path.len()).any(|skip| matches_pattern_components(rest, &path[skip..]))
        }
        Some((head, rest)) => {
            if let Some((path_head, path_rest)) = path.split_first() {
                component_pattern_matches(head, path_head)
                    && matches_pattern_components(rest, path_rest)
            } else {
                false
            }
        }
    }
}

fn component_pattern_matches(pattern: &str, value: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == value;
    }
    let mut remainder = value;
    let mut parts = pattern.split('*').peekable();
    let first = parts.next().unwrap_or_default();
    if !first.is_empty() {
        let Some(stripped) = remainder.strip_prefix(first) else {
            return false;
        };
        remainder = stripped;
    }
    while let Some(part) = parts.next() {
        if part.is_empty() {
            continue;
        }
        if parts.peek().is_none() {
            return remainder.ends_with(part);
        }
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }
    true
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
    fn virtual_dirs_disappear_after_last_nested_mount_is_removed() {
        let t1 = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", t1.path().join("s.log"));
        s.add_layer(t1.path(), SandboxPath::new("/a/b/c").unwrap());

        assert!(s.remove_layer(&SandboxPath::new("/a/b/c").unwrap()));
        assert!(s.resolve(&SandboxPath::new("/a").unwrap()).is_none());
        assert!(s.resolve(&SandboxPath::new("/a/b").unwrap()).is_none());
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

    #[test]
    fn protection_pattern_matching_uses_exact_single_component_and_recursive_globs() {
        let mut s = Sandbox::new("s", TempDir::new().unwrap().path().join("s.log"));
        s.protect(ProtectionKind::Read, SandboxPath::new("/secret").unwrap());
        s.protect(
            ProtectionKind::Write,
            SandboxPath::new("/direct/*").unwrap(),
        );
        s.protect(ProtectionKind::Read, SandboxPath::new("/tree/**").unwrap());
        s.protect(
            ProtectionKind::Read,
            SandboxPath::new("/glob/*.txt").unwrap(),
        );

        assert!(s.is_protected(ProtectionKind::Read, &SandboxPath::new("/secret").unwrap()));
        assert!(!s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/secret/file").unwrap()
        ));
        assert!(s.is_protected(ProtectionKind::Write, &SandboxPath::new("/direct").unwrap()));
        assert!(s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/direct/file").unwrap()
        ));
        assert!(!s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/direct/a/b").unwrap()
        ));
        assert!(s.is_protected(ProtectionKind::Read, &SandboxPath::new("/tree").unwrap()));
        assert!(s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/tree/a/b").unwrap()
        ));
        assert!(s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/glob/a.txt").unwrap()
        ));
        assert!(!s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/glob/a.md").unwrap()
        ));
    }

    #[test]
    fn protection_rules_are_idempotent_and_removed_by_exact_kind_and_pattern() {
        let mut s = Sandbox::new("s", TempDir::new().unwrap().path().join("s.log"));
        let pattern = SandboxPath::new("/secret/**").unwrap();

        assert_eq!(
            s.protect(ProtectionKind::Read, pattern.clone()),
            ProtectionRuleResult::Added
        );
        assert_eq!(
            s.protect(ProtectionKind::Read, pattern.clone()),
            ProtectionRuleResult::AlreadyPresent
        );
        assert_eq!(
            s.protect(ProtectionKind::Write, pattern.clone()),
            ProtectionRuleResult::Added
        );
        assert_eq!(s.protection_rules.len(), 2);
        assert_eq!(
            s.unprotect(
                ProtectionKind::Read,
                &SandboxPath::new("/secret/*").unwrap()
            ),
            ProtectionRuleResult::NotPresent
        );
        assert_eq!(
            s.unprotect(ProtectionKind::Read, &pattern),
            ProtectionRuleResult::Removed
        );
        assert_eq!(
            s.unprotect(ProtectionKind::Read, &pattern),
            ProtectionRuleResult::NotPresent
        );
        assert_eq!(s.protection_rules.len(), 1);
        assert!(s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/secret/file").unwrap()
        ));
    }

    #[test]
    fn protection_list_is_filtered_and_sorted_for_display() {
        let mut s = Sandbox::new("s", TempDir::new().unwrap().path().join("s.log"));
        s.protect(ProtectionKind::Write, SandboxPath::new("/b").unwrap());
        s.protect(ProtectionKind::Write, SandboxPath::new("/a").unwrap());
        s.protect(ProtectionKind::Read, SandboxPath::new("/b").unwrap());
        s.protect(ProtectionKind::Read, SandboxPath::new("/a").unwrap());

        let all = s.protection_rules(false, false);
        assert_eq!(
            all.iter()
                .map(|rule| (rule.kind, rule.pattern.to_string()))
                .collect::<Vec<_>>(),
            vec![
                (ProtectionKind::Read, "/a".to_string()),
                (ProtectionKind::Write, "/a".to_string()),
                (ProtectionKind::Read, "/b".to_string()),
                (ProtectionKind::Write, "/b".to_string()),
            ]
        );

        assert_eq!(s.protection_rules(true, false).len(), 2);
        assert_eq!(s.protection_rules(false, true).len(), 2);
        assert_eq!(s.protection_rules(true, true), all);
    }
}
