//! In-memory sandbox data model and overlay resolution.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType, INodeNo};
use serde::{Deserialize, Serialize};

use crate::overlay::{OverlayEffect, collapse_latest};
use crate::path::SandboxPath;
use crate::process_info::ProcessIdentityEvidence;
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
    Metadata,
}

impl ProtectionKind {
    pub fn log_name(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
            Self::Metadata => "METADATA",
        }
    }
}

impl std::fmt::Display for ProtectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.log_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PolicyPattern {
    raw: String,
    directory_only: bool,
}

impl PolicyPattern {
    pub fn new(pattern: impl AsRef<str>) -> Result<Self> {
        let raw = normalize_policy_pattern(pattern.as_ref())?;
        glob::Pattern::new(&glob_pattern_for_match(&raw))
            .map_err(|err| Error::msg(format!("invalid glob pattern {raw}: {err}")))?;
        let directory_only = raw != "/" && raw.ends_with('/');
        Ok(Self {
            raw,
            directory_only,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn matches(&self, path: &SandboxPath, target_is_dir: bool) -> bool {
        if self.directory_only && !target_is_dir {
            return false;
        }
        let Ok(pattern) = glob::Pattern::new(&glob_pattern_for_match(&self.raw)) else {
            return false;
        };
        pattern.matches_path_with(
            path.as_path(),
            glob::MatchOptions {
                case_sensitive: true,
                require_literal_separator: true,
                require_literal_leading_dot: false,
            },
        )
    }
}

impl std::fmt::Display for PolicyPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

impl FromStr for PolicyPattern {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl From<PolicyPattern> for String {
    fn from(pattern: PolicyPattern) -> Self {
        pattern.raw
    }
}

impl TryFrom<String> for PolicyPattern {
    type Error = Error;

    fn try_from(pattern: String) -> Result<Self> {
        Self::new(pattern)
    }
}

impl From<SandboxPath> for PolicyPattern {
    fn from(path: SandboxPath) -> Self {
        Self {
            raw: path.to_string(),
            directory_only: false,
        }
    }
}

impl From<&SandboxPath> for PolicyPattern {
    fn from(path: &SandboxPath) -> Self {
        Self {
            raw: path.to_string(),
            directory_only: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionRule {
    pub kind: ProtectionKind,
    pub pattern: PolicyPattern,
}

impl ProtectionRule {
    pub fn matches(&self, path: &SandboxPath, target_is_dir: bool) -> bool {
        self.pattern.matches(path, target_is_dir)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassthroughRule {
    pub kind: ProtectionKind,
    pub pattern: PolicyPattern,
}

impl PassthroughRule {
    pub fn matches(&self, path: &SandboxPath, target_is_dir: bool) -> bool {
        self.pattern.matches(path, target_is_dir)
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ReadWriteOperation {
    ReadFile { path: SandboxPath },
    ReadDirectory { path: SandboxPath },
    OpenWrite { path: SandboxPath },
    WriteFile { path: SandboxPath },
    Truncate { path: SandboxPath },
    Create { path: SandboxPath },
    Mkdir { path: SandboxPath },
    Mknod { path: SandboxPath },
    Symlink { path: SandboxPath },
    Link { from: SandboxPath, to: SandboxPath },
    Unlink { path: SandboxPath },
    Rmdir { path: SandboxPath },
    Rename { from: SandboxPath, to: SandboxPath },
}

impl ReadWriteOperation {
    pub fn kind(&self) -> ProtectionKind {
        match self {
            Self::ReadFile { .. } | Self::ReadDirectory { .. } => ProtectionKind::Read,
            Self::OpenWrite { .. }
            | Self::WriteFile { .. }
            | Self::Truncate { .. }
            | Self::Create { .. }
            | Self::Mkdir { .. }
            | Self::Mknod { .. }
            | Self::Symlink { .. }
            | Self::Link { .. }
            | Self::Unlink { .. }
            | Self::Rmdir { .. }
            | Self::Rename { .. } => ProtectionKind::Write,
        }
    }

    pub fn path(&self) -> &SandboxPath {
        match self {
            Self::ReadFile { path }
            | Self::ReadDirectory { path }
            | Self::OpenWrite { path }
            | Self::WriteFile { path }
            | Self::Truncate { path }
            | Self::Create { path }
            | Self::Mkdir { path }
            | Self::Mknod { path }
            | Self::Symlink { path }
            | Self::Unlink { path }
            | Self::Rmdir { path } => path,
            Self::Link { from, .. } | Self::Rename { from, .. } => from,
        }
    }

    pub fn protection_paths(&self) -> Vec<&SandboxPath> {
        match self {
            Self::Link { from, to } | Self::Rename { from, to } => vec![from, to],
            _ => vec![self.path()],
        }
    }

    pub fn description(&self) -> String {
        self.event_body()
    }

    pub fn event_body(&self) -> String {
        match self {
            Self::ReadFile { path } => format!("path={path} READ file"),
            Self::ReadDirectory { path } => format!("path={path} READ directory"),
            Self::OpenWrite { path } => format!("path={path} WRITE open"),
            Self::WriteFile { path } => format!("path={path} WRITE data"),
            Self::Truncate { path } => format!("path={path} WRITE truncate"),
            Self::Create { path } => format!("path={path} WRITE create"),
            Self::Mkdir { path } => format!("path={path} WRITE mkdir"),
            Self::Mknod { path } => format!("path={path} WRITE mknod"),
            Self::Symlink { path } => format!("path={path} WRITE symlink"),
            Self::Link { from, to } => format!("path={from} WRITE link to={to}"),
            Self::Unlink { path } => format!("path={path} WRITE unlink"),
            Self::Rmdir { path } => format!("path={path} WRITE rmdir"),
            Self::Rename { from, to } => format!("path={from} WRITE rename to={to}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MetadataObjectKey {
    pub layer_id: u64,
    pub relative_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataEntry {
    pub sandbox_path: SandboxPath,
    pub override_: MetadataOverride,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataOverride {
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub flags: Option<u32>,
    pub atime: Option<SystemTime>,
    pub mtime: Option<SystemTime>,
}

impl MetadataOverride {
    pub fn is_empty(&self) -> bool {
        self.mode.is_none()
            && self.uid.is_none()
            && self.gid.is_none()
            && self.flags.is_none()
            && self.atime.is_none()
            && self.mtime.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingOperationKind {
    Mode,
    Uid,
    Gid,
    Flags,
    Times,
    Xattr,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingOperationKey {
    pub sandbox: String,
    pub object: MetadataObjectKey,
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
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    },
    SetXattr {
        path: SandboxPath,
        name: String,
    },
    RemoveXattr {
        path: SandboxPath,
        name: String,
    },
}

impl MetadataOperation {
    pub fn path(&self) -> &SandboxPath {
        match self {
            Self::Chmod { path, .. }
            | Self::Chown { path, .. }
            | Self::Chattr { path, .. }
            | Self::SetAttr { path, .. }
            | Self::SetXattr { path, .. }
            | Self::RemoveXattr { path, .. } => path,
        }
    }

    pub fn description(&self) -> String {
        self.event_body()
    }

    pub fn event_body(&self) -> String {
        match self {
            Self::Chmod { path, mode } => format!("path={path} SETATTR mode={mode:04o}"),
            Self::Chown { path, uid, gid } => {
                format_setattr_body(path, None, *uid, *gid, None, None, None)
            }
            Self::Chattr { path, flags } => format!("path={path} CHATTR flags=0x{flags:x}"),
            Self::SetXattr { path, name } => format!("path={path} SETXATTR name={name}"),
            Self::RemoveXattr { path, name } => format!("path={path} REMOVEXATTR name={name}"),
            Self::SetAttr {
                path,
                mode,
                uid,
                gid,
                flags,
                atime,
                mtime,
            } => format_setattr_body(path, *mode, *uid, *gid, *flags, *atime, *mtime),
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
            Self::SetXattr { .. } | Self::RemoveXattr { .. } => {
                kinds.push(PendingOperationKind::Xattr);
            }
            Self::SetAttr {
                mode,
                uid,
                gid,
                flags,
                atime,
                mtime,
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
                if atime.is_some() || mtime.is_some() {
                    kinds.push(PendingOperationKind::Times);
                }
            }
        }
        kinds
    }

    pub fn shell_hint(&self) -> String {
        match self {
            Self::Chmod { path, mode } => format!("chmod {:o} {}", mode, path),
            Self::Chown { path, uid, gid } => format_chown_shell_hint(path, *uid, *gid),
            Self::Chattr { path, flags } => format!("chattr flags=0x{flags:x} {path}"),
            Self::SetXattr { path, name } => format!("setfattr -n {name} {path}"),
            Self::RemoveXattr { path, name } => format!("setfattr -x {name} {path}"),
            Self::SetAttr {
                path,
                mode,
                uid,
                gid,
                flags,
                atime,
                mtime,
            } => match (mode, uid, gid, flags, atime, mtime) {
                (Some(mode), None, None, None, None, None) => format!("chmod {:o} {}", mode, path),
                (None, Some(uid), None, None, None, None) => {
                    format_chown_shell_hint(path, Some(*uid), None)
                }
                (None, None, Some(gid), None, None, None) => {
                    format_chown_shell_hint(path, None, Some(*gid))
                }
                (None, Some(uid), Some(gid), None, None, None) => {
                    format_chown_shell_hint(path, Some(*uid), Some(*gid))
                }
                (None, None, None, Some(flags), None, None) => {
                    format!("chattr flags=0x{flags:x} {path}")
                }
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
    atime: Option<SystemTime>,
    mtime: Option<SystemTime>,
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
    if atime.is_some() {
        fields.push("atime=<set>".to_string());
    }
    if mtime.is_some() {
        fields.push("mtime=<set>".to_string());
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
#[serde(
    from = "SerializedPendingMetadataRequest",
    into = "SerializedPendingMetadataRequest"
)]
pub struct PendingMetadataRequest {
    pub id: u64,
    pub sandbox: String,
    pub attach_id: Option<u64>,
    pub operation: MetadataOperation,
    pub object: MetadataObjectKey,
    pub kinds: Vec<PendingOperationKind>,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedPendingMetadataRequest {
    pub id: u64,
    pub sandbox: String,
    pub attach_id: Option<u64>,
    pub operation: MetadataOperation,
    pub kinds: Vec<PendingOperationKind>,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub description: String,
}

impl From<PendingMetadataRequest> for SerializedPendingMetadataRequest {
    fn from(request: PendingMetadataRequest) -> Self {
        Self {
            id: request.id,
            sandbox: request.sandbox,
            attach_id: request.attach_id,
            operation: request.operation,
            kinds: request.kinds,
            pid: request.pid,
            uid: request.uid,
            gid: request.gid,
            description: request.description,
        }
    }
}

impl From<SerializedPendingMetadataRequest> for PendingMetadataRequest {
    fn from(request: SerializedPendingMetadataRequest) -> Self {
        let object = MetadataObjectKey {
            layer_id: 0,
            relative_path: PathBuf::new(),
        };
        Self {
            id: request.id,
            sandbox: request.sandbox,
            attach_id: request.attach_id,
            operation: request.operation,
            object,
            kinds: request.kinds,
            pid: request.pid,
            uid: request.uid,
            gid: request.gid,
            description: request.description,
        }
    }
}

impl PendingMetadataRequest {
    pub fn keys(&self) -> Vec<PendingOperationKey> {
        pending_metadata_keys(&self.sandbox, &self.object, &self.kinds)
    }
}

pub fn pending_metadata_keys(
    sandbox: &str,
    object: &MetadataObjectKey,
    kinds: &[PendingOperationKind],
) -> Vec<PendingOperationKey> {
    kinds
        .iter()
        .copied()
        .map(|kind| PendingOperationKey {
            sandbox: sandbox.to_string(),
            object: object.clone(),
            kind,
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequesterIdentity {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReadWriteRequest {
    pub id: u64,
    pub sandbox: String,
    pub attach_id: Option<u64>,
    pub operation: ReadWriteOperation,
    pub kind: ProtectionKind,
    pub path: SandboxPath,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub process_identity: Option<ProcessIdentityEvidence>,
    pub description: String,
}

impl PendingReadWriteRequest {
    pub fn new(
        id: u64,
        sandbox: String,
        operation: ReadWriteOperation,
        pid: u32,
        uid: u32,
        gid: u32,
    ) -> Self {
        let path = operation.path().clone();
        Self::new_with_path(id, sandbox, operation, path, pid, uid, gid)
    }

    pub fn new_with_path(
        id: u64,
        sandbox: String,
        operation: ReadWriteOperation,
        path: SandboxPath,
        pid: u32,
        uid: u32,
        gid: u32,
    ) -> Self {
        Self::new_with_attach_path(
            id,
            sandbox,
            None,
            operation,
            path,
            RequesterIdentity { pid, uid, gid },
        )
    }

    pub fn new_with_attach_path(
        id: u64,
        sandbox: String,
        attach_id: Option<u64>,
        operation: ReadWriteOperation,
        path: SandboxPath,
        requester: RequesterIdentity,
    ) -> Self {
        Self {
            id,
            sandbox,
            attach_id,
            kind: operation.kind(),
            path,
            description: operation.description(),
            operation,
            pid: requester.pid,
            uid: requester.uid,
            gid: requester.gid,
            process_identity: None,
        }
    }

    pub fn with_process_identity(mut self, identity: Option<ProcessIdentityEvidence>) -> Self {
        self.process_identity = identity;
        self
    }
}

pub const DEFAULT_READ_WRITE_GRANT_DURATION: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadWriteGrantLifetimeRequest {
    OneShot,
    Duration { seconds: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadWriteGrantOptions {
    pub path: Option<SandboxPath>,
    pub lifetime: ReadWriteGrantLifetimeRequest,
    pub tree: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadWriteGrantLifetime {
    OneShot,
    Duration { expires_at_epoch_ms: u128 },
}

impl ReadWriteGrantLifetime {
    pub fn log_name(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::Duration { .. } => "duration",
        }
    }

    pub fn is_expired(self, now: SystemTime) -> bool {
        match self {
            Self::OneShot => false,
            Self::Duration {
                expires_at_epoch_ms,
            } => epoch_millis(now) >= expires_at_epoch_ms,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum ReadWriteGrantSubject {
    Exact {
        identity: ProcessIdentityEvidence,
    },
    ProcessTree {
        identities: Vec<ProcessIdentityEvidence>,
    },
}

impl ReadWriteGrantSubject {
    pub fn log_name(&self) -> &'static str {
        match self {
            Self::Exact { .. } => "exact",
            Self::ProcessTree { .. } => "process-tree",
        }
    }

    pub fn matches(&self, identity: Option<ProcessIdentityEvidence>) -> bool {
        let Some(identity) = identity else {
            return false;
        };
        match self {
            Self::Exact { identity: expected } => *expected == identity,
            Self::ProcessTree { identities } => identities.contains(&identity),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Exact { .. } => 1,
            Self::ProcessTree { identities } => identities.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadWriteAccessGrant {
    pub id: u64,
    pub sandbox: String,
    pub kind: ProtectionKind,
    pub path_pattern: SandboxPath,
    pub subject: ReadWriteGrantSubject,
    pub lifetime: ReadWriteGrantLifetime,
    pub created_at_epoch_ms: u128,
}

impl ReadWriteAccessGrant {
    pub fn matches_request(&self, request: &PendingReadWriteRequest, now: SystemTime) -> bool {
        self.sandbox == request.sandbox
            && self.kind == request.kind
            && !self.lifetime.is_expired(now)
            && grant_pattern_matches(&self.path_pattern, &request.path)
            && self.subject.matches(request.process_identity)
    }

    pub fn matches_intent(
        &self,
        sandbox: &str,
        kind: ProtectionKind,
        path: &SandboxPath,
        identity: Option<ProcessIdentityEvidence>,
        now: SystemTime,
    ) -> bool {
        self.sandbox == sandbox
            && self.kind == kind
            && !self.lifetime.is_expired(now)
            && grant_pattern_matches(&self.path_pattern, path)
            && self.subject.matches(identity)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantMatchOutcome {
    Matched { grant_id: u64, consumed: bool },
    NotMatched,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "pending_kind", rename_all = "snake_case")]
pub enum PendingRequest {
    Metadata(PendingMetadataRequest),
    ReadWrite(PendingReadWriteRequest),
}

impl PendingRequest {
    pub fn id(&self) -> u64 {
        match self {
            Self::Metadata(request) => request.id,
            Self::ReadWrite(request) => request.id,
        }
    }

    pub fn sandbox(&self) -> &str {
        match self {
            Self::Metadata(request) => &request.sandbox,
            Self::ReadWrite(request) => &request.sandbox,
        }
    }

    pub fn attach_id(&self) -> Option<u64> {
        match self {
            Self::Metadata(request) => request.attach_id,
            Self::ReadWrite(request) => request.attach_id,
        }
    }

    pub fn path(&self) -> &SandboxPath {
        match self {
            Self::Metadata(request) => request.operation.path(),
            Self::ReadWrite(request) => &request.path,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::Metadata(request) => &request.description,
            Self::ReadWrite(request) => &request.description,
        }
    }

    pub fn metadata_shell_hint(&self) -> Option<String> {
        match self {
            Self::Metadata(request) => Some(request.operation.shell_hint()),
            Self::ReadWrite(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingDecision {
    Apply,
    DoNothing,
    Deny,
    Cancel,
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
    pub id: u64,
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

#[derive(Debug, Clone, Copy)]
enum OverlayEntry<'a> {
    Layer(&'a MountLayer),
    Hide(&'a HideRule),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OverlayResolution {
    Real {
        local_path: PathBuf,
        layer_id: u64,
        sandbox_path: SandboxPath,
    },
    VirtualDir {
        sandbox_path: SandboxPath,
    },
    Hidden,
    Missing,
}

#[derive(Debug, Clone)]
pub struct Sandbox {
    pub name: String,
    pub layers: Vec<MountLayer>,
    pub hides: Vec<HideRule>,
    pub metadata: BTreeMap<MetadataObjectKey, MetadataEntry>,
    pub protection_rules: Vec<ProtectionRule>,
    pub passthrough_rules: Vec<PassthroughRule>,
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
            passthrough_rules: Vec::new(),
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

    pub fn protect(
        &mut self,
        kind: ProtectionKind,
        pattern: impl Into<PolicyPattern>,
    ) -> ProtectionRuleResult {
        let pattern = pattern.into();
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
        pattern: impl Into<PolicyPattern>,
    ) -> ProtectionRuleResult {
        let pattern = pattern.into();
        let Some(index) = self
            .protection_rules
            .iter()
            .position(|rule| rule.kind == kind && rule.pattern == pattern)
        else {
            return ProtectionRuleResult::NotPresent;
        };
        self.protection_rules.remove(index);
        ProtectionRuleResult::Removed
    }

    pub fn add_passthrough(
        &mut self,
        kind: ProtectionKind,
        pattern: impl Into<PolicyPattern>,
    ) -> ProtectionRuleResult {
        let pattern = pattern.into();
        if self
            .passthrough_rules
            .iter()
            .any(|rule| rule.kind == kind && rule.pattern == pattern)
        {
            return ProtectionRuleResult::AlreadyPresent;
        }
        self.passthrough_rules
            .push(PassthroughRule { kind, pattern });
        ProtectionRuleResult::Added
    }

    pub fn remove_passthrough(
        &mut self,
        kind: ProtectionKind,
        pattern: impl Into<PolicyPattern>,
    ) -> ProtectionRuleResult {
        let pattern = pattern.into();
        let Some(index) = self
            .passthrough_rules
            .iter()
            .position(|rule| rule.kind == kind && rule.pattern == pattern)
        else {
            return ProtectionRuleResult::NotPresent;
        };
        self.passthrough_rules.remove(index);
        ProtectionRuleResult::Removed
    }

    pub fn protection_rules(
        &self,
        include_read: bool,
        include_write: bool,
        include_metadata: bool,
    ) -> Vec<ProtectionRule> {
        let include_all = !include_read && !include_write && !include_metadata;
        let include_read = include_read || include_all;
        let include_write = include_write || include_all;
        let include_metadata = include_metadata || include_all;
        let mut rules: Vec<ProtectionRule> = self
            .protection_rules
            .iter()
            .filter(|rule| match rule.kind {
                ProtectionKind::Read => include_read,
                ProtectionKind::Write => include_write,
                ProtectionKind::Metadata => include_metadata,
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

    pub fn passthrough_rules(
        &self,
        include_read: bool,
        include_write: bool,
        include_metadata: bool,
    ) -> Vec<PassthroughRule> {
        let include_all = !include_read && !include_write && !include_metadata;
        let include_read = include_read || include_all;
        let include_write = include_write || include_all;
        let include_metadata = include_metadata || include_all;
        let mut rules: Vec<PassthroughRule> = self
            .passthrough_rules
            .iter()
            .filter(|rule| match rule.kind {
                ProtectionKind::Read => include_read,
                ProtectionKind::Write => include_write,
                ProtectionKind::Metadata => include_metadata,
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

    pub fn is_protected(
        &self,
        kind: ProtectionKind,
        path: &SandboxPath,
        target_is_dir: bool,
    ) -> bool {
        self.protection_rules
            .iter()
            .any(|rule| rule.kind == kind && rule.matches(path, target_is_dir))
    }

    pub fn is_passthrough(
        &self,
        kind: ProtectionKind,
        path: &SandboxPath,
        target_is_dir: bool,
    ) -> bool {
        self.passthrough_rules
            .iter()
            .any(|rule| rule.kind == kind && rule.matches(path, target_is_dir))
    }

    pub fn is_hidden(&self, path: &SandboxPath) -> bool {
        matches!(self.resolve_overlay(path), OverlayResolution::Hidden)
    }

    pub fn resolve(&self, path: &SandboxPath) -> Option<ResolvedPath> {
        match self.resolve_overlay(path) {
            OverlayResolution::Real {
                local_path,
                layer_id,
                sandbox_path,
            } => Some(ResolvedPath::Real {
                local_path,
                layer_id,
                sandbox_path,
            }),
            OverlayResolution::VirtualDir { sandbox_path } => {
                Some(ResolvedPath::VirtualDir { sandbox_path })
            }
            OverlayResolution::Hidden | OverlayResolution::Missing => None,
        }
    }

    pub fn is_virtual_dir(&self, path: &SandboxPath) -> bool {
        matches!(
            self.resolve_overlay(path),
            OverlayResolution::VirtualDir { .. }
        )
    }

    fn resolve_overlay(&self, path: &SandboxPath) -> OverlayResolution {
        if path.as_path() == Path::new("/") {
            if let Some(layer) = self.newest_covering_layer(path) {
                return self.real_resolution(path, layer);
            }
            return OverlayResolution::VirtualDir {
                sandbox_path: path.clone(),
            };
        }

        let newest_covering = self.newest_covering_entry(path);
        let newest_descendant_layer = self.newest_descendant_layer(path);

        match newest_covering {
            Some(OverlayEntry::Layer(layer)) => self.real_resolution(path, layer),
            Some(OverlayEntry::Hide(hide)) => {
                if newest_descendant_layer.is_some_and(|layer| layer.id > hide.id) {
                    OverlayResolution::VirtualDir {
                        sandbox_path: path.clone(),
                    }
                } else {
                    OverlayResolution::Hidden
                }
            }
            None => {
                if newest_descendant_layer.is_some() {
                    OverlayResolution::VirtualDir {
                        sandbox_path: path.clone(),
                    }
                } else {
                    OverlayResolution::Missing
                }
            }
        }
    }

    fn real_resolution(&self, path: &SandboxPath, layer: &MountLayer) -> OverlayResolution {
        let Ok(rest) = path.strip_prefix(&layer.on_fs) else {
            return OverlayResolution::Missing;
        };
        OverlayResolution::Real {
            local_path: layer.local.join(rest),
            layer_id: layer.id,
            sandbox_path: path.clone(),
        }
    }

    fn newest_covering_entry(&self, path: &SandboxPath) -> Option<OverlayEntry<'_>> {
        let layer_entries = self
            .layers
            .iter()
            .filter(|layer| path.starts_with(&layer.on_fs))
            .map(|layer| (layer.id, OverlayEffect::Value(OverlayEntry::Layer(layer))));
        let hide_entries = self
            .hides
            .iter()
            .filter(|hide| path.starts_with(&hide.path))
            .map(|hide| (hide.id, OverlayEffect::Value(OverlayEntry::Hide(hide))));
        collapse_latest(layer_entries.chain(hide_entries))
    }

    fn newest_covering_layer(&self, path: &SandboxPath) -> Option<&MountLayer> {
        self.layers
            .iter()
            .filter(|layer| path.starts_with(&layer.on_fs))
            .max_by_key(|layer| layer.id)
    }

    fn newest_descendant_layer(&self, path: &SandboxPath) -> Option<&MountLayer> {
        self.layers
            .iter()
            .filter(|layer| layer.on_fs.starts_with(path) && &layer.on_fs != path)
            .max_by_key(|layer| layer.id)
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

    pub fn metadata_object_key(&self, path: &SandboxPath) -> Option<MetadataObjectKey> {
        match self.resolve(path)? {
            ResolvedPath::Real { layer_id, .. } => {
                let layer = self.layers.iter().find(|layer| layer.id == layer_id)?;
                let relative_path = path.strip_prefix(&layer.on_fs).ok()?;
                Some(MetadataObjectKey {
                    layer_id,
                    relative_path,
                })
            }
            ResolvedPath::VirtualDir { .. } => None,
        }
    }

    pub fn path_is_directory(&self, path: &SandboxPath) -> bool {
        match self.resolve(path) {
            Some(ResolvedPath::VirtualDir { .. }) => true,
            Some(ResolvedPath::Real { local_path, .. }) => local_path.is_dir(),
            None => false,
        }
    }

    pub fn metadata_override_for_path(&self, path: &SandboxPath) -> Option<MetadataOverride> {
        let key = self.metadata_object_key(path)?;
        let entries = self
            .metadata
            .iter()
            .filter(|(entry_key, _)| *entry_key == &key)
            .map(|(entry_key, entry)| {
                (
                    entry_key.layer_id,
                    OverlayEffect::Value(entry.override_.clone()),
                )
            });
        collapse_latest(entries)
    }

    pub fn apply_metadata_override(&mut self, op: &MetadataOperation) -> Result<()> {
        let path = op.path().clone();
        let key = self
            .metadata_object_key(&path)
            .ok_or_else(|| Error::msg(format!("path not found or not real: {path}")))?;
        self.apply_metadata_override_to_object(key, path, op)
    }

    pub fn apply_metadata_override_to_object(
        &mut self,
        key: MetadataObjectKey,
        sandbox_path: SandboxPath,
        op: &MetadataOperation,
    ) -> Result<()> {
        if !self.layers.iter().any(|layer| layer.id == key.layer_id) {
            return Err(Error::msg(format!(
                "metadata layer not found for path: {sandbox_path}"
            )));
        }
        let entry = self.metadata.entry(key).or_insert_with(|| MetadataEntry {
            sandbox_path,
            override_: MetadataOverride::default(),
        });
        entry.sandbox_path = op.path().clone();
        let override_ = &mut entry.override_;
        match op {
            MetadataOperation::Chmod { mode, .. } => override_.mode = Some(*mode),
            MetadataOperation::Chown { uid, gid, .. } => {
                if let Some(uid) = uid {
                    override_.uid = Some(*uid);
                }
                if let Some(gid) = gid {
                    override_.gid = Some(*gid);
                }
            }
            MetadataOperation::Chattr { flags, .. } => override_.flags = Some(*flags),
            MetadataOperation::SetXattr { .. } | MetadataOperation::RemoveXattr { .. } => {}
            MetadataOperation::SetAttr {
                mode,
                uid,
                gid,
                flags,
                atime,
                mtime,
                ..
            } => {
                if let Some(mode) = mode {
                    override_.mode = Some(*mode);
                }
                if let Some(uid) = uid {
                    override_.uid = Some(*uid);
                }
                if let Some(gid) = gid {
                    override_.gid = Some(*gid);
                }
                if let Some(flags) = flags {
                    override_.flags = Some(*flags);
                }
                if let Some(atime) = atime {
                    override_.atime = Some(*atime);
                }
                if let Some(mtime) = mtime {
                    override_.mtime = Some(*mtime);
                }
            }
        }
        Ok(())
    }

    pub fn metadata_differences(&self) -> Vec<SandboxPath> {
        self.metadata
            .iter()
            .filter_map(|(key, entry)| {
                if entry.override_.is_empty()
                    || self.metadata_object_key(&entry.sandbox_path).as_ref() != Some(key)
                {
                    None
                } else {
                    Some(entry.sandbox_path.clone())
                }
            })
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct SandboxRegistry {
    pub sandboxes: HashMap<String, Sandbox>,
    pub pending: BTreeMap<u64, PendingMetadataRequest>,
    pub pending_read_write: BTreeMap<u64, PendingReadWriteRequest>,
    pub pending_waiters: HashMap<u64, PendingWaiter>,
    pub pending_index: BTreeMap<PendingOperationKey, u64>,
    pub trusted: HashMap<String, TrustedOperation>,
    pub read_write_grants: BTreeMap<u64, ReadWriteAccessGrant>,
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

    pub fn insert_pending_read_write_request(&mut self, request: PendingReadWriteRequest) {
        self.pending_read_write.insert(request.id, request);
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

    pub fn remove_pending_read_write_request(
        &mut self,
        id: u64,
    ) -> Option<PendingReadWriteRequest> {
        self.pending_read_write.remove(&id)
    }

    pub fn remove_any_pending_request(&mut self, id: u64) -> Option<PendingRequest> {
        if let Some(request) = self.remove_pending_request(id) {
            return Some(PendingRequest::Metadata(request));
        }
        self.remove_pending_read_write_request(id)
            .map(PendingRequest::ReadWrite)
    }

    pub fn insert_any_pending_request(&mut self, request: PendingRequest) {
        match request {
            PendingRequest::Metadata(request) => self.insert_pending_request(request),
            PendingRequest::ReadWrite(request) => self.insert_pending_read_write_request(request),
        }
    }

    pub fn pending_requests_for_sandbox(&self, name: &str) -> Vec<PendingRequest> {
        let metadata = self
            .pending
            .values()
            .filter(|request| request.sandbox == name)
            .cloned()
            .map(PendingRequest::Metadata);
        let read_write = self
            .pending_read_write
            .values()
            .filter(|request| request.sandbox == name)
            .cloned()
            .map(PendingRequest::ReadWrite);
        let mut items: Vec<_> = metadata.chain(read_write).collect();
        items.sort_by_key(PendingRequest::id);
        items
    }

    pub fn insert_read_write_grant(&mut self, grant: ReadWriteAccessGrant) {
        self.read_write_grants.insert(grant.id, grant);
    }

    pub fn prune_expired_read_write_grants_for_sandbox(
        &mut self,
        sandbox: &str,
        now: SystemTime,
    ) -> Vec<ReadWriteAccessGrant> {
        let ids: Vec<u64> = self
            .read_write_grants
            .iter()
            .filter_map(|(id, grant)| {
                (grant.sandbox == sandbox && grant.lifetime.is_expired(now)).then_some(*id)
            })
            .collect();
        ids.into_iter()
            .filter_map(|id| self.read_write_grants.remove(&id))
            .collect()
    }

    pub fn match_read_write_grant_for_intent(
        &mut self,
        sandbox: &str,
        kind: ProtectionKind,
        path: &SandboxPath,
        identity: Option<ProcessIdentityEvidence>,
        now: SystemTime,
    ) -> GrantMatchOutcome {
        let Some(grant_id) = self.read_write_grants.iter().find_map(|(id, grant)| {
            grant
                .matches_intent(sandbox, kind, path, identity, now)
                .then_some(*id)
        }) else {
            return GrantMatchOutcome::NotMatched;
        };
        let consumed = matches!(
            self.read_write_grants
                .get(&grant_id)
                .map(|grant| grant.lifetime),
            Some(ReadWriteGrantLifetime::OneShot)
        );
        if consumed {
            self.read_write_grants.remove(&grant_id);
        }
        GrantMatchOutcome::Matched { grant_id, consumed }
    }

    pub fn matching_pending_read_write_ids_for_grant(
        &self,
        grant: &ReadWriteAccessGrant,
        now: SystemTime,
    ) -> Vec<u64> {
        self.pending_read_write
            .values()
            .filter(|request| grant.matches_request(request, now))
            .map(|request| request.id)
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

pub fn grant_pattern_matches(pattern: &SandboxPath, path: &SandboxPath) -> bool {
    let pattern = PolicyPattern::from(pattern);
    pattern.matches(path, false)
}

fn normalize_policy_pattern(pattern: &str) -> Result<String> {
    if pattern.is_empty() {
        return Err(Error::msg("policy pattern cannot be empty"));
    }
    if pattern.as_bytes().contains(&0) {
        return Err(Error::msg("policy pattern cannot contain NUL"));
    }
    let directory_only = pattern != "/" && pattern.ends_with('/');
    let normalized = crate::path::normalize_sandbox_path(pattern)?;
    let mut raw = normalized.to_string_lossy().into_owned();
    if directory_only && raw != "/" {
        raw.push('/');
    }
    Ok(raw)
}

fn glob_pattern_for_match(pattern: &str) -> String {
    if pattern != "/" && pattern.ends_with('/') {
        pattern.trim_end_matches('/').to_string()
    } else {
        pattern.to_string()
    }
}

pub fn epoch_millis(time: SystemTime) -> u128 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub fn duration_expires_at(now: SystemTime, duration: Duration) -> u128 {
    now.checked_add(duration)
        .map(epoch_millis)
        .unwrap_or(u128::MAX)
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
        if let Some(atime) = override_.atime {
            attr.atime = atime;
        }
        if let Some(mtime) = override_.mtime {
            attr.mtime = mtime;
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
    fn later_nested_layers_create_virtual_ancestors_through_hidden_parent() {
        let root = TempDir::new().unwrap();
        let pi = TempDir::new().unwrap();
        let cwd = TempDir::new().unwrap();
        std::fs::create_dir(root.path().join("root")).unwrap();
        std::fs::create_dir(root.path().join("root/Code")).unwrap();
        let mut s = Sandbox::new("s", root.path().join("s.log"));
        s.add_layer(root.path(), SandboxPath::new("/").unwrap());
        s.add_hide(SandboxPath::new("/root").unwrap());
        s.add_layer(pi.path(), SandboxPath::new("/root/.pi").unwrap());
        s.add_layer(cwd.path(), SandboxPath::new("/root/ai/sandbox-fs").unwrap());

        assert!(matches!(
            s.resolve(&SandboxPath::new("/root").unwrap()),
            Some(ResolvedPath::VirtualDir { .. })
        ));
        assert!(matches!(
            s.resolve(&SandboxPath::new("/root/ai").unwrap()),
            Some(ResolvedPath::VirtualDir { .. })
        ));
        assert!(matches!(
            s.resolve(&SandboxPath::new("/root/.pi").unwrap()),
            Some(ResolvedPath::Real { .. })
        ));
        assert!(matches!(
            s.resolve(&SandboxPath::new("/root/ai/sandbox-fs").unwrap()),
            Some(ResolvedPath::Real { .. })
        ));
        assert!(
            s.resolve(&SandboxPath::new("/root/Code").unwrap())
                .is_none()
        );

        let root_children = s.children(&SandboxPath::new("/root").unwrap()).unwrap();
        assert_eq!(
            root_children.keys().cloned().collect::<Vec<_>>(),
            vec![".pi".to_string(), "ai".to_string()]
        );
        let ai_children = s.children(&SandboxPath::new("/root/ai").unwrap()).unwrap();
        assert_eq!(
            ai_children.keys().cloned().collect::<Vec<_>>(),
            vec!["sandbox-fs".to_string()]
        );
    }

    #[test]
    fn virtual_ancestors_through_hidden_parent_disappear_as_layers_unwind() {
        let root = TempDir::new().unwrap();
        let pi = TempDir::new().unwrap();
        let cwd = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", root.path().join("s.log"));
        s.add_layer(root.path(), SandboxPath::new("/").unwrap());
        s.add_hide(SandboxPath::new("/root").unwrap());
        s.add_layer(pi.path(), SandboxPath::new("/root/.pi").unwrap());
        s.add_layer(cwd.path(), SandboxPath::new("/root/ai/sandbox-fs").unwrap());

        assert!(s.remove_layer(&SandboxPath::new("/root/ai/sandbox-fs").unwrap()));
        assert!(matches!(
            s.resolve(&SandboxPath::new("/root").unwrap()),
            Some(ResolvedPath::VirtualDir { .. })
        ));
        assert!(s.resolve(&SandboxPath::new("/root/ai").unwrap()).is_none());

        assert!(s.remove_layer(&SandboxPath::new("/root/.pi").unwrap()));
        assert!(s.resolve(&SandboxPath::new("/root").unwrap()).is_none());
    }

    #[test]
    fn remounting_same_path_unwinds_like_a_stack() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        std::fs::write(first.path().join("x"), "first").unwrap();
        std::fs::write(second.path().join("x"), "second").unwrap();
        let mut s = Sandbox::new("s", first.path().join("s.log"));
        s.add_layer(first.path(), SandboxPath::new("/mnt").unwrap());
        s.add_layer(second.path(), SandboxPath::new("/mnt").unwrap());

        match s.resolve(&SandboxPath::new("/mnt/x").unwrap()).unwrap() {
            ResolvedPath::Real { local_path, .. } => {
                assert_eq!(std::fs::read_to_string(local_path).unwrap(), "second")
            }
            _ => panic!("expected real"),
        }

        assert!(s.remove_layer(&SandboxPath::new("/mnt").unwrap()));
        match s.resolve(&SandboxPath::new("/mnt/x").unwrap()).unwrap() {
            ResolvedPath::Real { local_path, .. } => {
                assert_eq!(std::fs::read_to_string(local_path).unwrap(), "first")
            }
            _ => panic!("expected real"),
        }
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
    fn metadata_overrides_follow_resolved_layers_through_remount_stack() {
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", first.path().join("s.log"));
        s.add_layer(first.path(), SandboxPath::new("/data").unwrap());
        s.apply_metadata_override(&MetadataOperation::Chmod {
            path: SandboxPath::new("/data/file").unwrap(),
            mode: 0o444,
        })
        .unwrap();

        assert_eq!(
            s.metadata_override_for_path(&SandboxPath::new("/data/file").unwrap())
                .and_then(|override_| override_.mode),
            Some(0o444)
        );
        assert_eq!(
            s.metadata_differences(),
            vec![SandboxPath::new("/data/file").unwrap()]
        );

        s.add_layer(second.path(), SandboxPath::new("/data").unwrap());
        assert!(
            s.metadata_override_for_path(&SandboxPath::new("/data/file").unwrap())
                .is_none()
        );
        assert!(s.metadata_differences().is_empty());

        assert!(s.remove_layer(&SandboxPath::new("/data").unwrap()));
        assert_eq!(
            s.metadata_override_for_path(&SandboxPath::new("/data/file").unwrap())
                .and_then(|override_| override_.mode),
            Some(0o444)
        );
    }

    #[test]
    fn path_scoped_protection_applies_to_later_visible_descendants() {
        let root = TempDir::new().unwrap();
        let pi = TempDir::new().unwrap();
        let mut s = Sandbox::new("s", root.path().join("s.log"));
        s.add_layer(root.path(), SandboxPath::new("/").unwrap());
        s.protect(ProtectionKind::Write, SandboxPath::new("/root/**").unwrap());
        s.add_hide(SandboxPath::new("/root").unwrap());
        s.add_layer(pi.path(), SandboxPath::new("/root/.pi").unwrap());

        assert!(matches!(
            s.resolve(&SandboxPath::new("/root/.pi").unwrap()),
            Some(ResolvedPath::Real { .. })
        ));
        assert!(s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/root/.pi/config").unwrap(),
            false
        ));
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

        assert!(s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/secret").unwrap(),
            false
        ));
        assert!(!s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/secret/file").unwrap(),
            false
        ));
        assert!(!s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/direct").unwrap(),
            true
        ));
        assert!(s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/direct/file").unwrap(),
            false
        ));
        assert!(!s.is_protected(
            ProtectionKind::Write,
            &SandboxPath::new("/direct/a/b").unwrap(),
            false
        ));
        assert!(!s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/tree").unwrap(),
            true
        ));
        assert!(s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/tree/a/b").unwrap(),
            false
        ));
        assert!(s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/glob/a.txt").unwrap(),
            false
        ));
        assert!(!s.is_protected(
            ProtectionKind::Read,
            &SandboxPath::new("/glob/a.md").unwrap(),
            false
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
            s.unprotect(ProtectionKind::Read, SandboxPath::new("/secret/*").unwrap()),
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
            &SandboxPath::new("/secret/file").unwrap(),
            false
        ));
    }

    #[test]
    fn protection_list_is_filtered_and_sorted_for_display() {
        let mut s = Sandbox::new("s", TempDir::new().unwrap().path().join("s.log"));
        s.protect(ProtectionKind::Write, SandboxPath::new("/b").unwrap());
        s.protect(ProtectionKind::Write, SandboxPath::new("/a").unwrap());
        s.protect(ProtectionKind::Read, SandboxPath::new("/b").unwrap());
        s.protect(ProtectionKind::Read, SandboxPath::new("/a").unwrap());

        let all = s.protection_rules(false, false, false);
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

        assert_eq!(s.protection_rules(true, false, false).len(), 2);
        assert_eq!(s.protection_rules(false, true, false).len(), 2);
        assert_eq!(s.protection_rules(true, true, false), all);
    }

    #[test]
    fn read_write_operations_describe_kind_and_primary_path() {
        let read = ReadWriteOperation::ReadDirectory {
            path: SandboxPath::new("/data").unwrap(),
        };
        assert_eq!(read.kind(), ProtectionKind::Read);
        assert_eq!(read.path(), &SandboxPath::new("/data").unwrap());
        assert_eq!(read.event_body(), "path=/data READ directory");

        let rename = ReadWriteOperation::Rename {
            from: SandboxPath::new("/data/old").unwrap(),
            to: SandboxPath::new("/data/new").unwrap(),
        };
        assert_eq!(rename.kind(), ProtectionKind::Write);
        assert_eq!(rename.path(), &SandboxPath::new("/data/old").unwrap());
        assert_eq!(
            rename.event_body(),
            "path=/data/old WRITE rename to=/data/new"
        );
    }

    #[test]
    fn grant_patterns_use_plain_glob_semantics_without_protection_subtree_shortcut() {
        assert!(grant_pattern_matches(
            &SandboxPath::new("/secret/*").unwrap(),
            &SandboxPath::new("/secret/file").unwrap()
        ));
        assert!(!grant_pattern_matches(
            &SandboxPath::new("/secret/*").unwrap(),
            &SandboxPath::new("/secret").unwrap()
        ));
        assert!(!grant_pattern_matches(
            &SandboxPath::new("/secret/*").unwrap(),
            &SandboxPath::new("/secret/a/b").unwrap()
        ));
        assert!(grant_pattern_matches(
            &SandboxPath::new("/secret/**").unwrap(),
            &SandboxPath::new("/secret/a/b").unwrap()
        ));
    }

    #[test]
    fn registry_matches_grants_by_kind_path_and_requester_identity() {
        let mut registry = SandboxRegistry::new();
        let identity = ProcessIdentityEvidence {
            pid: 123,
            start_time: 456,
        };
        registry.insert_read_write_grant(ReadWriteAccessGrant {
            id: 7,
            sandbox: "s".to_string(),
            kind: ProtectionKind::Read,
            path_pattern: SandboxPath::new("/data/**").unwrap(),
            subject: ReadWriteGrantSubject::Exact { identity },
            lifetime: ReadWriteGrantLifetime::Duration {
                expires_at_epoch_ms: duration_expires_at(
                    SystemTime::now(),
                    Duration::from_secs(60),
                ),
            },
            created_at_epoch_ms: epoch_millis(SystemTime::now()),
        });

        assert_eq!(
            registry.match_read_write_grant_for_intent(
                "s",
                ProtectionKind::Read,
                &SandboxPath::new("/data/file").unwrap(),
                Some(identity),
                SystemTime::now(),
            ),
            GrantMatchOutcome::Matched {
                grant_id: 7,
                consumed: false
            }
        );
        assert_eq!(
            registry.match_read_write_grant_for_intent(
                "s",
                ProtectionKind::Write,
                &SandboxPath::new("/data/file").unwrap(),
                Some(identity),
                SystemTime::now(),
            ),
            GrantMatchOutcome::NotMatched
        );
        assert_eq!(
            registry.match_read_write_grant_for_intent(
                "s",
                ProtectionKind::Read,
                &SandboxPath::new("/other/file").unwrap(),
                Some(identity),
                SystemTime::now(),
            ),
            GrantMatchOutcome::NotMatched
        );
        assert_eq!(
            registry.match_read_write_grant_for_intent(
                "s",
                ProtectionKind::Read,
                &SandboxPath::new("/data/file").unwrap(),
                None,
                SystemTime::now(),
            ),
            GrantMatchOutcome::NotMatched
        );
    }

    #[test]
    fn one_shot_grants_are_consumed_on_first_match() {
        let mut registry = SandboxRegistry::new();
        let identity = ProcessIdentityEvidence {
            pid: 123,
            start_time: 456,
        };
        registry.insert_read_write_grant(ReadWriteAccessGrant {
            id: 7,
            sandbox: "s".to_string(),
            kind: ProtectionKind::Read,
            path_pattern: SandboxPath::new("/data/file").unwrap(),
            subject: ReadWriteGrantSubject::Exact { identity },
            lifetime: ReadWriteGrantLifetime::OneShot,
            created_at_epoch_ms: epoch_millis(SystemTime::now()),
        });

        assert_eq!(
            registry.match_read_write_grant_for_intent(
                "s",
                ProtectionKind::Read,
                &SandboxPath::new("/data/file").unwrap(),
                Some(identity),
                SystemTime::now(),
            ),
            GrantMatchOutcome::Matched {
                grant_id: 7,
                consumed: true
            }
        );
        assert!(registry.read_write_grants.is_empty());
        assert_eq!(
            registry.match_read_write_grant_for_intent(
                "s",
                ProtectionKind::Read,
                &SandboxPath::new("/data/file").unwrap(),
                Some(identity),
                SystemTime::now(),
            ),
            GrantMatchOutcome::NotMatched
        );
    }

    #[test]
    fn pending_metadata_serialization_hides_internal_object_key() {
        let operation = MetadataOperation::Chmod {
            path: SandboxPath::new("/data/file").unwrap(),
            mode: 0o444,
        };
        let request = PendingRequest::Metadata(PendingMetadataRequest {
            id: 2,
            sandbox: "s".to_string(),
            attach_id: None,
            operation: operation.clone(),
            object: MetadataObjectKey {
                layer_id: 99,
                relative_path: PathBuf::from("private/relative"),
            },
            kinds: operation.pending_kinds(),
            pid: 123,
            uid: 1000,
            gid: 1000,
            description: operation.description(),
        });

        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("object"));
        assert!(!json.contains("layer_id"));
        assert!(!json.contains("relative_path"));
        assert!(!json.contains("private/relative"));
        assert!(json.contains("/data/file"));
    }

    #[test]
    fn registry_tracks_read_write_pending_separately_and_lists_sorted() {
        let mut registry = SandboxRegistry::new();
        let metadata_operation = MetadataOperation::Chmod {
            path: SandboxPath::new("/data/file").unwrap(),
            mode: 0o444,
        };
        registry.insert_pending_request(PendingMetadataRequest {
            id: 2,
            sandbox: "s".to_string(),
            attach_id: None,
            operation: metadata_operation.clone(),
            object: MetadataObjectKey {
                layer_id: 1,
                relative_path: std::path::PathBuf::from("file"),
            },
            kinds: metadata_operation.pending_kinds(),
            pid: 123,
            uid: 1000,
            gid: 1000,
            description: metadata_operation.description(),
        });
        registry.insert_pending_read_write_request(PendingReadWriteRequest::new(
            1,
            "s".to_string(),
            ReadWriteOperation::ReadFile {
                path: SandboxPath::new("/data/file").unwrap(),
            },
            123,
            1000,
            1000,
        ));

        let items = registry.pending_requests_for_sandbox("s");
        assert_eq!(
            items.iter().map(PendingRequest::id).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(items[0].description(), "path=/data/file READ file");
        assert_eq!(items[1].description(), "path=/data/file SETATTR mode=0444");

        assert!(matches!(
            registry.remove_any_pending_request(1),
            Some(PendingRequest::ReadWrite(_))
        ));
        assert!(registry.pending_read_write.is_empty());
        assert!(registry.pending.contains_key(&2));
        assert_eq!(registry.pending_index.len(), 1);
    }
}
