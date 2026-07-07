//! JSON-lines Unix socket IPC protocol.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::path::SandboxPath;
use crate::state::{
    PassthroughRule, PendingRequest, PolicyPattern, ProtectionKind, ProtectionRule,
    ReadWriteGrantOptions, TrustedPathScope,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Shutdown {
        name: String,
    },
    Attach {
        name: String,
        mountpoint: String,
        temporary: bool,
    },
    Detach {
        name: String,
        mountpoint: String,
    },
    Mount {
        name: String,
        local: String,
        on_fs: SandboxPath,
    },
    Umount {
        name: String,
        on_fs: SandboxPath,
    },
    Hide {
        name: String,
        on_fs: SandboxPath,
    },
    Protect {
        name: String,
        kind: ProtectionKind,
        pattern: PolicyPattern,
    },
    Unprotect {
        name: String,
        kind: ProtectionKind,
        pattern: PolicyPattern,
    },
    Passthrough {
        name: String,
        kind: ProtectionKind,
        pattern: PolicyPattern,
    },
    Unpassthrough {
        name: String,
        kind: ProtectionKind,
        pattern: PolicyPattern,
    },
    ListProtection {
        name: String,
        include_read: bool,
        include_write: bool,
        include_metadata: bool,
    },
    ListPassthrough {
        name: String,
        include_read: bool,
        include_write: bool,
        include_metadata: bool,
    },
    ListMounts {
        name: String,
    },
    Metadata {
        name: String,
    },
    BeginTrustedOperation {
        name: String,
        command: String,
        mountpoint: String,
        paths: Vec<TrustedPathScope>,
    },
    RegisterTrustedPid {
        token: String,
        pid: u32,
        uid: u32,
    },
    EndTrustedOperation {
        token: String,
    },
    Pending {
        name: String,
    },
    Allow {
        name: String,
        id: u64,
        do_nothing: bool,
        #[serde(default)]
        grant: Option<ReadWriteGrantOptions>,
    },
    Deny {
        name: String,
        id: u64,
    },
    Cancel {
        name: String,
        id: u64,
    },
    CancelAll {
        name: String,
        mountpoint: Option<String>,
    },
    LogPath {
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Text {
        text: String,
    },
    Warning {
        message: String,
    },
    Pending {
        items: Vec<PendingRequest>,
    },
    ProtectionRules {
        items: Vec<ProtectionRule>,
    },
    PassthroughRules {
        items: Vec<PassthroughRule>,
    },
    Trusted {
        token: String,
        operation_id: u64,
        mountpoint: String,
    },
    Error {
        message: String,
    },
}

pub fn send(socket: &Path, request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

pub fn write_response(mut stream: UnixStream, response: &Response) -> Result<()> {
    serde_json::to_writer(&mut stream, response)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

pub fn read_request(stream: &UnixStream) -> Result<Request> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}
