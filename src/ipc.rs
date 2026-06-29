//! JSON-lines Unix socket IPC protocol.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::path::SandboxPath;
use crate::state::{MetadataOperation, PendingMetadataRequest};

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
    },
    RegisterTrustedPid {
        token: String,
        pid: u32,
    },
    EndTrustedOperation {
        token: String,
    },
    ApplyMetadata {
        name: String,
        operation: MetadataOperation,
    },
    Pending {
        name: String,
    },
    Allow {
        name: String,
        id: u64,
        do_nothing: bool,
    },
    Deny {
        name: String,
        id: u64,
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
    Pending {
        items: Vec<PendingMetadataRequest>,
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
