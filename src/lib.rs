pub mod cli;
pub mod fs;
pub mod ipc;
pub mod log;
pub mod path;
pub mod runtime;
pub mod session;
pub mod state;
pub mod tui;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Nix(#[from] nix::errno::Errno),
}

impl Error {
    pub fn msg(value: impl Into<String>) -> Self {
        Self::Message(value.into())
    }
}
