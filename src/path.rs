//! Sandbox path normalization and conservative CLI path rewriting.

use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxPath(PathBuf);

impl SandboxPath {
    pub fn root() -> Self {
        Self(PathBuf::from("/"))
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        normalize_sandbox_path(path).map(Self)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.to_str().unwrap_or("/")
    }

    pub fn parent(&self) -> Option<Self> {
        if self.0 == Path::new("/") {
            None
        } else {
            self.0.parent().and_then(|p| Self::new(p).ok())
        }
    }

    pub fn file_name(&self) -> Option<String> {
        self.0.file_name().map(|s| s.to_string_lossy().into_owned())
    }

    pub fn join(&self, child: impl AsRef<Path>) -> Result<Self> {
        let child = child.as_ref();
        if child.is_absolute() {
            Self::new(child)
        } else {
            Self::new(self.0.join(child))
        }
    }

    pub fn starts_with(&self, base: &SandboxPath) -> bool {
        self.0.starts_with(&base.0)
    }

    pub fn strip_prefix(&self, base: &SandboxPath) -> Result<PathBuf> {
        if base.0 == Path::new("/") {
            Ok(self.0.strip_prefix("/").unwrap_or(&self.0).to_path_buf())
        } else {
            self.0
                .strip_prefix(&base.0)
                .map(Path::to_path_buf)
                .map_err(|_| {
                    Error::msg(format!("{} is not under {}", self.as_str(), base.as_str()))
                })
        }
    }
}

impl std::fmt::Display for SandboxPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl serde::Serialize for SandboxPath {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for SandboxPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

pub fn normalize_sandbox_path(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(Error::msg("prefix paths are not valid sandbox paths"));
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                if out != Path::new("/") {
                    out.pop();
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    Ok(out)
}

pub fn rewrite_sandbox_path_arg(arg: &str) -> String {
    if arg == "/" {
        ".".to_string()
    } else if let Some(rest) = arg.strip_prefix('/') {
        format!("./{}", rest)
    } else {
        arg.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_root_relative_and_parent_components() {
        assert_eq!(SandboxPath::new("/").unwrap().as_str(), "/");
        assert_eq!(SandboxPath::new("a/b").unwrap().as_str(), "/a/b");
        assert_eq!(SandboxPath::new("/a/./b/../c").unwrap().as_str(), "/a/c");
        assert_eq!(SandboxPath::new("../../a").unwrap().as_str(), "/a");
    }

    #[test]
    fn rewrites_absolute_cli_path_args_to_cwd_relative() {
        assert_eq!(rewrite_sandbox_path_arg("/"), ".");
        assert_eq!(rewrite_sandbox_path_arg("/a/b"), "./a/b");
        assert_eq!(rewrite_sandbox_path_arg("a/b"), "a/b");
    }
}
