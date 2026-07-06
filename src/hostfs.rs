use std::path::{Path, PathBuf};

pub fn read_link(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::read_link(path)
}
