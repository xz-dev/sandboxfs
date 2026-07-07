use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatFs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
}

pub fn read_link(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::read_link(path)
}

pub fn statfs(path: &Path) -> std::io::Result<StatFs> {
    let path = cstring(path.as_os_str())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    Ok(StatFs {
        blocks: stat.f_blocks,
        bfree: stat.f_bfree,
        bavail: stat.f_bavail,
        files: stat.f_files,
        ffree: stat.f_ffree,
        bsize: stat.f_bsize as u32,
        namelen: stat.f_namemax as u32,
        frsize: stat.f_frsize as u32,
    })
}

pub fn getxattr(path: &Path, name: &OsStr) -> std::io::Result<Vec<u8>> {
    let path = cstring(path.as_os_str())?;
    let name = cstring(name)?;
    let size = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut value = vec![0; size as usize];
    let read = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    value.truncate(read as usize);
    Ok(value)
}

pub fn listxattr(path: &Path) -> std::io::Result<Vec<u8>> {
    let path = cstring(path.as_os_str())?;
    let size = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut names = vec![0; size as usize];
    let read = unsafe { libc::llistxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if read < 0 {
        return Err(std::io::Error::last_os_error());
    }
    names.truncate(read as usize);
    Ok(names)
}

pub fn setxattr(path: &Path, name: &OsStr, value: &[u8], flags: i32) -> std::io::Result<()> {
    let path = cstring(path.as_os_str())?;
    let name = cstring(name)?;
    let result = unsafe {
        libc::lsetxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn removexattr(path: &Path, name: &OsStr) -> std::io::Result<()> {
    let path = cstring(path.as_os_str())?;
    let name = cstring(name)?;
    let result = unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn mkdir(path: &Path, mode: u32) -> std::io::Result<()> {
    let path = cstring(path.as_os_str())?;
    let result = unsafe { libc::mkdir(path.as_ptr(), mode) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub fn rmdir(path: &Path) -> std::io::Result<()> {
    std::fs::remove_dir(path)
}

pub fn set_times(
    path: &Path,
    atime: Option<std::time::SystemTime>,
    mtime: Option<std::time::SystemTime>,
) -> std::io::Result<()> {
    let current = std::fs::symlink_metadata(path)?;
    let atime = atime.unwrap_or_else(|| system_time(current.atime(), current.atime_nsec()));
    let mtime = mtime.unwrap_or_else(|| system_time(current.mtime(), current.mtime_nsec()));
    let times = [timespec(atime), timespec(mtime)];
    let path = cstring(path.as_os_str())?;
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn timespec(time: std::time::SystemTime) -> libc::timespec {
    let duration = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    }
}

fn system_time(sec: i64, nsec: i64) -> std::time::SystemTime {
    if sec >= 0 {
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::new(sec as u64, nsec as u32)
    } else {
        std::time::SystemTime::UNIX_EPOCH
    }
}

fn cstring(value: &OsStr) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "paths and xattr names containing NUL are not supported",
        )
    })
}
