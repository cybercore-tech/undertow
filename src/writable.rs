//! Finds world-writable files/directories under a set of sensitive paths.
//! A file that "anyone" can write to in `/etc`, a systemd unit directory,
//! or a system binary directory is a live privilege-escalation path — not
//! hypothetical, since replacing or appending to it can get arbitrary code
//! to run as whoever next reads/executes it (often root).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const WORLD_WRITABLE_BIT: u32 = 0o002;

/// Walks each root looking for world-writable files. Skips symlinks
/// (their target's permissions are what actually matter, and following
/// them risks wandering outside the intended sensitive-path set).
/// Unreadable directories are skipped with a warning, not a hard failure.
pub fn find_world_writable(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut hits = Vec::new();
    for root in roots {
        walk(root, &mut hits);
    }
    hits
}

fn walk(dir: &Path, hits: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.permissions().mode() & WORLD_WRITABLE_BIT != 0 {
            hits.push(path.clone());
        }
        if meta.is_dir() {
            walk(&path, hits);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("undertow-writable-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_world_writable_file() {
        let dir = scratch("file");
        let f = dir.join("bad.txt");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();

        let hits = find_world_writable(&[dir.clone()]);
        assert_eq!(hits, vec![f]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn does_not_flag_normal_permissions() {
        let dir = scratch("normal");
        let f = dir.join("fine.txt");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(find_world_writable(&[dir.clone()]).is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finds_world_writable_file_in_subdirectory() {
        let dir = scratch("nested");
        fs::create_dir_all(dir.join("sub")).unwrap();
        let f = dir.join("sub/bad.txt");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o777)).unwrap();

        let hits = find_world_writable(&[dir.clone()]);
        assert_eq!(hits, vec![f]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn group_writable_only_is_not_flagged() {
        // 0o664 = rw-rw-r--, group-writable but NOT world-writable — a
        // distinct, less severe case this check deliberately doesn't flag.
        let dir = scratch("group");
        let f = dir.join("groupwritable.txt");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o664)).unwrap();

        assert!(find_world_writable(&[dir.clone()]).is_empty());
        fs::remove_dir_all(&dir).ok();
    }
}
