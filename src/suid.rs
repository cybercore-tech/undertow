//! Finds SUID/SGID binaries under a set of directories. Reports the *set*
//! of paths for `baseline::diff_and_update` to compare run-over-run — a
//! newly-appeared SUID binary is one of the most common privilege-
//! escalation backdoors (a dropped binary that runs as root regardless of
//! who invokes it), so "what's new" matters far more here than any
//! hardcoded "known good" list, which would immediately go stale across
//! different systems/package versions anyway.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SETUID: u32 = 0o4000;
const SETGID: u32 = 0o2000;

pub fn find(roots: &[PathBuf]) -> BTreeSet<String> {
    let mut hits = BTreeSet::new();
    for root in roots {
        walk(root, &mut hits);
    }
    hits
}

fn walk(dir: &Path, hits: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_file() && meta.permissions().mode() & (SETUID | SETGID) != 0 {
            hits.insert(path.to_string_lossy().into_owned());
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
        let dir = std::env::temp_dir().join(format!("undertow-suid-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_setuid_binary() {
        let dir = scratch("setuid");
        let f = dir.join("elevated");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o4755)).unwrap();

        let hits = find(&[dir.clone()]);
        assert!(hits.contains(&f.to_string_lossy().into_owned()));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finds_setgid_binary() {
        let dir = scratch("setgid");
        let f = dir.join("groupelevated");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o2755)).unwrap();

        let hits = find(&[dir.clone()]);
        assert!(hits.contains(&f.to_string_lossy().into_owned()));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ignores_normal_binary() {
        let dir = scratch("normal");
        let f = dir.join("plain");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(find(&[dir.clone()]).is_empty());
        fs::remove_dir_all(&dir).ok();
    }
}
