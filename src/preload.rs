//! `/etc/ld.so.preload` should be empty or nonexistent on a normal system.
//! Any entry forces the dynamic linker to load that library into *every*
//! dynamically-linked process on the system before anything else — the
//! classic mechanism a userspace rootkit uses to hook libc functions
//! (`readdir`, `stat`, `connect`, ...) and hide its own files, processes,
//! and network connections from `ls`/`ps`/`ss`/etc. There is no
//! "baseline" here the way there is for SUID binaries or kernel modules —
//! a non-empty file is *always* worth flagging, full stop.

use std::path::Path;

const PRELOAD_PATH: &str = "/etc/ld.so.preload";

/// Non-empty (non-comment, non-blank) lines from `/etc/ld.so.preload`.
/// Empty if the file doesn't exist or has no real entries.
pub fn check() -> Vec<String> {
    check_at(Path::new(PRELOAD_PATH))
}

fn check_at(path: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new(); // doesn't exist — the expected, safe state
    };
    content.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_empty_result() {
        assert!(check_at(Path::new("/nonexistent/ld.so.preload")).is_empty());
    }

    #[test]
    fn empty_file_is_empty_result() {
        let path = std::env::temp_dir().join(format!("undertow-preload-empty-{}", std::process::id()));
        std::fs::write(&path, "").unwrap();
        assert!(check_at(&path).is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn blank_lines_and_comments_are_ignored() {
        let path = std::env::temp_dir().join(format!("undertow-preload-comments-{}", std::process::id()));
        std::fs::write(&path, "# a comment\n\n   \n").unwrap();
        assert!(check_at(&path).is_empty());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn real_entry_is_flagged() {
        let path = std::env::temp_dir().join(format!("undertow-preload-real-{}", std::process::id()));
        std::fs::write(&path, "# comment\n/usr/lib/evil.so\n").unwrap();
        let entries = check_at(&path);
        assert_eq!(entries, vec!["/usr/lib/evil.so".to_string()]);
        std::fs::remove_file(&path).ok();
    }
}
