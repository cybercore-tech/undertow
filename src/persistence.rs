//! Enumerates *which files exist* across the common Linux persistence
//! surface — not their content (that's SigilWard's job for the paths it's
//! configured to watch) — so a brand-new autostart entry, cron job, or
//! systemd unit shows up as "new" the moment it appears, regardless of
//! whether anything is watching its content yet. New persistence is one
//! of the most common ways malware survives a reboot.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn persistence_paths(home: &Path) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();

    let dirs = [
        PathBuf::from("/etc/systemd/system"),
        PathBuf::from("/etc/cron.d"),
        PathBuf::from("/etc/cron.daily"),
        PathBuf::from("/etc/cron.hourly"),
        PathBuf::from("/etc/cron.weekly"),
        PathBuf::from("/etc/cron.monthly"),
        PathBuf::from("/etc/profile.d"),
        PathBuf::from("/etc/xdg/autostart"),
        home.join(".config/systemd/user"),
        home.join(".config/autostart"),
    ];
    for dir in &dirs {
        collect_files(dir, &mut paths);
    }

    // Individual dotfiles rather than a directory listing.
    for name in [".bashrc", ".bash_profile", ".profile", ".zshrc"] {
        let p = home.join(name);
        if p.is_file() {
            paths.insert(p.to_string_lossy().into_owned());
        }
    }

    paths
}

/// One level deep only — these directories are conventionally flat, and
/// going deeper risks pulling in unrelated content (e.g. a systemd
/// drop-in's own subdirectory structure) that isn't itself a new
/// persistence mechanism.
fn collect_files(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            out.insert(entry.path().to_string_lossy().into_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("undertow-persist-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn finds_dotfiles_in_home() {
        let home = scratch("dotfiles");
        fs::write(home.join(".bashrc"), "x").unwrap();

        let paths = persistence_paths(&home);
        assert!(paths.iter().any(|p| p.ends_with(".bashrc")));
    }

    #[test]
    fn finds_autostart_desktop_entries() {
        let home = scratch("autostart");
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::write(home.join(".config/autostart/malicious.desktop"), "x").unwrap();

        let paths = persistence_paths(&home);
        assert!(paths.iter().any(|p| p.ends_with("malicious.desktop")));
    }

    #[test]
    fn missing_home_autostart_dir_is_silently_skipped() {
        // /etc/xdg/autostart is scanned unconditionally (a real system-wide
        // path) regardless of `home`, so this only checks that the
        // *home-specific* directory being absent doesn't panic or produce
        // paths rooted there — not that "autostart" never appears anywhere.
        let home = scratch("missing");
        // no .config/autostart created under the fake home at all
        let paths = persistence_paths(&home);
        let home_autostart_prefix = home.join(".config/autostart").to_string_lossy().into_owned();
        assert!(paths.iter().all(|p| !p.starts_with(&home_autostart_prefix)));
    }
}
