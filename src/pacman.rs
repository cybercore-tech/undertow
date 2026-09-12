//! Verifies installed package files against `pacman`'s own recorded
//! metadata (`pacman -Qkk`) — a system binary whose content no longer
//! matches what its package claims to have installed is a strong
//! compromise indicator. Deliberately **not** bundled into the fast
//! checks: a full run takes several minutes on a normal desktop (~5m on
//! this box, checked for real before deciding this), since it touches
//! every file of every installed package. Meant to run on its own,
//! separate, less-frequent schedule.
//!
//! Not every hit is malicious — theme/icon packages in particular
//! commonly show "File type mismatch" after install-time icon-cache
//! regeneration touches their files. This reports what pacman found; it
//! doesn't try to guess intent.

use std::process::Command;

#[derive(Debug, Clone)]
pub struct PacmanIssue {
    pub package: String,
    pub path: String,
    pub reason: String,
}

/// Runs the full check across every installed package. Slow — see above.
/// `pacman -Qkk` exits non-zero when it finds any issue at all, which
/// isn't a failure of the check itself, so that's not treated as an error
/// here — only an actual failure to run the command is.
pub fn check_all() -> std::io::Result<Vec<PacmanIssue>> {
    let output = Command::new("pacman").arg("-Qkk").output()?;
    Ok(parse_warnings(&String::from_utf8_lossy(&output.stderr)))
}

fn parse_warnings(stderr: &str) -> Vec<PacmanIssue> {
    stderr
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("warning: ")?;
            let (package, rest) = rest.split_once(": ")?;
            let (path, reason) = rest.rsplit_once(" (")?;
            let reason = reason.strip_suffix(')')?;
            Some(PacmanIssue { package: package.to_string(), path: path.to_string(), reason: reason.to_string() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real `pacman -Qkk` stderr output for a package with genuine
    // alterations, captured verbatim on this box.
    const REAL_SAMPLE: &str = "warning: yaru-icon-theme: /usr/share/icons/Yaru/scalable/actions/go-next-symbolic.svg (File type mismatch)\nwarning: yaru-icon-theme: /usr/share/icons/Yaru/scalable/actions/go-previous-symbolic.svg (File type mismatch)\n";

    #[test]
    fn parses_real_warning_lines() {
        let issues = parse_warnings(REAL_SAMPLE);
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].package, "yaru-icon-theme");
        assert_eq!(issues[0].path, "/usr/share/icons/Yaru/scalable/actions/go-next-symbolic.svg");
        assert_eq!(issues[0].reason, "File type mismatch");
    }

    #[test]
    fn ignores_non_warning_lines() {
        let text = "yaru-icon-theme: 24163 total files, 2 altered files\n";
        assert!(parse_warnings(text).is_empty());
    }

    #[test]
    fn empty_input_produces_no_issues() {
        assert!(parse_warnings("").is_empty());
    }
}
