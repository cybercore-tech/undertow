use crate::baseline::SetDiff;
use crate::pacman::PacmanIssue;
use std::path::PathBuf;

pub enum Finding {
    /// Non-empty `/etc/ld.so.preload` — always critical, no baseline concept applies.
    Preload(Vec<String>),
    WorldWritable(Vec<PathBuf>),
    SuidDrift(SetDiff),
    ModuleDrift(SetDiff),
    PersistenceDrift(SetDiff),
    PacmanMismatch(Vec<PacmanIssue>),
}

fn severity_color(finding: &Finding) -> String {
    match finding {
        Finding::Preload(_) => cybercore::palette::red(),
        Finding::WorldWritable(_) => cybercore::palette::orange(),
        Finding::SuidDrift(_) => cybercore::palette::hot_pink(),
        Finding::ModuleDrift(_) => cybercore::palette::purple(),
        Finding::PersistenceDrift(_) => cybercore::palette::orange(),
        Finding::PacmanMismatch(_) => cybercore::palette::red(),
    }
}

fn reset() -> &'static str {
    cybercore::palette::RESET
}

pub fn render(findings: &[Finding], color_on: bool) -> String {
    if findings.is_empty() {
        return "No indicators found — all checks clean.\n".to_string();
    }

    let mut out = String::new();
    for f in findings {
        let (c, r) = if color_on { (severity_color(f), reset().to_string()) } else { (String::new(), String::new()) };
        match f {
            Finding::Preload(entries) => {
                out.push_str(&format!("{c}[CRITICAL] /etc/ld.so.preload is non-empty{r}\n"));
                for e in entries {
                    out.push_str(&format!("  {e}\n"));
                }
            }
            Finding::WorldWritable(paths) => {
                out.push_str(&format!("{c}[WORLD-WRITABLE] {} file(s) in sensitive paths{r}\n", paths.len()));
                for p in paths {
                    out.push_str(&format!("  {}\n", p.display()));
                }
            }
            Finding::SuidDrift(diff) => {
                out.push_str(&format!("{c}[SUID/SGID DRIFT]{r}\n"));
                render_diff(&mut out, diff);
            }
            Finding::ModuleDrift(diff) => {
                out.push_str(&format!("{c}[KERNEL MODULE DRIFT]{r}\n"));
                render_diff(&mut out, diff);
            }
            Finding::PersistenceDrift(diff) => {
                out.push_str(&format!("{c}[PERSISTENCE SURFACE DRIFT]{r}\n"));
                render_diff(&mut out, diff);
            }
            Finding::PacmanMismatch(issues) => {
                out.push_str(&format!("{c}[PACKAGE FILE MISMATCH] {} file(s) don't match their package{r}\n", issues.len()));
                for i in issues {
                    out.push_str(&format!("  {} ({}): {}\n", i.path, i.reason, i.package));
                }
            }
        }
    }
    out.push_str(&format!("\n{} finding(s).\n", findings.len()));
    out
}

fn render_diff(out: &mut String, diff: &SetDiff) {
    for item in &diff.added {
        out.push_str(&format!("  + {item}\n"));
    }
    for item in &diff.removed {
        out.push_str(&format!("  - {item}\n"));
    }
}
