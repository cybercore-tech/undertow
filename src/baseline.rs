//! A generic "did this set of names change" comparison, shared by three of
//! Undertow's checks (SUID/SGID binaries, persistence-surface files,
//! kernel modules) — all three are really the same question ("what's new
//! here since the trusted baseline") over a different domain, so this is
//! written once and reused three times rather than copy-pasted.
//!
//! Deliberately does **not** auto-advance the baseline when it finds a
//! diff (unlike Chronicle's rolling-log model, which is fine for an
//! activity log but wrong for a security check): if a genuine compromise
//! shows up once, then silently became "normal," it would stop being
//! reported on every check after the first. Establishing a new baseline
//! is a separate, explicit action (`undertow update`), same as SigilWard.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct SetBaseline {
    pub items: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SetDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

impl SetDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Pure comparison — never mutates `baseline`. `None` means no baseline
/// has been established yet (nothing to compare against).
pub fn diff(baseline: Option<&SetBaseline>, current: &BTreeSet<String>) -> Option<SetDiff> {
    let baseline = baseline?;
    let added: Vec<String> = current.difference(&baseline.items).cloned().collect();
    let removed: Vec<String> = baseline.items.difference(current).cloned().collect();
    let d = SetDiff { added, removed };
    if d.is_empty() {
        None
    } else {
        Some(d)
    }
}

pub fn establish(current: BTreeSet<String>) -> SetBaseline {
    SetBaseline { items: current }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_baseline_yet_produces_no_diff() {
        assert!(diff(None, &set(&["a", "b"])).is_none());
    }

    #[test]
    fn identical_set_produces_no_diff() {
        let baseline = establish(set(&["a", "b"]));
        assert!(diff(Some(&baseline), &set(&["a", "b"])).is_none());
    }

    #[test]
    fn detects_added_item() {
        let baseline = establish(set(&["a"]));
        let d = diff(Some(&baseline), &set(&["a", "b"])).expect("should detect a diff");
        assert_eq!(d.added, vec!["b".to_string()]);
        assert!(d.removed.is_empty());
    }

    #[test]
    fn detects_removed_item() {
        let baseline = establish(set(&["a", "b"]));
        let d = diff(Some(&baseline), &set(&["a"])).expect("should detect a diff");
        assert_eq!(d.removed, vec!["b".to_string()]);
        assert!(d.added.is_empty());
    }

    #[test]
    fn baseline_itself_is_never_mutated_by_diff() {
        let baseline = establish(set(&["a"]));
        diff(Some(&baseline), &set(&["a", "b"]));
        // Calling diff() again with the SAME stale baseline must report
        // the same drift again — this is the whole point of the fix.
        let d2 = diff(Some(&baseline), &set(&["a", "b"])).expect("drift must still be reported");
        assert_eq!(d2.added, vec!["b".to_string()]);
    }
}
