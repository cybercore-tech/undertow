//! Parses `lsmod` into a set of loaded module names, for baseline/drift
//! comparison. A kernel-level rootkit's signature move is loading a
//! hidden `.ko` — `lsmod` won't necessarily show a module that's actively
//! hiding itself, but plenty of real-world kernel rootkits don't bother
//! with that level of sophistication, and this check is nearly free.

use std::collections::BTreeSet;
use std::process::Command;

pub fn loaded_modules() -> BTreeSet<String> {
    let Ok(output) = Command::new("lsmod").output() else {
        return BTreeSet::new();
    };
    parse(&String::from_utf8_lossy(&output.stdout))
}

fn parse(text: &str) -> BTreeSet<String> {
    text.lines()
        .skip(1) // header: "Module Size Used by"
        .filter_map(|line| line.split_whitespace().next())
        .map(String::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real `lsmod` output captured on this box, verbatim.
    const REAL_SAMPLE: &str = "Module                  Size  Used by
udp_diag               12288  0
ip6t_REJECT            12288  1
nf_reject_ipv6         24576  1 ip6t_REJECT
xt_hl                  12288  22
";

    #[test]
    fn parses_module_names_skipping_header() {
        let modules = parse(REAL_SAMPLE);
        assert_eq!(modules.len(), 4);
        assert!(modules.contains("udp_diag"));
        assert!(modules.contains("ip6t_REJECT"));
        assert!(!modules.contains("Module"), "header row must not be parsed as a module");
    }
}
