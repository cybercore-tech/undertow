# 🌊 Undertow

`Rust` · `pacman` · rootkit indicators

**Compromise/rootkit indicator checks** — the `rkhunter`/`chkrootkit`
category, not a signature-database antivirus (that needs a continuously
updated threat database at a scale no side project matches; use `ClamAV`
if you want that). Detection only — this never deletes or modifies
anything it finds. An undertow is a dangerous current hidden beneath a
calm surface; that's the point.

## 🚀 Checks

| Check | What it catches |
|---|---|
| `/etc/ld.so.preload` | Non-empty — the classic mechanism a userspace rootkit uses to hook `libc` and hide files/processes/connections from `ls`/`ps`/`ss`. Always critical, no baseline needed — this file should just be empty. |
| World-writable sensitive files | Anything "anyone" can write to in `/etc`, `/usr/bin`, `/usr/sbin`, systemd unit dirs — a live privilege-escalation path if it exists. |
| SUID/SGID drift | A newly-appeared SUID/SGID binary is one of the most common privilege-escalation backdoors. Baseline + drift, not a hardcoded allowlist (which goes stale immediately across systems/package versions). |
| Kernel module drift | New module loaded since baseline — the signature move of a kernel-level rootkit. |
| Persistence-surface drift | New file in systemd units, cron, `/etc/profile.d`, shell rc files, or XDG autostart — the most common way malware survives a reboot. Tracks *presence*, not content (that's a different, complementary question). |
| `pacman -Qkk` (own subcommand) | Every installed package's files checked against pacman's own recorded metadata — a modified system binary that no longer matches its package is a strong compromise indicator. **Not every hit is malicious** — theme/icon packages commonly show "File type mismatch" from icon-cache regeneration after install; this reports what pacman found, it doesn't guess intent. |

## ▶️ Running

```bash
undertow init      # establish SUID/module/persistence baselines
undertow check      # run the fast checks (preload, writable, +3 drift checks) — ~0.1s
undertow update      # accept current state as new baseline, after reviewing check's output
undertow pacman      # the slow one — several minutes, run on its own schedule
```

`check` **never** modifies the baseline, even when it finds drift —
unlike a rolling activity log, a security check that silently absorbed
today's compromise into tomorrow's "normal" would stop reporting it after
the first alert. Drift keeps being reported on every `check` until you
explicitly `update` after reviewing it. (An earlier draft of this got that
wrong — auto-advanced the baseline every run — caught and fixed before
ever running against real system state; see `baseline.rs`'s doc comment
and the regression test for the exact case.)

Both `check` and `pacman` exit non-zero when something's found — for
cron/systemd-timer use.

## ⚙️ Configuration

`~/.config/undertow/config.toml` — enable/disable individual checks,
configure which paths get scanned for world-writable files and SUID
binaries. Full schema in the file itself.

## 🧩 Layout

```
src/baseline.rs      generic "did this set of names change" comparison,
                     shared by suid.rs/modules.rs/persistence.rs
src/preload.rs       ld.so.preload check
src/writable.rs      world-writable file scanner
src/suid.rs          SUID/SGID binary enumeration
src/modules.rs       lsmod parsing
src/persistence.rs   persistence-surface file enumeration
src/pacman.rs        pacman -Qkk integration (the slow one)
src/report.rs        rendering, cybercore-themed colors
```

Every check is unit-tested; `pacman.rs`'s parser is tested against a real
`pacman -Qkk` warning captured on this box (`yaru-icon-theme`'s genuine,
benign file-type mismatches from icon-cache regeneration), not a
synthetic guess at the format. Full CLI drift-detection cycle
(`init` → introduce real change → `check` detects it and keeps detecting
it → `update` → `check` goes clean) verified against a real scratch
directory before ever running against this box's real system paths.

## 🗺 Known limitations

- No de-obfuscation/behavioral analysis — this looks for indicators (unexpected files, permissions, drift), not malware behavior
- `/proc` vs `ps` process-hiding cross-check was scoped out of v1
- A sufficiently sophisticated kernel rootkit can hide its own module from `lsmod`; this check catches the common case, not a determined adversary who specifically evades it

## 📄 License

MIT
