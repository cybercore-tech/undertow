mod baseline;
mod config;
mod modules;
mod pacman;
mod persistence;
mod preload;
mod report;
mod state;
mod suid;
mod writable;

use clap::{Parser, Subcommand};
use report::Finding;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "undertow", version = "0.1.0", about = "Rootkit/compromise indicator checks")]
struct Args {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Establish baselines for SUID/SGID binaries, kernel modules, and the
    /// persistence surface. Run this once, when the current state is
    /// trustworthy.
    Init,
    /// Run every fast check and report findings. Never modifies the
    /// baseline — drift keeps being reported on every run until you
    /// explicitly `update`. Exits non-zero if anything was found.
    Check,
    /// Re-baseline SUID/SGID binaries, kernel modules, and the persistence
    /// surface to their current state. Run this only after reviewing
    /// `check`'s output and deciding the current state is trustworthy.
    Update,
    /// The slow check: verifies every installed package's files against
    /// pacman's own records (`pacman -Qkk`). Can take several minutes —
    /// deliberately separate from `check`, meant for its own, less
    /// frequent schedule.
    Pacman,
}

fn expand_all(cfg_paths: &[String]) -> Vec<PathBuf> {
    cfg_paths.iter().map(|p| config::expand_home(p)).collect()
}

fn home_dir() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/"))
}

fn collect_findings(cfg: &config::AppConfig, st: &state::State) -> Vec<Finding> {
    let mut findings = Vec::new();

    if cfg.check_preload {
        let entries = preload::check();
        if !entries.is_empty() {
            findings.push(Finding::Preload(entries));
        }
    }

    if cfg.check_writable {
        let hits = writable::find_world_writable(&expand_all(&cfg.writable_paths));
        if !hits.is_empty() {
            findings.push(Finding::WorldWritable(hits));
        }
    }

    if cfg.check_suid {
        let current = suid::find(&expand_all(&cfg.suid_paths));
        if let Some(d) = baseline::diff(Some(&st.suid), &current) {
            findings.push(Finding::SuidDrift(d));
        }
    }

    if cfg.check_modules {
        let current = modules::loaded_modules();
        if let Some(d) = baseline::diff(Some(&st.modules), &current) {
            findings.push(Finding::ModuleDrift(d));
        }
    }

    if cfg.check_persistence {
        let current = persistence::persistence_paths(&home_dir());
        if let Some(d) = baseline::diff(Some(&st.persistence), &current) {
            findings.push(Finding::PersistenceDrift(d));
        }
    }

    findings
}

fn load_config(args: &Args) -> config::AppConfig {
    let path = args.config.clone().or_else(config::default_config_path);
    match path {
        Some(p) => config::load(&p).unwrap_or_else(|e| {
            eprintln!("undertow: {e} — using defaults");
            config::AppConfig::default()
        }),
        None => config::AppConfig::default(),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let cfg = load_config(&args);
    let state_path = config::expand_home(&cfg.state_path);

    match args.command {
        Commands::Init | Commands::Update => {
            let mut st = if matches!(args.command, Commands::Update) { state::load(&state_path) } else { state::State::default() };
            st.suid = baseline::establish(suid::find(&expand_all(&cfg.suid_paths)));
            st.modules = baseline::establish(modules::loaded_modules());
            st.persistence = baseline::establish(persistence::persistence_paths(&home_dir()));
            match state::save(&st, &state_path) {
                Ok(()) => {
                    println!("undertow: baseline written to {}", state_path.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("undertow: failed to write baseline: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Commands::Check => {
            let st = state::load(&state_path);
            let findings = collect_findings(&cfg, &st);
            print!("{}", report::render(&findings, !args.no_color));
            if findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Commands::Pacman => match pacman::check_all() {
            Ok(issues) => {
                let findings = if issues.is_empty() { vec![] } else { vec![Finding::PacmanMismatch(issues)] };
                let failed = !findings.is_empty();
                print!("{}", report::render(&findings, !args.no_color));
                if failed {
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(e) => {
                eprintln!("undertow: failed to run pacman -Qkk: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
