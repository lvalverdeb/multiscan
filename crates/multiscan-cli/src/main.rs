//! MultiScan CLI entry point. Thin: parse, dispatch, map to exit code
//! (spec 4.4). All non-machine output goes to stderr (CLI-001).

mod cli;
mod configfile;
mod db;
mod exit;
mod history;
mod scan;

use clap::{CommandFactory, Parser};

use crate::cli::{Cli, Command};
use crate::exit::Exit;

fn main() -> std::process::ExitCode {
    // clap prints usage errors itself and exits 2 (spec 4.4).
    let parsed = Cli::parse();
    match run(parsed) {
        Ok(exit) => exit.into(),
        Err(err) => {
            eprintln!("multiscan: error: {err:#}");
            Exit::ScanError.into()
        }
    }
}

fn run(parsed: Cli) -> anyhow::Result<Exit> {
    match parsed.command {
        Command::Scan(args) => scan::run(&args),
        Command::Completions { shell } => {
            let mut command = Cli::command();
            clap_complete::generate(shell, &mut command, "multiscan", &mut std::io::stdout());
            Ok(Exit::Clean)
        }
        Command::Import { file, format } => {
            let fmt = match format.as_deref() {
                None => multiscan_report::Format::Table,
                Some(name) => match multiscan_report::Format::parse(name) {
                    Some(f) => f,
                    None => {
                        eprintln!("multiscan: error: unknown format `{name}`");
                        return Ok(Exit::Usage);
                    }
                },
            };
            history::import(&file, fmt)
        }
        Command::Report => not_yet("report", "T-301"),
        Command::Explain { .. } => not_yet("explain", "T-603"),
        Command::Diff { baseline } => history::diff(&baseline),
        Command::Suppress { action } => history::suppress(&action),
        Command::Db { action } => db::run(&action),
        Command::Rules { .. } => not_yet("rules", "T-204"),
        Command::Authorize { .. } => not_yet("authorize", "T-501"),
    }
}

fn not_yet(name: &str, lands_in: &str) -> anyhow::Result<Exit> {
    eprintln!("multiscan: `{name}` is not implemented yet (lands in {lands_in})");
    Ok(Exit::Usage)
}
