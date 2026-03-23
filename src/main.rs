pub mod core;
pub mod flat;
pub mod index;
pub mod session;
pub mod output;
pub mod func_stats;

use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(name = "trace-cli", about = "AI-first ARM64 trace analysis")]
struct Cli {
    /// Path to trace file
    file: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show trace structure (function call tree)
    Overview,
    /// Show trace lines in a range
    Lines {
        /// Line range, e.g. "100-200"
        range: String,
    },
    /// Backward taint analysis
    Taint {
        /// Target spec, e.g. "x0@last" or "x0@5000"
        spec: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let session = session::Session::open(&cli.file)?;

    match cli.command {
        Commands::Overview => {
            output::print_overview(&session);
        }
        Commands::Lines { range } => {
            let parts: Vec<&str> = range.splitn(2, '-').collect();
            if parts.len() != 2 {
                anyhow::bail!("invalid range '{}': expected format 'START-END' (e.g. 0-20)", range);
            }
            let start: u32 = parts[0].parse()?;
            let end: u32 = parts[1].parse()?;
            output::print_lines(&session, start, end);
        }
        Commands::Taint { spec } => {
            output::print_taint(&session, &spec)?;
        }
    }

    Ok(())
}
