//! `sb`: the Shielded Bitcoin command-line tool (wallet + indexer).

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sb", version, about = "Shielded Bitcoin wallet and indexer")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the implementation profile identifier.
    Profile,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Profile => println!("shielded-bitcoin profile v0.1 (draft)"),
    }
    Ok(())
}
