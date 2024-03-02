use std::io;

use clap::Parser;

use age_plugin_threshold::cmd::Cli;

fn main() -> io::Result<()> {
    let cmd = Cli::parse();

    cmd.main()
}
