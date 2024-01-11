use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets the input file (should not be limited to local paths)
    #[arg(short, long, value_name = "CONFIG")]
    config: Option<PathBuf>,

    /// Sets the input file (should not be limited to local paths)
    #[arg(short, long, value_name = "INPUT")]
    input: Option<PathBuf>,

    /// Sets the output file (should not be limited to local paths)
    #[arg(short, long, value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    log_level: u8,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Read pithos file
    Read {
        /// lists test values
        #[arg(short, long)]
        list: bool,
    },
    ///
    Write {},
    /// Create custom transformer order or something like that
    Custom {},
}

fn main() {
    // Parse cli input
    let cli = Cli::parse();

    if let Some(config_path) = cli.input.as_deref() {
        println!("Value for input: {}", config_path.display());
    }

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    match cli.log_level {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &cli.command {
        Some(Commands::Read { list }) => {
            if *list {
                println!("Printing testing lists...");
            } else {
                println!("Not printing testing lists...");
            }
        }
        None => {}
        Some(Commands::Write { .. }) => {}
        Some(Commands::Custom { .. }) => {}
    }

    // Continued program logic goes here...
}
