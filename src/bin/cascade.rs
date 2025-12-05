use std::process::ExitCode;

use cascade::cli::args::Args;
use clap::Parser;
use tracing::error;

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(args.log_level)
        .init();

    match args.execute().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            error!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}
