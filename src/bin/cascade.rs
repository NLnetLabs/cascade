use std::process::ExitCode;

use cascade::{
    cli::args::Args,
    config::{LogTarget, LoggingConfig, Setting},
    log::Logger,
};
use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let log_config = LoggingConfig {
        level: Setting::new(args.log_level),
        target: Setting::new(LogTarget::Stdout),
        trace_targets: Default::default(),
    };

    Logger::launch(&log_config).unwrap();

    match args.execute().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}
