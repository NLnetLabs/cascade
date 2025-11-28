use std::process::ExitCode;

use clap::Parser;
use tracing::error;

use cascade_api as api;

mod ansi;
mod args;
mod client;
mod commands;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = args::Args::parse();

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

#[macro_export]
macro_rules! println {
    ($($t:tt)*) => {{
        #[allow(clippy::disallowed_macros)]
        let x = anstream::println!($($t)*);
        x
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($t:tt)*) => {{
        #[allow(clippy::disallowed_macros)]
        let x = anstream::eprintln!($($t)*);
        x
    }};
}
