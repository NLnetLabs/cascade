use crate::cli::client::CascadeApiClient;

#[derive(Clone, Debug, clap::Args)]
pub struct Config {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {}

impl Config {
    pub async fn execute(self, _client: CascadeApiClient) -> Result<(), String> {
        match self.command {}
    }
}
