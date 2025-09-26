use crate::cli::client::CascadeApiClient;

#[derive(Clone, Debug, clap::Args)]
pub struct Template {
    #[command(subcommand)]
    command: FileSelection,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum FileSelection {
    /// Generate a config template
    #[command(name = "config")]
    Config,
    /// Generate a policy template
    #[command(name = "policy")]
    Policy,
}

impl Template {
    pub async fn execute(self, _client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            FileSelection::Config => println!("{}", include_str!("../../../etc/config.toml")),
            // TODO: Set file path once policy template exists
            // FileSelection::Policy => println!("{}", include_str!("../../../etc/policies/default.toml")),
            FileSelection::Policy => todo!(),
        }
        Ok(())
    }
}
