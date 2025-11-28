use crate::client::CascadeApiClient;
use crate::println;

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
            FileSelection::Config => {
                println!("{}", include_str!("../../../../etc/config.template.toml"))
            }
            FileSelection::Policy => {
                println!("{}", include_str!("../../../../etc/policy.template.toml"))
            }
        }
        Ok(())
    }
}
