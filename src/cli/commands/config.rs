use futures::TryFutureExt;

use crate::{
    api::{ConfigReload, ConfigReloadError, ConfigReloadOutput, ConfigReloadResult},
    cli::client::{format_http_error, CascadeApiClient},
    println,
};

#[derive(Clone, Debug, clap::Args)]
pub struct Config {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Reload the configuration file.
    #[command(name = "reload")]
    Reload {
        // TODO: Support dry-runs.
    },
}

impl Config {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            Command::Reload {} => {
                let res: ConfigReloadResult = client
                    .post("config/reload")
                    .json(&ConfigReload {})
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(format_http_error)?;

                match res {
                    Ok(ConfigReloadOutput {}) => {
                        println!("Reloaded the configuration file");
                        Ok(())
                    }

                    Err(ConfigReloadError::Load(path, error)) => Err(format!(
                        "Could not load the new configuration file '{path}': {error}"
                    )),

                    Err(ConfigReloadError::Parse(path, error)) => Err(format!(
                        "Could not parse the new configuration file '{path}': {error}"
                    )),
                }
            }
        }
    }
}
