use std::str::FromStr;

use cascade_api::{TsigAddError, TsigAddResult};

use crate::client::CascadeApiClient;
use crate::println;

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum TsigAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl FromStr for TsigAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac-sha1" => Ok(TsigAlgorithm::Sha1),
            "hmac-sha256" => Ok(TsigAlgorithm::Sha256),
            "hmac-sha384" => Ok(TsigAlgorithm::Sha384),
            "hmac-sha512" => Ok(TsigAlgorithm::Sha512),
            other => Err(format!("'{other}' is not a recognized TSIG algorithm")),
        }
    }
}

impl From<TsigAlgorithm> for crate::api::TsigAlgorithm {
    fn from(alg: TsigAlgorithm) -> Self {
        match alg {
            TsigAlgorithm::Sha1 => cascade_api::TsigAlgorithm::Sha1,
            TsigAlgorithm::Sha256 => cascade_api::TsigAlgorithm::Sha256,
            TsigAlgorithm::Sha384 => cascade_api::TsigAlgorithm::Sha384,
            TsigAlgorithm::Sha512 => cascade_api::TsigAlgorithm::Sha512,
        }
    }
}

#[derive(Clone, Debug, clap::Args)]
pub struct Tsig {
    #[command(subcommand)]
    command: TsigCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum TsigCommand {
    #[command(name = "add")]
    Add {
        /// The name of the TSIG key to add.
        ///
        /// Can also be in the form `[algorithm]:keyname:secret`.
        name: String,

        /// The TSIG algorithm to use.
        ///
        /// Can be omitted if provided as part of the name.
        /// Required if `[SECRET]` is provided.
        #[arg(requires = "secret")]
        alg: Option<TsigAlgorithm>,

        /// Base64 encoded secret key bytes.
        ///
        /// Can be omitted if provided as part of the name.
        /// Required if `[ALG]` is provided.
        #[arg(requires = "alg")]
        secret: Option<String>,
    },
}

impl Tsig {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            TsigCommand::Add { name, alg, secret } => {
                let (name, alg, secret) = match (alg, secret) {
                    (None, None) => {
                        let parts: Vec<&str> = name.split(':').collect();
                        match parts.as_slice() {
                            [alg_part, name_part, secret_part] => {
                                let alg = TsigAlgorithm::from_str(alg_part)?;
                                let name = name_part.to_string();
                                let secret = secret_part.to_string();
                                (name, alg, secret)
                            }

                            [name_part, secret_part] => {
                                let alg = TsigAlgorithm::Sha256;
                                let name = name_part.to_string();
                                let secret = secret_part.to_string();
                                (name, alg, secret)
                            }

                            _ => {
                                return Err(
                                    "Invalid TSIG key format, should be: [algorithm]:keyname:secret"
                                        .to_string(),
                                );
                            }
                        }
                    }

                    (Some(alg), Some(secret)) => (name, alg, secret),

                    _ => unreachable!("Excluded via Clap 'requires' rules"),
                };

                let res: Result<TsigAddResult, TsigAddError> = client
                    .post_json_with(
                        "tsig/add",
                        &crate::api::TsigAdd {
                            name: name.clone(),
                            alg: alg.into(),
                            secret,
                        },
                    )
                    .await?;

                match res {
                    Ok(TsigAddResult) => {
                        println!("Added TSIG key '{name}'");
                        Ok(())
                    }
                    Err(err) => Err(format!("Failed to add TSIG key '{name}': {err}")),
                }
            }
        }
    }
}
