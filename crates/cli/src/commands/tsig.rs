use std::str::FromStr;

use cascade_api::{
    TsigAddError, TsigAddResult, TsigKeyName, TsigListResult, TsigRemoveError, TsigRemoveResult,
};

use crate::client::CascadeApiClient;
use crate::println;

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum TsigAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl FromStr for TsigAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac-sha1" => Ok(TsigAlgorithm::HmacSha1),
            "hmac-sha256" => Ok(TsigAlgorithm::HmacSha256),
            "hmac-sha384" => Ok(TsigAlgorithm::HmacSha384),
            "hmac-sha512" => Ok(TsigAlgorithm::HmacSha512),
            other => Err(format!("'{other}' is not a recognized TSIG algorithm")),
        }
    }
}

impl From<TsigAlgorithm> for crate::api::TsigAlgorithm {
    fn from(alg: TsigAlgorithm) -> Self {
        match alg {
            TsigAlgorithm::HmacSha1 => cascade_api::TsigAlgorithm::Sha1,
            TsigAlgorithm::HmacSha256 => cascade_api::TsigAlgorithm::Sha256,
            TsigAlgorithm::HmacSha384 => cascade_api::TsigAlgorithm::Sha384,
            TsigAlgorithm::HmacSha512 => cascade_api::TsigAlgorithm::Sha512,
        }
    }
}

#[derive(Clone, Debug, clap::Args)]
pub struct Tsig {
    #[command(subcommand)]
    command: TsigCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
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

    #[command(name = "remove")]
    Remove { name: TsigKeyName },

    #[command(name = "list")]
    List,
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
                                let alg = TsigAlgorithm::HmacSha256;
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

                let tsig_key_name = TsigKeyName::from_str(&name)
                    .map_err(|err| format!("Invalid TSIG key name: {err}"))?;

                let res: Result<TsigAddResult, TsigAddError> = client
                    .post_json_with(
                        "tsig/add",
                        &crate::api::TsigAdd {
                            name: tsig_key_name,
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
            TsigCommand::Remove { name } => {
                let res: Result<TsigRemoveResult, TsigRemoveError> =
                    client.post_json(&format!("tsig/{name}/remove")).await?;

                match res {
                    Ok(TsigRemoveResult) => {
                        println!("Removed TSIG key {name}");
                        Ok(())
                    }
                    Err(e) => Err(format!("Failed to remove TSIG key: {e}")),
                }
            }
            TsigCommand::List => {
                let response: TsigListResult = client.get_json("tsig/").await?;

                for (tsig_key_name, key_info) in response.tsig_keys {
                    let zones = key_info
                        .zones
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(", ");

                    print!("{tsig_key_name}: used by zones: ");
                    if !zones.is_empty() {
                        println!("{zones}");
                    } else {
                        println!("none");
                    }
                }
                Ok(())
            }
        }
    }
}
