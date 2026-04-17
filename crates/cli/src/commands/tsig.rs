use std::str::FromStr;

use cascade_api::{
    TsigAddError, TsigAddResult, TsigKeyName, TsigListResult, TsigRemoveError, TsigRemoveResult,
};

use crate::client::CascadeApiClient;
use crate::println;

#[derive(Clone, Debug, clap::Args)]
pub struct Tsig {
    #[command(subcommand)]
    command: TsigCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum TsigCommand {
    /// Register a TSIG key
    #[command(name = "add")]
    Add {
        /// The name of the TSIG key to register.
        ///
        /// Can also be in the form `[algorithm]:keyname:secret`.
        name: String,

        /// The TSIG algorithm to use.
        ///
        /// Can be omitted if provided as part of the name.
        /// Required if `[SECRET]` is provided.
        ///
        /// Must be one of:
        ///   hmac-sha1
        ///   hmac-sha256
        ///   hmac-sha384
        ///   hmac-sha512
        #[arg(requires = "secret")]
        alg: Option<TsigAlgorithm>,

        /// The secret key material in base64 encoded form.
        ///
        /// Can be omitted if provided as part of the name.
        /// Required if `[ALG]` is provided.
        #[arg(requires = "alg")]
        secret: Option<String>,
    },

    /// Remove a TSIG key
    #[command(name = "remove")]
    Remove { name: TsigKeyName },

    /// List registered TSIG keys
    #[command(name = "list")]
    List,
}

impl Tsig {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            // Add a TSIG key to Cascade.
            TsigCommand::Add { name, alg, secret } => {
                let (name, alg, secret) = match (alg, secret) {
                    // No separate algorithm or secret argument values
                    // were provided, instead they must be extracted
                    // from the name string which should be in the form
                    // [algorithm]:keyname:secret.
                    (None, None) => {
                        let parts: Vec<&str> = name.split(':').collect();
                        match parts.as_slice() {
                            // The algorithm was provided.
                            [alg_part, name_part, secret_part] => {
                                let alg = TsigAlgorithm::from_str(alg_part)?;
                                let name = name_part.to_string();
                                let secret = secret_part.to_string();
                                (name, alg, secret)
                            }

                            // The algorithm was not provided, use the default.
                            [name_part, secret_part] => {
                                let alg = TsigAlgorithm::HmacSha256;
                                let name = name_part.to_string();
                                let secret = secret_part.to_string();
                                (name, alg, secret)
                            }

                            // The name value was not in the expected format.
                            _ => {
                                return Err(
                                    "Invalid TSIG key format, should be: [algorithm]:keyname:secret"
                                        .to_string(),
                                );
                            }
                        }
                    }

                    // Separate name, algorithm and secret argument values
                    // were provided.
                    (Some(alg), Some(secret)) => (name, alg, secret),

                    // An unsupported combination of arguments was provided
                    // but this should not be possible due to the Clap
                    // attributes that we used.
                    _ => unreachable!("Excluded via Clap 'requires' rules"),
                };

                // Parse the TSIG key name as a domain name.
                let tsig_key_name = TsigKeyName::from_str(&name)
                    .map_err(|err| format!("Invalid TSIG key name: {err}"))?;

                // Send a TSIG add message to the Cascade HTTP API.
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

                // Handle the API command result.
                match res {
                    // Success, the key was added!
                    Ok(TsigAddResult) => {
                        println!("Added TSIG key '{name}'");
                        Ok(())
                    }

                    // Failure, something went wrong.
                    Err(err) => Err(format!("Failed to add TSIG key '{name}': {err}")),
                }
            }

            // Remove a TSIG key (if possible).
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

            // List the set of TSIG keys known to Cascade.
            TsigCommand::List => {
                let response: TsigListResult = client.get_json("tsig/").await?;

                for (tsig_key_name, key_info) in response.tsig_keys {
                    // For each TSIG key also list the zones that it is used
                    // with.
                    let zones = key_info
                        .zones
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(", ");

                    println!("{tsig_key_name}");
                    print!("  zones: ");
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

//------------ TsigAlgorithm -------------------------------------------------

/// The TSIG key algorithms supported by Cascade.
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
