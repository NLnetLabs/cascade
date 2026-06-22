use std::str::FromStr;

use camino::Utf8PathBuf;
use cascade_api::{
    TsigAddError, TsigAddResult, TsigKeyName, TsigListResult, TsigRemoveError, TsigRemoveResult,
};

use crate::client::CascadeApiClient;
use crate::{eprintln, println};

#[derive(Clone, Debug, clap::Args)]
pub struct Tsig {
    #[command(subcommand)]
    command: TsigCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum TsigCommand {
    /// Add a TSIG key
    #[command(name = "add")]
    Add {
        /// The name of the TSIG key to add.
        ///
        /// Can also be in the form `[algorithm:]keyname:secret`.
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

        /// Base64 encoded secret key material.
        ///
        /// Can be omitted if provided as part of the name.
        /// Required if `[ALG]` is provided.
        ///
        /// Can also be a path to a file containing the Base64 encoded secret
        /// key material.
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
                    (Some(alg), Some(secret)) => {
                        let path = Utf8PathBuf::from_str(&secret).unwrap();
                        if path.exists() {
                            // Assume that the secret is contained in the
                            // specified file.
                            let secret = std::fs::read_to_string(&path)
                                .map_err(|err| {
                                    format!("Failed to read TSIG key file '{path}': {err}")
                                })?
                                .trim()
                                .to_string();
                            (name, alg, secret)
                        } else {
                            // Assume that the secret was provided directly.
                            (name, alg, secret)
                        }
                    }

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

                if response.tsig_key_info.is_empty() {
                    eprintln!("No TSIG keys to show");
                }

                for (tsig_key_name, key_info) in response.tsig_key_info {
                    // For each TSIG key also list the zones and policies that
                    // it is used with.
                    let zone_names = key_info
                        .zone_names
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(", ");

                    let policy_names = key_info
                        .policy_names
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(", ");

                    println!("{tsig_key_name}");
                    print!("  zones: ");
                    if !zone_names.is_empty() {
                        println!("{zone_names}");
                    } else {
                        println!("none");
                    }
                    print!("  policies: ");
                    if !policy_names.is_empty() {
                        println!("{policy_names}");
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
            other => Err(format!("'{other}' is not a supported TSIG algorithm")),
        }
    }
}

impl From<TsigAlgorithm> for crate::api::TsigAlgorithm {
    fn from(alg: TsigAlgorithm) -> Self {
        match alg {
            TsigAlgorithm::HmacSha1 => cascade_api::TsigAlgorithm::HmacSha1,
            TsigAlgorithm::HmacSha256 => cascade_api::TsigAlgorithm::HmacSha256,
            TsigAlgorithm::HmacSha384 => cascade_api::TsigAlgorithm::HmacSha384,
            TsigAlgorithm::HmacSha512 => cascade_api::TsigAlgorithm::HmacSha512,
        }
    }
}
