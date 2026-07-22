use std::str::FromStr;

use camino::Utf8PathBuf;
use cascade_api::{
    TsigAddError, TsigAddResult, TsigKeyName, TsigKeyUsageReference, TsigListResult,
    TsigRemoveError, TsigRemoveResult,
};
use clap::ValueEnum;
use tracing::info;

use crate::client::CascadeApiClient;
use crate::{eprintln, println};

/// Representation of wrapper around TSIG key in a file.
///
/// This ([`TsigKeyWrap`]) and [`TsigKeyValues`] are used to represent the
/// format of a TSIG key in a file (e.g. .yaml, .json).
///
/// The following example shows how such format looks in YAML. The example
/// originates from here [domain#695].
///
/// ```yaml
/// key:
///   name: test.key
///   algorithm: hmac-sha256
///   secret: "B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE="
/// ```
///
/// [domain#695]: https://github.com/NLnetLabs/domain/issues/695
#[derive(Debug, serde::Deserialize)]
pub struct TsigKeyWrap {
    key: TsigKeyValues,
}

/// Representation of TSIG key values in a file.
///
/// This ([`TsigKeyValues`]) and [`TsigKeyWrap`] are used to represent the
/// format of a TSIG key in a file (e.g. .yaml, .json).
///
/// See [`TsigKeyWrap`] for an example.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsigKeyValues {
    name: String,
    algorithm: TsigAlgorithm,
    secret: String,
}

#[derive(Clone, Debug, clap::Args)]
pub struct Tsig {
    #[command(subcommand)]
    command: TsigCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
#[cfg_attr(test, derive(PartialEq))]
#[allow(clippy::large_enum_variant)]
pub enum TsigCommand {
    /// Add a TSIG key
    #[command(name = "add")]
    #[command(group(
        clap::ArgGroup::new("source")
            .args(["name", "from_file_yaml"])
            .required(true)
    ))]
    Add {
        /// Name of the TSIG key to add.
        ///
        /// Can also be in the form `algorithm:keyname:secret`.
        name: Option<String>,

        /// Algorithm used for the TSIG key.
        ///
        /// Can be omitted if provided as part of the name.
        /// Required if `[SECRET]` is provided.
        #[arg(requires = "secret", ignore_case = true)]
        alg: Option<TsigAlgorithm>,

        /// Base64 encoded secret key material or path to key material.
        ///
        /// Can be omitted if provided as part of the `[NAME]`.
        /// Required if `[ALG]` is provided.
        #[arg(requires = "alg", value_name = "SECRET|FILE")]
        secret: Option<String>,

        /// Path to file containing a TSIG key in the YAML format.
        ///
        /// ```yaml
        /// key:
        ///   name: test.key
        ///   algorithm: hmac-sha256
        ///   secret: "<redacted>"
        /// ```
        #[arg(long, value_name="FILE", conflicts_with_all = ["alg", "secret"])]
        from_file_yaml: Option<Utf8PathBuf>,
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
            TsigCommand::Add {
                name,
                alg,
                secret,
                from_file_yaml,
            } => {
                let (name, alg, secret) = tsig_assemble(name, alg, secret, from_file_yaml)?;

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
                    Err(err) => {
                        let mut msg = "Failed to remove TSIG key: ".to_string();
                        match err {
                            TsigRemoveError::NotFound => {
                                msg.push_str("key not found");
                            }
                            TsigRemoveError::InUse(key_refs) if key_refs.is_empty() => {
                                // This should not happen.
                                msg.push_str("key is still in use by: Unknown");
                            }
                            TsigRemoveError::InUse(key_refs) => {
                                msg.push_str("key is still in use by:");
                                for key_ref in key_refs {
                                    let cause = match key_ref {
                                        TsigKeyUsageReference::ZoneSource(name) => {
                                            format!("  - The source of zone '{name}'")
                                        }
                                        TsigKeyUsageReference::ZoneOther(name) => {
                                            format!("  - Zone '{name}'")
                                        }
                                        TsigKeyUsageReference::Policy(name) => {
                                            format!("  - Policy '{name}'")
                                        }
                                    };
                                    msg.push('\n');
                                    msg.push_str(&cause);
                                }
                            }
                        }
                        Err(msg)
                    }
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

/// Assemble TSIG key values based on the CLI arguments.
///
/// Given the values received through the [`TsigCommand::Add`] command. Parse
/// or read the TSIG key in the appropriate way and return the individual key
/// values.
///
/// Possible are the following combinations. Any other combination is
/// blocked through claps `source`, `conflicts_with_all` and `require`
/// rules and result in an error in this function.
///
/// - name
/// - name, alg, secret
/// - from_file_yaml
fn tsig_assemble(
    name: Option<String>,
    alg: Option<TsigAlgorithm>,
    secret: Option<String>,
    from_file_yaml: Option<Utf8PathBuf>,
) -> Result<(String, TsigAlgorithm, String), String> {
    // Figure out in which combination the TSIG key was provided.
    match (name, alg, secret, from_file_yaml) {
        // Only the `name` was provided.
        // In this case the TSIG key is expected in the compact form.
        (Some(name), None, None, None) => {
            let parts: Vec<&str> = name.split(':').collect();

            if let [alg_part, name_part, secret_part] = parts.as_slice() {
                let alg = TsigAlgorithm::from_str(alg_part, true)
                    .map_err(|_| format!("'{alg_part}' is not a supported TSIG algorithm."))?;
                Ok((name_part.to_string(), alg, secret_part.to_string()))
            } else {
                Err("Invalid TSIG key format, should be: algorithm:keyname:secret".to_string())
            }
        }

        // All TSIG key values are passed directly on the command-line.
        //
        // The `secret` could be a path to a file containing the secret.
        (Some(name), Some(alg), Some(secret), None) => {
            let path: Utf8PathBuf = (&secret).into();

            // Check if the `secret` value points to an existing file and try
            // to read the value from there.
            let secret = match std::fs::read_to_string(&path) {
                // The plain value is a file path, use the value provided in
                // the file. The start- and ending whitespaces are trimmed.
                Ok(s) => {
                    info!(file_path = ?path, "Reading TSIG key secret from file.");
                    s.trim().to_string()
                }
                // The file does not exit, fallback to the plain value.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => secret,
                // Any other error kind might indicate the intention to read
                // from a file. But it failed in an other way.
                Err(e) => return Err(format!("Failed to read TSIG key secret file '{path}': {e}")),
            };

            Ok((name, alg, secret))
        }

        // TSIG key is stored in a YAML file.
        (None, None, None, Some(from_file_yaml)) => {
            info!(file_path = ?from_file_yaml, "Reading TSIG from YAML file.");

            let yaml_unparsed = std::fs::read_to_string(&from_file_yaml)
                .map_err(|e| format!("Failed to read TSIG key yaml file '{from_file_yaml}: {e}"))?;

            let tsig_key: TsigKeyValues = yaml_serde::from_str::<TsigKeyWrap>(&yaml_unparsed)
                .map_err(|e| format!("Failed to parse TSIG key YAML file '{from_file_yaml}: {e}"))?
                .key;

            Ok((tsig_key.name, tsig_key.algorithm, tsig_key.secret))
        }

        // An unsupported combination of arguments was provided but this
        // should not be possible due to the Clap attributes used.
        _ => Err("Invalid combination of TSIG key values passed.".to_string()),
    }
}

//------------ TsigAlgorithm -------------------------------------------------

/// The TSIG key algorithms supported by Cascade.
#[derive(Clone, Debug, PartialEq, clap::ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
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

#[cfg(test)]
mod tests {
    use clap::{Parser, ValueEnum};

    use crate::{
        args::Args,
        commands::{
            Command::Tsig,
            tsig::{TsigAlgorithm, TsigCommand, TsigKeyWrap, tsig_assemble},
        },
    };

    /// Parse against the binary name only, so tests read as plain arg lists.
    #[track_caller]
    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("cascade").chain(args.iter().copied()))
    }

    /// Validate TSIG command values parsed from cli argument.
    #[track_caller]
    fn validate_arguments(cli: &[&str], tsig_expected: TsigCommand) {
        let cli = parse(cli).unwrap();
        let tsig_cmd = match cli.command {
            Tsig(tsig) => tsig,
            other => panic!("Wrong command parsed. {other:?}"),
        };

        assert_eq!(tsig_cmd.command, tsig_expected);
    }

    //--- Validate clap parsing functionality

    #[test]
    fn test_tsig_add_parse_separate_values() {
        validate_arguments(
            // Additionally: test that capitalization is ignored in algorithm.
            &["tsig", "add", "my-key", "hmac-SHA256", "abc="],
            TsigCommand::Add {
                name: Some("my-key".into()),
                alg: Some(TsigAlgorithm::HmacSha256),
                secret: Some("abc=".into()),
                from_file_yaml: None,
            },
        );
    }

    #[test]
    fn test_tsig_add_parse_combined_value() {
        validate_arguments(
            &["tsig", "add", "hmac-sha256:my-key:abc="],
            TsigCommand::Add {
                name: Some("hmac-sha256:my-key:abc=".into()),
                alg: None,
                secret: None,
                from_file_yaml: None,
            },
        );
    }

    #[test]
    fn test_tsig_add_parse_from_file_yaml() {
        validate_arguments(
            &["tsig", "add", "--from-file-yaml", "tsig.yaml"],
            TsigCommand::Add {
                name: None,
                alg: None,
                secret: None,
                from_file_yaml: Some("tsig.yaml".into()),
            },
        );
    }

    //--- Validate TSIG assemble functionality.

    #[test]
    fn test_tsig_add_assemble_separate_values() {
        let tsig_name = "name";
        let tsig_alg = TsigAlgorithm::HmacSha256;
        let tsig_secret = "secret";

        let result = tsig_assemble(
            Some(tsig_name.into()),
            Some(tsig_alg.clone()),
            Some(tsig_secret.into()),
            None,
        );

        assert_eq!(result, Ok((tsig_name.into(), tsig_alg, tsig_secret.into())));
    }

    #[test]
    fn test_tsig_add_assemble_combined_values() {
        let tsig_name = "name";
        let tsig_alg = TsigAlgorithm::HmacSha256;
        let tsig_secret = "secret";

        // Additionally: test that capitalization is ignored in algorithm.
        let result = tsig_assemble(Some("hmac-SHA256:name:secret".into()), None, None, None);

        assert_eq!(result, Ok((tsig_name.into(), tsig_alg, tsig_secret.into())));
    }

    #[test]
    fn test_tsig_add_assemble_combined_value() {
        let err = tsig_assemble(Some("keyname".into()), None, None, None).unwrap_err();
        assert!(
            err.contains("Invalid TSIG key format, should be: algorithm:keyname:secret"),
            "Original error: {:?}",
            err.to_string()
        );
    }

    #[test]
    fn test_tsig_add_assemble_invalid_combination() {
        let err = tsig_assemble(Some("keyname".into()), None, None, Some("file.yaml".into()))
            .unwrap_err();
        assert!(err.contains("Invalid combination of TSIG key values passed."),);
    }

    //--- Validate failing parsing behavior.

    #[test]
    fn test_tsig_add_parse_invalid_combination_1() {
        // Positional arguments like NAME in this case are not allowed
        // together with --from-file-yaml.
        let cli = parse(&["tsig", "add", "keyname", "--from-file-yaml", "tsig.yaml"]);
        assert_eq!(
            cli.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn test_tsig_add_parse_invalid_combination_2() {
        // Positional arguments like NAME, ALG and SECRET in this case are not
        // allowed together with --from-file-yaml.
        let cli = parse(&[
            "tsig",
            "add",
            "--from-file-yaml",
            "tsig.yaml",
            "keyname",
            "hmac-sha256",
            "secret",
        ]);
        assert_eq!(
            cli.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn test_tsig_add_parse_missing_value() {
        // If more than one positional argument is given, all of them have to
        // be given.
        let cli = parse(&["tsig", "add", "keyname", "hmac-sha256"]);
        assert_eq!(
            cli.unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn test_tsig_algorithm_clap_serde_parsing() {
        // Verify that both `kebab-case` conversions are compatible.
        TsigAlgorithm::value_variants().iter().for_each(|value| {
            yaml_serde::from_str::<TsigAlgorithm>(value.to_possible_value().unwrap().get_name())
                .unwrap();
        });
    }

    //--- Validate YAML parsing.

    // Valid and normally expected TSIG key in a YAML including comments file.
    #[test]
    fn test_tsig_yaml_structures() {
        let yaml_unparsed = r#"
            # hmac-sha256:test.key:B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE=
            key:
                name: test.key
                # NOTE: serde is unable to parse the algorithm value case insensitive.
                algorithm: hmac-sha256
                secret: "B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE="
        "#;

        let yaml_parsed: TsigKeyWrap = yaml_serde::from_str(yaml_unparsed).unwrap();

        assert_eq!(yaml_parsed.key.name, "test.key");
        assert_eq!(yaml_parsed.key.algorithm, TsigAlgorithm::HmacSha256);
        assert_eq!(
            yaml_parsed.key.secret,
            "B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE="
        );
    }

    // The TSIG key might be in a bigger YAML file surrounded by other YAML
    // keys. This is allowed.
    #[test]
    fn test_tsig_yaml_additional_keys_in_wrap() {
        let yaml_unparsed = r#"
            hello: world
            key:
                name: A
                algorithm: hmac-sha256
                secret: B
            hello2: world2
        "#;

        let _: TsigKeyWrap = yaml_serde::from_str(yaml_unparsed).unwrap();
    }

    #[test]
    fn test_tsig_yaml_fail_unexpected_keys_in_values() {
        let yaml_unparsed = r#"
            key:
                hello: world
                name: A
                algorithm: hmac-sha256
                secret: B
        "#;

        let yaml_error: yaml_serde::Error =
            yaml_serde::from_str::<TsigKeyWrap>(yaml_unparsed).unwrap_err();
        assert!(yaml_error.to_string().contains("unknown field `hello`"));
    }

    #[test]
    fn test_tsig_yaml_fail_unexpected_algorithm_value() {
        let yaml_unparsed = r#"
            key:
                name: A
                algorithm: not-an-algorithm
                secret: B
        "#;

        let yaml_error: yaml_serde::Error =
            yaml_serde::from_str::<TsigKeyWrap>(yaml_unparsed).unwrap_err();
        assert!(
            yaml_error
                .to_string()
                .contains("key.algorithm: unknown variant `not-an-algorithm`"),
            "Original error: {:?}",
            yaml_error.to_string()
        );
    }

    // Create a temporary directory, read the YAML contents and verify the
    // parsed values.
    #[test]
    fn test_tsig_add_from_file_yaml() {
        use assert_fs::prelude::*;
        let temp = assert_fs::TempDir::new().unwrap();
        let input_file = temp.child("tsig.key.yaml");

        input_file
            .write_str(
                r#"
                key:
                  name: test.key
                  algorithm: hmac-sha256
                  secret: "abc="
                "#,
            )
            .unwrap();

        let result = tsig_assemble(None, None, None, Some(input_file.to_str().unwrap().into()));
        assert_eq!(
            result,
            Ok(("test.key".into(), TsigAlgorithm::HmacSha256, "abc=".into()))
        );
        temp.close().unwrap();
    }
}
