use clap::ValueEnum;
use core::fmt;
use std::str::FromStr;

use camino::Utf8PathBuf;
use cascade_api::{
    TsigAddError, TsigAddResult, TsigKeyName, TsigKeyUsageReference, TsigListResult,
    TsigRemoveError, TsigRemoveResult,
};

use crate::client::CascadeApiClient;
use crate::{eprintln, println};

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
    Add {
        /// Path to the file.
        path: Utf8PathBuf,

        /// Format used in the file.
        ///
        /// The file isn't parsed as a real YAML file, therefore not all
        /// features are allowed.
        ///
        /// The same goes for the BIND format.
        #[arg(long, default_value_t=TsigFileFormat::Yaml, ignore_case=true, required = false)]
        format: TsigFileFormat,
    },

    /// Remove a TSIG key
    #[command(name = "remove")]
    Remove { name: TsigKeyName },

    /// List registered TSIG keys
    #[command(name = "list")]
    List,
}

impl Tsig {
    pub async fn tsig_add(
        path: Utf8PathBuf,
        format: TsigFileFormat,
    ) -> Result<(TsigKeyName, TsigAlgorithm, String), String> {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read TSIG file '{path}' as '{format}' format: {e}"))?;

        let (tsig_name_raw, tsig_alg_raw, tsig_secret) = parse_tsig(&content, format)?;

        let tsig_alg = TsigAlgorithm::from_str(&tsig_alg_raw, true).map_err(|_| {
            format!(
                "Unable to parse {} possible values are {:?}",
                tsig_alg_raw,
                TsigAlgorithm::value_variants()
            )
        })?;

        let tsig_name = TsigKeyName::from_str(&tsig_name_raw)
            .map_err(|err| format!("Invalid TSIG key name: {err}"))?;

        Ok((tsig_name, tsig_alg, tsig_secret))
    }
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            // Add a TSIG key to Cascade.
            TsigCommand::Add { path, format } => {
                let (tsig_name, tsig_alg, tsig_secret) = Tsig::tsig_add(path, format).await?;

                // Send a TSIG add message to the Cascade HTTP API.
                let res: Result<TsigAddResult, TsigAddError> = client
                    .post_json_with(
                        "tsig/add",
                        &crate::api::TsigAdd {
                            name: tsig_name.clone(),
                            alg: tsig_alg.into(),
                            secret: tsig_secret,
                        },
                    )
                    .await?;

                // Handle the API command result.
                match res {
                    // Success, the key was added!
                    Ok(TsigAddResult) => {
                        println!("Added TSIG key '{tsig_name}'");
                        Ok(())
                    }
                    // Failure, something went wrong.
                    Err(err) => Err(format!("Failed to add TSIG key '{tsig_name}': {err}")),
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

//------------ TsigAlgorithm -------------------------------------------------

/// The TSIG key algorithms supported by Cascade.
#[derive(Clone, Debug, clap::ValueEnum)]
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

//------------ TsigFileFormat ------------------------------------------------

#[derive(Clone, Debug, PartialEq, clap::ValueEnum)]
pub enum TsigFileFormat {
    Yaml,
    Bind,
}

impl fmt::Display for TsigFileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TsigFileFormat::Yaml => write!(f, "YAML"),
            TsigFileFormat::Bind => write!(f, "BIND"),
        }
    }
}
impl TsigFileFormat {
    fn keywords(&self) -> (&'static str, &'static str, &'static str) {
        match self {
            TsigFileFormat::Bind => ("key", "algorithm", "secret"),
            TsigFileFormat::Yaml => ("name", "algorithm", "secret"),
        }
    }
}

// Parse TSIG key values from a file.
//
// The function searches for the certain keywords, each at the beginning of
// the line - ignoring whitespaces. The line is then split on the first
// whitespace and first consecutive sequence of non-whitespace characters is
// taken as the value. Quotes lead to a preemptive match on the value.
//
// The keywords depend on the format used.
fn parse_tsig(content: &str, format: TsigFileFormat) -> Result<(String, String, String), String> {
    fn is_whitespace(c: char) -> bool {
        c == ' ' || c == '\t'
    }
    fn value_cleanup(line: &str, format: &TsigFileFormat) -> Result<String, String> {
        let mut output = String::new();
        let mut in_quote = false;

        let (key, value) = line
            .split_once(is_whitespace)
            .ok_or::<String>(format!("Unable to split on whitespace for line '{line}'"))?;

        for character in value.trim().chars() {
            match character {
                c if is_whitespace(c) => break,
                c if format == &TsigFileFormat::Bind && c == ';' => break,
                '"' => {
                    if in_quote {
                        // End of quotation reached.
                        break;
                    }
                    // Now inside of quotes, only go until the end of the quote.
                    in_quote = true;
                    continue;
                }
                _ => (),
            }

            output.push(character);
        }
        if output.is_empty() {
            return Err(format!("Value is empty for keyword '{key}'!"));
        };
        Ok(output)
    }

    let lines = content.trim().lines();

    let mut name: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut secret: Option<String> = None;

    let keywords = format.keywords();
    for line in lines {
        match line.trim() {
            line if line.starts_with(keywords.0) => name = Some(value_cleanup(line, &format)?),
            line if line.starts_with(keywords.1) => algorithm = Some(value_cleanup(line, &format)?),
            line if line.starts_with(keywords.2) => secret = Some(value_cleanup(line, &format)?),
            _ => (),
        }
    }

    match (name, algorithm, secret) {
        (Some(n), Some(a), Some(s)) => Ok((n, a, s)),
        _ => Err("Unable to parse all three values.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use clap::Parser;

    use crate::{
        args::Args,
        commands::{Command::Tsig, tsig::TsigCommand},
    };
    /// Parse against the binary name only, so tests read as plain argument lists.
    #[track_caller]
    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("cascade").chain(args.iter().copied()))
    }

    /// Validate TSIG command values parsed from command line arguments.
    #[track_caller]
    fn validate_arguments(cli: &[&str], tsig_expected: TsigCommand) {
        let cli = parse(cli).unwrap();
        let tsig_cmd = match cli.command {
            Tsig(tsig) => tsig,
            other => panic!("Wrong command parsed. {other:?}"),
        };

        assert_eq!(tsig_cmd.command, tsig_expected);
    }

    #[test]
    fn parse_tsig_add_command_1() {
        validate_arguments(
            &["tsig", "add", "file.key"],
            TsigCommand::Add {
                path: "file.key".into(),
                format: TsigFileFormat::Yaml,
            },
        );
    }
    #[test]
    fn parse_tsig_add_command_2() {
        validate_arguments(
            &["tsig", "add", "file.key", "--format=yamL"],
            TsigCommand::Add {
                path: "file.key".into(),
                format: TsigFileFormat::Yaml,
            },
        );
    }
    #[test]
    fn parse_tsig_add_command_3() {
        validate_arguments(
            &["tsig", "add", "file.key", "--format=binD"],
            TsigCommand::Add {
                path: "file.key".into(),
                format: TsigFileFormat::Bind,
            },
        );
    }

    #[test]
    fn parse_tsig_yaml_invalid_1() {
        let result = parse_tsig("name:", TsigFileFormat::Yaml).unwrap_err();
        assert!(result.contains("split on whitespace"), "{}", result);
    }

    #[test]
    fn parse_tsig_yaml_invalid_2() {
        let result = parse_tsig("name: ", TsigFileFormat::Yaml).unwrap_err();
        assert!(result.contains("split on whitespace"), "{}", result);
    }

    #[test]
    fn parse_tsig_yaml_invalid_3() {
        let result = parse_tsig("name: f", TsigFileFormat::Yaml).unwrap_err();
        assert!(result.contains("parse all three values"), "{}", result);
    }

    #[test]
    fn parse_tsig_yaml_minimal() {
        let result = parse_tsig("name f\nalgorithm: f\nsecret: f", TsigFileFormat::Yaml).unwrap();
        assert_eq!(result, ("f".into(), "f".into(), "f".into()));
    }

    #[test]
    fn parse_tsig_bind_minimal() {
        let result = parse_tsig("key f\nalgorithm f\nsecret f", TsigFileFormat::Bind).unwrap();
        assert_eq!(result, ("f".into(), "f".into(), "f".into()));
    }

    #[test]
    fn parse_tsig_yaml_format() {
        let content = r#"---
# this is a comment
# test.key:hmac-sha256:B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE=
tsig-key: # could also be called key
    name: test.key #name doesn't matter
algorithm: hmac-sha256

    secret: "B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE=""#;

        let result = parse_tsig(content, TsigFileFormat::Yaml);
        assert_eq!(
            result,
            Ok((
                "test.key".into(),
                "hmac-sha256".into(),
                "B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE=".into(),
            ))
        );
    }

    #[test]
    fn parse_tsig_bind_format() {
        let content = r#"
// this is a comment
// test.key:hmac-sha256:B22jiD30pKL541XsOZ28y+NxbcIRoGqnumH2SFC8QDE=
key "tsig-key" { //name doesn't matter
algorithm hmac-sha256;

    secret "TwdyUE7Q5w6Jd/A1dmreYqINEyQWtWUAVb6p4pCQ3JI=";};"#;

        let result = parse_tsig(content, TsigFileFormat::Bind);
        assert_eq!(
            result,
            Ok((
                "tsig-key".into(),
                "hmac-sha256".into(),
                "TwdyUE7Q5w6Jd/A1dmreYqINEyQWtWUAVb6p4pCQ3JI=".into(),
            ))
        );
    }
}
