use std::str::FromStr;

use cascade_api::{
    CatalogAdd, CatalogAddError, CatalogAddResult, CatalogGroup, CatalogListResult,
    CatalogRemoveError, CatalogRemoveResult, ZoneName,
};

use crate::client::CascadeApiClient;
use crate::commands::zone::ZoneSource;
use crate::{eprintln, println};

#[derive(Clone, Debug, clap::Args)]
pub struct Catalog {
    #[command(subcommand)]
    command: CatalogCommand,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, clap::Subcommand)]
pub enum CatalogCommand {
    /// Register a catalog zone
    #[command(name = "add")]
    Add {
        /// The apex name of the catalog zone.
        name: ZoneName,

        /// The primary to transfer the catalog (and, by default, its
        /// members) from: `IP:[PORT][^TSIG_KEY_NAME]` (port defaults to 53).
        #[arg(long = "source")]
        source: ZoneSource,

        /// The policy applied to members without a matching group mapping.
        #[arg(long = "default-policy")]
        default_policy: String,

        /// A per-group override, as `GROUP=POLICY[=SOURCE]`.
        ///
        /// `SOURCE` overrides where members of this group are transferred
        /// from, in the same form as `--source`. May be given repeatedly.
        #[arg(long = "group")]
        group: Vec<CatalogGroupArg>,

        /// The apex name of a catalog zone to produce downstream.
        #[arg(long = "produced-catalog")]
        produced_catalog: Option<ZoneName>,
    },

    /// Remove a catalog and all of the member zones it manages
    #[command(name = "remove")]
    Remove { name: ZoneName },

    /// Reload a catalog immediately
    #[command(name = "reload")]
    Reload { name: ZoneName },

    /// List registered catalogs
    #[command(name = "list")]
    List,
}

impl Catalog {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            CatalogCommand::Add {
                name,
                source,
                default_policy,
                group,
                produced_catalog,
            } => {
                let groups = group
                    .into_iter()
                    .map(CatalogGroupArg::into_api)
                    .collect::<Result<Vec<_>, _>>()?;

                let res: Result<CatalogAddResult, CatalogAddError> = client
                    .post_json_with(
                        "catalog/add",
                        &CatalogAdd {
                            name: name.clone(),
                            source: source.try_into()?,
                            default_policy,
                            groups,
                            produced_catalog,
                        },
                    )
                    .await?;

                match res {
                    Ok(res) => {
                        println!(
                            "Registered catalog {}, use 'cascade catalog list' to see its members.",
                            res.name
                        );
                        Ok(())
                    }
                    Err(err) => Err(format!("Failed to add catalog: {err}")),
                }
            }

            CatalogCommand::Remove { name } => {
                let res: Result<CatalogRemoveResult, CatalogRemoveError> =
                    client.post_json(&format!("catalog/{name}/remove")).await?;
                match res {
                    Ok(res) => {
                        println!("Removed catalog {}", res.name);
                        Ok(())
                    }
                    Err(err) => Err(format!("Failed to remove catalog: {err}")),
                }
            }

            CatalogCommand::Reload { name } => {
                let res: Result<CatalogRemoveResult, CatalogRemoveError> =
                    client.post_json(&format!("catalog/{name}/reload")).await?;
                match res {
                    Ok(res) => {
                        println!("Triggered reload of catalog {}", res.name);
                        Ok(())
                    }
                    Err(err) => Err(format!("Failed to reload catalog: {err}")),
                }
            }

            CatalogCommand::List => {
                let response: CatalogListResult = client.get_json("catalog/").await?;

                if response.catalogs.is_empty() {
                    eprintln!("No catalogs to show");
                }

                for catalog in response.catalogs {
                    println!("{}", catalog.name);
                    println!("  default policy: {}", catalog.default_policy);
                    if let Some(produced) = &catalog.produced_catalog {
                        println!("  produced catalog: {produced}");
                    }
                    if catalog.members.is_empty() {
                        println!("  members: none");
                    } else {
                        println!("  members:");
                        for member in catalog.members {
                            println!("    - {member}");
                        }
                    }
                }

                Ok(())
            }
        }
    }
}

//------------ CatalogGroupArg -----------------------------------------------

/// A `--group GROUP=POLICY[=SOURCE]` argument.
#[derive(Clone, Debug)]
pub struct CatalogGroupArg {
    group: String,
    policy: String,
    source: Option<ZoneSource>,
}

impl CatalogGroupArg {
    /// Converts this argument into the API representation.
    fn into_api(self) -> Result<CatalogGroup, String> {
        let source = match self.source {
            Some(source) => Some(source.try_into()?),
            None => None,
        };
        Ok(CatalogGroup {
            group: self.group,
            policy: self.policy,
            source,
        })
    }
}

impl FromStr for CatalogGroupArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, '=');
        let group = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "a group mapping must be 'GROUP=POLICY[=SOURCE]'".to_string())?;
        let policy = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "a group mapping must be 'GROUP=POLICY[=SOURCE]'".to_string())?;
        let source = parts.next().map(ZoneSource::from);
        Ok(Self {
            group: group.to_string(),
            policy: policy.to_string(),
            source,
        })
    }
}
