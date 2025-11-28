use futures_util::TryFutureExt;

use crate::api::keyset as api;
use crate::api::ZoneName;
use crate::client::{format_http_error, CascadeApiClient};
use crate::println;

#[derive(Clone, Debug, clap::Args)]
pub struct KeySet {
    zone: ZoneName,

    #[command(subcommand)]
    command: KeySetCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
enum KeySetCommand {
    /// Command for KSK rolls.
    Ksk {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: KeyRollCommand,
    },
    /// Command for ZSK rolls.
    Zsk {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: KeyRollCommand,
    },
    /// Command for CSK rolls.
    Csk {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: KeyRollCommand,
    },
    /// Command for algorithm rolls.
    Algorithm {
        /// The specific key roll subcommand.
        #[command(subcommand)]
        subcommand: KeyRollCommand,
    },

    /// Remove a key from the key set.
    RemoveKey {
        /// Force a key to be removed even if the key is not stale.
        #[arg(long)]
        force: bool,

        /// Continue when removing the underlying keys fails.
        #[arg(long = "continue")]
        continue_flag: bool,

        /// The key to remove.
        key: String,
    },
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum KeyRollCommand {
    /// Start a key roll.
    StartRoll,
    /// Report that the first propagation step has completed.
    Propagation1Complete {
        /// The TTL that is required to be reported by the Report actions.
        ttl: u32,
    },
    /// Cached information from before Propagation1Complete should have
    /// expired by now.
    CacheExpired1,
    /// Report that the second propagation step has completed.
    Propagation2Complete {
        /// The TTL that is required to be reported by the Report actions.
        ttl: u32,
    },
    /// Cached information from before Propagation2Complete should have
    /// expired by now.
    CacheExpired2,
    /// Report that the final changes have propagated and the the roll is done.
    RollDone,
}

impl From<KeyRollCommand> for api::KeyRollCommand {
    fn from(value: KeyRollCommand) -> Self {
        match value {
            KeyRollCommand::StartRoll => Self::StartRoll,
            KeyRollCommand::Propagation1Complete { ttl } => Self::Propagation1Complete { ttl },
            KeyRollCommand::CacheExpired1 => Self::CacheExpired1,
            KeyRollCommand::Propagation2Complete { ttl } => Self::Propagation2Complete { ttl },
            KeyRollCommand::CacheExpired2 => Self::CacheExpired2,
            KeyRollCommand::RollDone => Self::RollDone,
        }
    }
}

impl KeySet {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            KeySetCommand::Ksk { subcommand } => {
                roll_command(&client, self.zone, subcommand, api::KeyRollVariant::Ksk).await
            }
            KeySetCommand::Zsk { subcommand } => {
                roll_command(&client, self.zone, subcommand, api::KeyRollVariant::Zsk).await
            }
            KeySetCommand::Csk { subcommand } => {
                roll_command(&client, self.zone, subcommand, api::KeyRollVariant::Csk).await
            }
            KeySetCommand::Algorithm { subcommand } => {
                roll_command(
                    &client,
                    self.zone,
                    subcommand,
                    api::KeyRollVariant::Algorithm,
                )
                .await
            }

            KeySetCommand::RemoveKey {
                key,
                force,
                continue_flag,
            } => remove_key_command(&client, self.zone, key, force, continue_flag).await,
        }?;
        Ok(())
    }
}

async fn roll_command(
    client: &CascadeApiClient,
    zone: ZoneName,
    cmd: KeyRollCommand,
    variant: api::KeyRollVariant,
) -> Result<(), String> {
    let res: Result<(), String> = client
        .post(&format!("key/{zone}/roll"))
        .json(&api::KeyRoll {
            variant,
            cmd: cmd.into(),
        })
        .send()
        .and_then(|r| r.json())
        .await
        .map_err(format_http_error)?;
    match res {
        Ok(_) => {
            println!("Manual key roll for {} successful", zone);
            Ok(())
        }
        Err(err) => Err(format!("Failed manual key roll for {zone}: {err}")),
    }
}

async fn remove_key_command(
    client: &CascadeApiClient,
    zone: ZoneName,
    key: String,
    force: bool,
    continue_flag: bool,
) -> Result<(), String> {
    let res: Result<(), String> = client
        .post(&format!("key/{zone}/remove"))
        .json(&api::KeyRemove {
            key: key.clone(),
            force,
            continue_flag,
        })
        .send()
        .and_then(|r| r.json())
        .await
        .map_err(format_http_error)?;
    match res {
        Ok(_) => {
            println!("Removed key {} from zone {}", key, zone);
            Ok(())
        }
        Err(err) => Err(format!("Failed to remove key {key} from {zone}: {err}")),
    }
}

// match self.command {
// KeySetCommand::List => {
//     let res: PolicyListResult = client
//         .get("policy/list")
//         .send()
//         .and_then(|r| r.json())
//         .await
//         .map_err(|e| {
//             error!("HTTP request failed: {e:?}");
//         })?;

//     for policy in res.policies {
//         println!("{policy}");
//     }
// }
// KeySetCommand::Show { name } => {
//     let res: Result<PolicyInfo, PolicyInfoError> = client
//         .get(&format!("policy/{name}"))
//         .send()
//         .and_then(|r| r.json())
//         .await
//         .map_err(|e| {
//             error!("HTTP request failed: {e:?}");
//         })?;

//     let p = match res {
//         Ok(p) => p,
//         Err(e) => {
//             error!("{e:?}");
//             return Err(());
//         }
//     };

//     print_policy(&p);
// }
// KeySetCommand::Reload => {
//     let res: Result<PolicyChanges, PolicyReloadError> = client
//         .post("policy/reload")
//         .send()
//         .and_then(|r| r.json())
//         .await
//         .map_err(|e| {
//             error!("HTTP request failed: {e:?}");
//         })?;

//     let res = match res {
//         Ok(res) => res,
//         Err(err) => {
//             error!("{err}");
//             return Err(());
//         }
//     };

//     println!("Policies reloaded:");

//     let max_width = res.changes.iter().map(|(s, _)| s.len()).max().unwrap_or(0);

//     for p in res.changes {
//         let name = p.0;

//         let change = match p.1 {
//             PolicyChange::Added => "added",
//             PolicyChange::Removed => "removed",
//             PolicyChange::Updated => "updated",
//             PolicyChange::Unchanged => "unchanged",
//         };

//         let color = match p.1 {
//             PolicyChange::Added => ansi::GREEN,
//             PolicyChange::Removed => ansi::RED,
//             PolicyChange::Updated => ansi::BLUE,
//             PolicyChange::Unchanged => ansi::GRAY,
//         };

//         println!(
//             "{color} - {name:<width$} {change}{reset}",
//             width = max_width,
//             reset = ansi::RESET
//         );
//     }
// }
// }
