use bytes::Bytes;
use domain::base::Name;
use futures::TryFutureExt;

use crate::api::keyset::*;
use crate::cli::client::{format_http_error, CascadeApiClient};

#[derive(Clone, Debug, clap::Args)]
pub struct KeySet {
    zone: Name<Bytes>,

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

impl KeySet {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self.command {
            KeySetCommand::Ksk { subcommand } => {
                roll_command(&client, self.zone, subcommand, KeyRollVariant::Ksk).await
            }
            KeySetCommand::Zsk { subcommand } => {
                roll_command(&client, self.zone, subcommand, KeyRollVariant::Zsk).await
            }
            KeySetCommand::Csk { subcommand } => {
                roll_command(&client, self.zone, subcommand, KeyRollVariant::Csk).await
            }
            KeySetCommand::Algorithm { subcommand } => {
                roll_command(&client, self.zone, subcommand, KeyRollVariant::Algorithm).await
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
    zone: Name<Bytes>,
    cmd: KeyRollCommand,
    variant: KeyRollVariant,
) -> Result<(), String> {
    let res: Result<KeyRollResult, KeyRollError> = client
        .post(&format!("key/{zone}/roll"))
        .json(&KeyRoll { variant, cmd })
        .send()
        .and_then(|r| r.json())
        .await
        .map_err(format_http_error)?;
    match res {
        Ok(_) => {
            println!("Manual key roll for {} successful", zone);
            Ok(())
        }
        Err(e) => match e {
            KeyRollError::DnstCommandError {
                status: _,
                stdout: _,
                stderr,
            } => Err(format!("Failed manual key roll for {zone}: {stderr}")),
            KeyRollError::RxError => Err(format!(
                "Failed manual key roll for {zone}: Internal Server Error"
            )),
        },
    }
}

async fn remove_key_command(
    client: &CascadeApiClient,
    zone: Name<Bytes>,
    key: String,
    force: bool,
    continue_flag: bool,
) -> Result<(), String> {
    let res: Result<KeyRemoveResult, KeyRemoveError> = client
        .post(&format!("key/{zone}/remove"))
        .json(&KeyRemove {
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
        Err(e) => match e {
            KeyRemoveError::DnstCommandError {
                status: _,
                stdout: _,
                stderr,
            } => Err(format!("Failed to remove key {key} from {zone}: {stderr}")),
            KeyRemoveError::RxError => Err(format!(
                "Failed to remove key {key} from {zone}: Internal Server Error"
            )),
        },
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
