//! The commands of _cascade_.

pub mod catalog;
pub mod debug;
pub mod hsm;
pub mod keyset;
pub mod policy;
pub mod status;
pub mod template;
pub mod tsig;
pub mod zone;

use crate::client::CascadeApiClient;
use crate::println;

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, clap::Subcommand)]
pub enum Command {
    /// Utilities for debugging Cascade.
    #[command(name = "debug")]
    Debug(self::debug::Debug),

    /// Check if Cascade is healthy.
    #[command(name = "health")]
    Health,

    /// Manage zones
    #[command(name = "zone")]
    Zone(self::zone::Zone),

    /// Manage catalog zones
    #[command(name = "catalog")]
    Catalog(self::catalog::Catalog),

    /// Get the status of different systems
    #[command(name = "status")]
    Status(self::status::Status),

    /// Manage policies
    #[command(name = "policy")]
    Policy(self::policy::Policy),

    /// Execute manual key roll or key removal commands
    #[command(name = "keyset")]
    KeySet(self::keyset::KeySet),

    /// Manage TSIG keys
    #[command(name = "tsig")]
    Tsig(self::tsig::Tsig),
    // - Command: add/remove/modify a zone
    // - Command: add/remove/modify a key for a zone
    // - Command: add/remove/modify a key

    // /// Manage signing operations
    // #[command(name = "signer")]
    // Signer(self::signer::Signer),
    // - Command: add/remove/modify a zone // TODO: ask Arya what we meant by that
    // - Command: resign a zone immediately (optionally with custom config)
    /// Manage HSMs
    #[command(name = "hsm")]
    Hsm(self::hsm::Hsm),
    // /// Show the manual pages
    // Help(self::help::Help),
    /// Print example config or policy files
    #[command(name = "template")]
    Template(self::template::Template),
}

impl Command {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        match self {
            Self::Debug(cmd) => cmd.execute(client).await,
            Self::Health => {
                let health = client.get_json::<cascade_api::Health>("health").await?;
                if health.healthy {
                    println!("Ok");
                } else {
                    // This path is unreachable in practice at the moment.
                    println!("The Cascade daemon is reachable but reports itself as unhealthy.");
                }
                Ok(())
            }
            Self::Zone(zone) => zone.execute(client).await,
            Self::Catalog(catalog) => catalog.execute(client).await,
            Self::Status(status) => status.execute(client).await,
            Self::Policy(policy) => policy.execute(client).await,
            Self::KeySet(keyset) => keyset.execute(client).await,
            Self::Hsm(hsm) => hsm.execute(client).await,
            Self::Tsig(tsig) => tsig.execute(client).await,
            Self::Template(template) => template.execute(client).await,
        }
    }
}
