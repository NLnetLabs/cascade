use bytes::Bytes;
use domain::base::Name;
use futures::TryFutureExt;
use log::error;

use crate::api::{
    PolicyInfo, PolicyInfoError, ZoneAdd, ZoneAddError, ZoneAddResult, ZoneSource, ZoneStatus,
    ZoneStatusError, ZonesListResult,
};
use crate::cli::client::CascadeApiClient;

#[derive(Clone, Debug, clap::Args)]
pub struct Zone {
    #[command(subcommand)]
    command: ZoneCommand,
}

#[derive(Clone, Debug, clap::Subcommand)]
pub enum ZoneCommand {
    /// Register a new zone
    #[command(name = "add")]
    Add {
        name: Name<Bytes>,
        /// The zone source can be an IP address (with or without port,
        /// defaults to port 53) or a file path.
        // TODO: allow supplying different tcp and/or udp port?
        #[arg(long = "source")]
        source: ZoneSource,

        /// Policy to use for this zone
        #[arg(long = "policy")]
        policy: String,
    },

    /// Remove a zone
    #[command(name = "remove")]
    Remove { name: Name<Bytes> },

    /// List registered zones
    #[command(name = "list")]
    List,

    /// Reload a zone
    #[command(name = "reload")]
    Reload { zone: Name<Bytes> },

    /// Get the status of a single zone
    #[command(name = "status")]
    Status { zone: Name<Bytes> },
}

// From brainstorm in beginning of April 2025
// - Command: reload a zone immediately
// - Command: register a new zone
// - Command: de-register a zone
// - Command: reconfigure a zone

// From discussion in August 2025
// At least:
// - register zone
// - list zones
// - get status (what zones are there, what are things doing)
// - get dnssec status on zone
// - reload zone (i.e. from file)

impl Zone {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), ()> {
        match self.command {
            ZoneCommand::Add {
                name,
                source,
                policy,
            } => {
                let res: Result<ZoneAddResult, ZoneAddError> = client
                    .post("zone/add")
                    .json(&ZoneAdd {
                        name,
                        source,
                        policy,
                    })
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

                match res {
                    Ok(res) => {
                        println!("Added zone {}", res.name);
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Failed to add zone: {e}");
                        Err(())
                    }
                }
            }
            ZoneCommand::Remove { name } => {
                let res: ZoneAddResult = client
                    .post(&format!("zone/{name}/remove"))
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

                println!("Removed zone {}", res.name);
                Ok(())
            }
            ZoneCommand::List => {
                let response: ZonesListResult = client
                    .get("zones/list")
                    .send()
                    .and_then(|r| r.json())
                    .await
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

                for zone in response.zones {
                    Self::print_zone_status(client.clone(), zone).await?;
                }
                Ok(())
            }
            ZoneCommand::Reload { zone } => {
                let url = format!("zone/{zone}/reload");
                client
                    .post(&url)
                    .send()
                    .and_then(|r| async { r.error_for_status() })
                    .await
                    .map_err(|e| {
                        error!("HTTP request failed: {e}");
                    })?;

                println!("Success: Sent zone reload command for {}", zone);
                Ok(())
            }
            ZoneCommand::Status { zone } => Self::status(client, zone).await,
        }
    }

    async fn status(client: CascadeApiClient, zone: Name<Bytes>) -> Result<(), ()> {
        // TODO: move to function that can be called by the general
        // status command with a zone arg?
        let url = format!("zone/{}/status", zone);
        let response: Result<ZoneStatus, ZoneStatusError> = client
            .get(&url)
            .send()
            .and_then(|r| r.json())
            .await
            .map_err(|e| {
                error!("HTTP request failed: {e}");
            })?;

        match response {
            Ok(status) => Self::print_zone_status(client, status).await,
            Err(ZoneStatusError::ZoneDoesNotExist) => {
                println!("zone `{zone}` does not exist");
                Err(())
            }
        }
    }

    async fn print_zone_status(client: CascadeApiClient, zone: ZoneStatus) -> Result<(), ()> {
        let url = format!("policy/{}", zone.policy);
        let response: Result<PolicyInfo, PolicyInfoError> = client
            .get(&url)
            .send()
            .and_then(|r| r.json())
            .await
            .map_err(|e| {
                error!("HTTP request failed: {e}");
            })?;

        let policy = match response {
            Ok(policy) => policy,
            Err(PolicyInfoError::PolicyDoesNotExist) => {
                println!(
                    "policy `{}` used by zone `{}` does not exist",
                    zone.policy, zone.name
                );
                return Err(());
            }
        };

        println!("Zone: {}", zone.name);
        println!("Stage: {}", zone.stage);
        println!("Policy: {}", zone.policy);

        println!("Latest input:");
        println!(
            "  Serial: {}",
            zone.unsigned_serial
                .map(|s| s.to_string())
                .unwrap_or("Unknown".to_string())
        );
        match &zone.source {
            ZoneSource::None => println!("  No source configured"),
            ZoneSource::Zonefile { path } => println!("  Loaded from the zonefile '{path}'"),
            ZoneSource::Server { addr, .. } => println!("  Received from {addr}"),
        }
        println!("  Loaded at ? (? minutes ago)");
        match (policy.loader.review.required, policy.loader.review.cmd_hook) {
            (true, None) => println!("  Configured for manual review"),
            (true, Some(path)) => println!("  Configured for automatic review by '{path}'"),
            (false, _) => println!("  Not configured for review"),
        }
        match &zone.source {
            ZoneSource::None => { /* Nothing to do */ }
            ZoneSource::Zonefile { .. } => {
                // Zonefile watching is not implemented yet.
                println!("  Waiting for zone reload command to receive changes");
            }
            ZoneSource::Server {
                addr, xfr_status, ..
            } => {
                println!("  XFR from {addr} {xfr_status}");
            }
        }
        if let Some(addr) = zone.unsigned_review_addr {
            println!("  Unsigned zone available on {addr}");
        }

        println!("Latest output:");
        if let Some(serial) = zone.signed_serial {
            println!("  Signed serial: {serial}");
            if let Some(addr) = zone.signed_review_addr {
                println!("  Signed zone available on {addr}");
            }
        }
        match (policy.signer.review.required, policy.signer.review.cmd_hook) {
            (true, None) => println!("  Configured for manual review"),
            (true, Some(path)) => println!("  Configured for automatic review by '{path}'"),
            (false, _) => println!("  Not configured for review"),
        }
        if let Some(serial) = zone.published_serial {
            println!("  Published serial: {serial}");
            println!("  Published zone available on {}", zone.publish_addr);
        }
        println!("  Re-signing scheduled at ? (in ?)");

        println!("DNSSEC keys:");
        if let Some(key_status) = zone.key_status {
            for line in key_status.lines() {
                println!("    {line}");
            }
        }
        Ok(())
    }
}
