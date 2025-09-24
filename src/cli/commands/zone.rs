use bytes::Bytes;
use camino::Utf8PathBuf;
use domain::base::Name;
use futures::TryFutureExt;
use log::error;

use crate::api::{
    FileKeyImport, KeyImport, KeyType, KmipKeyImport, ZoneAdd, ZoneAddError, ZoneAddResult,
    ZoneSource, ZoneStatus, ZoneStatusError, ZonesListResult,
};
use crate::cli::client::CascadeApiClient;

#[derive(Clone, Debug, clap::Args)]
pub struct Zone {
    #[command(subcommand)]
    command: ZoneCommand,
}

#[allow(clippy::large_enum_variant)]
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

        #[arg(long = "import-public-key")]
        import_public_key: Vec<Utf8PathBuf>,

        #[arg(long = "import-ksk-file")]
        import_ksk_file: Vec<Utf8PathBuf>,

        #[arg(long = "import-zsk-file")]
        import_zsk_file: Vec<Utf8PathBuf>,

        #[arg(long = "import-csk-file")]
        import_csk_file: Vec<Utf8PathBuf>,

        #[arg(long = "import-ksk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
        import_ksk_kmip: Vec<String>,

        #[arg(long = "import-zsk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
        import_zsk_kmip: Vec<String>,

        #[arg(long = "import-csk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
        import_csk_kmip: Vec<String>,
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
                import_public_key,
                import_ksk_file,
                import_zsk_file,
                import_csk_file,
                import_ksk_kmip,
                import_zsk_kmip,
                import_csk_kmip,
            } => {
                let import_public_key = import_public_key.into_iter().map(KeyImport::PublicKey);
                let import_ksk_file = import_ksk_file.into_iter().map(|p| {
                    KeyImport::File(FileKeyImport {
                        key_type: KeyType::Ksk,
                        path: p,
                    })
                });
                let import_csk_file = import_csk_file.into_iter().map(|p| {
                    KeyImport::File(FileKeyImport {
                        key_type: KeyType::Csk,
                        path: p,
                    })
                });
                let import_zsk_file = import_zsk_file.into_iter().map(|p| {
                    KeyImport::File(FileKeyImport {
                        key_type: KeyType::Zsk,
                        path: p,
                    })
                });
                let import_ksk_kmip = kmip_imports(KeyType::Ksk, &import_ksk_kmip);
                let import_csk_kmip = kmip_imports(KeyType::Csk, &import_csk_kmip);
                let import_zsk_kmip = kmip_imports(KeyType::Zsk, &import_zsk_kmip);

                let key_imports = import_public_key
                    .chain(import_ksk_file)
                    .chain(import_csk_file)
                    .chain(import_zsk_file)
                    .chain(import_ksk_kmip)
                    .chain(import_csk_kmip)
                    .chain(import_zsk_kmip)
                    .collect();

                let res: Result<ZoneAddResult, ZoneAddError> = client
                    .post("zone/add")
                    .json(&ZoneAdd {
                        name,
                        source,
                        policy,
                        key_imports,
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
                    Self::print_zone_status(zone);
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
            Ok(status) => {
                Self::print_zone_status(status);
                Ok(())
            }
            Err(ZoneStatusError::ZoneDoesNotExist) => {
                println!("zone `{zone}` does not exist");
                Err(())
            }
        }
    }

    fn print_zone_status(zone: ZoneStatus) {
        println!("{}", zone.name);
        println!("  source: {}", zone.source);
        println!("  policy: {}", zone.policy);
        println!("  stage: {}", zone.stage);

        if let Some(key_status) = zone.key_status {
            println!("  key:");
            for line in key_status.lines() {
                println!("    {line}");
            }
        } else {
            println!("  key: <none>");
        }
    }
}

fn kmip_imports(key_type: KeyType, x: &[String]) -> Vec<KeyImport> {
    let chunks = x.chunks_exact(5);

    // If this fails then clap is not doing what we expect.
    assert!(chunks.remainder().is_empty());

    chunks
        .into_iter()
        .map(|chunk| {
            let [server, public_id, private_id, algorithm, flags] = chunk else {
                panic!()
            };
            KeyImport::Kmip(KmipKeyImport {
                key_type,
                server: server.clone(),
                public_id: public_id.clone(),
                private_id: private_id.clone(),
                algorithm: algorithm.clone(),
                flags: flags.clone(),
            })
        })
        .collect()
}
