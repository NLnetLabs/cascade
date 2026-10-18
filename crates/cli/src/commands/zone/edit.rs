use camino::Utf8PathBuf;
use cascade_api::{ZoneEditError, ZoneEditResult, ZoneName};

use crate::{client::CascadeApiClient, commands::zone::ZoneSource, println};

#[derive(Clone, Debug, clap::Args)]
pub struct ZoneEdit {
    pub name: ZoneName,

    /// The source to obtain the zone content from:
    /// `IP:[PORT][^TSIG_KEY_NAME]` (port defaults to 53) or the path to
    /// a zone file locally available to the `cascaded` daemon.
    // TODO: allow supplying different tcp and/or udp port?
    #[arg(long = "source")]
    pub source: Option<ZoneSource>,

    /// Policy to use for this zone
    #[arg(long = "policy")]
    pub policy: Option<String>,
}

impl ZoneEdit {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        let Self {
            name,
            mut source,
            policy,
        } = self;

        if policy.is_none() && source.is_none() {
            return Err("nothing to do".into());
        }

        if let Some(ZoneSource::Zonefile { path }) = &mut source {
            let canonicalized_path = path
                .canonicalize()
                .map_err(|err| format!("Failed to canonicalize zonefile path '{}': {err}", path))?;
            let path_str = canonicalized_path.to_str().ok_or_else(|| {
                format!("Failed to convert path '{}'", canonicalized_path.display())
            })?;
            *path = Utf8PathBuf::from(path_str).into_boxed_path();
        }

        let res: Result<ZoneEditResult, ZoneEditError> = client
            .post_json_with(
                &format!("zone/{name}/edit"),
                &cascade_api::ZoneEdit {
                    source: source.clone().map(|s| s.into()),
                    policy: policy.clone(),
                },
            )
            .await?;

        match res {
            Ok(res) => {
                println!("Edited zone {}:", res.name);
                if let Some(old) = res.old_source {
                    let old = match old {
                        cascade_api::ZoneSource::None => "'none'".to_string(),
                        cascade_api::ZoneSource::Zonefile { path } => {
                            format!("zonefile '{path}'")
                        }
                        cascade_api::ZoneSource::Server {
                            addr,
                            tsig_key: None,
                        } => format!("server {addr}"),
                        cascade_api::ZoneSource::Server {
                            addr,
                            tsig_key: Some(tsig_key),
                        } => format!("server {addr} with TSIG key {tsig_key}"),
                    };
                    let new = source.unwrap();
                    println!("- Source changed from {old} to {new}");
                }
                if let Some(old) = res.old_policy {
                    let new = policy.unwrap();
                    println!("- Policy changed from {old} to {new}");
                }
                Ok(())
            }
            Err(e) => Err(format!("Failed to edit zone: {e}")),
        }
    }
}
