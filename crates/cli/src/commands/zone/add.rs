use camino::Utf8PathBuf;
use cascade_api::{
    FileKeyImport, KeyImport, KeyType, KmipKeyImport, ZoneAddError, ZoneAddResult, ZoneName,
};

use crate::{client::CascadeApiClient, commands::zone::ZoneSource, println};

#[derive(Clone, Debug, clap::Args)]
pub struct ZoneAdd {
    pub name: ZoneName,

    /// The source to obtain the zone content from:
    /// `IP:[PORT][^TSIG_KEY_NAME]` (port defaults to 53) or the path to
    /// a zone file locally available to the `cascaded` daemon.
    // TODO: allow supplying different tcp and/or udp port?
    #[arg(long = "source")]
    pub source: ZoneSource,

    /// Policy to use for this zone
    #[arg(long = "policy")]
    pub policy: String,

    #[arg(long = "import-public-key")]
    pub import_public_key: Vec<Utf8PathBuf>,

    #[arg(long = "import-ksk-file")]
    pub import_ksk_file: Vec<Utf8PathBuf>,

    #[arg(long = "import-zsk-file")]
    pub import_zsk_file: Vec<Utf8PathBuf>,

    #[arg(long = "import-csk-file")]
    pub import_csk_file: Vec<Utf8PathBuf>,

    #[arg(long = "import-ksk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
    pub import_ksk_kmip: Vec<String>,

    #[arg(long = "import-zsk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
    pub import_zsk_kmip: Vec<String>,

    #[arg(long = "import-csk-kmip", value_names = ["server", "public_id", "private_id", "algorithm", "flags"])]
    pub import_csk_kmip: Vec<String>,
}

impl ZoneAdd {
    pub async fn execute(self, client: CascadeApiClient) -> Result<(), String> {
        let Self {
            name,
            mut source,
            policy,
            import_public_key,
            import_ksk_file,
            import_zsk_file,
            import_csk_file,
            import_ksk_kmip,
            import_zsk_kmip,
            import_csk_kmip,
        } = self;

        let import_public_key = import_public_key.into_iter().map(KeyImport::PublicKey);
        let import_ksk_file = key_file_imports(import_ksk_file, KeyType::Ksk)?;
        let import_csk_file = key_file_imports(import_csk_file, KeyType::Csk)?;
        let import_zsk_file = key_file_imports(import_zsk_file, KeyType::Zsk)?;
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

        if let ZoneSource::Zonefile { path } = &mut source {
            let canonicalized_path = path
                .canonicalize()
                .map_err(|err| format!("Failed to canonicalize zonefile path '{}': {err}", path))?;
            let path_str = canonicalized_path.to_str().ok_or_else(|| {
                format!("Failed to convert path '{}'", canonicalized_path.display())
            })?;
            *path = Utf8PathBuf::from(path_str).into_boxed_path();
        }

        let res: Result<ZoneAddResult, ZoneAddError> = client
            .post_json_with(
                "zone/add",
                &cascade_api::ZoneAdd {
                    name,
                    source: source.into(),
                    policy,
                    key_imports,
                },
            )
            .await?;

        match res {
            Ok(res) => {
                println!(
                    "Zone {} scheduled for loading, use 'cascade zone status {}' to see the status.",
                    res.name, res.name
                );
                Ok(())
            }
            Err(e) => Err(format!("Failed to add zone: {e}")),
        }
    }
}

fn key_file_imports(
    key_paths: Vec<Utf8PathBuf>,
    key_type: KeyType,
) -> Result<Vec<KeyImport>, String> {
    let mut key_imports = Vec::with_capacity(key_paths.len());
    for key_path in key_paths {
        key_imports.push(KeyImport::File(expand_key_path(key_path, key_type)?));
    }
    Ok(key_imports)
}

// This is not done as impl TryFrom<Utf8PathBuf> for FileKeyImport as neither
// Utf8PathBuf nor FileKeyImport are not defined in this crate and Rust
// doesn't allow impl for a type defined in another crate.
fn expand_key_path(key_file_path: Utf8PathBuf, key_type: KeyType) -> Result<FileKeyImport, String> {
    // Is the given path to a .key file or a .private file? We need both
    // so generate the other one from the one given. Note that we don't
    // do any actual checking against the filesystem, that is left to the
    // daemon as the files have to be loaded by the daemon which may have
    // different access rights (or even be on a different filesystem/host)
    // than the client.
    let (public_key_path, private_key_path) = match key_file_path.extension() {
        Some("key") => {
            let pri_path = key_file_path.with_extension("private");
            let pub_path = key_file_path;
            Ok((pub_path, pri_path))
        }
        Some("private") => {
            let pub_path = key_file_path.with_extension("key");
            let pri_path = key_file_path;
            Ok((pub_path, pri_path))
        }
        _ => Err(format!(
            "Key file path '{key_file_path}' does not end in .key or .private"
        )),
    }?;

    Ok(FileKeyImport {
        key_type,
        public_key_path,
        private_key_path,
    })
}

fn kmip_imports(key_type: KeyType, x: &[String]) -> Vec<KeyImport> {
    let (chunks, remainder) = x.as_chunks::<5>();

    // If this fails then clap is not doing what we expect.
    assert!(remainder.is_empty());

    chunks
        .iter()
        .map(|[server, public_id, private_id, algorithm, flags]| {
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
