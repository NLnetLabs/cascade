//! KMIP HSM credential anagement
use std::{
    fmt::Formatter,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use camino::{Utf8Path, Utf8PathBuf};
use foldhash::HashMap;
use serde::{Deserialize, Serialize};

use crate::util::write_file;

//------------ KmipClientCredentials -----------------------------------------

/// Credentials for connecting to a KMIP server.
///
/// Intended to be read from a JSON file stored separately to the main
/// configuration so that separate security policy can be applied to sensitive
/// credentials.
///
/// Note: This format is shared with `dnst keyset`. Changes to this struct or
/// its (de)serialization need to be coordinated with `dnst keyset`.
//
// TODO: Maybe rename this to KmipUsernameAndPassword? I didn't do that yet
// as this same struct appears with the same name in `dnst keyset` code. Maybe
// "shared" should be in the name to signal its shared nature with
// `dnst keyset`?
#[derive(Debug, Deserialize, Serialize)]
pub struct KmipClientCredentials {
    /// KMIP username credential.
    ///
    /// Mandatory if the KMIP "Credential Type" is "Username and Password".
    ///
    /// See: <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458>
    pub username: String,

    /// KMIP password credential.
    ///
    /// Optional when KMIP "Credential Type" is "Username and Password".
    ///
    /// See: <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613458>
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub password: Option<String>,
}

//------------ KmipClientCredentialSet ---------------------------------------

/// A set of KMIP server credentials.
//
// TODO: Use libraries like secrecy, secrets and serdect to limit the risk of
// having secrets in memory?
#[derive(Debug, Default, Deserialize, Serialize)]
struct KmipClientCredentialsSet(HashMap<String, KmipClientCredentials>);

//------------ KmipClientCredentialsFileMode ---------------------------------

/// The access mode to use when accessing a credentials file.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KmipServerCredentialsFileMode {
    /// Open an existing credentials file for reading. Saving will fail.
    ReadOnly,

    /// Open an existing credentials file for reading and writing.
    #[expect(dead_code)]
    ReadWrite,

    /// Open or create the credentials file for reading and writing.
    CreateReadWrite,
}

//--- impl Display

impl std::fmt::Display for KmipServerCredentialsFileMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KmipServerCredentialsFileMode::ReadOnly => write!(f, "read-only"),
            KmipServerCredentialsFileMode::ReadWrite => write!(f, "read-write"),
            KmipServerCredentialsFileMode::CreateReadWrite => write!(f, "create-read-write"),
        }
    }
}

//------------ KmipCredentialsManager ----------------------------------------

/// Management of persisted KMIP HSM related credentials.
#[derive(Debug)]
pub struct KmipCredentialsManager {
    /// The file from which the credentials were loaded, and will be saved
    /// back to.
    file: File,

    /// The path from which the file was loaded. Used for generating error
    /// messages.
    path: PathBuf,

    /// The actual set of loaded credentials.
    credentials: KmipClientCredentialsSet,

    /// The read/write/create mode.
    #[allow(dead_code)]
    mode: KmipServerCredentialsFileMode,
}

impl KmipCredentialsManager {
    /// Load credentials from disk.
    ///
    /// Optionally:
    ///   - Create the file if missing.
    ///   - Keep the file open for writing back changes. See [`Self::save()`].
    pub fn new(path: &Path, mode: KmipServerCredentialsFileMode) -> Result<Self, String> {
        let (read, write, create) = match mode {
            KmipServerCredentialsFileMode::ReadOnly => (true, false, false),
            KmipServerCredentialsFileMode::ReadWrite => (true, true, false),
            KmipServerCredentialsFileMode::CreateReadWrite => (true, true, true),
        };

        let file = OpenOptions::new()
            .read(read)
            .write(write)
            .create(create)
            .mode(0o600) // Limit read-write access to the user we are running as.
            .truncate(false)
            .open(path)
            .map_err(|e| {
                format!(
                    "unable to open KMIP credentials file {} in {mode} mode: {e}",
                    path.display()
                )
            })?;

        // Determine the length of the file as JSON parsing fails if the file
        // is completely empty.
        let len = file.metadata().map(|m| m.len()).map_err(|e| {
            format!(
                "unable to query metadata of KMIP credentials file {}: {e}",
                path.display()
            )
        })?;

        // Buffer reading as apparently JSON based file reading is extremely
        // slow without buffering, even for small files.
        let mut reader = BufReader::new(&file);

        // Load or create the credential set.
        let credentials: KmipClientCredentialsSet = if len > 0 {
            serde_json::from_reader(&mut reader).map_err(|e| {
                format!(
                    "error loading KMIP credentials file {:?}: {e}\n",
                    path.display()
                )
            })?
        } else {
            KmipClientCredentialsSet::default()
        };

        // Save the path for use in generating error messages.
        let path = path.to_path_buf();

        Ok(KmipCredentialsManager {
            file,
            path,
            credentials,
            mode,
        })
    }

    /// Write the credential set back to the file it was loaded from.
    ///
    /// See also: [`Self::save_mtls_data()`].
    pub fn save(&mut self) -> std::io::Result<()> {
        // TODO: Change the model here to not hold a File object and write
        // back to it but instead to read the file and close it, then use
        // util::write_file() to write it back atomically?

        // Ensure that writing happens at the start of the file.
        self.file.seek(SeekFrom::Start(0))?;

        // Use a buffered writer as writing JSON to a file directly is
        // apparently very slow, even for small files.
        //
        // Enclose the use of the BufWriter in a block so that it is
        // definitely no longer using the file when we next act on it.
        {
            let mut writer = BufWriter::new(&self.file);
            serde_json::to_writer_pretty(&mut writer, &self.credentials).map_err(|e| {
                std::io::Error::other(format!(
                    "error writing KMIP credentials file {}: {e}",
                    self.path.display()
                ))
            })?;

            // Ensure that the BufWriter is flushed as advised by the
            // BufWriter docs.
            writer.flush()?;
        }

        // Truncate the file to the length of data we just wrote..
        let pos = self.file.stream_position()?;
        self.file.set_len(pos)?;

        // Ensure that any write buffers are flushed.
        self.file.flush()?;

        Ok(())
    }

    /// Does this credential set include credentials for the specified KMIP
    /// server.
    #[expect(dead_code)]
    pub fn contains(&self, server_id: &str) -> bool {
        self.credentials.0.contains_key(server_id)
    }

    pub fn get(&self, server_id: &str) -> Option<&KmipClientCredentials> {
        self.credentials.0.get(server_id)
    }

    /// Add credentials for the specified KMIP server, replacing any that
    /// previously existed for the same server.-
    ///
    /// Returns any previous configuration if found.
    pub fn insert(
        &mut self,
        server_id: String,
        credentials: KmipClientCredentials,
    ) -> Option<KmipClientCredentials> {
        self.credentials.0.insert(server_id, credentials)
    }

    /// Remove any existing configuration for the specified KMIP server.
    ///
    /// Returns any previous configuration if found.
    #[expect(dead_code)]
    pub fn remove(&mut self, server_id: &str) -> Option<KmipClientCredentials> {
        self.credentials.0.remove(server_id)
    }

    #[expect(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.credentials.0.is_empty()
    }

    /// Save given mTLS KMIP related data to disk.
    ///
    /// Returns the path to which the data was written.
    pub fn save_mtls_data(
        &self,
        server_id: &str,
        data: KmipMtlsAuthData,
    ) -> std::io::Result<Utf8PathBuf> {
        // Make sure we are in write mode.
        if self.mode == KmipServerCredentialsFileMode::ReadOnly {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }

        // Determine the path to save the given mTLS data to.
        let target_dir = self
            .path
            .parent()
            .expect("KMIP credential store path should be set");
        let (related_name, ext, bytes) = match data {
            KmipMtlsAuthData::ClientCertificate(bytes) => ("client", "cert", bytes),
            KmipMtlsAuthData::ClientKey(bytes) => ("client", "key", bytes),
            KmipMtlsAuthData::ServerCertificate(bytes) => ("server", "cert", bytes),
            KmipMtlsAuthData::CaCertificate(bytes) => ("ca", "cert", bytes),
        };
        let data_file_name = format!("{server_id}_{related_name}",);
        let data_file_path = target_dir.join(data_file_name).with_extension(ext);
        let data_file_path = Utf8PathBuf::from_path_buf(data_file_path)
            .map_err(|_| std::io::ErrorKind::InvalidFilename)?;

        // Write the PEM base64 encoded mTLS data to the chosen path.
        write_file(&data_file_path, bytes)?;

        Ok(data_file_path)
    }

    /// Load previously saved mTLS data from disk.
    ///
    /// Does no parsing or interpretation of the loaded bytes, that is left to
    /// the `kmip-protcool` connection establishment code.
    pub fn load_mtls_data(path: &Utf8Path) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?.read_to_end(&mut bytes)?;
        std::io::Result::Ok(bytes)
    }
}

/// mTLS data related to KMIP HSM authentication.
pub enum KmipMtlsAuthData<'a> {
    ClientCertificate(&'a [u8]),
    ClientKey(&'a [u8]),
    ServerCertificate(&'a [u8]),
    CaCertificate(&'a [u8]),
}
