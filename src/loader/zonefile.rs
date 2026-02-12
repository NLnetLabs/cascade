//! Loading zones from zonefiles.

use std::{
    fmt,
    fs::File,
    sync::{Arc, atomic::Ordering::Relaxed},
};

use bytes::BufMut;
use camino::Utf8Path;
use cascade_zonedata::{RegularRecord, ReplaceError, SoaRecord, ZoneBuilder};
use domain::{
    base::{ToName, iana::Class},
    new::{
        base::{Record, name::RevNameBuf, wire::ParseBytes},
        rdata::{BoxedRecordData, RecordData},
    },
    utils::dst::UnsizedCopy,
    zonefile::inplace,
};

use crate::{loader::ActiveLoadMetrics, zone::Zone};

//----------- load() -----------------------------------------------------------

/// Load a zone from a zonefile.
///
/// This will always read the entire zone, regardless of the serial in the SOA.
pub fn load(
    zone: &Arc<Zone>,
    path: &Utf8Path,
    builder: &mut ZoneBuilder,
    metrics: &ActiveLoadMetrics,
) -> Result<(), Error> {
    let mut reader = make_reader(zone, path, metrics)?;
    let mut writer = builder.replace_unsigned().unwrap();

    // A scratch buffer that we can use to parse
    let mut buf = Vec::new();

    // Parse all the records, extracting the SOA. We always read the whole zone.
    while let Some(record) = parse_record(&mut buf, zone, &mut reader)? {
        metrics.num_loaded_records.fetch_add(1, Relaxed);
        match record {
            Parsed::Soa(soa) => {
                writer.set_soa(soa)?;
            }
            Parsed::Record(record) => writer.add(record)?,
        }
    }

    writer.apply()?;
    Ok(())
}

//----------- Helper functions -------------------------------------------------

/// Make a zonefile reader for the file at the given path
///
/// It will add the size of the file to the byte count of the metrics.
fn make_reader(
    zone: &Arc<Zone>,
    path: &Utf8Path,
    metrics: &ActiveLoadMetrics,
) -> Result<inplace::Zonefile, Error> {
    // Open the zonefile.
    let mut file = File::open(path).map_err(Error::Open)?;

    let file_len = file.metadata().map_err(Error::Open)?.len();

    metrics
        .num_loaded_bytes
        .fetch_add(file_len as usize, Relaxed);

    let mut zone_file = inplace::Zonefile::with_capacity(file_len as usize).writer();

    std::io::copy(&mut file, &mut zone_file).map_err(Error::Open)?;

    let mut reader = zone_file.into_inner();
    reader.set_origin(zone.name.clone());
    reader.set_default_class(Class::IN);

    Ok(reader)
}

/// Parse a single record from a zonefile
fn parse_record(
    buf: &mut Vec<u8>,
    zone: &Arc<Zone>,
    reader: &mut inplace::Zonefile,
) -> Result<Option<Parsed>, Error> {
    buf.clear();

    let Some(entry) = reader.next_entry().map_err(Error::Misformatted)? else {
        return Ok(None);
    };
    let record = match entry {
        inplace::Entry::Record(record) => record,
        inplace::Entry::Include { .. } => return Err(Error::UnsupportedInclude),
    };

    let record_name = record.owner();

    record.compose(buf).unwrap();
    let record = Record::<_, BoxedRecordData>::parse_bytes(buf)
        .expect("'Record' serializes records correctly")
        .transform(|name: RevNameBuf| name.unsized_copy_into(), |data| data);

    if let RecordData::Soa(new_soa) = record.rdata.get() {
        // We have to compare with an old base name here so we use the record_name
        // instead of record.name.
        if !record_name.name_eq(&zone.name) {
            // TODO: Check this in 'UnsignedZoneReplacer'.
            return Err(Error::MismatchedOrigin);
        }

        let record = Record {
            rname: record.rname,
            rtype: record.rtype,
            rclass: record.rclass,
            ttl: record.ttl,
            rdata: new_soa.map_names(|n| n.unsized_copy_into()),
        };

        let soa_record = SoaRecord(record);

        Ok(Some(Parsed::Soa(soa_record)))
    } else {
        Ok(Some(Parsed::Record(RegularRecord(record))))
    }
}

/// A parsed record.
enum Parsed {
    Soa(SoaRecord),
    Record(RegularRecord),
}

//----------- Error ------------------------------------------------------------

/// An error in loading a zone from a zonefile.
#[derive(Debug)]
pub enum Error {
    /// The zonefile could not be opened.
    Open(std::io::Error),

    /// The zonefile was misformatted.
    Misformatted(inplace::Error),

    /// The zonefile contains a SOA record for a different zone.
    MismatchedOrigin,

    /// Zonefile include directives are not supported.
    UnsupportedInclude,

    /// The zone data could not be written.
    Write(ReplaceError),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Open(error) => Some(error),
            Error::Misformatted(error) => Some(error),
            Error::MismatchedOrigin => None,
            Error::UnsupportedInclude => None,
            Error::Write(error) => Some(error),
        }
    }
}

impl From<ReplaceError> for Error {
    fn from(error: ReplaceError) -> Self {
        Self::Write(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Open(error) => error.fmt(f),
            Error::Misformatted(error) => error.fmt(f),
            Error::MismatchedOrigin => write!(f, "the zonefile has the wrong origin name"),
            Error::UnsupportedInclude => write!(f, "zonefile include directives are not supported"),
            Error::Write(ReplaceError::MissingSoa) => {
                write!(f, "the zonefile does not contain a SOA record")
            }
            Error::Write(ReplaceError::MultipleSoas) => {
                write!(f, "the zonefile contain multiple SOA records")
            }
        }
    }
}
