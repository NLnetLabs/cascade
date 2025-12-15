//! Loading zones from zonefiles.

use std::{
    fmt,
    fs::File,
    sync::{Arc, atomic::Ordering::Relaxed},
};

use bytes::BufMut;
use camino::Utf8Path;
use domain::{
    base::{ToName, iana::Class},
    new::{
        base::{Record, name::RevNameBuf, wire::ParseBytes},
        rdata::{BoxedRecordData, RecordData},
    },
    utils::dst::UnsizedCopy,
    zonefile::inplace,
};

use crate::zone::{
    Zone,
    contents::{RegularRecord, SoaRecord, Uncompressed},
    loader::LoaderMetrics,
};

enum Parsed {
    Soa(SoaRecord),
    Record(RegularRecord),
}

//----------- load() -----------------------------------------------------------

/// Load a zone from a zonefile.
///
/// This will always read the entire zone, regardless of the serial in the SOA.
pub fn load(
    metrics: &LoaderMetrics,
    zone: &Arc<Zone>,
    path: &Utf8Path,
) -> Result<Uncompressed, Error> {
    let mut reader = make_reader(metrics, zone, path)?;

    // The collection of all the records that we will parse
    let mut all = Vec::<RegularRecord>::new();

    // A scratch buffer that we can use to parse
    let mut buf = Vec::new();

    // The SOA of the file
    let mut soa = None;

    // Parse all the records, extracting the SOA. We always read the whole zone.
    while let Some(record) = parse_record(&mut buf, zone, &mut reader)? {
        metrics.record_count.fetch_add(1, Relaxed);
        match record {
            Parsed::Soa(soa_record) => {
                if soa.is_some() {
                    return Err(Error::MultipleSoaRecords);
                }
                soa = Some(soa_record);
            }
            Parsed::Record(regular_record) => all.push(regular_record),
        }
    }

    let Some(soa) = soa else {
        return Err(Error::MissingSoaRecord);
    };

    // Finalize the remote copy.
    all.sort_unstable();
    let all = all.into_boxed_slice();

    Ok(Uncompressed { soa, all })
}

//----------- Helper functions -------------------------------------------------

/// Make a zonefile reader for the file at the given path
///
/// It will add the zize ofthe file to the byte count of the metrics.
fn make_reader(
    metrics: &LoaderMetrics,
    zone: &Arc<Zone>,
    path: &Utf8Path,
) -> Result<inplace::Zonefile, Error> {
    // Open the zonefile.
    let mut file = File::open(path).map_err(Error::Open)?;

    let file_len = file.metadata().map_err(Error::Open)?.len();

    metrics.byte_count.fetch_add(file_len as usize, Relaxed);

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

//----------- Error ------------------------------------------------------------

/// An error in loading a zone from a zonefile.
#[derive(Debug)]
pub enum Error {
    /// The zonefile could not be opened.
    Open(std::io::Error),

    /// The zonefile was misformatted.
    Misformatted(inplace::Error),

    /// The zonefile starts with a SOA record for a different zone.
    MismatchedOrigin,

    /// The zonefile did not contain a SOA record.
    MissingSoaRecord,

    /// The zonefile did not start with a SOA record.
    MultipleSoaRecords,

    /// Zonefile include directories are not supported.
    UnsupportedInclude,
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Open(error) => Some(error),
            Error::Misformatted(error) => Some(error),
            Error::MismatchedOrigin => None,
            Error::MissingSoaRecord => None,
            Error::MultipleSoaRecords => None,
            Error::UnsupportedInclude => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Open(error) => error.fmt(f),
            Error::Misformatted(error) => error.fmt(f),
            Error::MismatchedOrigin => write!(f, "the zonefile has the wrong origin name"),
            Error::MissingSoaRecord => write!(f, "the zonefile does not contain a SOA record"),
            Error::MultipleSoaRecords => write!(f, "the zonefile contain multiple SOA records"),
            Error::UnsupportedInclude => write!(f, "zonefile include directives are not supported"),
        }
    }
}
