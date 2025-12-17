//! Zone storage for [Cascade].
//!
//! [Cascade]: https://nlnetlabs.nl/projects/cascade
//!
//! The zone store is an essential part of Cascade.  It provides the following
//! functionality:
//!
//! - Storage for the zones loaded by Cascade.
//! - Storage for the signed versions of those zones.
//! - Storage for candidate versions of a zone and rollback.
//! - Identification of different versions of a zone.
//! - Storage for diffs between versions of a zone.
//! - Efficient lookups and traversals over zones.
//! - Persistence of zone data (to/from disk).
//!
//! The zone store is highly memory-efficient and offers parallelized access to
//! stored zones.  It is particularly tailored to parallelized signing.

mod abs;
pub use abs::{AbsSignedData, AbsUnsignedData};

mod rel;
use std::{
    cmp, fmt,
    iter::Peekable,
    ops::{Deref, DerefMut},
};

use domain::{
    new::{
        base::{
            CanonicalRecordData,
            name::{Name, NameBuf, RevName, RevNameBuf},
            wire::{BuildBytes, ParseBytes},
        },
        rdata::{BoxedRecordData, Soa},
    },
    utils::dst::UnsizedCopy,
};

pub use rel::{RelSignedData, RelUnsignedData};

//============ Helpers =========================================================

pub type OldName = domain::base::ParsedName<bytes::Bytes>;
pub type OldRecordData = domain::rdata::ZoneRecordData<bytes::Bytes, OldName>;
pub type OldRecord = domain::base::Record<OldName, OldRecordData>;

//----------- Record -----------------------------------------------------------

/// A DNS record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record(domain::new::base::Record<Box<RevName>, BoxedRecordData>);

impl PartialOrd for Record {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Record {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        (&self.rname, self.rtype, self.ttl)
            .cmp(&(&other.rname, other.rtype, other.ttl))
            .then_with(|| self.rdata.cmp_canonical(&other.rdata))
    }
}

impl Deref for Record {
    type Target = domain::new::base::Record<Box<RevName>, BoxedRecordData>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Record {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<OldRecord> for Record {
    fn from(value: OldRecord) -> Self {
        let mut bytes = Vec::new();
        value.compose(&mut bytes).unwrap();
        let record = domain::new::base::Record::parse_bytes(&bytes)
            .expect("'Record' serializes records correctly")
            .transform(|name: RevNameBuf| name.unsized_copy_into(), |data| data);
        Record(record)
    }
}

impl From<Record> for OldRecord {
    fn from(value: Record) -> Self {
        let mut bytes = vec![0u8; value.0.built_bytes_size()];
        value.0.build_bytes(&mut bytes).unwrap();
        let bytes = bytes::Bytes::from(bytes);
        let mut parser = domain::dep::octseq::Parser::from_ref(&bytes);
        OldRecord::parse(&mut parser).unwrap().unwrap()
    }
}

//----------- SoaRecord --------------------------------------------------------

/// A DNS SOA record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoaRecord(pub domain::new::base::Record<Box<RevName>, Soa<Box<Name>>>);

impl PartialOrd for SoaRecord {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SoaRecord {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        (&self.rname, self.rtype, self.ttl)
            .cmp(&(&other.rname, other.rtype, other.ttl))
            .then_with(|| {
                self.rdata
                    .map_names_by_ref(|n| n.as_ref())
                    .cmp_canonical(&other.rdata.map_names_by_ref(|n| n.as_ref()))
            })
    }
}

impl Deref for SoaRecord {
    type Target = domain::new::base::Record<Box<RevName>, Soa<Box<Name>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SoaRecord {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<OldRecord> for SoaRecord {
    fn from(value: OldRecord) -> Self {
        let mut bytes = Vec::new();
        value.compose(&mut bytes).unwrap();
        let record = domain::new::base::Record::parse_bytes(&bytes)
            .expect("'Record' serializes records correctly")
            .transform(
                |name: RevNameBuf| name.unsized_copy_into(),
                |data: Soa<NameBuf>| data.map_names(|name| name.unsized_copy_into()),
            );
        SoaRecord(record)
    }
}

impl From<SoaRecord> for OldRecord {
    fn from(value: SoaRecord) -> Self {
        let mut bytes = vec![0u8; value.0.built_bytes_size()];
        value.0.build_bytes(&mut bytes).unwrap();
        let bytes = bytes::Bytes::from(bytes);
        let mut parser = domain::dep::octseq::Parser::from_ref(&bytes);
        OldRecord::parse(&mut parser).unwrap().unwrap()
    }
}

//----------- merge() ----------------------------------------------------------

/// Merge sorted iterators.
fn merge<T: Ord, I: IntoIterator<Item = T>, const N: usize>(
    iters: [I; N],
) -> impl Iterator<Item = [Option<T>; N]> {
    struct Merge<T: Ord, I: Iterator<Item = T>, const N: usize>([Peekable<I>; N]);

    impl<T: Ord, I: Iterator<Item = T>, const N: usize> Iterator for Merge<T, I, N> {
        type Item = [Option<T>; N];

        fn next(&mut self) -> Option<Self::Item> {
            let set = self.0.each_mut().map(|e| e.peek());
            let min = set.iter().cloned().flatten().min()?;
            let used = set.map(|e| e == Some(min));
            let mut index = 0usize;
            Some(self.0.each_mut().map(|i| {
                let used = used[index];
                index += 1;
                i.next_if(|_| used)
            }))
        }
    }

    Merge(iters.map(|i| i.into_iter().peekable()))
}

//----------- InconsistencyError -----------------------------------------------

/// An inconsistency between instances of a zone.
#[derive(Clone, Debug)]
pub struct InconsistencyError;

impl std::error::Error for InconsistencyError {}

impl fmt::Display for InconsistencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("A change to a zone is inconsistent with its current data")
    }
}
