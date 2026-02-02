//! Zone storage for [Cascade].
//!
//! [Cascade]: https://nlnetlabs.nl/projects/cascade
//!
//! The zone store is an essential part of Cascade. It provides the following
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
//! stored zones. It is particularly tailored to parallelized signing.
//!
//! # Design
//!
//! A zone's _contents_ are the DNS records making up the zone. Those records
//! can change over time, leading to different versions, or "instances", of a
//! zone. The zone store organizes its data based on zone instances.
//!
//! Cascade's primary function is to sign zones, transforming an unsigned
//! instance of a zone into a signed one. The signed instance will have all
//! the records of the unsigned one, but adds special signing-related records.
//! The zone store tracks both signed and unsigned instances of zones; signed
//! instances point to the unsigned instance they were created from.
//!
//! In general, it is expected that consecutive instances of a zone (whether
//! signed or unsigned) have few changes between them. The zone store selects
//! an _authoritative instance_ of each zone, compromising signed and unsigned
//! halves; the remaining instances are stored as diffs from this. Older
//! instances of a zone are mostly used as a basis for zone transfers, where
//! their representation as a diff is ideal.
//!
//! Cascade is designed so that there is at most one _upcoming_ instance of a
//! zone at any time. The zone loader and zone signer are capable of building
//! new instances; they do not operate simultaneously. This upcoming instance
//! is expected to have relatively few differences from the authoritative one,
//! and is stored within the same data structure so it can be used efficiently.
//!
//! Authoritative instances are stored in absolute terms, and use specialized
//! data structures for (memory and runtime) efficiency. These are described
//! below.
//!
//! ## Structure
//!
//! Operations on zone contents will typically use the different sets of records
//! in different ways, and separating them at this level is helpful for noticing
//! how different types of records get used.
//!
//! The authoritative contents of a zone are broken down into the following
//! categories:
//!
//! - **Apex records**: These live at the top of the zone and have special
//!   meaning/semantics. Storing them separately makes them easier to access.
//!
//! - **Basic records**: These make up the vast majority of unsigned zone
//!   contents.
//!
//! - **Basic record signatures**.
//!
//! - **Zone cuts**: These are the `NS` and `DS` records delimiting this zone
//!   from its descendants. These are the biggest component of large TLD zones,
//!   and are important to identify for most traversals of a zone.
//!
//! - **Obscured records**: These records lie below zone cuts, and while part of
//!   the zone, are not considered authoritative for the zone. This includes
//!   glue records, and is often ignored (e.g. during signing).
//!
//! - **NSEC and NSEC3 records**: These records identify non-existent portions
//!   of the zone, and are signed to establish the authenticity of `NXDOMAIN`
//!   responses to DNS queries. They are subject to special lookups and so
//!   have special representations.
//!
//! - **NSEC/NSEC3 record signatures**.
//!
//! - **The owner tree**: This is not a set of records, but instead identifies
//!   all record owner names in the zone. It is important for certain lookups
//!   (e.g. to find the descendants of a particular owner) that appear rarely
//!   but need relatively efficient implementation.
//!
//! ## Implementation
//!
//! Each of the defined categories uses a special representation for greater
//! efficiency. Different categories are used in different ways, and so have
//! different needs.
//!
//! - Apex records are stored simply; there is a small, constant number of them,
//!   making them trivial to store and look up. They don't need optimization.
//!
//! - Basic records are stored in a hash table, mapping `(owner, RRtype)` to
//!   `RRset` data. Lookups for specific records are very efficient, and the
//!   records can be traversed in parallel.
//!
//!   At the moment, all record types use the same representation, where they
//!   are serialized in the wire format. These records are relatively uncommon
//!   in large TLD zones and so rarely impact memory use.
//!
//! - `NS` records make up the vast majority of large (unsigned) TLD zones.
//!   They are stored in a hash table, mapping owner names to `RRset` data.
//!
//!   `NS` records are typically provided by domain registrars, and they tend to
//!   use the same set of name servers for all their zones. It is very common
//!   to find the same `NS` record set repeated many times in a TLD zone. For
//!   this reason, those record sets are deduplicated and identified by 32-bit
//!   integers. The actual name server lists are stored separately.
//!
//! - While `DS` records are associated with `NS` records, they are not always
//!   present. To avoid adding to the overhead of `NS` records, they are stored
//!   in a separate hash table, with the same mapping.
//!
//! - Obscured records are stored in a hash table, mapping `(owner, RRtype)` to
//!   `RRset` data. Lookups for specific records (e.g. glue for a nameserver)
//!   are fast.
//!
//!   Obscured records tend to be rare and don't need significant optimization
//!   effort. Still, `A` and `AAAA` records are very common here, and it may
//!   be worthwhile to provide specialized representations for them.
//!
//! - NSEC records are stored in a B-tree, sorted by owner name. This tree
//!   represents the NSEC chain for the zone. As a B-tree, it is efficient
//!   to query for the "nearest" or "next" NSEC record.
//!
//!   The data for these records includes the next name in the NSEC chain;
//!   since the tree represents the chain, those next-name fields can be
//!   omitted entirely.
//!
//! - NSEC3 records are stored in a specialized hash table. The leading bits
//!   of the NSEC3 hash (which are naturally uniformly distributed) are used to
//!   index the table. The hash table uses linear probing and maintains the
//!   ordering of entries in probe sequences. This provides fast lookups for
//!   the same "nearest" and "next" queries.
//!
//! - The owner tree is implemented as a hash table, mapping owner names to
//!   nodes. These nodes point to a descendant of that owner name in the tree
//!   (if any); they also form a linked list with sibling nodes. These provide
//!   a fast-enough implementation for discovering the descendants of owner
//!   names; this is important in rare cases involving obscured records.
//!
//! - Signature records (i.e. `RRsig`s) are stored in the same kind of data
//!   structure as the records they sign. While the signature material cannot
//!   be optimized, many of the other fields can be deduplicated.

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

mod builder;
pub use builder::{SignedZoneBuilder, SignedZoneBuilt, UnsignedZoneBuilt, ZoneBuilder, ZoneBuilt};

mod viewer;
pub use viewer::{UnsignedZoneReviewer, ZoneReviewer, ZoneViewer};

mod cleaner;
pub use cleaner::{SignedZoneCleaned, SignedZoneCleaner, ZoneCleaned, ZoneCleaner};

mod data;
use data::{Data, InstanceData};

mod diff;
pub use diff::DiffData;

mod reader;
pub use reader::{SignedZoneReader, UnsignedZoneReader};

mod writer;
pub use writer::{
    PatchError, ReplaceError, SignedZonePatcher, SignedZoneReplacer, UnsignedZonePatcher,
    UnsignedZoneReplacer,
};

//============ Helpers =========================================================

pub type OldName = domain::base::ParsedName<bytes::Bytes>;
pub type OldRecordData = domain::rdata::ZoneRecordData<bytes::Bytes, OldName>;
pub type OldRecord = domain::base::Record<OldName, OldRecordData>;

//----------- Record -----------------------------------------------------------

/// A DNS record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegularRecord(pub domain::new::base::Record<Box<RevName>, BoxedRecordData>);

impl PartialOrd for RegularRecord {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RegularRecord {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        (&self.rname, self.rtype, self.ttl)
            .cmp(&(&other.rname, other.rtype, other.ttl))
            .then_with(|| self.rdata.cmp_canonical(&other.rdata))
    }
}

impl Deref for RegularRecord {
    type Target = domain::new::base::Record<Box<RevName>, BoxedRecordData>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RegularRecord {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<OldRecord> for RegularRecord {
    fn from(value: OldRecord) -> Self {
        let mut bytes = Vec::new();
        value.compose(&mut bytes).unwrap();
        let record = domain::new::base::Record::parse_bytes(&bytes)
            .expect("'Record' serializes records correctly")
            .transform(|name: RevNameBuf| name.unsized_copy_into(), |data| data);
        RegularRecord(record)
    }
}

impl From<RegularRecord> for OldRecord {
    fn from(value: RegularRecord) -> Self {
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
