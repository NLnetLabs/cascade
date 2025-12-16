//! Representing zone data absolutely.

use std::{collections::BTreeMap, fmt};

use domain::new::{
    base::{RType, TTL, name::RevName},
    rdata::BoxedRecordData,
};

//----------- AbsUnsignedData --------------------------------------------------

/// The data of the unsigned authoritative instance of a zone.
pub struct AbsUnsignedData {
    /// The records.
    pub records: BTreeMap<(Box<RevName>, RType), (TTL, Vec<BoxedRecordData>)>,
}

impl fmt::Debug for AbsUnsignedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbsUnsignedData").finish_non_exhaustive()
    }
}

//----------- AbsSignedData ----------------------------------------------------

/// The data of the signed authoritative instance of a zone.
pub struct AbsSignedData {
    /// The records.
    pub records: BTreeMap<(Box<RevName>, RType), (TTL, Vec<BoxedRecordData>)>,
}

impl fmt::Debug for AbsSignedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbsSignedData").finish_non_exhaustive()
    }
}
