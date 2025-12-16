//! Representing zone data relatively.

use std::collections::BTreeMap;

use domain::new::{
    base::{RType, TTL, name::RevName},
    rdata::BoxedRecordData,
};

//----------- RelUnsignedData --------------------------------------------------

/// The data of an unsigned zone, as a diff relative to some base.
pub struct RelUnsignedData {
    /// Record sets to remove from the base.
    pub remove: BTreeMap<(Box<RevName>, RType), (TTL, Vec<BoxedRecordData>)>,

    /// Record sets to add to the base.
    pub add: BTreeMap<(Box<RevName>, RType), (TTL, Vec<BoxedRecordData>)>,
}

//----------- RelSignedData ----------------------------------------------------

/// The data of a signed zone, as a diff relative to some base.
pub struct RelSignedData {
    /// Record sets to remove from the base.
    pub remove: BTreeMap<(Box<RevName>, RType), (TTL, Vec<BoxedRecordData>)>,

    /// Record sets to add to the base.
    pub add: BTreeMap<(Box<RevName>, RType), (TTL, Vec<BoxedRecordData>)>,
}
