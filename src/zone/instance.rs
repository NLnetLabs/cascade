//! Instances of zones.
//!
//! An instance of a zone is an immutable snapshot of its contents (its
//! DNS records).  Instances are not a native DNS concept, but they are a
//! generalized version of SOA serial numbers, with stricter semantics.
//!
//! Cascade differentiates between unsigned and signed instances.  It loads
//! unsigned instances from an external source, and (with few exceptions) it
//! generates signed instances itself.
//
// TODO: Instance IDs: hashes or counters or somewhere in between?

use std::{collections::VecDeque, fmt, sync::Arc};

use cascade_zonedata::{AbsData, RelSignedData, RelUnsignedData};

use crate::zone::review::ApprovedReviewState;

//----------- Instances --------------------------------------------------------

/// The (signed and unsigned) instances of a zone.
#[derive(Default)]
pub struct Instances {
    /// The current instance, if any.
    pub current: Option<CurrentInstance>,

    /// The data of the current instance.
    ///
    /// This field is available even if an instance is not (although it is then
    /// empty).  It is an expensive data structure and gets reused even if the
    /// current instance is deleted (if the data for a zone is cleared).
    pub current_data: Arc<AbsData>,

    /// Old instances, if any.
    pub old: OldInstances,
}

impl fmt::Debug for Instances {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Instances")
    }
}

//----------- Current ----------------------------------------------------------

/// The current instance of a zone.
pub struct CurrentInstance {
    /// The unsigned instance.
    pub unsigned: CurrentUnsignedInstance,

    /// The signed instance, if any.
    pub signed: Option<CurrentSignedInstance>,
}

/// The current unsigned instance of a zone, if any.
pub struct CurrentUnsignedInstance {
    /// The review state of the zone.
    pub review: ApprovedReviewState,
}

/// The current signed instance of a zone, if any.
pub struct CurrentSignedInstance {
    /// The review state of the zone.
    pub review: ApprovedReviewState,
}

//----------- Old --------------------------------------------------------------

/// Old (signed and unsigned) instances of a zone.
///
/// Old instances have been replaced by newer ones, which have been reviewed and
/// have become the authoritative ones for the zone.  These can no longer be
/// changed, but they can be removed as they accumulate over time.
#[derive(Default)]
pub struct OldInstances {
    /// The underlying instances.
    ///
    /// This contains both signed and unsigned instances.  Instances are
    /// sorted from oldest (the front of the queue) to newest (the back of the
    /// queue).  Both signed and unsigned instances are relative to the closest
    /// succeeding unsigned instance.
    inner: VecDeque<OldInstance>,
}

/// An old instance of a zone.
enum OldInstance {
    /// An old unsigned instance.
    Unsigned(Arc<OldUnsignedInstance>),

    /// An old signed instance.
    Signed(Arc<OldSignedInstance>),
}

/// An old unsigned instance of a zone.
pub struct OldUnsignedInstance {
    /// The review state of the zone.
    pub review: ApprovedReviewState,

    /// The data of the instance.
    ///
    /// It is expressed as a diff from the contents of this instance to the
    /// contents of the closest succeeding unsigned instance.
    pub data: RelUnsignedData,
}

/// An old signed instance of a zone.
pub struct OldSignedInstance {
    /// The review state of the zone.
    pub review: ApprovedReviewState,

    /// The data of the instance.
    ///
    /// It is expressed as a diff from the contents of this instance to the
    /// contents of the closest succeeding signed instance.  It is also relative
    /// to the closest succeeding unsigned instance.
    pub data: RelSignedData,
}
