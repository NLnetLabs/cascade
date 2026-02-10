//! States for the zone data storage.

use std::sync::Arc;

use crate::{DiffData, data::Data};

#[cfg(doc)]
use super::ZoneDataStorage;

#[cfg(doc)]
use crate::{
    SignedZoneBuilder, SignedZoneCleaner, UnsignedZonePersister, UnsignedZoneReviewer, ZoneBuilder,
    ZoneCleaner, ZonePersister, ZoneReviewer, ZoneViewer,
};

//----------- PassiveStorage ---------------------------------------------------

/// The [`ZoneDataStorage::Passive`] state.
///
/// This is the most common state.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is no upcoming instance of the zone.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::Passive`] can transition into:
///
/// - [`ZoneDataStorage::Building`], to load a new instance.
///
/// - [`ZoneDataStorage::BuildingResigned`], to resign the current instance.
pub struct PassiveStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- BuildingStorage --------------------------------------------------

/// The [`ZoneDataStorage::Building`] state.
///
/// This is used to load a new instance of the zone (whether it only has an
/// unsigned component, which is the common case, or it has both an unsigned and
/// a signed component, as in pass-through mode).
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these are optional, but a signed component cannot exist
/// without an unsigned one.
///
/// There is an upcoming instance of the zone. Its unsigned component, and
/// possibly its signed component, are being built.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// The [`ZoneBuilder`] references the current authoritative instance and builds
/// the upcoming instance.
///
/// There is no [`SignedZoneBuilder`], [`ZoneCleaner`], [`SignedZoneCleaner`],
/// [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given [`UnsignedZoneBuilt`], [`ZoneDataStorage::Building`] transitions into
/// [`ZoneDataStorage::PendingUnsignedReview`], to review the built unsigned
/// component.
///
/// Given [`ZoneBuilt`], [`ZoneDataStorage::Building`] transitions into
/// [`ZoneDataStorage::PendingWholeReview`], to review the whole built instance.
///
/// Given the [`ZoneBuilder`], [`ZoneDataStorage::Building`] can transition into
/// [`ZoneDataStorage::Cleaning`], to clean up leftover data on failure.
pub struct BuildingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- BuildingSignedStorage --------------------------------------------

/// The [`ZoneDataStorage::BuildingSigned`] state.
///
/// This is used to sign a freshly-loaded unsigned instance of the zone.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has a prepared unsigned
/// component (which may be empty). Its signed component is being built.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] point to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] points to the prepared unsigned instance.
///
/// The [`SignedZoneBuilder`] references the current authoritative instance
/// and the unsigned component of the upcoming instance, and builds the signed
/// component of the upcoming instance.
///
/// There is no [`ZoneBuilder`], [`ZoneCleaner`], [`SignedZoneCleaner`],
/// [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given [`ZoneBuilt`], [`ZoneDataStorage::BuildingSigned`] transitions
/// into [`ZoneDataStorage::PendingSignedReview`], to review the built signed
/// component.
///
/// Given the [`SignedZoneBuilder`], [`ZoneDataStorage::BuildingSigned`] can
/// transition into:
///
/// - [`ZoneDataStorage::CleaningSigned`], to clean up leftover data on failure.
///
/// - [`ZoneDataStorage::PendingUnsignedClean`], to clean up the whole instance.
pub struct BuildingSignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,
}

//----------- BuildingResignedStorage ------------------------------------------

/// The [`ZoneDataStorage::BuildingResigned`] state.
///
/// This is used to resign an existing unsigned instance of the zone.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has a non-empty
/// unsigned component, and a possibly-empty signed component.
///
/// There is an upcoming instance of the zone. It re-uses the unsigned component
/// of the current authoritative instance. Its signed component is being built.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// The [`SignedZoneBuilder`] references the current authoritative instance and
/// builds (the signed component of) the upcoming instance.
///
/// There is no [`ZoneBuilder`], [`ZoneCleaner`], [`SignedZoneCleaner`],
/// [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given [`SignedZoneBuilt`], [`ZoneDataStorage::BuildingResigned`] transitions
/// into [`ZoneDataStorage::PendingResignedReview`], to review the built
/// instance.
///
/// Given the [`SignedZoneBuilder`], [`ZoneDataStorage::BuildingResigned`] can
/// transition into [`ZoneDataStorage::Cleaning`], to clean up leftover data
/// on failure.
pub struct BuildingResignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- PendingUnsignedReviewStorage -------------------------------------

/// The [`ZoneDataStorage::PendingUnsignedReview`] state.
///
/// This is an intermediate state, where an unsigned instance has been built but
/// is waiting to be reviewed.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has an unsigned component
/// (which may be empty), and no signed component.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`UnsignedZoneReviewer`],
/// [`ZoneDataStorage::PendingUnsignedReview`] transitions into
/// [`ZoneDataStorage::ReviewingUnsigned`].
pub struct PendingUnsignedReviewStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,
}

//----------- PendingSignedReviewStorage ---------------------------------------

/// The [`ZoneDataStorage::PendingSignedReview`] state.
///
/// This is an intermediate state, where an instance has been signed and the
/// signed component is waiting for review.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] points to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] points to the upcoming instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`ZoneReviewer`], [`ZoneDataStorage::PendingSignedReview`]
/// transitions into [`ZoneDataStorage::ReviewingSigned`].
pub struct PendingSignedReviewStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- PendingResignedReviewStorage -------------------------------------

/// The [`ZoneDataStorage::PendingResignedReview`] state.
///
/// This is an intermediate state, where an instance has been resigned and the
/// signed component is waiting for review.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has a non-empty
/// unsigned component, and a possibly-empty signed component.
///
/// There is an upcoming instance of the zone. It re-uses the unsigned component
/// of the current authoritative instance. It has a (possibly empty) signed
/// component.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`ZoneReviewer`], [`ZoneDataStorage::PendingResignedReview`]
/// transitions into [`ZoneDataStorage::ReviewingResigned`].
pub struct PendingResignedReviewStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- PendingWholeReviewStorage ----------------------------------------

/// The [`ZoneDataStorage::PendingWholeReview`] state.
///
/// This is an intermediate state, where an instance has been loaded in
/// pass-through mode and is pending review.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`UnsignedZoneReviewer`],
/// [`ZoneDataStorage::PendingWholeReview`] transitions into
/// [`ZoneDataStorage::PendingWholeSignedReview`].
pub struct PendingWholeReviewStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- PendingWholeSignedReviewStorage ----------------------------------

/// The [`ZoneDataStorage::PendingWholeSignedReview`] state.
///
/// This is an intermediate state, where an instance has been loaded in
/// pass-through mode and is pending review.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] point to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] points to the upcoming instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`ZoneReviewer`], [`ZoneDataStorage::PendingWholeSignedReview`]
/// transitions into [`ZoneDataStorage::ReviewingWhole`].
pub struct PendingWholeSignedReviewStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- ReviewingUnsignedStorage -----------------------------------------

/// The [`ZoneDataStorage::ReviewingUnsigned`] state.
///
/// This is used to review a freshly-loaded unsigned instance of a zone.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has an unsigned component
/// (which may be empty), and no signed component.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] point to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] points to the prepared unsigned instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::ReviewingUnsigned`] can transition into:
///
/// - [`ZoneDataStorage::PersistingUnsigned`], to persist the unsigned component
///   once it is approved.
///
/// - [`ZoneDataStorage::PendingUnsignedClean`], to clean up the rejected
/// instance.
pub struct ReviewingUnsignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,
}

//----------- ReviewingSignedStorage -------------------------------------------

/// The [`ZoneDataStorage::ReviewingSigned`] state.
///
/// This is used to review a freshly-signed instance of a zone.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current authoritative instance.
///
/// The [`UnsignedZoneReviewer`] and [`ZoneReviewer`] point to the upcoming
/// instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::ReviewingSigned`] can transition into:
///
/// - [`ZoneDataStorage::Persisting`], to persist the signed component once it
///   is approved.
///
/// - [`ZoneDataStorage::PendingSignedClean`], to clean up the rejected signed
///   component.
///
/// - [`ZoneDataStorage::PendingWholeClean`], to clean up the whole upcoming
///   instance.
pub struct ReviewingSignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- ReviewingResignedStorage -----------------------------------------

/// The [`ZoneDataStorage::ReviewingResigned`] state.
///
/// This is used to review a freshly-resigned instance of a zone.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has a non-empty
/// unsigned component, and a possibly-empty signed component.
///
/// There is an upcoming instance of the zone. It re-uses the unsigned component
/// of the current authoritative instance. It has a (possibly empty) signed
/// component.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`] and [`ZoneViewer`] points to the current
/// authoritative instance.
///
/// The [`ZoneReviewer`] points to the upcoming instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::ReviewingResigned`] can transition into:
///
/// - [`ZoneDataStorage::Persisting`], to persist the approved instance.
///
/// - [`ZoneDataStorage::PendingResignedClean`], to clean up the rejected
///   instance.
pub struct ReviewingResignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- ReviewingWholeStorage --------------------------------------------

/// The [`ZoneDataStorage::ReviewingWhole`] state.
///
/// This is used to review a freshly-loaded instance of a zone in pass-through
/// mode (where it includes both an unsigned and a signed component).
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current authoritative instance.
///
/// The [`UnsignedZoneReviewer`] and [`ZoneReviewer`] point to the upcoming
/// instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::ReviewingResigned`] can transition into:
///
/// - [`ZoneDataStorage::Persisting`], to persist the approved instance.
///
/// - [`ZoneDataStorage::PendingWholeClean`], to clean up the rejected instance.
pub struct ReviewingWholeStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- PersistingUnsignedStorage ----------------------------------------

/// The [`ZoneDataStorage::PersistingUnsigned`] state.
///
/// This is used to persist an approved unsigned instance of the zone before it
/// is signed.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has a (possibly empty)
/// unsigned component, and no signed component.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] point to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] and [`UnsignedZonePersister`] point to the
/// prepared unsigned instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given [`UnsignedZonePersisted`], [`ZoneDataStorage::PersistingUnsigned`] can
/// transition into:
///
/// - [`ZoneDataStorage::BuildingSigned`], to sign the now-persisted instance.
pub struct PersistingUnsignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,
}

//----------- PersistingStorage ------------------------------------------------

/// The [`ZoneDataStorage::Persisting`] state.
///
/// This is used to persist an approved instance of the zone before it becomes
/// authoritative.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has a (possibly empty)
/// unsigned component, or it re-uses the unsigned component of the current
/// authoritative instance. It has a (possibly empty) signed component; a
/// non-empty signed component cannot exist without an unsigned one.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current authoritative instance.
///
/// The [`ZoneReviewer`], [`UnsignedZoneReviewer`], and [`ZonePersister`] point
/// to the prepared unsigned instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], or [`UnsignedZonePersister`].
///
/// ## Transitions
///
/// Given [`ZonePersisted`], [`ZoneDataStorage::Persisting`] can transition
/// into:
///
/// - [`ZoneDataStorage::Switching`], to make the now-persisted instance
///   authoritative.
pub struct PersistingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The index of the next unsigned instance.
    pub(super) next_unsigned_index: bool,

    /// The index of the next signed instance.
    pub(super) next_signed_index: bool,
}

//----------- PendingUnsignedCleanStorage --------------------------------------

/// The [`ZoneDataStorage::PendingUnsignedClean`] state.
///
/// This is an intermediate state, where an instance has been rejected or
/// replaced and is waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an old instance of the zone. It has unsigned and signed components;
/// these may be empty, but a non-empty signed component cannot exist without an
/// unsigned one. It needs to be cleaned out.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] point to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] points to the old instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`UnsignedZoneReviewer`],
/// [`ZoneDataStorage::PendingUnsignedClean`] transitions into
/// [`ZoneDataStorage::Cleaning`].
pub struct PendingUnsignedCleanStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- PendingSignedCleanStorage ----------------------------------------

/// The [`ZoneDataStorage::PendingSignedClean`] state.
///
/// This is an intermediate state, where an instance has been rejected and is
/// waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one. Its signed component needs to be cleaned out.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current authoritative instance.
///
/// The [`UnsignedZoneReviewer`] and [`ZoneReviewer`] point to the upcoming
/// instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`ZoneReviewer`], [`ZoneDataStorage::PendingSignedClean`]
/// transitions into [`ZoneDataStorage::CleaningSigned`].
pub struct PendingSignedCleanStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,
}

//----------- PendingResignedCleanStorage --------------------------------------

/// The [`ZoneDataStorage::PendingResignedClean`] state.
///
/// This is an intermediate state, where an instance has been rejected or
/// replaced and is waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an old instance of the zone. It re-uses the unsigned component
/// of the current authoritative instance. It has a (possibly empty) signed
/// component. It needs to be cleaned out.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`] and [`ZoneViewer`] point to the current
/// authoritative instance.
///
/// The [`ZoneReviewer`] points to the old instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`ZoneReviewer`], [`ZoneDataStorage::PendingResignedClean`]
/// transitions into [`ZoneDataStorage::Cleaning`].
pub struct PendingResignedCleanStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- PendingWholeCleanStorage -----------------------------------------

/// The [`ZoneDataStorage::PendingWholeClean`] state.
///
/// This is an intermediate state, where an instance has been rejected or
/// replaced and is waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an old instance of the zone. It has unsigned and signed components;
/// these may be empty, but a non-empty signed component cannot exist without an
/// unsigned one. It needs to be cleaned out.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current authoritative instance.
///
/// The [`UnsignedZoneReviewer`] and [`ZoneReviewer`] point to the old instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the old [`ZoneReviewer`], [`ZoneDataStorage::PendingWholeClean`]
/// transitions into [`ZoneDataStorage::PendingUnsignedClean`].
pub struct PendingWholeCleanStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- CleaningStorage --------------------------------------------------

/// The [`ZoneDataStorage::Cleaning`] state.
///
/// This is used to clean up a previous instance, whether it could not be built
/// successfully, it was rejected, or a different instance has been switched to.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an old instance of the zone. It has unsigned and signed components;
/// these may be empty, but a non-empty signed component cannot exist without an
/// unsigned one. It is being cleaned out.
///
/// ## Access
///
/// The [`UnsignedZoneReviewer`], [`ZoneReviewer`], and [`ZoneViewer`] all point
/// to the current authoritative instance.
///
/// The [`ZoneCleaner`] points to the old instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`SignedZoneCleaner`],
/// [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given [`ZoneCleaned`], [`ZoneDataStorage::Cleaning`] transitions into
/// [`ZoneDataStorage::Passive`].
pub struct CleaningStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- CleaningSignedStorage --------------------------------------------

/// The [`ZoneDataStorage::CleaningSigned`] state.
///
/// This is used to clean up the signed component of an upcoming instance,
/// because it could not be built or it was rejected.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one. The signed component is being cleaned out.
///
/// ## Access
///
/// The [`ZoneReviewer`] and [`ZoneViewer`] point to the current authoritative
/// instance.
///
/// The [`UnsignedZoneReviewer`] points to the prepared unsigned instance.
///
/// The [`SignedZoneCleaner`] points to the signed component of the upcoming
/// instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given [`SignedZoneCleaned`], [`ZoneDataStorage::CleaningSigned`] transitions
/// into [`ZoneDataStorage::BuildingSigned`], to attempt rebuilding the signed
/// component.
pub struct CleaningSignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming unsigned instance.
    pub(super) unsigned_diff: Arc<DiffData>,
}

//----------- SwitchingStorage -------------------------------------------------

/// The [`ZoneDataStorage::Switching`] state.
///
/// This is used to make an approved and persisted instance authoritative.
///
/// ## Data
///
/// There is a current authoritative instance of the zone. It has unsigned and
/// signed components; these may be empty, but a non-empty signed component
/// cannot exist without an unsigned one.
///
/// There is an upcoming instance of the zone. It has unsigned and signed
/// components; these may be empty, but a non-empty signed component cannot
/// exist without an unsigned one. It is being switched to.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current authoritative instance.
///
/// The [`UnsignedZoneReviewer`] and [`ZoneReviewer`] point to the upcoming
/// instance.
///
/// There is no [`ZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`UnsignedZonePersister`], or [`ZonePersister`].
///
/// ## Transitions
///
/// Given the [`ZoneViewer`], [`ZoneDataStorage::Switching`] transitions into
/// [`ZoneDataStorage::Cleaning`], to remove the old instance.
pub struct SwitchingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current unsigned instance.
    pub(super) curr_unsigned_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The index of the next unsigned instance.
    pub(super) next_unsigned_index: bool,

    /// The index of the next signed instance.
    pub(super) next_signed_index: bool,
}
