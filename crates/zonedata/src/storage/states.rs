//! States for the zone data storage.

use std::sync::Arc;

use crate::{DiffData, data::Data};

#[cfg(doc)]
use super::ZoneDataStorage;

#[cfg(doc)]
use crate::{
    LoadedZoneBuilder, LoadedZonePersister, LoadedZoneReviewer, SignedZoneBuilder,
    SignedZoneCleaner, SignedZonePersister, SignedZoneReviewer, ZoneCleaner, ZoneViewer,
};

//----------- PassiveStorage ---------------------------------------------------

/// The [`ZoneDataStorage::Passive`] state.
///
/// This is the most common state.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There is no upcoming instance of the zone.
///
/// ## Access
///
/// The [`LoadedZoneReviewer`], [`SignedZoneReviewer`], and [`ZoneViewer`] all
/// point to the current instances.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::Passive`] can transition into:
///
/// - [`ZoneDataStorage::Loading`], to load a new instance.
///
/// - [`ZoneDataStorage::Signing`], to re-sign the current instance.
pub struct PassiveStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- LoadingStorage ---------------------------------------------------

/// The [`ZoneDataStorage::Loading`] state.
///
/// This is used to load a new instance of the zone.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There is an upcoming loaded instance of the zone.
///
/// ## Access
///
/// The [`LoadedZoneReviewer`], [`SignedZoneReviewer`], and [`ZoneViewer`] all
/// point to the current instances.
///
/// The [`LoadedZoneBuilder`] references the current instance and builds the
/// upcoming instance.
///
/// There is no [`SignedZoneBuilder`], [`ZoneCleaner`], [`SignedZoneCleaner`],
/// [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given [`LoadedZoneBuilt`], [`ZoneDataStorage::Loading`] transitions into
/// [`ZoneDataStorage::ReviewLoadedPending`], to review the built instance.
///
/// Given the [`LoadedZoneBuilder`], [`ZoneDataStorage::Loading`] can transition
/// into [`ZoneDataStorage::Cleaning`], to clean up leftover data on failure.
pub struct LoadingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- SigningStorage ---------------------------------------------------

/// The [`ZoneDataStorage::Signing`] state.
///
/// This is used to sign a freshly loaded instance of the zone, or to re-sign
/// the current instance.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There may be an upcoming loaded instance of the zone (which may be empty).
/// If there isn't one, the current loaded instance is non-empty. There is an
/// upcoming signed instance, which is being built.
///
/// ## Access
///
/// The [`SignedZoneReviewer`] and [`ZoneViewer`] point to the current
/// instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance if it
/// exists, else the current one.
///
/// The [`SignedZoneBuilder`] references the current instances and the upcoming
/// loaded instance (if any), and builds the upcoming signed instance.
///
/// There is no [`LoadedZoneBuilder`], [`ZoneCleaner`], [`SignedZoneCleaner`],
/// [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given [`SignedZoneBuilt`], [`ZoneDataStorage::Signing`] transitions into
/// [`ZoneDataStorage::ReviewSignedPending`], to review the built instance.
///
/// Given the [`SignedZoneBuilder`], [`ZoneDataStorage::Signing`] can
/// transition into:
///
/// - [`ZoneDataStorage::CleaningSigned`], to clean up leftover data on failure.
///
/// - [`ZoneDataStorage::PendingLoadedClean`], to clean up the whole instance.
pub struct SigningStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff towards the upcoming loaded instance, if any.
    pub(super) loaded_diff: Option<Arc<DiffData>>,
}

//----------- ReviewLoadedPendingStorage ---------------------------------------

/// The [`ZoneDataStorage::ReviewLoadedPending`] state.
///
/// This is an intermediate state, where a loaded instance has been built but
/// is waiting to be reviewed.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There is an upcoming loaded instance of the zone (which may be empty). It
/// has been built and is awaiting review.
///
/// ## Access
///
/// The [`LoadedZoneReviewer`], [`SignedZoneReviewer`], and [`ZoneViewer`] all
/// point to the current instances.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given the old [`LoadedZoneReviewer`],
/// [`ZoneDataStorage::ReviewLoadedPending`] transitions into
/// [`ZoneDataStorage::ReviewingLoaded`].
pub struct ReviewLoadedPendingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff towards the upcoming loaded instance.
    pub(super) loaded_diff: Arc<DiffData>,
}

//----------- ReviewSignedPendingStorage ---------------------------------------

/// The [`ZoneDataStorage::ReviewSignedPending`] state.
///
/// This is an intermediate state, where an instance has been (re-)signed and is
/// awaiting review.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There may be an upcoming loaded instance of the zone (which may be empty).
/// There is an upcoming signed instance, which has been built and is awaiting
/// review.
///
/// ## Access
///
/// The [`SignedZoneReviewer`] and [`ZoneViewer`] points to the current
/// instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance if it
/// exists, else the current one.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given the old [`SignedZoneReviewer`],
/// [`ZoneDataStorage::ReviewPendingSigned`] transitions into
/// [`ZoneDataStorage::ReviewingSigned`].
pub struct ReviewSignedPendingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming loaded instance, if any.
    pub(super) loaded_diff: Option<Arc<DiffData>>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- ReviewingLoadedStorage -------------------------------------------

/// The [`ZoneDataStorage::ReviewingLoaded`] state.
///
/// This is used to review a freshly-loaded loaded instance of a zone.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There is an upcoming loaded instance of the zone (which may be empty). It
/// has been built and is being reviewed.
///
/// ## Access
///
/// The [`SignedZoneReviewer`] and [`ZoneViewer`] point to the current
/// instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::ReviewingLoaded`] can transition into:
///
/// - [`ZoneDataStorage::PersistingLoaded`], to persist the instance once it
///   is approved.
///
/// - [`ZoneDataStorage::PendingLoadedClean`], to clean up the instance if it
///   has been rejected.
pub struct ReviewingLoadedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming loaded instance.
    pub(super) loaded_diff: Arc<DiffData>,
}

//----------- ReviewingSignedStorage -------------------------------------------

/// The [`ZoneDataStorage::ReviewingSigned`] state.
///
/// This is used to review a freshly (re-)signed instance of a zone.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There may be an upcoming loaded instance of the zone (which may be empty).
/// There is an upcoming signed instance (which may be empty), which has been
/// built and is being reviewed.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance if it
/// exists, else the current one.
///
/// The [`SignedZoneReviewer`] points to the upcoming signed instance.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// [`ZoneDataStorage::ReviewingSigned`] can transition into:
///
/// - [`ZoneDataStorage::PersistingSigned`], to persist the signed instance once
///   it is approved.
///
/// - [`ZoneDataStorage::CleanSignedPending`], to clean up the signed instance
///   if it has been rejected, and try again.
///
/// - [`ZoneDataStorage::CleanWholePending`], to clean up the whole upcoming
///   instance if it has been rejected, and give up.
pub struct ReviewingSignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming loaded instance, if any.
    pub(super) loaded_diff: Option<Arc<DiffData>>,

    /// The diff of the upcoming signed instance.
    pub(super) signed_diff: Arc<DiffData>,
}

//----------- PersistingLoadedStorage ----------------------------------------

/// The [`ZoneDataStorage::PersistingLoaded`] state.
///
/// This is used to persist an approved upcoming loaded instance of the zone
/// before it is signed.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There is an upcoming loaded instance of the zone (which may be empty). It
/// has been built, approved, and is now being persisted.
///
/// ## Access
///
/// The [`SignedZoneReviewer`] and [`ZoneViewer`] point to the current
/// instances.
///
/// The [`LoadedZoneReviewer`] and [`LoadedZonePersister`] point to the
/// prepared loaded instance.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given [`LoadedZonePersisted`], [`ZoneDataStorage::PersistingLoaded`]
/// transitions into [`ZoneDataStorage::Signing`], to sign the now-persisted
/// instance.
pub struct PersistingLoadedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff of the upcoming loaded instance.
    pub(super) loaded_diff: Arc<DiffData>,
}

//----------- PersistingSignedStorage ------------------------------------------

/// The [`ZoneDataStorage::PersistingSigned`] state.
///
/// This is used to persist an approved upcoming instance of the zone before it
/// becomes authoritative.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There may be an upcoming loaded instance of the zone (which may be empty).
/// There is an upcoming signed instance (which may be empty), which has been
/// built, approved, and is now being persisted.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance if it
/// exists, else the current one.
///
/// The [`SignedZoneReviewer`] and [`SignedZonePersister`] point to the upcoming
/// signed instance.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], or [`LoadedZonePersister`].
///
/// ## Transitions
///
/// Given [`ZonePersisted`], [`ZoneDataStorage::PersistingSigned`] transitions
/// into [`ZoneDataStorage::Switching`], to make the now-persisted instance
/// authoritative.
pub struct PersistingSignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The index of the next loaded instance.
    pub(super) next_loaded_index: bool,

    /// The index of the next signed instance.
    pub(super) next_signed_index: bool,
}

//----------- CleanLoadedPendingStorage ----------------------------------------

/// The [`ZoneDataStorage::CleanLoadedPending`] state.
///
/// This is an intermediate state, where an instance has been rejected or
/// replaced and is waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There is a loaded instance of the zone that needs to be removed. There may
/// be a signed instance of the zone that needs to be removed.
///
/// ## Access
///
/// The [`SignedZoneReviewer`] and [`ZoneViewer`] point to the current
/// instances.
///
/// The [`LoadedZoneReviewer`] points to the loaded instance pending removal.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given the old [`LoadedZoneReviewer`], [`ZoneDataStorage::CleanLoadedPending`]
/// transitions into [`ZoneDataStorage::Cleaning`].
pub struct CleanLoadedPendingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- CleanSignedPendingStorage ----------------------------------------

/// The [`ZoneDataStorage::CleanSignedPending`] state.
///
/// This is an intermediate state, where an instance has been rejected and is
/// waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There may be an upcoming loaded instance of the zone (which may be empty).
/// There is a signed instance of the zone that needs to be removed.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance if it
/// exists, else the current one.
///
/// The [`SignedZoneReviewer`] points to the signed instance pending removal.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given the old [`SignedZoneReviewer`], [`ZoneDataStorage::CleanSignedPending`]
/// transitions into [`ZoneDataStorage::CleaningSigned`].
pub struct CleanSignedPendingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff towards the upcoming loaded instance, if any.
    pub(super) loaded_diff: Option<Arc<DiffData>>,
}

//----------- CleanWholePendingStorage -----------------------------------------

/// The [`ZoneDataStorage::CleanWholePending`] state.
///
/// This is an intermediate state, where an instance has been rejected or
/// replaced and is waiting to be unlocked for cleaning.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There are upcoming loaded and signed instances of the zone, that need to be
/// removed.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current instances.
///
/// The [`LoadedZoneReviewer`] and [`SignedZoneReviewer`] point to the instances
/// pending removal.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given the old [`SignedZoneReviewer`], [`ZoneDataStorage::CleanWholePending`]
/// transitions into [`ZoneDataStorage::CleanLoadedPending`].
pub struct CleanWholePendingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

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
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There are loaded and/or signed instances of the zone that are being
/// removed.
///
/// ## Access
///
/// The [`LoadedZoneReviewer`], [`SignedZoneReviewer`], and [`ZoneViewer`] all
/// point to the current instances.
///
/// The [`ZoneCleaner`] points to the instances being removed.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given [`ZoneCleaned`], [`ZoneDataStorage::Cleaning`] transitions into
/// [`ZoneDataStorage::Passive`].
pub struct CleaningStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,
}

//----------- CleaningSignedStorage --------------------------------------------

/// The [`ZoneDataStorage::CleaningSigned`] state.
///
/// This is used to clean up a previous signed instance, because it could not be
/// built or it was rejected.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There may be an upcoming loaded instance of the zone (which may be empty).
/// There is a signed instance of the zone that needs to be removed.
///
/// ## Access
///
/// The [`SignedZoneReviewer`] and [`ZoneViewer`] point to the current
/// instances.
///
/// The [`LoadedZoneReviewer`] points to the upcoming loaded instance if it
/// exists, else the current one.
///
/// The [`SignedZoneCleaner`] points to the signed instance being removed.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given [`SignedZoneCleaned`], [`ZoneDataStorage::CleaningSigned`] transitions
/// into [`ZoneDataStorage::Signing`], to attempt rebuilding the instance.
pub struct CleaningSignedStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The diff towards the upcoming loaded instance, if any.
    pub(super) loaded_diff: Option<Arc<DiffData>>,
}

//----------- SwitchingStorage -------------------------------------------------

/// The [`ZoneDataStorage::Switching`] state.
///
/// This is used to make an approved and persisted instance authoritative.
///
/// ## Data
///
/// There are current loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance.
///
/// There are upcoming loaded and signed instances of the zone. These may be
/// empty, but a non-empty signed instance cannot exist without a non-empty
/// loaded instance. It is being switched to.
///
/// ## Access
///
/// The [`ZoneViewer`] points to the current instances.
///
/// The [`LoadedZoneReviewer`] and [`SignedZoneReviewer`] point to the upcoming
/// instances.
///
/// There is no [`LoadedZoneBuilder`], [`SignedZoneBuilder`], [`ZoneCleaner`],
/// [`SignedZoneCleaner`], [`LoadedZonePersister`], or [`SignedZonePersister`].
///
/// ## Transitions
///
/// Given the [`ZoneViewer`], [`ZoneDataStorage::Switching`] transitions into
/// [`ZoneDataStorage::Cleaning`], to remove the previous instances.
pub struct SwitchingStorage {
    /// The underlying data.
    pub(super) data: Arc<Data>,

    /// The index of the current loaded instance.
    pub(super) curr_loaded_index: bool,

    /// The index of the current signed instance.
    pub(super) curr_signed_index: bool,

    /// The index of the next loaded instance.
    pub(super) next_loaded_index: bool,

    /// The index of the next signed instance.
    pub(super) next_signed_index: bool,
}
