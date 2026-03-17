//! Tracking instances of zones.

use std::collections::VecDeque;

//----------- Instances --------------------------------------------------------

/// Current and old instances of a zone.
#[derive(Debug, Default)]
pub struct Instances {
    /// The ID of the next loaded instance.
    pub next_loaded_id: u64,

    /// The ID of the next signed instance.
    pub next_signed_id: u64,

    /// The current instance of the zone.
    pub current: Option<CurrentInstance>,

    /// An upcoming instance of the zone, if any.
    pub upcoming: Option<UpcomingInstance>,

    /// Abandoned instances of the zone.
    pub abandoned: Vec<AbandonedInstance>,

    /// Old instances of the zone.
    pub old: OldInstances,
}

/// # Loader Operations
impl Instances {
    /// Start loading a new instance of the zone.
    ///
    /// A new upcoming instance of the zone is prepared, and it is assigned an
    /// ID (which is returned).
    ///
    /// ## Panics
    ///
    /// Panics if an upcoming instance of the zone already exists.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn start_load(&mut self) -> LoadedInstanceID {
        assert!(
            self.upcoming.is_none(),
            "Cannot start a load while an upcoming instance exists"
        );

        let id = LoadedInstanceID(self.next_loaded_id);
        // TODO(MSRV 1.91): Use 'strict_add()'.
        self.next_loaded_id = self.next_loaded_id.checked_add(1).unwrap();
        self.upcoming = Some(UpcomingInstance::Loading { id });
        id
    }

    /// Abandon an ongoing load.
    ///
    /// The upcoming instance of the zone, initialized by
    /// [`Self::start_load()`], will be abandoned.
    ///
    /// ## Panics
    ///
    /// Panics if the specified `id` does not match the upcoming (loaded)
    /// instance of the zone. Panics if an upcoming signed instance of the zone
    /// exists.
    #[tracing::instrument(level = "trace", skip_all, fields(?expected_id))]
    pub fn abandon_load(&mut self, expected_id: LoadedInstanceID) {
        match self.upcoming.take() {
            Some(UpcomingInstance::Loading { id } | UpcomingInstance::ReviewingLoaded { id }) => {
                assert_eq!(id, expected_id, "The loaded instance has a different ID");
                self.abandoned
                    .push(AbandonedInstance::Loaded(AbandonedLoadedInstance { id }));
            }
            other => panic!("A loaded instance is not being built or reviewed: {other:?}"),
        }
    }
}

/// # Signer Operations
impl Instances {
    /// Start signing a newly loaded instance of the zone.
    ///
    /// A new upcoming signed instance of the zone is prepared, and it is
    /// assigned an ID (which is returned).
    ///
    /// ## Panics
    ///
    /// Panics if the upcoming loaded instance of the zone does not exist, or
    /// has a different ID. Panics if the upcoming signed instance of the zone
    /// already exists.
    #[tracing::instrument(level = "trace", skip_all, fields(?loaded_id))]
    pub fn start_new_sign(&mut self, loaded_id: LoadedInstanceID) -> SignedInstanceID {
        let (upcoming, id) = self
            .upcoming
            .take()
            .unwrap_or_else(|| panic!("There is no upcoming instance"))
            .into_signing_new();
        self.upcoming = Some(upcoming);
        id
    }

    /// Start re-signing the zone.
    ///
    /// A new upcoming signed instance of the zone is prepared, relative to the
    /// current loaded instance. The upcoming instance is assigned an ID (which
    /// is returned).
    ///
    /// Note that a current signed instance does not have to exist (e.g. if
    /// signing was previously disabled).
    ///
    /// ## Panics
    ///
    /// Panics if a current *loaded* instance of the zone does not exist. Panics
    /// if an upcoming instance of the zone already exists.
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn start_resign(&mut self) -> SignedInstanceID {
        let current = self
            .current
            .as_ref()
            .unwrap_or_else(|| panic!("There is no current instance to re-sign"));
        assert!(
            self.upcoming.is_none(),
            "An upcoming instance already exists"
        );

        let id = SignedInstanceID(current.loaded.id, self.next_signed_id);
        // TODO(MSRV 1.91): Use 'strict_add()'.
        self.next_signed_id = self.next_signed_id.checked_add(1).unwrap();
        self.upcoming = Some(UpcomingInstance::Resigning { id });
        id
    }

    // TODO: `retry_sign()`

    /// Abandon an ongoing signing operation.
    ///
    /// The upcoming signed and (if any) loaded instance of the zone will be
    /// abandoned.
    ///
    /// ## Panics
    ///
    /// Panics if there is no upcoming instance of the zone. Panics if the
    /// specified `id` does not match the upcoming instance of the zone.
    #[tracing::instrument(level = "trace", skip_all, fields(?expected_id))]
    pub fn abandon_sign(&mut self, expected_id: SignedInstanceID) {
        match self.upcoming.take() {
            Some(
                UpcomingInstance::SigningNew { id } | UpcomingInstance::ReviewingNewSigned { id },
            ) => {
                assert_eq!(id, expected_id, "The signed instance has a different ID");
                self.abandoned
                    .push(AbandonedInstance::Signed(AbandonedSignedInstance { id }));
                self.abandoned
                    .push(AbandonedInstance::Loaded(AbandonedLoadedInstance {
                        id: id.0,
                    }));
            }
            Some(
                UpcomingInstance::Resigning { id } | UpcomingInstance::ReviewingResigned { id },
            ) => {
                assert_eq!(id, expected_id, "The signed instance has a different ID");
                self.abandoned
                    .push(AbandonedInstance::Signed(AbandonedSignedInstance { id }));
            }
            other => panic!("A signed instance is not being built or reviewed: {other:?}"),
        }
    }

    /// Accept the upcoming signed instance.
    ///
    /// The upcoming signed instance will replace the current instance.
    ///
    /// ## Panics
    ///
    /// Panics if there is no upcoming instance of the zone. Panics if the
    /// upcoming instance has a different ID.
    #[tracing::instrument(level = "trace", skip_all, fields(?expected_id))]
    pub fn accept_signed(&mut self, expected_id: SignedInstanceID) {
        match self.upcoming.take() {
            Some(
                UpcomingInstance::SigningNew { id } | UpcomingInstance::ReviewingNewSigned { id },
            ) => {
                assert_eq!(id, expected_id, "The signed instance has a different ID");
                self.current = Some(CurrentInstance {
                    loaded: CurrentLoadedInstance { id: id.0 },
                    signed: Some(CurrentSignedInstance { id }),
                });
            }
            Some(
                UpcomingInstance::Resigning { id } | UpcomingInstance::ReviewingResigned { id },
            ) => {
                assert_eq!(id, expected_id, "The signed instance has a different ID");
                self.current
                    .as_mut()
                    .expect("Re-signing only occurs if a current instance exists")
                    .signed = Some(CurrentSignedInstance { id });
            }
            other => panic!("A signed instance is not being built or reviewed: {other:?}"),
        }
    }
}

//----------- CurrentInstance --------------------------------------------------

/// The current instance of the zone.
#[derive(Debug)]
pub struct CurrentInstance {
    /// The current loaded instance of the zone, if any.
    pub loaded: CurrentLoadedInstance,

    /// The current signed instance of the zone, if any.
    ///
    /// If this exists, there is also a current loaded instance, and it has a
    /// corresponding ID.
    pub signed: Option<CurrentSignedInstance>,
}

/// The current loaded instance of a zone.
#[derive(Debug)]
pub struct CurrentLoadedInstance {
    /// The ID of this instance.
    pub id: LoadedInstanceID,
}

/// The current signed instance of a zone.
#[derive(Debug)]
pub struct CurrentSignedInstance {
    /// The ID of this instance.
    pub id: SignedInstanceID,
}

//----------- UpcomingInstance -------------------------------------------------

/// An upcoming instance of a zone.
#[derive(Debug)]
pub enum UpcomingInstance {
    /// A new instance is being loaded.
    Loading {
        /// The ID of the instance.
        id: LoadedInstanceID,
    },

    /// A newly loaded instance is being reviewed.
    ReviewingLoaded {
        /// The ID of the instance.
        id: LoadedInstanceID,
    },

    /// A newly loaded instance is being signed.
    SigningNew {
        /// The ID of the instance.
        id: SignedInstanceID,
    },

    /// A newly loaded and signed instance is being reviewed.
    ReviewingNewSigned {
        /// The ID of the instance.
        id: SignedInstanceID,
    },

    /// The current instance is being re-signed.
    Resigning {
        /// The ID of the instance.
        id: SignedInstanceID,
    },

    /// A re-signed instance is being reviewed.
    ReviewingResigned {
        /// The ID of the instance.
        id: SignedInstanceID,
    },
}

impl UpcomingInstance {
    /// Begin reviewing the newly loaded instance.
    ///
    /// ## Panics
    ///
    /// Panics if `self` is not [`Self::Loading`].
    #[tracing::instrument(level = "trace")]
    pub fn into_reviewing_loaded(self) -> Self {
        match self {
            Self::Loading { id } => Self::ReviewingLoaded { id },
            other => panic!("An instance is not being loaded: {other:?}"),
        }
    }

    /// Accept the newly loaded instance and transition to [`Self::SigningNew`].
    ///
    /// Returns the ID of the new signed instance being built.
    ///
    /// ## Panics
    ///
    /// Panics if `self` is not [`Self::Loading`] or [`Self::ReviewingLoaded`].
    #[tracing::instrument(level = "trace")]
    pub fn into_signing_new(self) -> (Self, SignedInstanceID) {
        match self {
            Self::Loading { id } | Self::ReviewingLoaded { id } => {
                let id = SignedInstanceID(id, 0);
                (Self::SigningNew { id }, id)
            }
            other => panic!("An instance is not being loaded: {other:?}"),
        }
    }

    /// Begin reviewing the signed instance.
    ///
    /// ## Panics
    ///
    /// Panics if `self` is not [`Self::SigningNew`] or [`Self::Resigning`].
    #[tracing::instrument(level = "trace")]
    pub fn into_reviewing_signed(self) -> Self {
        match self {
            Self::SigningNew { id } => Self::ReviewingNewSigned { id },
            Self::Resigning { id } => Self::ReviewingResigned { id },
            other => panic!("An instance is not being signed: {other:?}"),
        }
    }
}

//----------- OldInstances -----------------------------------------------------

/// Old instances of a zone.
#[derive(Debug, Default)]
pub struct OldInstances {
    /// The instances, in order of replacement.
    ///
    /// When a new pair of loaded and signed instances replace the current ones,
    /// the signed instance and the loaded instance (in that order) are pushed
    /// to the back of this queue.
    ///
    /// Signed instances are based on the closest succeeding loaded instance.
    pub instances: VecDeque<OldInstance>,
}

/// An old instance of a zone.
#[derive(Debug)]
pub enum OldInstance {
    /// An old loaded instance.
    Loaded(OldLoadedInstance),

    /// An old signed instance.
    Signed(OldSignedInstance),
}

/// An old loaded instance of a zone.
#[derive(Debug)]
pub struct OldLoadedInstance {
    /// The ID of this instance.
    pub id: LoadedInstanceID,
}

/// An old signed instance of a zone.
#[derive(Debug)]
pub struct OldSignedInstance {
    /// The ID of this instance.
    pub id: SignedInstanceID,
}

//----------- AbandonedInstance ------------------------------------------------

/// An abandoned instance of a zone.
#[derive(Debug)]
pub enum AbandonedInstance {
    /// An abandoned loaded instance.
    Loaded(AbandonedLoadedInstance),

    /// An abandoned signed instance.
    Signed(AbandonedSignedInstance),
}

/// An abandoned loaded instance of a zone.
#[derive(Debug)]
pub struct AbandonedLoadedInstance {
    /// The ID of this instance.
    pub id: LoadedInstanceID,
}

/// An abandoned signed instance of a zone.
#[derive(Debug)]
pub struct AbandonedSignedInstance {
    /// The ID of this instance.
    pub id: SignedInstanceID,
}

//----------- LoadedInstanceID -------------------------------------------------

/// A unique identifier for a loaded instance of a zone.
///
/// Every loaded instance is assigned an ID; it uniquely identifies them, even
/// if two instances have the same SOA serial number.
///
/// The very first loaded instance of the zone is assigned ID 0. Every following
/// instance is assigned the succeeding integer. These IDs disambiguate
/// instances even if they have the same SOA serial number.
///
/// Integer overflow is considered impossible due to the sheer number of
/// instances necessary for it. If the ID does overflow, Cascade will crash.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoadedInstanceID(pub u64);

//----------- SignedInstanceID -------------------------------------------------

/// A unique identifier for a signed instance of a zone.
///
/// Every instance is assigned an ID (including the ID of the loaded instance
/// it is based on); it uniquely identifies them, even if two instances have the
/// same SOA serial number.
///
/// When a loaded instance is signed for the first time, the signed instance is
/// assigned ID 0. Every following instance based on the same loaded instance is
/// assigned the succeeding integer. When a new loaded instance is signed, the
/// ID resets to 0 (this is unambiguous because the loaded instance ID is also
/// included).
///
/// Integer overflow is considered impossible due to the sheer number of
/// instances necessary for it. If the ID does overflow, Cascade will crash.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedInstanceID(pub LoadedInstanceID, pub u64);
