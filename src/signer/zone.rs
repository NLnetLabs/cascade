//! Zone-specific signing state.

use std::{sync::Arc, time::SystemTime};

use cascade_zonedata::SignedZoneBuilder;

use crate::{
    center::Center,
    util::AbortOnDrop,
    zone::{Zone, ZoneHandle, ZoneState},
};

//----------- SignerZoneHandle -------------------------------------------------

/// A handle for signer-related operations on a [`Zone`].
pub struct SignerZoneHandle<'a> {
    /// The zone being operated on.
    pub zone: &'a Arc<Zone>,

    /// The locked zone state.
    pub state: &'a mut ZoneState,

    /// Cascade's global state.
    pub center: &'a Arc<Center>,
}

impl SignerZoneHandle<'_> {
    /// Access the generic [`ZoneHandle`].
    pub const fn zone(&mut self) -> ZoneHandle<'_> {
        ZoneHandle {
            zone: self.zone,
            state: self.state,
            center: self.center,
        }
    }
}

//----------- SignerState ------------------------------------------------------

/// State for signing a zone.
#[derive(Debug, Default)]
pub struct SignerState {
    /// A handle to an ongoing operation, if any.
    pub ongoing: Option<AbortOnDrop>,

    /// An enqueued signing operation, if any.
    pub enqueued_sign: Option<EnqueuedSign>,

    /// An enqueued re-signing operation, if any.
    pub enqueued_resign: Option<EnqueuedResign>,
}

//----------- EnqueuedSign -----------------------------------------------------

/// An enqueued sign of a zone.
#[derive(Debug)]
pub struct EnqueuedSign {
    /// The zone builder.
    pub builder: SignedZoneBuilder,
}

//----------- EnqueuedResign ---------------------------------------------------

/// An enqueued re-sign of a zone.
#[derive(Debug)]
pub struct EnqueuedResign {
    /// The zone builder, if obtained.
    ///
    /// The builder is necessary to begin re-signing. It is optional because
    /// it might not be available when the re-sign operation is enqueued.
    /// Even if the builder is obtained, the operation might not be ready
    /// to start.
    pub builder: Option<SignedZoneBuilder>,

    /// Whether zone signing keys have changed.
    ///
    /// This indicates the reason for re-signing; if it is `true`, re-signing
    /// has been enqueued because the keys used to sign the zone have changed.
    pub keys_changed: bool,

    /// Whether signatures need to be refreshed.
    ///
    /// This indicates the reason for re-signing; if it is `true`, re-signing
    /// has been enqueued because signatures in the current instance of the zone
    /// will expire soon.
    pub sigs_need_refresh: bool,

    /// When signatures in the zone will expire.
    ///
    /// `self` represents an enqueued re-sign, which means that a current signed
    /// instance of the zone exists. This field tracks the expiration time (not
    /// the time to enqueue re-signing) for that instance, to ensure it will be
    /// re-signed in time.
    //
    // TODO: Force loading to cancel if this gets too close?
    pub expiration_time: SystemTime,
    //
    // TODO:
    // - The ID of the signed instance to re-sign.
    //   Panic if the actual obtained instance does not match this.
}
