//! Zone-specific signing state.

use std::{sync::Arc, time::SystemTime};

use cascade_zonedata::SignedZoneBuilder;

use crate::{
    center::Center,
    util::AbortOnDrop,
    zone::{SigningTrigger, Zone, ZoneHandle, ZoneState},
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

    /// Enqueue a signing operation for a newly loaded instance of the zone.
    pub fn enqueue_sign(&mut self, builder: SignedZoneBuilder) {
        // A zone can have at most one 'SignedZoneBuilder' at a time. Because
        // we have 'builder', we are guaranteed that no other signing operations
        // are ongoing right now. A re-signing operation may be enqueued, but it
        // has lower priority than this (for now).

        assert!(self.state.signer.enqueued_sign.is_none());
        assert!(self.state.signer.ongoing.is_none());

        // TODO: Keep state for a queue of pending (re-)signing operations, so
        // that the number of simultaneous operations can be limited. At the
        // moment, this queue is opaque and is handled within the asynchronous
        // task.

        let handle = tokio::task::spawn(super::sign(
            self.center.clone(),
            self.zone.clone(),
            builder,
            SigningTrigger::ZoneChangesApproved,
        ));

        self.state.signer.ongoing = Some(handle.into());
    }

    /// Enqueue a re-signing operation for the zone.
    ///
    /// ## Panics
    ///
    /// Panics if `keys_changed` and `sigs_need_refresh` are both `false`.
    pub fn enqueue_resign(&mut self, keys_changed: bool, sigs_need_refresh: bool) {
        assert!(
            keys_changed || sigs_need_refresh,
            "a reason for re-signing was not specified"
        );

        // If a re-signing operation has already been enqueued, add to it.
        if let Some(resign) = &mut self.state.signer.enqueued_resign {
            resign.keys_changed |= keys_changed;
            resign.sigs_need_refresh |= sigs_need_refresh;
            return;
        }

        // Try to obtain a 'SignedZoneBuilder' so building can begin.
        let builder = self.zone().storage().start_resign();

        // TODO: Keep state for a queue of pending (re-)signing operations, so
        // that the number of simultaneous operations can be limited. At the
        // moment, this queue is opaque and is handled within the asynchronous
        // task.

        // Try to initiate the re-sign immediately.
        if let Some(builder) = builder {
            // A zone can have at most one 'SignedZoneBuilder' at a time.
            // Because we have 'builder', we are guaranteed that no other
            // signing operations are ongoing right now. A re-signing operation
            // may be enqueued, but it has lower priority than this (for now).

            assert!(self.state.signer.enqueued_sign.is_none());
            assert!(self.state.signer.ongoing.is_none());

            // TODO: 'SigningTrigger' can't express multiple reasons.
            let trigger = if keys_changed {
                SigningTrigger::KeySetModifiedAfterCron
            } else {
                SigningTrigger::SignatureExpiration
            };

            let handle = tokio::task::spawn(super::sign(
                self.center.clone(),
                self.zone.clone(),
                builder,
                trigger,
            ));

            self.state.signer.ongoing = Some(handle.into());
        } else {
            // TODO: Track expiration time in 'SignerState'.
            let expiration_time = self
                .state
                .next_min_expiration
                .or(self.state.min_expiration)
                .unwrap_or_else(|| panic!("re-sign enqueued but the zone has not been signed"))
                .to_system_time(SystemTime::now());

            self.state.signer.enqueued_resign = Some(EnqueuedResign {
                builder: None,
                keys_changed,
                sigs_need_refresh,
                expiration_time,
            });
        }
    }

    /// Start a pending enqueued re-sign.
    ///
    /// This should be called when the zone data storage is idle. If a re-sign
    /// has been enqueued, it will be initiated, and `true` will be returned.
    ///
    /// This method cannot initiate enqueued signing operations; when a signing
    /// operation is enqueued, it prevents the data storage from idling.
    pub fn start_pending(&mut self) -> bool {
        // An enqueued or ongoing signing operation holds a 'SignedZoneBuilder',
        // which prevents the zone data storage from being idle. This method is
        // only called if the zone data storage is idle.
        assert!(self.state.signer.enqueued_sign.is_none());
        assert!(
            self.state
                .signer
                .enqueued_resign
                .as_ref()
                .is_none_or(|o| o.builder.is_none())
        );
        assert!(self.state.signer.ongoing.is_none());

        // Load the one enqueued re-sign operation, if it exists.
        let Some(resign) = self.state.signer.enqueued_resign.take() else {
            // A re-sign is not enqueued, nothing to do.
            return false;
        };
        let EnqueuedResign {
            builder: _,
            keys_changed,
            sigs_need_refresh: _, // TODO
            expiration_time: _,   // TODO
        } = resign;

        let builder = self
            .zone()
            .storage()
            .start_resign()
            .expect("'start_pending()' is only called when the zone data storage is idle");

        // TODO: Once an explicit queue of signing operations has been
        // implemented (for limiting the number of simultaneous operations),
        // add the operation to the queue before starting the re-sign. If the
        // queue is too full to start the operation yet, leave it enqueued.

        // TODO: 'SigningTrigger' can't express multiple reasons.
        let trigger = if keys_changed {
            SigningTrigger::KeySetModifiedAfterCron
        } else {
            SigningTrigger::SignatureExpiration
        };

        let handle = tokio::task::spawn(super::sign(
            self.center.clone(),
            self.zone.clone(),
            builder,
            trigger,
        ));

        self.state.signer.ongoing = Some(handle.into());

        true
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
