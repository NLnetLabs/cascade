//! Signing zones.
//!
//! Signing operations can be categorized in different ways:
//!
//! - When a new instance of a zone has been loaded and needs to be signed, a
//!   *new-signing* operation is enqueued. When an existing signed instance is
//!   updated (e.g. because signing keys have changed), a *re-signing* operation
//!   is enqueued.
//!
//! - An *incremental signing operation* generates a new signed instance of a
//!   zone by making (small) modifications to the previous, existing signed
//!   instance. An incremental new-signing operation may consider diffs between
//!   the old and new loaded instances of the zone. A *full signing operation*
//!   (sometimes termed a *non-incremental signing operation*) generates a new
//!   signed instance of a zone from scratch, only considering the current
//!   loaded instance of the zone; it does not consider any diffs.
//
// TODO: Move 'src/units/zone_signer.rs' here.

use std::{
    ops::{BitOr, BitOrAssign},
    sync::Arc,
};

use cascade_zonedata::SignedZoneBuilder;
use tracing::{debug, error};

use crate::{
    center::{Center, halt_zone},
    manager::record_zone_event,
    zone::{HistoricalEvent, Zone},
};

pub mod zone;

//----------- sign() -----------------------------------------------------------

/// Sign a zone.
///
/// This is the top-level entry point for signing. It can perform a new-sign or
/// re-sign, incrementally or non-incrementally. Its input and output is
/// controlled by `builder`.
///
/// `builder` provides access to:
/// - The loaded instance of the zone to sign.
/// - A previous loaded instance to diff against, if any.
/// - A previous signed instance to build relative to, if any.
/// - Writers for building the new signed instance.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(zone = %zone.name, ?trigger),
)]
async fn sign(
    center: Arc<Center>,
    zone: Arc<Zone>,
    builder: SignedZoneBuilder,
    trigger: SigningTrigger,
) {
    match center
        .signer
        .join_sign_zone_queue(&center, &zone.name, !builder.have_next_loaded(), trigger)
        .await
    {
        Ok(()) => {}
        Err(error) if error.is_benign() => {
            // Ignore this benign case. It was probably caused by dnst keyset
            // cron triggering resigning before we even signed the first time,
            // either because the zone was large and slow to load and sign, or
            // because the unsigned zone was pending review.
            debug!("Ignoring probably benign failure: {error}");
        }
        Err(error) => {
            error!("Signing failed: {error}");

            // TODO: Inline these methods and use a single 'ZoneState' lock.

            halt_zone(&center, &zone.name, true, &error.to_string());

            record_zone_event(
                &center,
                &zone.name,
                HistoricalEvent::SigningFailed {
                    trigger: trigger.into(),
                    reason: error.to_string(),
                },
                None, // TODO
            );
        }
    }
}

//----------- SigningTrigger ---------------------------------------------------
//
// TODO: Can these be named better?
// TODO: This is mostly relevant for re-signing.
// TODO: These may be subsumed by a more generic causality tracking system.

/// The trigger for a (re-)signing operation.
#[derive(Copy, Clone, Debug)]
pub enum SigningTrigger {
    /// A new instance of a zone has been loaded.
    Load,

    /// A trigger for re-signing.
    Resign(ResigningTrigger),
}

impl From<SigningTrigger> for cascade_api::SigningTrigger {
    fn from(value: SigningTrigger) -> Self {
        match value {
            SigningTrigger::Load => Self::Load,
            SigningTrigger::Resign(trigger) => Self::Resign(trigger.into()),
        }
    }
}

/// The trigger for a re-signing operation.
#[derive(Copy, Clone, Debug)]
pub struct ResigningTrigger {
    /// Whether zone signing keys have changed.
    keys_changed: bool,

    /// Whether signatures need to be refreshed.
    sigs_need_refresh: bool,
}

impl ResigningTrigger {
    /// Re-signing because keys have changed.
    pub const KEYS_CHANGED: Self = Self {
        keys_changed: true,
        sigs_need_refresh: false,
    };

    /// Re-signing because signatures need to be refreshed.
    pub const SIGS_NEED_REFRESH: Self = Self {
        keys_changed: false,
        sigs_need_refresh: true,
    };
}

impl BitOr for ResigningTrigger {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl BitOrAssign for ResigningTrigger {
    fn bitor_assign(&mut self, rhs: Self) {
        let Self {
            keys_changed,
            sigs_need_refresh,
        } = rhs;
        self.keys_changed |= keys_changed;
        self.sigs_need_refresh |= sigs_need_refresh;
    }
}

impl From<ResigningTrigger> for cascade_api::ResigningTrigger {
    fn from(value: ResigningTrigger) -> Self {
        let ResigningTrigger {
            keys_changed,
            sigs_need_refresh,
        } = value;
        Self {
            keys_changed,
            sigs_need_refresh,
        }
    }
}
