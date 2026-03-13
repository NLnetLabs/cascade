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
use tracing::error;

use crate::{
    center::{Center, halt_zone},
    zone::{HistoricalEvent, Zone, ZoneHandle},
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
    mut builder: SignedZoneBuilder,
    trigger: SigningTrigger,
) {
    let (status, _permits) = center.signer.wait_to_sign(&zone).await;

    let (result, builder) = tokio::task::spawn_blocking({
        let center = center.clone();
        let zone = zone.clone();
        let status = status.clone();
        move || {
            let result = center
                .signer
                .sign_zone(&center, &zone, &mut builder, trigger, status);
            (result, builder)
        }
    })
    .await
    .unwrap();

    let mut status = status.write().unwrap();
    let mut state = zone.state.lock().unwrap();
    let mut handle = ZoneHandle {
        zone: &zone,
        state: &mut state,
        center: &center,
    };
    handle.state.signer.ongoing.finish();

    match result {
        Ok(()) => {
            let built = builder.finish().unwrap_or_else(|_| unreachable!());
            handle.storage().finish_sign(built);
            status.status.finish(true);
            status.current_action = "Finished".to_string();
        }
        Err(error) => {
            error!("Signing failed: {error}");
            handle.storage().abandon_sign(builder);
            status.status.finish(false);
            status.current_action = "Aborted".to_string();

            handle.state.record_event(
                HistoricalEvent::SigningFailed {
                    trigger: trigger.into(),
                    reason: error.to_string(),
                },
                None, // TODO
            );

            std::mem::drop(state);

            // TODO: Inline.
            halt_zone(&center, &zone.name, true, &error.to_string());
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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
