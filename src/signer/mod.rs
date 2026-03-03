//! Signing zones.
//
// TODO: Move 'src/units/zone_signer.rs' here.

use std::sync::Arc;

use cascade_zonedata::SignedZoneBuilder;
use tracing::error;

use crate::{
    center::{Center, halt_zone},
    zone::{HistoricalEvent, SigningTrigger, Zone, ZoneHandle},
};

pub mod zone;

//----------- sign() -----------------------------------------------------------

/// Sign or re-sign a zone.
///
/// A new signed instance of the zone will be generated using `builder`.
/// `builder` provides access to the actual zone content, including previous
/// instances of the zone for incremental signing.
#[tracing::instrument(
    level = "debug",
    skip_all,
    fields(zone = %zone.name),
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

    match result {
        Ok(()) => {
            let built = builder.finish().unwrap_or_else(|_| unreachable!());
            handle.storage().finish_sign(built);
            status.status.finish(true);
            status.current_action = "Finished".to_string();
        }
        Err(error) => {
            error!("Signing failed: {error}");
            handle.storage().give_up_sign(builder);
            status.status.finish(false);
            status.current_action = "Aborted".to_string();

            handle.state.record_event(
                HistoricalEvent::SigningFailed {
                    trigger,
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
