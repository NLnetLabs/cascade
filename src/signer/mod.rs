//! Signing zones.
//
// TODO: Move 'src/units/zone_signer.rs' here.

use std::sync::Arc;

use cascade_zonedata::SignedZoneBuilder;
use tracing::{debug, error};

use crate::{
    center::{Center, halt_zone},
    manager::record_zone_event,
    zone::{HistoricalEvent, SigningTrigger, Zone},
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
    builder: SignedZoneBuilder,
    trigger: SigningTrigger,
) {
    let (status, _permits) = center.signer.wait_to_sign(&zone).await;

    let result = center
        .signer
        .sign_zone(
            &center,
            &zone,
            !builder.have_next_loaded(),
            trigger,
            status.clone(),
        )
        .await;

    let mut status = status.write().unwrap();

    match result {
        Ok(()) => {
            status.status.finish(true);
            status.current_action = "Finished".to_string();
        }
        Err(error) if error.is_benign() => {
            // Ignore this benign case. It was probably caused by dnst keyset
            // cron triggering resigning before we even signed the first time,
            // either because the zone was large and slow to load and sign, or
            // because the unsigned zone was pending review.
            debug!("Ignoring probably benign failure: {error}");
            status.status.finish(false);
            status.current_action = "Aborted".to_string();
        }
        Err(error) => {
            error!("Signing failed: {error}");
            status.status.finish(false);
            status.current_action = "Aborted".to_string();

            // TODO: Inline these methods and use a single 'ZoneState' lock.

            halt_zone(&center, &zone.name, true, &error.to_string());

            record_zone_event(
                &center,
                &zone.name,
                HistoricalEvent::SigningFailed {
                    trigger,
                    reason: error.to_string(),
                },
                None, // TODO
            );
        }
    }
}
