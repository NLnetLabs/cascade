//! Persisting zone data.

use std::sync::Arc;

use cascade_zonedata::{
    LoadedZonePersisted, LoadedZonePersister, SignedZonePersisted, SignedZonePersister,
};

use crate::{center::Center, zone::Zone};

/// Persist the data for a loaded instance of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn persist_loaded(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    persister: LoadedZonePersister,
) -> LoadedZonePersisted {
    // TODO
    let _ = (zone, center);
    persister.mark_complete()
}

/// Persist the data for a signed instance of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn persist_signed(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    persister: SignedZonePersister,
) -> SignedZonePersisted {
    // TODO
    let _ = center;

    // Store the signed diff in-memory for serving IXFR.
    // Only push a diff if a SOA was removed, otherwise this is not a diff to
    // a previous version of the zone but actually the entire new zone content
    // compared to an empty zone. Also don't store a diff to the same serial.
    let signed_diff = persister.signed_diff();

    if signed_diff.removed_soa.is_some() && signed_diff.removed_soa != signed_diff.added_soa {
        let mut state = zone.state.lock().unwrap();
        state.storage.diffs.push(signed_diff.clone());
    }

    persister.mark_complete()
}
