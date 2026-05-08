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

    // Store the diffs in-memory for serving IXFR.
    //
    // Only store a diff if the SOA from the previous version of the signed
    // zone was removed and a new one added, otherwise this is not a diff to a
    // previous version of the zone but actually a snapshot of the zone after
    // having been signed for the first time.
    let loaded_diff = persister.loaded_diff();
    let signed_diff = persister.signed_diff();

    if let Some(loaded_diff) = loaded_diff
        && signed_diff.removed_soa.is_some()
        && signed_diff.removed_soa != signed_diff.added_soa
    {
        let mut state = zone.state.lock().unwrap();

        // Store anything that changed when the zone was re-loaded, i.e.
        // unsigned zone content changes. Note that the SOA SERIAL is not
        // required to change unless using 'keep' policy and so we should not
        // require the SOA to have been removed and a new one added.

        // Store anything that changed when the zone was re-signed, i.e.
        // changes DNSSEC RRs that can be caused by unsigned content changes
        // or changing from NSEC <-> NSEC3 or using a new key to sign with or
        // just regenerating signatures to avoid them expiring. Signed zones
        // MUST always have a new SOA SERIAL compared to the previous version
        // of the signed zone.

        let complete_diff = (loaded_diff.clone(), signed_diff.clone());
        state.storage.diffs.push(complete_diff);
    }

    persister.mark_complete()
}
