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
    let _ = center;

    // Store the loaded diff in-memory for serving IXFR out.

    let loaded_diff = persister.loaded_diff();

    // Only store a diff if something has changed compared to the previous
    // version of the loaded zone, otherwise this is not a diff to a previous
    // version of the zone but actually a snapshot of the zone after having
    // been loaded for the first time. If the SOA serial didn't change (which
    // is legal for a loaded zone) don't store a diff because the IXFR protocol
    // requires a SOA serial number change so we won't be able to serve the diff
    // anyway.
    if !loaded_diff.is_empty() && loaded_diff.removed_soa.is_some() {
        // Store anything that changed when the zone was re-loaded, i.e.
        // unsigned zone content changes. Note that the SOA SERIAL is not
        // required to change unless using 'keep' policy and so we should not
        // require the SOA to have been removed and a new one added.
        let mut state = zone.state.lock().unwrap();

        let loaded_only_diff = (Some(persister.loaded_diff().clone()), None);
        state.storage.diffs.push(loaded_only_diff);
    }

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
    let _ = center;

    // Store the signed diff in-memory for serving IXFR out.
    //
    // Only store a diff if the SOA from the previous version of the signed
    // zone was removed and a new one added, otherwise this is not a diff to a
    // previous version of the zone but actually a snapshot of the zone after
    // having been signed for the first time.
    let loaded_diff = persister.loaded_diff();
    let signed_diff = persister.signed_diff();

    if signed_diff.removed_soa.is_some() && signed_diff.removed_soa != signed_diff.added_soa {
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

        let complete_diff = (loaded_diff.cloned(), Some(signed_diff.clone()));
        state.storage.diffs.push(complete_diff);
    }

    persister.mark_complete()
}
