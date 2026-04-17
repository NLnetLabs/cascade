//! Restoring persisted zone data.

use std::sync::Arc;

use cascade_zonedata::{
    LoadedZoneRestored, LoadedZoneRestorer, SignedZoneRestored, SignedZoneRestorer,
};

use crate::{center::Center, zone::Zone};

/// Restore the loaded instance data of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_loaded(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: LoadedZoneRestorer,
) -> LoadedZoneRestored {
    todo!()
}

/// Restore the loaded instance data of a zone.
#[tracing::instrument(
    level = "trace",
    skip_all,
    fields(zone = %zone.name),
)]
pub fn restore_signed(
    zone: &Arc<Zone>,
    center: &Arc<Center>,
    restorer: SignedZoneRestorer,
) -> SignedZoneRestored {
    todo!()
}
