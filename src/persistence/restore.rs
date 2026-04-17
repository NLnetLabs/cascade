//! Restoring persisted zone data.

use std::{io, sync::Arc};

use cascade_zonedata::{LoadedZoneRestorer, SignedZoneRestorer};

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
    restorer: &mut LoadedZoneRestorer,
) -> io::Result<()> {
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
    restorer: &mut SignedZoneRestorer,
) -> io::Result<()> {
    todo!()
}
