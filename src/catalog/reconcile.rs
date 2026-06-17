//! Reconciling a catalog's membership with the zones Cascade manages.
//!
//! Reconciliation transfers the catalog zone, computes the difference between
//! its membership and the member zones currently managed, and applies that
//! difference by adding and removing member zones. It is idempotent: running
//! it repeatedly against an unchanged catalog makes no changes.

use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use domain::base::{Name, Ttl};
use tracing::{error, info, warn};

use crate::api;
use crate::center::{self, Center, ZoneAddError};

use super::transfer::{self, TransferError};

//----------- reconcile() ----------------------------------------------------

/// Transfers a catalog and reconciles its membership.
///
/// Returns the catalog zone's SOA REFRESH interval, used to schedule the next
/// reconciliation.
pub async fn reconcile(center: &Arc<Center>, apex: &Name<Bytes>) -> Result<Ttl, ReconcileError> {
    // Snapshot the catalog configuration and resolve its TSIG key.
    let (addr, tsig_key, snapshot) = {
        let state = center.state.lock().unwrap();
        let config = state
            .catalogs
            .get(apex)
            .ok_or(ReconcileError::NotFound)?
            .clone();
        let api::ZoneSource::Server { addr, tsig_key } = &config.source else {
            return Err(ReconcileError::UnsupportedSource);
        };
        let addr = *addr;
        let tsig_key = match tsig_key {
            Some(name) => Some(
                state
                    .tsig_store
                    .get(name)
                    .ok_or(ReconcileError::MissingTsigKey)?
                    .inner
                    .as_ref()
                    .clone(),
            ),
            None => None,
        };
        (addr, tsig_key, config)
    };

    // Transfer and parse the catalog zone.
    let transferred = transfer::transfer(apex, &addr, tsig_key).await?;
    let diff = snapshot.diff(&transferred.catalog);

    // Add new member zones.
    for member in diff.to_add {
        add_member(center, apex, member).await;
    }

    // Remove member zones that have left the catalog.
    for name in diff.to_remove {
        remove_member(center, apex, name);
    }

    Ok(transferred.refresh)
}

/// Adds a single member zone on behalf of a catalog.
async fn add_member(center: &Arc<Center>, apex: &Name<Bytes>, member: super::ResolvedMember) {
    let name = member.name.clone();
    match center::add_zone(
        center,
        name.clone(),
        member.policy.clone(),
        member.source.clone(),
        Vec::new(),
    )
    .await
    {
        Ok(()) => {
            // Mark the new zone as managed by this catalog.
            if let Some(zone) = center::get_zone(center, &name) {
                zone.write(center).catalog = Some(apex.clone());
            }

            // Record the member against the catalog and persist.
            let mut state = center.state.lock().unwrap();
            if let Some(config) = state.catalogs.get_mut(apex) {
                config.members.insert(name.clone());
            }
            state.mark_dirty(center);

            info!("Added catalog '{apex}' member zone '{name}'");
        }

        Err(ZoneAddError::AlreadyExists) => {
            warn!(
                "Catalog '{apex}' lists member zone '{name}', but a zone of \
                 that name already exists; leaving it untouched"
            );
        }

        Err(err) => {
            error!("Could not add catalog '{apex}' member zone '{name}': {err}");
        }
    }
}

/// Removes a single member zone that has left a catalog.
fn remove_member(center: &Arc<Center>, apex: &Name<Bytes>, name: Name<Bytes>) {
    match center::remove_zone_forced(center, name.clone()) {
        Ok(()) => {
            info!("Removed catalog '{apex}' member zone '{name}'");
        }
        Err(err) => {
            warn!(
                "Could not remove catalog '{apex}' member zone '{name}': \
                 {err}"
            );
        }
    }

    let mut state = center.state.lock().unwrap();
    if let Some(config) = state.catalogs.get_mut(apex) {
        config.members.remove(&name);
    }
    state.mark_dirty(center);
}

//============ Errors ========================================================

//----------- ReconcileError -------------------------------------------------

/// An error reconciling a catalog.
#[derive(Debug)]
pub enum ReconcileError {
    /// The catalog is no longer registered.
    NotFound,

    /// The catalog is not transferred from a primary.
    UnsupportedSource,

    /// The catalog's TSIG key could not be found.
    MissingTsigKey,

    /// The catalog zone could not be transferred or parsed.
    Transfer(TransferError),
}

impl std::error::Error for ReconcileError {}

impl fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("the catalog is no longer registered"),
            Self::UnsupportedSource => f.write_str("the catalog is not transferred from a primary"),
            Self::MissingTsigKey => f.write_str("the catalog's TSIG key could not be found"),
            Self::Transfer(error) => write!(f, "{error}"),
        }
    }
}

impl From<TransferError> for ReconcileError {
    fn from(value: TransferError) -> Self {
        Self::Transfer(value)
    }
}
