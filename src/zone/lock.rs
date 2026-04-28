//! Locking zone state.

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::ZoneState;

#[cfg(doc)]
use super::{Zone, ZoneHandle};

/// A lock around [`ZoneState`].
///
/// [`ZoneState`] is locked so that it can be used and modified across threads,
/// while keeping all parts of the zone state consistent with each other. This
/// is important for preventing race conditions.
///
/// `ZoneLock` is a wrapper around `RwLock<ZoneState>` that provides some
/// convenience functionality. It hides lock poisoning (Cascade does not try
/// to recover in case of panics) and prevents callers from writing to the
/// zone state without marking it dirty. It eliminates boilerplate and avoids
/// inconsistent uses of the zone state across the codebase.
#[derive(Debug)]
pub struct ZoneStateLock {
    /// The underlying lock.
    inner: RwLock<ZoneState>,
}

impl ZoneStateLock {
    /// Construct a new [`ZoneStateLock`].
    #[must_use]
    pub const fn new(state: ZoneState) -> Self {
        Self {
            inner: RwLock::new(state),
        }
    }

    /// Destructure this into the underlying [`ZoneState`].
    #[must_use]
    pub fn into_inner(self) -> ZoneState {
        self.inner.into_inner().unwrap_or_else(handle_poison)
    }

    /// Obtain a read lock over the [`ZoneState`].
    ///
    /// A read lock which [deref]s to [`ZoneState`] is returned.
    ///
    /// Prefer using [`Zone::read()`]; it is more convenient.
    ///
    /// The current thread is blocked until the read lock can be acquired.
    ///
    /// [deref]: std::ops::Deref
    pub fn read(&self) -> ReadableZoneState<'_> {
        self.inner.read().unwrap_or_else(handle_poison)
    }

    /// Obtain a write lock over the [`ZoneState`] **without marking it dirty**.
    ///
    /// A write lock which [deref]s to [`ZoneState`] is returned.
    ///
    /// Prefer using [`Zone::write()`], which will mark the state as dirty. If
    /// a [`ZoneHandle`] is needed, use [`Zone::write_handle()`].
    ///
    /// The current thread is blocked until the write lock can be acquired.
    ///
    /// The state will **not** be marked dirty; it is the caller's
    /// responsibility to mark the state as dirty if/when a change is made.
    ///
    /// [deref]: std::ops::DerefMut
    pub fn write_cleanly(&self) -> WritableZoneState<'_> {
        self.inner.write().unwrap_or_else(handle_poison)
    }
}

/// A read guard to a zone's state.
pub type ReadableZoneState<'a> = RwLockReadGuard<'a, ZoneState>;

/// A write guard to a zone's state.
pub type WritableZoneState<'a> = RwLockWriteGuard<'a, ZoneState>;

/// Handle a lock poisoning failure.
//
// TODO: Return '!'.
#[track_caller]
fn handle_poison<T, R>(_: PoisonError<T>) -> R {
    panic!("A zone state lock is poisoned; see its panic message")
}
