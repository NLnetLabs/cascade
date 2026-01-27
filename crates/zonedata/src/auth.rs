//! Authoritative instances.
//!
//! Every zone has a single authoritative instance -- this is the approved and
//! published instance of the zone. It is stored in absolute representation,
//! while prior instances are represented as diffs from it. The data structure
//! for the authoritative instance can also hold a single _upcoming_ instance
//! of the zone, which can be read/written efficiently and eventually _applied_.
//! See [the crate-level documentation](crate) for more information.

use std::{
    cell::UnsafeCell,
    sync::atomic::{self, AtomicI32},
};

use crate::Instance;

//----------- AuthData ---------------------------------------------------------

/// Data for the authoritative instance of a zone.
///
/// Every zone has (at most) one authoritative instance, which is the latest
/// approved and published one. All other instances are relative to this. See
/// [the module-level documentation](self) for more information.
///
/// [`AuthData`] stores the authoritative instance and an optional upcoming
/// instance of the zone. The data for these instances is stored in a compact,
/// efficient manner. These instances can be accessed efficiently, and the
/// upcoming instance can be manipulated efficiently.
pub struct AuthData {
    /// Locking control.
    pub(crate) ctrl: AuthCtrl,

    /// The current (i.e. authoritative) instance.
    pub(crate) curr: UnsafeCell<Instance>,

    /// The next (i.e. upcoming) instance.
    pub(crate) next: UnsafeCell<Instance>,
}

impl AuthData {
    /// Construct a new, empty [`AuthData`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ctrl: AuthCtrl::new(),
            curr: UnsafeCell::new(Instance::new()),
            next: UnsafeCell::new(Instance::new()),
        }
    }
}

impl Default for AuthData {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: 'AuthData' implements locking correctly.
unsafe impl Sync for AuthData {}

//----------- AuthCtrl ---------------------------------------------------------

/// Locking control for [`AuthData`].
///
/// This is an atomic variable that controls read and write access to
/// [`AuthData`].
///
/// # Rationale
///
/// Manual locking offers greater flexibility and is significantly simpler than
/// `std`, `tokio`, or other conventional lock types.
///
/// 1. `AuthData` requires individual locking of the current and upcoming
///    instances. These components are individual fields today, but they will
///    become a single complex data structure in the future. Standard locks
///    will simply not suffice.
///
/// 2. Locking `AuthData` will never require blocking -- success should be
///    guaranteed by the caller's lock on `ZoneState`. [`AuthCtrl`]'s only
///    purpose is to verify that locks are taken properly, thereby ensuring
///    memory safety.
///
///    A secondary effect of this is that lock contention, and the performance
///    characteristics around it, are irrelevant. The custom implementation can
///    be very simple.
///
/// 3. Customized lock guards can hold `Arc<AuthData>` and avoid the annoying
///    lifetime parameter that comes with conventional lock guards. And custom
///    read guards can implement `Clone`.
//
// TODO: Update once the fancy data structure has been implemented.
pub(crate) struct AuthCtrl {
    /// For the unsigned part of the current instance.
    pub curr_un: RwLockCtrl,

    /// For the unsigned part of the next instance.
    pub next_un: RwLockCtrl,

    /// For the signed part of the current instance.
    pub curr_si: RwLockCtrl,

    /// For the signed part of the next instance.
    pub next_si: RwLockCtrl,
}

impl AuthCtrl {
    /// Construct a new [`AuthCtrl`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            curr_un: RwLockCtrl::new(),
            next_un: RwLockCtrl::new(),
            curr_si: RwLockCtrl::new(),
            next_si: RwLockCtrl::new(),
        }
    }
}

/// A simple non-blocking read-write lock control.
///
/// The internal atomic variable is 0 if unlocked, -1 if a write lock is held,
/// or a positive number if (that many) read locks are held.
pub(crate) struct RwLockCtrl(AtomicI32);

impl RwLockCtrl {
    /// Construct a new [`RwLockCtrl`] in the unlocked state.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicI32::new(0))
    }

    /// Obtain a read lock.
    ///
    /// Returns `true` on success, and `false` if a write lock exists.
    ///
    /// ## Panics
    ///
    /// Panics if `2^31` readers are present simultaneously.
    #[must_use = "On success, the read lock must be dropped eventually"]
    pub fn read(&self) -> bool {
        // 'Acquire' so that any previous changes are visible.
        self.0
            .fetch_update(
                atomic::Ordering::Acquire,
                atomic::Ordering::Relaxed,
                |state| {
                    // Increment 'state' if possible.
                    assert!(state < i32::MAX);
                    (state >= 0).then_some(state + 1)
                },
            )
            .is_ok()
    }

    /// Drop a read lock.
    ///
    /// ## Safety
    ///
    /// `self.stop_read()` is sound if and only if it corresponds to a unique
    /// previous successful call to `self.read()`.
    pub unsafe fn stop_read(&self) {
        self.0.fetch_sub(1, atomic::Ordering::Relaxed);
    }

    /// Obtain a write lock.
    ///
    /// Returns `true` on success, and `false` if any read locks exist.
    #[must_use = "On success, the write lock must be dropped eventually"]
    pub fn write(&self) -> bool {
        // 'Acquire' so that any previous changes are visible.
        self.0
            .fetch_update(
                atomic::Ordering::Acquire,
                atomic::Ordering::Relaxed,
                |state| (state == 0).then_some(-1),
            )
            .is_ok()
    }

    /// Drop a write lock.
    ///
    /// ## Safety
    ///
    /// `self.stop_write()` is sound if and only if it corresponds to a unique
    /// previous successful call to `self.write()`.
    pub unsafe fn stop_write(&self) {
        // 'Release' so that new changes are visible to others.
        self.0.store(0, atomic::Ordering::Release);
    }
}

impl Default for RwLockCtrl {
    fn default() -> Self {
        Self::new()
    }
}
