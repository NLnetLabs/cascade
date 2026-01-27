//! Applying changes to zones.

use std::sync::Arc;

use crate::{AuthData, InstanceHalf, UnsignedZoneViewer, ZoneViewer};

//----------- ZoneApplier ------------------------------------------------------

/// An applier of changes to a zone.
///
/// Once a new instance of a zone has been built (e.g. by [`ZoneBuilder`]),
/// it needs to be applied, so it can replace the current authoritative
/// instance; but this is an asynchronous process. Existing read locks of the
/// authoritative instance have to be released, and switched to read locks of
/// the upcoming instance.
///
/// [`ZoneBuilder`]: crate::ZoneBuilder
///
/// [`ZoneApplier`] represents this point in time, where both the authoritative
/// and upcoming instances of the zone are read-locked. Once all read locks of
/// the authoritative instance have been dropped, the upcoming instance can be
/// copied to the authoritative instance using [`apply()`].
///
/// [`apply()`]: Self::apply()
pub struct ZoneApplier {
    /// The underlying data.
    ///
    /// [`ZoneApplier`] has a read lock over the upcoming instance.
    data: Arc<AuthData>,
}

impl ZoneApplier {
    /// Obtain a [`ZoneApplier`].
    ///
    /// ## Panics
    ///
    /// Panics if `data` has conflicting locks (write locks of the upcoming
    /// instance), or if too many read locks were established.
    pub(crate) fn new(data: Arc<AuthData>) -> Self {
        // Lock every component of the data appropriately.
        assert!(
            data.ctrl.next_un.read(),
            "the upcoming unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.next_si.read(),
            "the upcoming signed instance is write-locked"
        );

        // Construct 'Self' now that the requisite locks are taken.
        Self { data }
    }

    /// Obtain a [`ZoneViewer`] over the upcoming instance.
    pub fn view(&self) -> ZoneViewer {
        ZoneViewer::obtain_next(self.data.clone())
    }

    /// Obtain an [`UnsignedZoneViewer`] over the upcoming instance.
    pub fn view_unsigned(&self) -> UnsignedZoneViewer {
        UnsignedZoneViewer::obtain_next(self.data.clone())
    }

    /// Apply the change.
    ///
    /// All read locks of the authoritative instance should have been released.
    /// The upcoming instance will be copied to the authoritative instance. On
    /// success, the authoritative instance will become available to read-lock
    /// once more, and a [`ZoneCleaner`] is returned to handle cleaning up the
    /// upcoming instance state.
    ///
    /// ## Panics
    ///
    /// Panics if the authoritative instance is still read-locked.
    pub fn apply(self) -> ZoneCleaner {
        // Write-lock the authoritative instance.
        assert!(self.data.ctrl.curr_un.write());
        assert!(self.data.ctrl.curr_si.write());

        // SAFETY: 'self' has a read lock over 'data.next'.
        let next = unsafe { &*self.data.next.get() };

        // SAFETY: A write lock over 'data.curr' has been taken.
        let curr = unsafe { &mut *self.data.curr.get() };

        // Copy over the new instance.
        curr.unsigned = next.unsigned.as_ref().map(|i| InstanceHalf {
            soa: i.soa.clone(),
            all: i.all.clone(),
        });
        curr.signed = next.signed.as_ref().map(|i| InstanceHalf {
            soa: i.soa.clone(),
            all: i.all.clone(),
        });

        // Done; release the write lock.
        // SAFETY: These write locks were taken at the start of the function.
        unsafe {
            self.data.ctrl.curr_un.stop_write();
            self.data.ctrl.curr_si.stop_write();
        }

        ZoneCleaner::new(self.data.clone())
    }
}

impl Drop for ZoneApplier {
    fn drop(&mut self) {
        // SAFETY: 'ZoneApplier' is built with a read lock of the upcoming
        // instance.
        unsafe {
            // Drop all locks.
            self.data.ctrl.next_un.stop_read();
            self.data.ctrl.next_si.stop_read();
        }
    }
}

//----------- ZoneCleaner ------------------------------------------------------

/// A cleaner of applied changes to a zone.
///
/// After changes to a zone have been applied with [`ZoneApplier`], the built
/// upcoming instance is copied to the authoritative instance; at this time,
/// there may be external read locks of the upcoming instance. [`ZoneCleaner`]
/// waits until those read locks are eleased, and then cleans up leftover
/// state in the upcoming instance.
pub struct ZoneCleaner {
    /// The underlying data.
    ///
    /// [`ZoneCleaner`] has a read lock over the authoritative instance.
    data: Arc<AuthData>,
}

impl ZoneCleaner {
    /// Obtain a [`ZoneCleaner`].
    ///
    /// ## Panics
    ///
    /// Panics if `data` has conflicting locks (write locks of the authoritative
    /// instance), or if too many read locks were established.
    pub(crate) fn new(data: Arc<AuthData>) -> Self {
        // Lock every component of the data appropriately.
        assert!(
            data.ctrl.curr_un.read(),
            "the authoritative unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.curr_si.read(),
            "the authoritative signed instance is write-locked"
        );

        // Construct 'Self' now that the requisite locks are taken.
        Self { data }
    }

    /// Obtain a [`ZoneViewer`] over the authoritative instance.
    pub fn view(&self) -> ZoneViewer {
        ZoneViewer::obtain_curr(self.data.clone())
    }

    /// Obtain an [`UnsignedZoneViewer`] over the authoritative instance.
    pub fn view_unsigned(&self) -> UnsignedZoneViewer {
        UnsignedZoneViewer::obtain_curr(self.data.clone())
    }

    /// Clean up post-application changes.
    ///
    /// All read locks of the upcoming instance must have been released. It
    /// will be write-locked and any leftover state within it will be cleaned
    /// up.
    ///
    /// ## Panics
    ///
    /// Panics if the upcoming instance is still read-locked.
    pub fn clean(self) {
        // Write-lock the upcoming instance.
        assert!(self.data.ctrl.next_un.write());
        assert!(self.data.ctrl.next_si.write());

        // SAFETY: A write lock over 'data.next' has been taken.
        let next = unsafe { &mut *self.data.next.get() };

        // Clear the new instance.
        next.unsigned = None;
        next.signed = None;

        // Done; release the write lock.
        // SAFETY: These write locks were taken at the start of the function.
        unsafe {
            self.data.ctrl.next_un.stop_write();
            self.data.ctrl.next_si.stop_write();
        }
    }
}

impl Drop for ZoneCleaner {
    fn drop(&mut self) {
        // SAFETY: 'ZoneCleaner' is built with a read lock of the authoritative
        // instance.
        unsafe {
            // Drop all locks.
            self.data.ctrl.curr_un.stop_read();
            self.data.ctrl.curr_si.stop_read();
        }
    }
}
