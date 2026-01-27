//! Building new instances of zones.

use std::sync::Arc;

use crate::{AuthData, SignedZoneReader, UnsignedZoneReader};

//----------- ZoneBuilder ------------------------------------------------------

/// A builder of a new instance of a zone.
///
/// [`ZoneBuilder`] controls the _upcoming instance_ of a zone, allowing it to
/// be built (e.g. by loading new zone data from a DNS server). It also offers
/// read-only access to the current _authoritative instance_.
pub struct ZoneBuilder {
    /// The underlying data.
    ///
    /// [`ZoneBuilder`] has a read lock over the current (i.e. authoritative)
    /// instance and a write lock over the next (i.e. upcoming) instance.
    data: Arc<AuthData>,

    /// Whether the built changes have been applied.
    ///
    /// If this is unset, the drop guard will clear all pending changes. This
    /// ensures that intermediate state is cleaned up in case of failure.
    applied: bool,
}

impl ZoneBuilder {
    /// Obtain a [`ZoneBuilder`].
    ///
    /// ## Panics
    ///
    /// Panics if `data` has conflicting locks (write locks of the authoritative
    /// instance or read locks of the upcoming instance), or if too many read
    /// locks were established.
    pub(crate) fn obtain(data: Arc<AuthData>) -> Self {
        // Lock every component of the data appropriately.
        assert!(
            data.ctrl.curr_un.read(),
            "the authoritative unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.curr_si.read(),
            "the authoritative signed instance is write-locked"
        );
        assert!(
            data.ctrl.next_un.write(),
            "the upcoming unsigned instance is locked"
        );
        assert!(
            data.ctrl.next_si.write(),
            "the upcoming signed instance is locked"
        );

        // Construct 'Self' now that the requisite locks are taken.
        Self {
            data,
            applied: false,
        }
    }
}

impl ZoneBuilder {
    /// The unsigned component of the authoritative instance, if any.
    pub fn unsigned_curr(&self) -> Option<UnsignedZoneReader<'_>> {
        // SAFETY: 'self' has a read lock over 'self.data.curr'.
        let instance = unsafe { &(*self.data.curr.get()).unsigned };

        instance
            .as_ref()
            .map(|instance| UnsignedZoneReader { data: instance })
    }

    /// The signed component of the authoritative instance, if any.
    pub fn signed_curr(&self) -> Option<SignedZoneReader<'_>> {
        // SAFETY: 'self' has a read lock over 'self.data.curr'.
        let instance = unsafe { &(*self.data.curr.get()).signed };

        instance
            .as_ref()
            .map(|instance| SignedZoneReader { data: instance })
    }
}

impl Drop for ZoneBuilder {
    fn drop(&mut self) {
        // SAFETY: 'ZoneBuilder' is built with a read lock of the current
        // instance and a write lock of the next instance.
        unsafe {
            // Clear up any unapplied changes.
            if !self.applied {
                let next = &mut *self.data.next.get();
                next.unsigned.take();
                next.signed.take();
            }

            // Drop all locks.
            self.data.ctrl.curr_un.stop_read();
            self.data.ctrl.curr_si.stop_read();
            self.data.ctrl.next_un.stop_write();
            self.data.ctrl.next_si.stop_write();
        }
    }
}

//----------- SignedZoneBuilder ------------------------------------------------

/// A builder of a new signed instance of a zone.
///
/// [`SignedZoneBuilder`] controls the _upcoming instance_ of a zone, allowing
/// it to be built (e.g. by signing some loaded data). It offers read-only
/// access to the current _authoritative instance_ and the _upcoming unsigned
/// instance_ (if any).
pub struct SignedZoneBuilder {
    /// The underlying data.
    ///
    /// [`ZoneBuilder`] has a read lock over the current (i.e. authoritative)
    /// instance and the next (i.e. upcoming) unsigned instance, and a write
    /// lock over the next signed instance.
    pub(crate) data: Arc<AuthData>,

    /// Whether the built changes have been applied.
    ///
    /// If this is unset, the drop guard will clear all pending changes. This
    /// ensures that intermediate state is cleaned up in case of failure.
    pub(crate) applied: bool,
}

impl SignedZoneBuilder {
    /// Obtain a [`SignedZoneBuilder`].
    ///
    /// ## Panics
    ///
    /// Panics if `data` has conflicting locks (write locks of the authoritative
    /// instance or upcoming unsigned instance, or read locks of the upcoming
    /// signed instance), or if too many read locks were established.
    pub(crate) fn obtain(data: Arc<AuthData>) -> Self {
        // Lock every component of the data appropriately.
        assert!(
            data.ctrl.curr_un.read(),
            "the authoritative unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.curr_si.read(),
            "the authoritative signed instance is write-locked"
        );
        assert!(
            data.ctrl.next_un.read(),
            "the upcoming unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.next_si.write(),
            "the upcoming signed instance is locked"
        );

        // Construct 'Self' now that the requisite locks are taken.
        Self {
            data,
            applied: false,
        }
    }
}

impl SignedZoneBuilder {
    /// The unsigned component of the authoritative instance, if any.
    pub fn unsigned_curr(&self) -> Option<UnsignedZoneReader<'_>> {
        // SAFETY: 'self' has a read lock over 'self.data.curr'.
        let instance = unsafe { &(*self.data.curr.get()).unsigned };

        instance
            .as_ref()
            .map(|instance| UnsignedZoneReader { data: instance })
    }

    /// The signed component of the authoritative instance, if any.
    pub fn signed_curr(&self) -> Option<SignedZoneReader<'_>> {
        // SAFETY: 'self' has a read lock over 'self.data.curr'.
        let instance = unsafe { &(*self.data.curr.get()).signed };

        instance
            .as_ref()
            .map(|instance| SignedZoneReader { data: instance })
    }

    /// The unsigned component of the upcoming instance, if any.
    pub fn unsigned_next(&self) -> Option<UnsignedZoneReader<'_>> {
        // SAFETY: 'self' has a read lock over 'self.data.next'.
        let instance = unsafe { &(*self.data.next.get()).unsigned };

        instance
            .as_ref()
            .map(|instance| UnsignedZoneReader { data: instance })
    }
}

impl Drop for SignedZoneBuilder {
    fn drop(&mut self) {
        // SAFETY: 'SignedZoneBuilder' is built with a read lock of the current
        // instance and next unsigned instance and a write lock of the next
        // signed instance.
        unsafe {
            // Clear up any unapplied changes.
            if !self.applied {
                (*self.data.next.get()).signed.take();
            }

            // Drop all locks.
            self.data.ctrl.curr_un.stop_read();
            self.data.ctrl.curr_si.stop_read();
            self.data.ctrl.next_un.stop_read();
            self.data.ctrl.next_si.stop_write();
        }
    }
}
