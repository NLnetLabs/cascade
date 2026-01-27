//! Reading instances of zones.

use std::sync::Arc;

use crate::{AuthData, SignedZoneReader, UnsignedZoneReader};

//----------- ZoneViewer -------------------------------------------------------

/// A viewer for an instance of a zone.
///
/// [`ZoneViewer`] provides access to (the signed and unsigned components of)
/// the _authoritative_ or _upcoming_ instance of a zone.
pub struct ZoneViewer {
    /// The underlying data.
    ///
    /// [`ZoneViewer`] has a read lock over the signed and unsigned components
    /// of the authoritative or upcoming instance (depending on `self.curr`).
    data: Arc<AuthData>,

    /// Whether the authoritative instance is being read.
    curr: bool,
}

impl ZoneViewer {
    /// Obtain a [`ZoneViewer`] for the authoritative instance of a zone.
    ///
    /// ## Panics
    ///
    /// Panics if (either the unsigned or signed component of) the instance
    /// is write-locked or if the number of simultaneous read locks causes an
    /// overflow.
    pub(crate) fn obtain_curr(data: Arc<AuthData>) -> Self {
        assert!(
            data.ctrl.curr_un.read(),
            "the authoritative unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.curr_si.read(),
            "the authoritative signed instance is write-locked"
        );

        Self { data, curr: true }
    }

    /// Obtain a [`ZoneViewer`] for the upcoming instance of a zone.
    ///
    /// ## Panics
    ///
    /// Panics if (either the unsigned or signed component of) the instance
    /// is write-locked or if the number of simultaneous read locks causes an
    /// overflow.
    pub(crate) fn obtain_next(data: Arc<AuthData>) -> Self {
        assert!(
            data.ctrl.next_un.read(),
            "the upcoming unsigned instance is write-locked"
        );
        assert!(
            data.ctrl.next_si.read(),
            "the upcoming signed instance is write-locked"
        );

        Self { data, curr: true }
    }
}

impl ZoneViewer {
    /// The unsigned component of this instance, if any.
    pub fn unsigned(&self) -> Option<UnsignedZoneReader<'_>> {
        let instance = if self.curr {
            &self.data.curr
        } else {
            &self.data.next
        };

        // SAFETY: 'self' has a read lock over 'instance'.
        let instance = unsafe { &(*instance.get()).unsigned };

        instance
            .as_ref()
            .map(|instance| UnsignedZoneReader { data: instance })
    }

    /// The signed component of this instance, if any.
    pub fn signed(&self) -> Option<SignedZoneReader<'_>> {
        let instance = if self.curr {
            &self.data.curr
        } else {
            &self.data.next
        };

        // SAFETY: 'self' has a read lock over 'instance'.
        let instance = unsafe { &(*instance.get()).signed };

        instance
            .as_ref()
            .map(|instance| SignedZoneReader { data: instance })
    }
}

impl Drop for ZoneViewer {
    fn drop(&mut self) {
        // SAFETY: 'self' has a read lock over the signed and unsigned
        // components of either the authoritative or the upcoming instance,
        // depending on 'self.curr'.
        unsafe {
            if self.curr {
                self.data.ctrl.curr_un.stop_read();
                self.data.ctrl.curr_si.stop_read();
            } else {
                self.data.ctrl.next_un.stop_read();
                self.data.ctrl.next_si.stop_read();
            }
        }
    }
}

//----------- UnsignedZoneViewer -----------------------------------------------

/// A viewer for an unsigned instance of a zone.
///
/// [`UnsignedZoneViewer`] provides access to unsigned component of the
/// _authoritative_ or _upcoming_ instance of a zone.
pub struct UnsignedZoneViewer {
    /// The underlying data.
    ///
    /// [`UnsignedZoneViewer`] has a read lock over the unsigned component of
    /// the authoritative or upcoming instance (depending on `self.curr`).
    data: Arc<AuthData>,

    /// Whether the authoritative instance is being read.
    curr: bool,
}

impl UnsignedZoneViewer {
    /// Obtain a [`UnsignedZoneViewer`] for the authoritative instance of
    /// a zone.
    ///
    /// ## Panics
    ///
    /// Panics if (the unsigned component of) the instance is write-locked or if
    /// the number of simultaneous read locks causes an overflow.
    pub(crate) fn obtain_curr(data: Arc<AuthData>) -> Self {
        assert!(
            data.ctrl.curr_un.read(),
            "the authoritative unsigned instance is write-locked"
        );

        Self { data, curr: true }
    }

    /// Obtain a [`UnsignedZoneViewer`] for the upcoming instance of a zone.
    ///
    /// ## Panics
    ///
    /// Panics if (the unsigned component of) the instance is write-locked or if
    /// the number of simultaneous read locks causes an overflow.
    pub(crate) fn obtain_next(data: Arc<AuthData>) -> Self {
        assert!(
            data.ctrl.next_un.read(),
            "the upcoming unsigned instance is write-locked"
        );

        Self { data, curr: true }
    }
}

impl UnsignedZoneViewer {
    /// Obtain a reader over the underlying data, if it exists.
    pub fn reader(&self) -> Option<UnsignedZoneReader<'_>> {
        let instance = if self.curr {
            &self.data.curr
        } else {
            &self.data.next
        };

        // SAFETY: 'self' has a read lock over 'instance.unsigned'.
        let instance = unsafe { &(*instance.get()).unsigned };

        instance
            .as_ref()
            .map(|instance| UnsignedZoneReader { data: instance })
    }
}

impl Drop for UnsignedZoneViewer {
    fn drop(&mut self) {
        // SAFETY: 'self' has a read lock over the signed component of either
        // the authoritative or the upcoming instance, depending on 'self.curr'.
        unsafe {
            if self.curr {
                self.data.ctrl.curr_un.stop_read();
            } else {
                self.data.ctrl.next_un.stop_read();
            }
        }
    }
}
