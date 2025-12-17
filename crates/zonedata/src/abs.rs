//! Representing zone data absolutely.

use std::sync::Arc;

use crate::{InconsistencyError, Record, RelSignedData, RelUnsignedData, SoaRecord, merge};

//----------- AbsData ----------------------------------------------------------

/// The contents of an instance of a zone, in absolute representation.
///
/// `AbsData` stores:
///
/// - The contents of an unsigned instance, if any.
///
/// - The contents of a signed instance, if any.
///
///   The signed instance is associated with the unsigned instance (which then
///   also exists) and extends it with signing-related records.
///
/// - A new (un)signed instance in the process of being built.
///
///   A single such instance can be built at a time.  It will be efficiently
///   stored alongside the existing instance.  When the new instance is ready,
///   it will replace the existing instance atomically.
#[derive(Default)]
pub struct AbsData {
    // TODO: Use specialized representations for the various (kinds of) records.
    // This would result in faster traversals, faster lookups, and better memory
    // efficiency.
    //
    // TODO: Merge the current and new instance, and store the differences in
    // place.  This would require 'InstanceData' (currently based on slices) to
    // support concurrent modification.
    //
    // TODO: Support persistence (probably using file-backed memory maps).
    //
    /// The data of the current instance, if any.
    cur: Arc<tokio::sync::RwLock<InstanceData>>,

    /// The data of the new instance, if any.
    new: Arc<tokio::sync::RwLock<InstanceData>>,
}

/// Data for a single instance.
#[derive(Default, Clone)]
struct InstanceData {
    /// Data for the unsigned portion.
    unsigned: Option<InstanceDataHalf>,

    /// Data for the signed portion.
    signed: Option<InstanceDataHalf>,
}

/// Data for a signed/unsigned half of an instance.
#[derive(Clone)]
struct InstanceDataHalf {
    /// The SOA record.
    soa: SoaRecord,

    /// Other records, in DNSSEC canonical order.
    records: Box<[Record]>,
}

impl AbsData {
    /// Obtain a reader for the currently published instance.
    ///
    /// ## Panics
    ///
    /// Panics if there is no current instance, or if it is write-locked.
    pub fn read(self: &Arc<Self>) -> AbsReader {
        let guard = self
            .cur
            .clone()
            .try_read_owned()
            .unwrap_or_else(|_| panic!("'cur' is currently write-locked"));

        assert!(
            guard.unsigned.is_some(),
            "an instance of the zone is not available"
        );

        AbsReader {
            _data: self.clone(),
            guard,
        }
    }

    /// Obtain a reader for the upcoming instance.
    ///
    /// This should be called when it is known that a new instance of the zone
    /// has been created and is ready for use.
    ///
    /// ## Panics
    ///
    /// Panics if there is no new instance, or if it is write-locked.
    pub fn read_new(self: &Arc<Self>) -> AbsReader {
        let guard = self
            .new
            .clone()
            .try_read_owned()
            .unwrap_or_else(|_| panic!("'new' is currently write-locked"));

        assert!(guard.unsigned.is_some(), "'new' is not available");

        AbsReader {
            _data: self.clone(),
            guard,
        }
    }

    /// Obtain a writer for building a new instance.
    ///
    /// ## Panics
    ///
    /// Panics if another write is ongoing or was left incomplete.
    pub fn write(self: &Arc<Self>) -> AbsWriter {
        // Lock 'cur'.  If it is unavailable, another write is ongoing.
        let cur = self
            .cur
            .clone()
            .try_read_owned()
            .unwrap_or_else(|_| panic!("'cur' is write-locked"));

        // Lock 'new'.  If it is unavailable, another write is ongoing.
        let mut new = self
            .new
            .clone()
            .try_write_owned()
            .unwrap_or_else(|_| panic!("'new' is locked"));

        // TODO: This will go away with a better data structure.
        assert!(
            new.unsigned.is_none() && new.signed.is_none(),
            "found leftover data from a previous write"
        );
        new.unsigned = cur.unsigned.as_ref().cloned();
        new.signed = cur.signed.as_ref().cloned();

        AbsWriter {
            _data: self.clone(),
            _cur: cur,
            new,
        }
    }

    /// Resume a previous write session.
    ///
    /// ## Panics
    ///
    /// Panics if another write is ongoing.
    pub fn resume_write(self: &Arc<Self>) -> AbsWriter {
        // Lock 'cur'.  If it is unavailable, another write is ongoing.
        let cur = self
            .cur
            .clone()
            .try_read_owned()
            .unwrap_or_else(|_| panic!("'cur' is write-locked"));

        // Lock 'new'.  If it is unavailable, another write is ongoing.
        let new = self
            .new
            .clone()
            .try_write_owned()
            .unwrap_or_else(|_| panic!("'new' is locked"));

        // TODO: We don't have enough state to know whether there is a previous
        // write we are resuming. We could keep some...

        AbsWriter {
            _data: self.clone(),
            _cur: cur,
            new,
        }
    }

    /// Apply a prepared change.
    ///
    /// ## Panics
    ///
    /// Panics if the current published version is read- or write- locked (i.e.
    /// there are live [`AbsReader`]s from [`Self::read()`]) or the prepared
    /// version is write-locked (i.e. there are live [`AbsWriter`]s).
    pub fn apply(&self) {
        // TODO: We don't have enough state to know whether there is a prepared
        // change. We could keep some...

        let mut cur = self
            .cur
            .clone()
            .try_write_owned()
            .unwrap_or_else(|_| panic!("'cur' is locked"));
        let new = self
            .new
            .clone()
            .try_read_owned()
            .unwrap_or_else(|_| panic!("'new' is write-locked"));

        cur.unsigned = new.unsigned.as_ref().cloned();
        cur.signed = new.signed.as_ref().cloned();
    }

    /// Clean up an applied change.
    ///
    /// ## Panics
    ///
    /// Panics if the prepared change is read- or write- locked (i.e. there are
    /// live [`AbsWriter`]s or [`AbsReader`]s from [`Self::read_new()`]).
    pub fn clean_up_applied(&self) {
        // TODO: We don't have enough state to know whether there is a prepared
        // change. We could keep some...

        let mut new = self
            .new
            .clone()
            .try_write_owned()
            .unwrap_or_else(|_| panic!("'new' is locked"));
        new.unsigned = None;
        new.signed = None;
    }
}

//----------- AbsReader --------------------------------------------------------

/// A reader for the contents of a zone.
pub struct AbsReader {
    /// The underlying data.
    _data: Arc<AbsData>,

    /// The read lock guard.
    ///
    /// This refers to [`AbsData::cur`] or [`AbsData::new`].  In either case,
    /// there is definitely an unsigned instance; there may be a signed one too.
    guard: tokio::sync::OwnedRwLockReadGuard<InstanceData>,
}

impl AbsReader {
    /// Retrieve the unsigned data.
    pub fn unsigned(&self) -> AbsUnsignedReader<'_> {
        AbsUnsignedReader {
            _reader: self,
            data: self.guard.unsigned.as_ref().expect(
                "An 'AbsReader' can only be constructed when an unsigned instance is available",
            ),
        }
    }

    /// Retrieve the signed data.
    ///
    /// ## Panics
    ///
    /// Panics if no signed data is available.
    pub fn signed(&self) -> AbsSignedReader<'_> {
        AbsSignedReader {
            _reader: self,
            data: self
                .guard
                .signed
                .as_ref()
                .unwrap_or_else(|| panic!("the zone did not have a signed instance")),
        }
    }
}

/// A reader for the unsigned contents of a zone.
pub struct AbsUnsignedReader<'r> {
    /// The underlying reader.
    _reader: &'r AbsReader,

    /// The data.
    data: &'r InstanceDataHalf,
}

impl<'r> AbsUnsignedReader<'r> {
    /// The SOA record.
    pub const fn soa(&self) -> &SoaRecord {
        &self.data.soa
    }

    /// The records.
    ///
    /// These are sorted in DNSSEC canonical order.
    pub const fn records(&self) -> &[Record] {
        &self.data.records
    }
}

/// A reader for the signed contents of a zone.
pub struct AbsSignedReader<'r> {
    /// The underlying reader.
    _reader: &'r AbsReader,

    /// The data.
    data: &'r InstanceDataHalf,
}

impl<'r> AbsSignedReader<'r> {
    /// The SOA record.
    pub const fn soa(&self) -> &SoaRecord {
        &self.data.soa
    }

    /// The records.
    ///
    /// These are sorted in DNSSEC canonical order.
    pub const fn records(&self) -> &[Record] {
        &self.data.records
    }
}

//----------- AbsWriter --------------------------------------------------------

/// A writer for the contents of a zone.
pub struct AbsWriter {
    /// The underlying data.
    _data: Arc<AbsData>,

    /// The read lock on the existing data.
    ///
    /// This refers to [`AbsData::cur`].
    _cur: tokio::sync::OwnedRwLockReadGuard<InstanceData>,

    /// The write lock on the new slot.
    ///
    /// This refers to [`AbsData::new`].
    new: tokio::sync::OwnedRwLockWriteGuard<InstanceData>,
}

impl AbsWriter {
    /// Apply a diff to the unsigned instance.
    ///
    /// ## Errors
    ///
    /// Fails if the diff is not consistent with the unsigned instance.  In this
    /// case, the zone data is completely unaffected.
    ///
    /// ## Panics
    ///
    /// Panics if there wasn't an old unsigned instance to apply the diff to.
    pub fn apply_unsigned_diff(&mut self, diff: RelUnsignedData) -> Result<(), InconsistencyError> {
        // Find the base to apply the diff to.
        //
        // If the caller has begun building the unsigned instance, it will be
        // used as the base.  Otherwise, the old unsigned instance (which must
        // exist) will be used.
        let base = self
            .new
            .unsigned
            .as_ref()
            .unwrap_or_else(|| panic!("no absolute unsigned instance to apply the diff to"));

        // Update the SOA record.
        if base.soa != *diff.removed_soa() {
            return Err(InconsistencyError);
        }
        let soa = diff.added_soa().clone();

        // Build a new record set with the diff.
        let records = merge([
            base.records.iter(),
            diff.removed().iter(),
            diff.added().iter(),
        ])
        .map(|records| match records {
            // Removing a record that doesn't exist.
            [None, Some(_), _] => Err(InconsistencyError),

            // Adding a record that already exists.
            [Some(_), None, Some(_)] => Err(InconsistencyError),

            // Removing and adding the same record.
            [_, Some(_), Some(_)] => Err(InconsistencyError),

            // No change.
            [r, None, None] => Ok(r.cloned()),

            // Adding a record.
            [None, None, Some(r)] => Ok(Some(r.clone())),

            // Removing a record.
            [Some(_), Some(_), None] => Ok(None),
        })
        .filter_map(|x| x.transpose())
        .collect::<Result<_, _>>()?;

        // Save the new record set.
        self.new.unsigned = Some(InstanceDataHalf { soa, records });
        Ok(())
    }

    /// Apply a diff to the signed instance.
    ///
    /// ## Errors
    ///
    /// Fails if the diff is not consistent with the signed instance.  In this
    /// case, the zone data is completely unaffected.
    ///
    /// ## Panics
    ///
    /// Panics if there wasn't an old signed instance to apply the diff to.
    pub fn apply_signed_diff(&mut self, diff: RelSignedData) -> Result<(), InconsistencyError> {
        // Find the base to apply the diff to.
        //
        // If the caller has begun building the signed instance, it will be
        // used as the base.  Otherwise, the old signed instance (which must
        // exist) will be used.
        let base = self
            .new
            .signed
            .as_ref()
            .unwrap_or_else(|| panic!("no absolute signed instance to apply the diff to"));

        // Update the SOA record.
        if base.soa != *diff.removed_soa() {
            return Err(InconsistencyError);
        }
        let soa = diff.added_soa().clone();

        // Build a new record set with the diff.
        let records = merge([
            base.records.iter(),
            diff.removed().iter(),
            diff.added().iter(),
        ])
        .map(|records| match records {
            // Removing a record that doesn't exist.
            [None, Some(_), _] => Err(InconsistencyError),

            // Adding a record that already exists.
            [Some(_), None, Some(_)] => Err(InconsistencyError),

            // Removing and adding the same record.
            [_, Some(_), Some(_)] => Err(InconsistencyError),

            // No change.
            [r, None, None] => Ok(r.cloned()),

            // Adding a record.
            [None, None, Some(r)] => Ok(Some(r.clone())),

            // Removing a record.
            [Some(_), Some(_), None] => Ok(None),
        })
        .filter_map(|x| x.transpose())
        .collect::<Result<_, _>>()?;

        // Save the new record set.
        self.new.signed = Some(InstanceDataHalf { soa, records });
        Ok(())
    }

    /// Add new absolute unsigned data.
    ///
    /// ## Panics
    ///
    /// Panics if there was existing instance of the unsigned data.
    pub fn add_unsigned(&mut self, soa: SoaRecord, records: Box<[Record]>) {
        assert!(
            self.new.unsigned.is_none(),
            "cannot implicitly overwrite an existing unsigned instance"
        );

        self.new.unsigned = Some(InstanceDataHalf { soa, records });
    }

    /// Add new absolute signed data.
    ///
    /// ## Panics
    ///
    /// Panics if there was existing instance of the signed data.
    pub fn add_signed(&mut self, soa: SoaRecord, records: Box<[Record]>) {
        assert!(
            self.new.signed.is_none(),
            "cannot implicitly overwrite an existing signed instance"
        );

        self.new.signed = Some(InstanceDataHalf { soa, records });
    }

    /// Delete the previous instance completely.
    ///
    /// This is a no-op if the instance was already wiped.
    pub fn wipe(&mut self) {
        self.new.unsigned = None;
        self.new.signed = None;
    }

    /// Delete the previous signed instance.
    ///
    /// This is a no-op if there was no signed instance.
    pub fn wipe_signed(&mut self) {
        self.new.signed = None;
    }
}
