//! The raw storage for zone data.
//!
//! This module provides [`Data`], which stores data for the authoritative
//! instance and one upcoming instance for a zone. It can be used concurrently
//! in certain situations, but it does not provide a safe API. Building a safe
//! abstraction is handled elsewhere; this module focuses on the implementation
//! of the concurrent data structures.
//!
//! # Implementation
//!
//! At the moment, the implementation is very simple; [`Data`] stores two slots
//! for unsigned content and two slots for signed content. Each slot can be used
//! concurrently. There is no data shared between slots. Significant changes are
//! planned (which will also affect the public API for reading and writing this
//! data).

use std::cell::UnsafeCell;

use crate::{RegularRecord, SoaRecord};

//----------- Data -------------------------------------------------------------

/// Raw storage for the data of a zone.
#[derive(Default)]
pub struct Data {
    /// The unsigned components of the zone.
    pub unsigned: [UnsafeCell<InstanceData>; 2],

    /// The signed components of the zone.
    pub signed: [UnsafeCell<InstanceData>; 2],
}

impl Data {
    /// Construct a new [`Data`].
    pub const fn new() -> Self {
        Self {
            unsigned: [const { UnsafeCell::new(InstanceData::new()) }; 2],
            signed: [const { UnsafeCell::new(InstanceData::new()) }; 2],
        }
    }
}

// SAFETY: 'Data' is externally read-write locked.
unsafe impl Sync for Data {}

/// Data for an unsigned or signed instance of a zone.
//
// TODO: This will separate into an unsigned and a signed variant.
#[derive(Clone, Default)]
pub struct InstanceData {
    /// The SOA record.
    ///
    /// A complete instance will always have a SOA record.
    pub soa: Option<SoaRecord>,

    /// All other records.
    ///
    /// Records are sorted in DNSSEC canonical order. The SOA record is not
    /// included.
    pub records: Vec<RegularRecord>,
}

impl InstanceData {
    /// Construct a new [`InstanceData`].
    pub const fn new() -> Self {
        Self {
            soa: None,
            records: Vec::new(),
        }
    }
}
