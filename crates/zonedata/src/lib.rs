//! Zone storage for [Cascade].
//!
//! [Cascade]: https://nlnetlabs.nl/projects/cascade
//!
//! The zone store is an essential part of Cascade.  It provides the following
//! functionality:
//!
//! - Storage for the zones loaded by Cascade.
//! - Storage for the signed versions of those zones.
//! - Storage for candidate versions of a zone and rollback.
//! - Identification of different versions of a zone.
//! - Storage for diffs between versions of a zone.
//! - Efficient lookups and traversals over zones.
//! - Persistence of zone data (to/from disk).
//!
//! The zone store is highly memory-efficient and offers parallelized access to
//! stored zones.  It is particularly tailored to parallelized signing.
