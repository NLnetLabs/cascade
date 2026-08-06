//! Applying changes to zone data.

use std::iter::Peekable;

use cascade_zonedata::{RegularRecord, SoaRecord};

use super::{InstanceDiff, LoadedInstanceData, SignedInstanceData};

//----------- LoadedInstanceData -----------------------------------------------

impl LoadedInstanceData {
    /// Whether a diff can be applied to this.
    ///
    /// ## Errors
    ///
    /// Fails if the diff is inconsistent with `self`, and returns an error
    /// describing the inconsistency.
    pub fn can_apply_diff(&self, diff: &InstanceDiff) -> Result<(), Inconsistency> {
        if let Some(removed_soa) = &diff.removed_soa
            && *removed_soa != self.soa
        {
            return Err(Inconsistency::RemoveWrongSoa {
                base: self.soa.clone(),
                removing: removed_soa.clone(),
            });
        } else if let None = &diff.removed_soa
            && let Some(added_soa) = &diff.added_soa
        {
            return Err(Inconsistency::AddExistingSoa {
                base: self.soa.clone(),
                adding: added_soa.clone(),
            });
        }

        for [o, r, a] in merge([&self.records, &diff.removed_records, &diff.added_records]) {
            match [o, r, a] {
                [None, None, None] => unreachable!(),

                [_, Some(_), Some(_)] => panic!("A diff adds and removes the same record"),

                [None, Some(removing), _] => {
                    return Err(Inconsistency::RemoveNonexistent {
                        removing: Box::new(removing.clone()),
                    });
                }

                [Some(_), _, Some(adding)] => {
                    return Err(Inconsistency::AddExisting {
                        adding: Box::new(adding.clone()),
                    });
                }

                // Regular cases.
                [Some(_), None, None] | [None, None, Some(_)] | [Some(_), Some(_), None] => {}
            }
        }

        Ok(())
    }

    /// Apply a diff.
    ///
    /// ## Errors
    ///
    /// Fails if the diff is inconsistent with `self`, and returns an error
    /// describing the inconsistency. [`Self::can_apply()`] returns exactly the
    /// same error, without borrowing `self` mutably.
    pub fn apply_diff(&mut self, diff: &InstanceDiff) -> Result<(), Inconsistency> {
        if let Some(removed_soa) = &diff.removed_soa
            && *removed_soa != self.soa
        {
            return Err(Inconsistency::RemoveWrongSoa {
                base: self.soa.clone(),
                removing: removed_soa.clone(),
            });
        } else if let None = &diff.removed_soa
            && let Some(added_soa) = &diff.added_soa
        {
            return Err(Inconsistency::AddExistingSoa {
                base: self.soa.clone(),
                adding: added_soa.clone(),
            });
        }

        if let Some(added_soa) = &diff.added_soa {
            self.soa = added_soa.clone();
        }

        let mut records = Vec::new();
        for [o, r, a] in merge([&self.records, &diff.removed_records, &diff.added_records]) {
            match [o, r, a] {
                [None, None, None] => unreachable!(),

                [_, Some(_), Some(_)] => panic!("A diff adds and removes the same record"),

                [None, Some(removing), _] => {
                    return Err(Inconsistency::RemoveNonexistent {
                        removing: Box::new(removing.clone()),
                    });
                }

                [Some(_), _, Some(adding)] => {
                    return Err(Inconsistency::AddExisting {
                        adding: Box::new(adding.clone()),
                    });
                }

                // Carry a record through.
                [Some(r), None, None] => records.push(r.clone()),

                // Add a new record.
                [None, None, Some(r)] => records.push(r.clone()),

                // Remove an existing record.
                [Some(_), Some(_), None] => {}
            }
        }

        Ok(())
    }
}

//----------- SignedInstanceData -----------------------------------------------

impl SignedInstanceData {
    /// Whether a diff can be applied to this.
    ///
    /// ## Errors
    ///
    /// Fails if the diff is inconsistent with `self`, and returns an error
    /// describing the inconsistency.
    pub fn can_apply_diff(&self, diff: &InstanceDiff) -> Result<(), Inconsistency> {
        if let Some(removed_soa) = &diff.removed_soa
            && *removed_soa != self.soa
        {
            return Err(Inconsistency::RemoveWrongSoa {
                base: self.soa.clone(),
                removing: removed_soa.clone(),
            });
        } else if let None = &diff.removed_soa
            && let Some(added_soa) = &diff.added_soa
        {
            return Err(Inconsistency::AddExistingSoa {
                base: self.soa.clone(),
                adding: added_soa.clone(),
            });
        }

        for [o, r, a] in merge([&self.records, &diff.removed_records, &diff.added_records]) {
            match [o, r, a] {
                [None, None, None] => unreachable!(),

                [_, Some(_), Some(_)] => panic!("A diff adds and removes the same record"),

                [None, Some(removing), _] => {
                    return Err(Inconsistency::RemoveNonexistent {
                        removing: Box::new(removing.clone()),
                    });
                }

                [Some(_), _, Some(adding)] => {
                    return Err(Inconsistency::AddExisting {
                        adding: Box::new(adding.clone()),
                    });
                }

                // Regular cases.
                [Some(_), None, None] | [None, None, Some(_)] | [Some(_), Some(_), None] => {}
            }
        }

        Ok(())
    }

    /// Apply a diff.
    ///
    /// ## Errors
    ///
    /// Fails if the diff is inconsistent with `self`, and returns an error
    /// describing the inconsistency. [`Self::can_apply()`] returns exactly the
    /// same error, without borrowing `self` mutably.
    pub fn apply_diff(&mut self, diff: &InstanceDiff) -> Result<(), Inconsistency> {
        if let Some(removed_soa) = &diff.removed_soa
            && *removed_soa != self.soa
        {
            return Err(Inconsistency::RemoveWrongSoa {
                base: self.soa.clone(),
                removing: removed_soa.clone(),
            });
        } else if let None = &diff.removed_soa
            && let Some(added_soa) = &diff.added_soa
        {
            return Err(Inconsistency::AddExistingSoa {
                base: self.soa.clone(),
                adding: added_soa.clone(),
            });
        }

        if let Some(added_soa) = &diff.added_soa {
            self.soa = added_soa.clone();
        }

        let mut records = Vec::new();
        for [o, r, a] in merge([&self.records, &diff.removed_records, &diff.added_records]) {
            match [o, r, a] {
                [None, None, None] => unreachable!(),

                [_, Some(_), Some(_)] => panic!("A diff adds and removes the same record"),

                [None, Some(removing), _] => {
                    return Err(Inconsistency::RemoveNonexistent {
                        removing: Box::new(removing.clone()),
                    });
                }

                [Some(_), _, Some(adding)] => {
                    return Err(Inconsistency::AddExisting {
                        adding: Box::new(adding.clone()),
                    });
                }

                // Carry a record through.
                [Some(r), None, None] => records.push(r.clone()),

                // Add a new record.
                [None, None, Some(r)] => records.push(r.clone()),

                // Remove an existing record.
                [Some(_), Some(_), None] => {}
            }
        }
        self.records = records;

        Ok(())
    }
}

//----------- InstanceDiff -----------------------------------------------------

impl InstanceDiff {
    /// Compose two diffs together.
    ///
    /// A new diff, equivalent to `self` followed by `diff`, is returned.
    ///
    /// ## Errors
    ///
    /// Fails if the diffs are inconsistent, and returns an error
    /// describing the inconsistency.
    pub fn compose(&self, diff: &Self) -> Result<Self, Inconsistency> {
        let (removed_soa, added_soa) = match [
            &self.removed_soa,
            &self.added_soa,
            &diff.removed_soa,
            &diff.added_soa,
        ] {
            [Some(_), None, Some(r), _] => {
                return Err(Inconsistency::RemoveNonexistentSoa {
                    removing: r.clone(),
                });
            }

            [_, Some(a), Some(r), _] if a != r => {
                return Err(Inconsistency::RemoveWrongSoa {
                    base: a.clone(),
                    removing: r.clone(),
                });
            }

            [_, Some(a), None, Some(b)] => {
                return Err(Inconsistency::AddExistingSoa {
                    base: a.clone(),
                    adding: b.clone(),
                });
            }

            // Join the diffs.
            [r, Some(_), Some(_), a] | [r, None, None, a] => (r.clone(), a.clone()),

            // Ignore an empty diff.
            [r, a, None, None] | [None, None, r, a] => (r.clone(), a.clone()),
        };

        let mut removed_records = Vec::new();
        let mut added_records = Vec::new();
        for [ar, aa, br, ba] in merge([
            &self.removed_records,
            &self.added_records,
            &diff.removed_records,
            &diff.added_records,
        ]) {
            match [ar, aa, br, ba] {
                [None, None, None, None] => unreachable!(),

                [Some(_), Some(_), _, _] | [_, _, Some(_), Some(_)] => {
                    panic!("A diff adds and removes the same record");
                }

                [None, Some(_), None, Some(a)] => {
                    return Err(Inconsistency::AddExisting {
                        adding: Box::new(a.clone()),
                    });
                }

                [Some(_), None, Some(r), None] => {
                    return Err(Inconsistency::RemoveNonexistent {
                        removing: Box::new(r.clone()),
                    });
                }

                // Carry forward unchanged diffs.
                [None, Some(r), None, None] | [None, None, None, Some(r)] => {
                    added_records.push(r.clone());
                }
                [Some(r), None, None, None] | [None, None, Some(r), None] => {
                    removed_records.push(r.clone());
                }

                // Add a removed record.
                [Some(_), None, None, Some(_)] => {}

                // Remove an added record.
                [None, Some(_), Some(_), None] => {}
            }
        }

        Ok(Self {
            removed_soa,
            added_soa,
            removed_records,
            added_records,
        })
    }
}

//----------- merge() ----------------------------------------------------------

/// Merge sorted iterators.
fn merge<T: Ord, I: IntoIterator<Item = T>, const N: usize>(
    iters: [I; N],
) -> impl Iterator<Item = [Option<T>; N]> {
    struct Merge<T: Ord, I: Iterator<Item = T>, const N: usize>([Peekable<I>; N]);

    impl<T: Ord, I: Iterator<Item = T>, const N: usize> Iterator for Merge<T, I, N> {
        type Item = [Option<T>; N];

        fn next(&mut self) -> Option<Self::Item> {
            let set = self.0.each_mut().map(|e| e.peek());
            let min = set.iter().cloned().flatten().min()?;
            let used = set.map(|e| e == Some(min));
            let mut index = 0usize;
            Some(self.0.each_mut().map(|i| {
                let used = used[index];
                index += 1;
                i.next_if(|_| used)
            }))
        }
    }

    Merge(iters.map(|i| i.into_iter().peekable()))
}

//----------- Inconsistency ----------------------------------------------------

/// A zone/diff is inconsistent with a diff.
#[derive(Clone, Debug)]
pub enum Inconsistency {
    /// A SOA record was removed when none existed.
    RemoveNonexistentSoa {
        /// The SOA record to be removed.
        removing: Box<SoaRecord>,
    },

    /// The wrong SOA record was removed.
    RemoveWrongSoa {
        /// The base SOA record.
        base: Box<SoaRecord>,

        /// The SOA record to be removed.
        removing: Box<SoaRecord>,
    },

    /// A SOA record was added but one already existed.
    AddExistingSoa {
        /// The base SOA record.
        base: Box<SoaRecord>,

        /// The SOA record to be removed.
        adding: Box<SoaRecord>,
    },

    /// A nonexistent record was removed.
    RemoveNonexistent {
        /// The record to be removed.
        removing: Box<RegularRecord>,
    },

    /// An existing record was added.
    AddExisting {
        /// The record to be added.
        adding: Box<RegularRecord>,
    },
}
