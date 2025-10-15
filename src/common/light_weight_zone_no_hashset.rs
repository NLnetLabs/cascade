/// A quick PoC to see if using a BTree compared to default in-memory zone
/// store uses less memory, and it does, even with its dumb way of storing
/// values in the tree. It's not a fair comparison either as the default
/// in-memory store also supports proper answers to queries, versioning and
/// IXFR diff generation.
use std::{
    any::Any,
    collections::{hash_map::Entry, HashMap, HashSet},
    future::{ready, Future},
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use bytes::{Bytes, BytesMut};
use domain::{
    base::{
        iana::{Class, Rcode},
        name::Label,
        Name, NameBuilder, Rtype,
    },
    rdata::ZoneRecordData,
    zonetree::{
        error::OutOfZone, Answer, InMemoryZoneDiff, ReadableZone, Rrset, SharedRrset, StoredName,
        WalkOp, WritableZone, WritableZoneNode, Zone, ZoneStore,
    },
};
use log::trace;

// #[derive(Debug, Eq)]
// struct HashedByRtypeSharedRrset(SharedRrset);

// impl std::hash::Hash for HashedByRtypeSharedRrset {
//     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
//         self.0.rtype().hash(state);
//     }
// }

// impl std::ops::Deref for HashedByRtypeSharedRrset {
//     type Target = SharedRrset;

//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl PartialEq for HashedByRtypeSharedRrset {
//     fn eq(&self, other: &Self) -> bool {
//         self.0.rtype() == other.0.rtype()
//     }
// }

#[derive(Clone, Debug)]
struct SimpleZoneInner {
    root: StoredName,
    unsigned_zone: Option<Zone>,
    tree: Arc<std::sync::RwLock<HashMap<(StoredName, Rtype), SharedRrset>>>,
    skipped: Arc<AtomicUsize>,
    skip_signed: bool,
}

#[derive(Clone, Debug)]
pub struct LightWeightZone {
    inner: SimpleZoneInner,
}

impl LightWeightZone {
    pub fn new(root: StoredName, unsigned_zone: Option<Zone>, skip_signed: bool) -> Self {
        Self {
            inner: SimpleZoneInner {
                root,
                unsigned_zone,
                tree: Default::default(),
                skipped: Default::default(),
                skip_signed,
            },
        }
    }
}

impl ZoneStore for LightWeightZone {
    fn class(&self) -> Class {
        Class::IN
    }

    fn apex_name(&self) -> &StoredName {
        &self.inner.root
    }

    fn read(self: Arc<Self>) -> Box<dyn ReadableZone> {
        trace!("READ");
        Box::new(self.inner.clone()) as Box<dyn ReadableZone>
    }

    fn write(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone + 'static>> + Send + Sync + 'static>>
    {
        trace!("WRITE");
        Box::pin(ready(Box::new(self.inner.clone()) as Box<dyn WritableZone>))
    }

    fn as_any(&self) -> &dyn Any {
        trace!("ANY");
        self as &dyn Any
    }
}

impl ReadableZone for SimpleZoneInner {
    fn query(&self, qname: Name<Bytes>, qtype: Rtype) -> Result<Answer, OutOfZone> {
        trace!("QUERY");
        Ok(self
            .tree
            .read()
            .unwrap()
            .get(&(qname, qtype))
            .map(|rrset| {
                trace!("QUERY RRSETS");
                let mut answer = Answer::new(Rcode::NOERROR);
                answer.add_answer(rrset.clone());
                answer
            })
            .unwrap_or(Answer::new(Rcode::NOERROR)))
    }

    fn walk(&self, op: WalkOp) {
        trace!("WALK");
        for ((name, _rtype), rrset) in self.tree.read().unwrap().iter() {
            if rrset.rtype() == Rtype::RRSIG {
                for data in rrset.data() {
                    let ZoneRecordData::Rrsig(rrsig) = data else {
                        unreachable!();
                    };
                    let mut rrset = Rrset::new(Rtype::RRSIG, rrsig.original_ttl());
                    rrset.push_data(data.clone());
                    (op)(name.clone(), &rrset.into_shared(), false)
                }
            } else {
                // TODO: Set false to proper value for "at zone cut or not"
                (op)(name.clone(), rrset, false)
            }
        }

        struct OpContainer {
            op: WalkOp,
        }

        if let Some(unsigned_zone) = &self.unsigned_zone {
            let c = Arc::new(OpContainer { op });

            let op = Box::new(move |owner, rrset: &SharedRrset, _at_zone_cut| {
                // Skip the SOA, use the new one that was part of the signed data.
                if matches!(rrset.rtype(), Rtype::SOA) {
                    return;
                }

                (c.op)(owner, rrset, _at_zone_cut)
            });
            unsigned_zone.read().walk(op);
        }
        trace!("WALK FINISHED");
    }

    fn is_async(&self) -> bool {
        false
    }
}

impl WritableZone for SimpleZoneInner {
    fn open(
        &self,
        _create_diff: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<Box<dyn WritableZoneNode>, std::io::Error>> + Send + Sync>,
    > {
        trace!("OPEN FOR WRITING");
        self.skipped.store(0, Ordering::SeqCst);
        Box::pin(ready(Ok(Box::new(SimpleZoneNode::new(
            self.tree.clone(),
            self.root.clone(),
            self.skipped.clone(),
            self.skip_signed,
        )) as Box<dyn WritableZoneNode>)))
    }

    fn commit(
        &mut self,
        _bump_soa_serial: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Option<InMemoryZoneDiff>, std::io::Error>> + Send + Sync>>
    {
        trace!(
            "COMMITTING: Skipped {} records",
            self.skipped.load(Ordering::SeqCst)
        );
        Box::pin(ready(Ok(None)))
    }
}

struct SimpleZoneNode {
    pub tree: Arc<std::sync::RwLock<HashMap<(StoredName, Rtype), SharedRrset>>>,
    pub name: StoredName,
    pub skipped: Arc<AtomicUsize>,
    pub skip_signed: bool,
}

impl SimpleZoneNode {
    fn new(
        tree: Arc<std::sync::RwLock<HashMap<(StoredName, Rtype), SharedRrset>>>,
        name: StoredName,
        skipped: Arc<AtomicUsize>,
        skip_signed: bool,
    ) -> Self {
        Self {
            tree,
            name,
            skipped,
            skip_signed,
        }
    }
}

impl WritableZoneNode for SimpleZoneNode {
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<dyn Future<Output = Result<Box<dyn WritableZoneNode>, std::io::Error>> + Send + Sync>,
    > {
        let mut builder = NameBuilder::<BytesMut>::new();
        builder.append_label(label.as_slice()).unwrap();
        let child_name = builder.append_origin(&self.name).unwrap();
        let node = Self::new(
            self.tree.clone(),
            child_name,
            self.skipped.clone(),
            self.skip_signed,
        );
        Box::pin(ready(Ok(Box::new(node) as Box<dyn WritableZoneNode>)))
    }

    fn get_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SharedRrset>, std::io::Error>> + Send + Sync>>
    {
        Box::pin(ready(Ok(self
            .tree
            .read()
            .unwrap()
            .get(&(self.name.clone(), rtype))
            .cloned())))
    }

    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + Sync>> {
        // Filter out attempts to add or change DNSSEC records to/in this zone.
        match rrset.rtype() {
            Rtype::DNSKEY
            // | Rtype::DS
            | Rtype::RRSIG
            | Rtype::NSEC
            | Rtype::NSEC3
            | Rtype::NSEC3PARAM
                if self.skip_signed =>
            {
                self.skipped.fetch_add(1, Ordering::SeqCst);
                Box::pin(ready(Ok(())))
            }

            _ => {
                match self.tree.write().unwrap().entry((self.name.clone(), rrset.rtype())) {
                    Entry::Vacant(e) => {
                        let _ = e.insert(rrset);
                    }
                    Entry::Occupied(mut e) => {
                        let existing_rrset = e.get_mut();
                        *existing_rrset = rrset;
                        // let new_rrset = HashedByRtypeSharedRrset(rrset);
                        // // There can only be one RRset of a given RType at a given name.
                        // let _ = rrsets.replace(new_rrset);
                    }
                }

                Box::pin(ready(Ok(())))
            }
        }
    }

    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + Sync>> {
        let _ = self.tree.write().unwrap().remove(&(self.name.clone(), rtype));
        Box::pin(ready(Ok(())))
    }

    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + Sync>> {
        Box::pin(ready(Ok(())))
    }

    fn make_zone_cut(
        &self,
        _cut: domain::zonetree::types::ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + Sync>> {
        Box::pin(ready(Ok(())))
    }

    fn make_cname(
        &self,
        _cname: domain::zonetree::SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + Sync>> {
        Box::pin(ready(Ok(())))
    }

    fn remove_all(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), std::io::Error>> + Send + Sync>> {
        self.tree.write().unwrap().clear();
        Box::pin(ready(Ok(())))
    }
}
