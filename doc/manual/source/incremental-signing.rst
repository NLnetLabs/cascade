Incremental Signing
===================

.. note:: This page documents how Cascade's incremental signer works, so that
   you can understand what to expect from its output, and how the associated
   settings will affect it. 
   
   Note that Cascade does *not* use a jitter-based mechanism (as one would
   find in OpenDNSSEC) for spreading out the re-signing of records. Read on to
   understand Cascade's "re-signing window" mechanism.

Context
-------

Cascade can sign your zone in two modes: full signing and incremental signing.
Full signing unconditionally signs every record in the loaded zone, even if
some of those records had valid signatures. Incremental signing will examine
previously generated signatures and only sign records that are missing
signatures or whose signatures need updating. Incremental signing is more
complicated than full signing, but it has two benefits:

1. It greatly reduces the number of signatures that need to be generated. This
   is important for performance, especially if an :term:`HSM <Hardware Security
   Module (HSM)>` is used.

2. It greatly reduces the number of records that change in the signed zone.
   With full signing, every change to the loaded zone would result in brand
   new signatures for *every* record. With incremental signing, small changes
   in the loaded zone will translate to small changes in the signed zone. This
   reduces the size of :term:`IXFRs <Incremental Zone Transfers (IXFRs)>`,
   improving network latency and bandwidth for propagating the zone.

Cascade uses full signing for the first time it signs a zone, as it does not
know of any previous signatures. After the initial signing operation, a signed
copy of the zone will always be available, so Cascade will only use incremental
signing. In the future, we may add support for forcing the use of the full
signer even if a signed copy of the zone is available.

Key Rollovers
-------------

Cascade has a key manager, which can direct the signer to change the set of
keys it signs the zone with. With full signing, this is relatively simple:
all signatures will be re-generated using the new set of signing keys. But for
the reasons discussed above, this is suboptimal. Thus, the incremental signer
supports performing key rollovers over a period of time, where it will gradually
update the signatures of all the records in the zone. Re-signing is performed
such that the zone is always DNSSEC valid; for most key rollovers, this implies
signing all records with an additional key, and once the new signatures have
propagated, removing signatures with a previous key.

The incremental signer follows the same procedure whether a key rollover is
occurring or not. Internally, it will first determine which signatures need
updating, and then calculate when they should be updated. If a key rollover
is occurring, it will mark signatures signed with the previous set of keys to
be updated.

Algorithm
---------

The incremental signer has to satisfy the following needs:

1. If records in the loaded zone have changed, new signatures need to be
   generated for them, and the NSEC/NSEC3 chain must be updated.

2. If signatures are nearing (a particular point before) expiry, they will be
   regenerated.

3. If a key rollover is ongoing (as discussed above), new signatures need to be
   generated if new keys are being added, and old signatures need to be removed
   if old keys are being removed.

These three needs are handled independently.

First of all, all changes in the loaded zone are accounted for, from NSEC/NSEC3
chain updates to generating new signatures.

Then: every signature that needs re-generating (because it is sufficiently close
to expiry) will be considered. Signatures that are *too* close to expiry will be
re-generated immediately. The rest will be sorted into a *re-signing schedule*,
which is a deterministic way to spread out incremental signing work. They will
be sorted by ascending order of expiry, and then by DNSSEC canonical order. The
first ``N`` such signatures will be re-generated, where ``N`` is chosen so that
re-signing will complete within a certain period of time.

Finally, the ongoing key rollover (if any) is handled. If the key rollover has
taken longer than planned, it will be completed immediately. Otherwise, another
re-signing schedule will be constructed. The signatures pending updates will
be sorted in DNSSEC canonical order and the first ``N`` such signatures will
be re-generated.

Configuration
-------------

The incremental signer can be configured using the following policy settings:

* `signer.signature-refresh-interval`: The interval at which the incremental
  signer will re-generate signatures pending expiry and update signatures for
  key rollovers.

* `signer.key-roll-time`: The total amount of time a key rollover
  should take. Signature updates (which happen periodically at interval
  `signer.signature-refresh-interval`) will be spread out across this. If the
  key rollover takes longer than this, all remaining signatures will be updated
  at the next invocation of the incremental signer.
