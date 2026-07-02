Incremental Signing
===================

This page documents how Cascade's incremental signer works, so that you can
understand what to expect from its output, and how the associated settings will
affect it.
   
Note that Cascade does *not* use a jitter-based mechanism (as one would find
in OpenDNSSEC) for spreading out the re-signing of records. It uses a different
mechanism to achieve this, a "re-signing schedule"; read on to learn more.

Context
-------

Cascade can sign zones in either of two modes: full signing and incremental
signing. It will automatically choose one (as explained below). Full signing
unconditionally signs every record in the loaded zone, even if some of those
records had valid signatures. Incremental signing will examine previously
generated signatures and only sign records that are missing signatures or whose
signatures need updating. Incremental signing is more complicated than full
signing, but it has two benefits:

1. It can reuse existing signatures, significantly reducing the number of
   cryptographic signatures it needs to generate. This is important for
   performance, especially if an :term:`HSM <Hardware Security Module (HSM)>`
   is used.

2. It greatly reduces the number of records that change in the signed zone.
   Full signing results in new signatures for *every* record. With incremental
   signing, small changes in the loaded zone will translate to small changes
   in the signed zone. This reduces the size of :term:`IXFRs <Incremental Zone
   Transfers (IXFRs)>`.

Cascade uses full signing for the first time it signs a zone, as it does not
know of any previous signatures. After the initial signing operation, a signed
copy of the zone will always be available, so Cascade will only use incremental
signing.

Key Rollovers
-------------

Cascade has a key manager, which can direct the signer to change the set of
keys it signs the zone with. With full signing, this is relatively simple:
all signatures will be re-generated using the new set of signing keys. The
incremental signer supports performing key rollovers over a period of time,
where it will gradually update the signatures of all the records in the zone.
Re-signing is performed such that the zone is always DNSSEC valid; for most key
rollovers, this implies adding new keys to the `DNSKEY` record, (incrementally)
replacing signatures with old keys for signatures with new keys, and removing
old keys from `DNSKEY`.

Regardless of whether a key roll is occurring, the incremental signer starts by
re-generating signatures that are expiring or whose underlying data (the RRset
signed) has changed. In case a key roll is occurring, these signatures are
generated with the new set of keys. Afterwards, the signer will consider other
signatures that were signed with the previous set of keys, and update some of
them.

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
re-signing of the entire zone will complete within a certain period of time.

Finally, the ongoing key rollover (if any) is handled. If the key rollover
has taken longer than planned, it will be completed immediately. Otherwise,
all the signatures in the zone are sorted in DNSSEC canonical order, and among
the first ``N`` of those, signatures still using the previous set of keys are
re-generated.

Comparison to Jitter
--------------------

OpenDNSSEC uses a "jitter" based mechanism, where the expiration times of
signatures are randomly generated and spread out over a period of time.
Signatures are refreshed as soon as they are close to expiry; if many signatures
get close to expiry at the same time, they will all be refreshed immediately.

In contrast, Cascade sets the expiration times of records to a fixed offset into
the future (regardless of whether it is full-signing or incremental-signing).
If many signatures expire at the same time, Cascade will refresh
them in batches, spread out over a period of time. It selects batches in a
determistic way. We call the result a re-signing schedule. This approach is more
predictable, easier to tune, and easier to test.

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
