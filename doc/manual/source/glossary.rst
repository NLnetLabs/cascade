Glossary
========

This page explains DNS and signing terms used in the Cascade documentation.
Definitions are based on :RFC:`9499` and the protocol references cited below;
Cascade-specific entries describe how these concepts apply to the signer.

.. glossary::
  :sorted:

  Apex (Zone)
    The point in the tree at an owner of an SOA and corresponding
    authoritative NS RRset.  This is also called the "zone apex". :RFC:`4033`
    defines it as "the name at the child's side of a zone cut".  The "apex"
    can usefully be thought of as a data-theoretic description of a tree
    structure, and "origin" is the name of the same concept when it is
    implemented in zone files.  The distinction is not always maintained in
    use, however, and one can find uses that conflict subtly with this
    definition.  :RFC:`1034` uses the term "top node of the zone" as a
    synonym of "apex", but that term is not widely used.  These days, the
    first sense of "origin" and "apex" are often used
    interchangeably.

  Origin (Zone)
    There are two different uses for this term:

    1. "The domain name that appears at the top of a zone (just
       below the cut that separates the zone from its parent)... The
       name of the zone is the same as the name of the domain at the
       zone's origin."  (Quoted from :RFC:`2181#section-6`) These
       days, this sense of "origin" and "apex" are
       often used interchangeably.
    2. The domain name within which a given relative domain name appears in
       zone files.  Generally seen in the context of "$ORIGIN", which is a
       control entry defined in :RFC:`1035#section-5.1`, as part of the
       master file format.  For example, if the $ORIGIN is set to
       ``example.org.``, then a master file line for "www" is in fact an
       entry for ``www.example.org.``.

  Resource Record Set (RRset)
    A set of resource records "with the same label, class and type, but with
    different data" (according to :RFC:`2181#section-5`).  Also written as
    "RRSet" in some documents.  As a clarification, "same label" in this
    definition means "same owner name".  In addition, :RFC:`2181` states that
    "the TTLs of all RRs in an RRSet must be the same".

    RRSIG records are an exception: multiple signatures can cover one RRset,
    but RRSIG records with the same owner name do not themselves form an
    RRset and need not share a TTL. See :RFC:`4035#section-2.2`.

  TTL
    The maximum "time to live" of a resource record. "A TTL value is an
    unsigned number, with a minimum value of 0, and a maximum value of
    2147483647. That is, a maximum of 2^31 - 1.  When transmitted, this
    value shall be encoded in the less significant 31 bits of the 32 bit TTL
    field, with the most significant, or sign, bit set to zero."  (Quoted
    from :RFC:`2181#section-8`) Note that :RFC:`1035` erroneously stated that
    this is a signed integer; that was fixed by :RFC:`2181`.

    The TTL "specifies the time interval that the resource record may be
    cached before the source of the information should again be consulted."
    (Quoted from :RFC:`1035#section-3.2.1`) :RFC:`1035#section-4.1.3` states
    "the time interval (in seconds) that the resource record may be cached
    before it should be discarded". Despite being defined for a resource
    record, the TTL of every resource record in an RRset is required to be
    the same (:RFC:`2181#section-5.2`).

    The reason that the TTL is the maximum time to live is that a cache
    operator might decide to shorten the time to live for operational
    purposes, for example, if there is a policy to disallow TTL values over a
    certain number.  Some servers are known to ignore the TTL on some RRsets
    (such as when the authoritative data has a very short TTL) even though
    this is against the advice in :RFC:`1035`.  An RRset can be flushed from
    the cache before the end of the TTL interval, at which point, the value
    of the TTL becomes unknown because the RRset with which it was associated
    no longer exists.

    There is also the concept of a "default TTL" for a zone, which can be a
    configuration parameter in the server software.  This is often expressed
    by a default for the entire server, and a default for a zone using the
    $TTL directive in a zone file.  The ``$TTL`` directive was added to the
    master file format by :RFC:`2308`.

  Recursive resolver
    A resolver that acts in recursive mode.  In general, a recursive resolver
    is expected to cache the answers it receives (which would make it a
    full-service resolver), but some recursive resolvers might not cache.

    :RFC:`4697` tried to differentiate between a recursive resolver and an
    iterative resolver.

  Zone transfer
    The act of a client requesting a copy of a zone and an authoritative
    server sending the needed information. There are two common standard ways
    to do zone transfers: the AXFR ("Authoritative Transfer") mechanism to
    copy the full zone (described in :RFC:`5936`), and the IXFR ("Incremental
    Transfer") mechanism to copy only parts of the zone that have changed
    (described in :RFC:`1995`). Many systems use non-standard methods for
    zone transfers outside the DNS protocol.

  Signed zone
    "A zone whose RRsets are signed and that contains properly constructed
    DNSKEY, Resource Record Signature (RRSIG), Next Secure (NSEC), and
    (optionally) DS records."  (Quoted from :RFC:`4033#section-2`) It has
    been noted in other contexts that the zone itself is not really signed,
    but all the relevant RRsets in the zone are signed.  Nevertheless, if a
    zone that should be signed contains any RRsets that are not signed (or
    opted out), those RRsets will be treated as bogus, so the whole zone
    needs to be handled in some way.

    It should also be noted that, since the publication of :RFC:`6840`, NSEC
    records are no longer required for signed zones: a signed zone might
    include NSEC3 records instead.  :RFC:`7129` provides additional
    background commentary and some context for the NSEC and NSEC3 mechanisms
    used by DNSSEC to provide authenticated denial-of-existence responses.
    See :term:`NSEC` and :term:`NSEC3`.

  Online signing
    :RFC:`4470` defines "on-line signing" (note the hyphen) as "generating
    and signing these records on demand", where "these" was defined as NSEC
    records.  The current definition expands that to generating and signing
    RRSIG, NSEC, and NSEC3 records on demand.

    This does not simply mean running a signer continuously. Cascade signs
    zones before publication and refreshes signatures through
    :term:`incremental signing`; that is distinct from generating signatures
    in response to individual DNS queries.

  Unsigned zone
    :RFC:`4033#section-2` defines this as "a zone that is not signed".
    :RFC:`4035#section-2` defines this as a "zone that does not include these
    records [properly constructed DNSKEY, Resource Record Signature (RRSIG),
    Next Secure (NSEC), and (optionally) DS records] according to the rules
    in this section..." There is an important note at the end of
    :RFC:`4035#section-5.2` that defines an additional situation in which a
    zone is considered unsigned: "If the resolver does not support any of the
    algorithms listed in an authenticated DS RRset, then the resolver will
    not be able to verify the authentication path to the child zone.  In this
    case, the resolver SHOULD treat the child zone as if it were unsigned."

  NSEC
    "The NSEC record allows a security-aware resolver to authenticate a
    negative reply for either name or type non-existence with the same
    mechanisms used to authenticate other DNS replies."  (Quoted from
    :RFC:`4033#section-3.2`) In short, an NSEC record provides authenticated
    denial of existence.

    "The NSEC resource record lists two separate things: the next
    owner name (in the canonical ordering of the zone) that contains
    authoritative data or a delegation point NS RRset, and the set of
    RR types present at the NSEC RR's owner name."  (Quoted from
    :RFC:`4034#section-4`).

  NSEC3
    Like the NSEC record, the NSEC3 record also provides authenticated denial
    of existence; however, NSEC3 records mitigate zone enumeration and
    support Opt-Out. NSEC3 resource records require associated NSEC3PARAM
    resource records.  NSEC3 and NSEC3PARAM resource records are defined in
    :RFC:`5155`.

    Note that :RFC:`6840` says that :RFC:`5155` "is now considered part of
    the DNS Security Document Family as described by :RFC:`4033#section-10`".
    This means that some of the definitions from earlier RFCs that only talk
    about NSEC records should probably be considered to be talking about both
    NSEC and NSEC3.

  Opt-out
    "The Opt-Out Flag indicates whether this NSEC3 RR may cover unsigned
    delegations."  (Quoted from :RFC:`5155#section-3.1.2.1`) Opt-out tackles
    the high costs of securing a delegation to an insecure zone.  When using
    Opt-Out, names that are an insecure delegation (and empty non-terminals
    that are only derived from insecure delegations) don't require an NSEC3
    record or its corresponding RRSIG records.  Opt-Out NSEC3 records are not
    able to prove or deny the existence of the insecure delegations. (Adapted
    from :RFC:`7129#section-5.1`)

  Insecure delegation
    "A signed name containing a delegation (NS RRset), but lacking a DS
    RRset, signifying a delegation to an unsigned subzone."  (Quoted from
    :RFC:`4956#section-2`)

  Zone enumeration
    "The practice of discovering the full content of a zone via successive
    queries."  (Quoted from :RFC:`5155#section-1.3`) This is also sometimes
    called "zone walking".  Zone enumeration is different from zone content
    guessing where the guesser uses a large dictionary of possible labels and
    sends successive queries for them, or matches the contents of NSEC3
    records against such a dictionary.

  Validation
    Validation, in the context of DNSSEC, refers to one of the following:

    -  Checking the validity of DNSSEC signatures,
    -  Checking the validity of DNS responses, such as those including
       authenticated denial of existence, or
    -  Building an authentication chain from a trust anchor to a DNS
       response or individual DNS RRsets in a response.

    The first two definitions above consider only the validity of individual
    DNSSEC components, such as the RRSIG validity or NSEC proof validity.
    The third definition considers the components of the entire DNSSEC
    authentication chain; thus, it requires "configured knowledge of at least
    one authenticated DNSKEY or DS RR" (as described in
    :RFC:`4035#section-5`).

    :RFC:`4033#section-2`, says that a "Validating Security-Aware Stub
    Resolver... performs signature validation" and uses a trust anchor "as a
    starting point for building the authentication chain to a signed DNS
    response"; thus, it uses the first and third definitions above.  The
    process of validating an RRSIG resource record is described in
    :RFC:`4035#section-5.3`.

    :RFC:`5155` refers to validating responses throughout the document in the
    context of hashed authenticated denial of existence; this uses the second
    definition above.

    The term "authentication" is used interchangeably with "validation", in
    the sense of the third definition above. :RFC:`4033#section-2`, describes
    the chain linking trust anchor to DNS data as the "authentication chain".
    A response is considered to be authentic if "all RRsets in the Answer and
    Authority sections of the response [are considered] to be authentic"
    (Quoted from :RFC:`4035`) DNS data or responses deemed to be authentic or
    validated have a security status of "secure" (:RFC:`4035#section-4.3`;
    :RFC:`4033#section-5`).  "Authenticating both DNS keys and data is a
    matter of local policy, which may extend or even override the [DNSSEC]
    protocol extensions..." (Quoted from :RFC:`4033#section-3.1`).

    The term "verification", when used, is usually a synonym for
    "validation".

  Validating resolver
    A security-aware recursive name server, security-aware resolver, or
    security-aware stub resolver that is applying at least one of the
    definitions of validation (above) as appropriate to the resolution
    context.  For the same reason that the generic term "resolver" is
    sometimes ambiguous and needs to be evaluated in context, "validating
    resolver" is a context-sensitive term.

  Key signing key (KSK)
    DNSSEC keys that "only sign the apex DNSKEY RRset in a zone."  (Quoted
    from :RFC:`6781#section-3.1`)

  Zone signing key (ZSK)
    "DNSSEC keys that can be used to sign all the RRsets in a zone that
    require signatures, other than the apex DNSKEY RRset."  (Quoted from
    :RFC:`6781#section-3.1`) Also note that a ZSK is sometimes used to sign
    the apex DNSKEY RRset.

  Combined signing key (CSK)
    "In cases where the differentiation between the KSK and ZSK is not made,
    i.e., where keys have the role of both KSK and ZSK, we talk about a
    Single-Type Signing Scheme."  (Quoted from :RFC:`6781#section-3.1`) This
    is sometimes called a "combined signing key" or "CSK".  It is operational
    practice, not protocol, that determines whether a particular key is a
    ZSK, a KSK, or a CSK.

  Secure Entry Point (SEP)
    A flag in the DNSKEY RDATA that "can be used to distinguish between keys
    that are intended to be used as the secure entry point into the zone when
    building chains of trust, i.e., they are (to be) pointed to by parental
    DS RRs or configured as a trust anchor....  Therefore, it is suggested
    that the SEP flag be set on keys that are used as KSKs and not on keys
    that are used as ZSKs, while in those cases where a distinction between a
    KSK and ZSK is not made (i.e., for a Single-Type Signing Scheme), it is
    suggested that the SEP flag be set on all keys." (Quoted from
    :RFC:`6781#section-3.2.3`) Note that the SEP flag is only a hint, and its
    presence or absence may not be used to disqualify a given DNSKEY RR from
    use as a KSK or ZSK during validation.

    The original definition of SEPs was in :RFC:`3757`.  That definition
    clearly indicated that the SEP was a key, not just a bit in the key.  The
    abstract of :RFC:`3757` says: "With the Delegation Signer (DS) resource
    record (RR), the concept of a public key acting as a secure entry point
    (SEP) has been introduced.  During exchanges of public keys with the
    parent there is a need to differentiate SEP keys from other public keys
    in the Domain Name System KEY (DNSKEY) resource record set.  A flag bit
    in the DNSKEY RR is defined to indicate that DNSKEY is to be used as a
    SEP."  That definition of the SEP as a key was made obsolete by
    :RFC:`4034`, and the definition from :RFC:`6781` is consistent with
    :RFC:`4034`.

  Trust anchor
    "A configured DNSKEY RR or DS RR hash of a DNSKEY RR. A validating
    security-aware resolver uses this public key or hash as a starting point
    for building the authentication chain to a signed DNS response.  In
    general, a validating resolver will have to obtain the initial values of
    its trust anchors via some secure or trusted means outside the DNS
    protocol."  (Quoted from :RFC:`4033#section-2`)

  DNSSEC Policy (DP)
    A statement that "sets forth the security requirements and standards to
    be implemented for a DNSSEC-signed zone."  (Quoted from
    :RFC:`6841#section-2`)

  DNSSEC Practice Statement (DPS)
    "A practices disclosure document that may support and be a supplemental
    document to the DNSSEC Policy (if such exists), and it states how the
    management of a given zone implements procedures and controls at a high
    level." (Quoted from :RFC:`6841#section-2`)

  Hardware security module (HSM)
    A specialized piece of hardware that is used to create keys for
    signatures and to sign messages without ever disclosing the private key.
    In DNSSEC, HSMs are often used to hold the private keys for KSKs and ZSKs
    and to create the signatures used in RRSIG records at periodic intervals.

  Zone
    "Authoritative information is organized into units called ZONEs, and
    these zones can be automatically distributed to the name servers which
    provide redundant service for the data in a zone."  (Quoted from
    :RFC:`1034#section-2.4`)

  Child (Zone)
    "The entity on record that has the delegation of the domain from the
    Parent."  (Quoted from :RFC:`7344#section-1.1`)

  Parent (Zone)
    "The domain in which the Child is registered."  (Quoted from
    :RFC:`7344#section-1.1`) Earlier, "parent name server" was defined in
    :RFC:`0882` as "the name server that has authority over the place in the
    domain name space that will hold the new domain".  (Note that :RFC:`0882`
    was obsoleted by :RFC:`1034` and :RFC:`1035`.) :RFC:`819` also has some
    description of the relationship between parents and children.

  Secure (DNSSEC State)
    :RFC:`4033#section-5` says: "The validating resolver has a trust anchor,
    has a chain of trust, and is able to verify all the signatures in the
    response."

    :RFC:`4035#section-4.3` says: "An RRset for which the resolver is able to
    build a chain of signed DNSKEY and DS RRs from a trusted security anchor
    to the RRset.  In this case, the RRset should be signed and is subject to
    signature validation, as described above."

  Insecure (DNSSEC State)
    :RFC:`4033#section-5` says: "The validating resolver has a trust anchor,
    a chain of trust, and, at some delegation point, signed proof of the non-
    existence of a DS record.  This indicates that subsequent branches in the
    tree are provably insecure.  A validating resolver may have a local
    policy to mark parts of the domain space as insecure."

    :RFC:`4035#section-4.3` says: "An RRset for which the resolver knows that
    it has no chain of signed DNSKEY and DS RRs from any trusted starting
    point to the RRset.  This can occur when the target RRset lies in an
    unsigned zone or in a descendent [sic] of an unsigned zone.  In this
    case, the RRset may or may not be signed, but the resolver will not be
    able to verify the signature."

  Bogus (DNSSEC State)
    :RFC:`4033#section-5` says: "The validating resolver has a trust anchor
    and a secure delegation indicating that subsidiary data is signed, but
    the response fails to validate for some reason: missing signatures,
    expired signatures, signatures with unsupported algorithms, data missing
    that the relevant NSEC RR says should be present, and so forth."

    :RFC:`4035#section-4.3` says: "An RRset for which the resolver believes
    that it ought to be able to establish a chain of trust but for which it
    is unable to do so, either due to signatures that for some reason fail to
    validate or due to missing data that the relevant DNSSEC RRs indicate
    should be present. This case may indicate an attack but may also indicate
    a configuration error or some form of data corruption."

  Indeterminate (DNSSEC State)
    :RFC:`4033#section-5` says: "There is no trust anchor that would indicate
    that a specific portion of the tree is secure.  This is the default
    operation mode."

    :RFC:`4035#section-4.3` says: "An RRset for which the resolver is not
    able to determine whether the RRset should be signed, as the resolver is
    not able to obtain the necessary DNSSEC RRs.  This can occur when the
    security-aware resolver is not able to contact security-aware name
    servers for the relevant zones."

  Primary server
    "Any authoritative server configured to be the source of zone transfer
    for one or more [secondary] servers." (Quoted from
    :RFC:`1996#section-2.1`) Or, more specifically, :RFC:`2136` calls it "an
    authoritative server configured to be the source of AXFR or IXFR data for
    one or more [secondary] servers". Primary servers are also discussed in
    :RFC:`1034`.  Although early DNS RFCs such as :RFC:`1996` referred to
    this as a "master", the current common usage has shifted to "primary".

  Secondary server
    "An authoritative server which uses zone transfer to retrieve the zone."
    (Quoted from :RFC:`1996#section-2.1`) Secondary servers are also
    discussed in :RFC:`1034`.  :RFC:`2182` describes secondary servers in
    more detail.  Although early DNS RFCs such as :RFC:`1996` referred to
    this as a "slave", the current common usage has shifted to calling it a
    "secondary".

  Authoritative server
    A DNS server that answers queries about a zone using locally held zone
    data. See :RFC:`9499#section-6`. Cascade is not a general-purpose
    authoritative server: downstream authoritative servers publish the
    signed zones to DNS clients.

  Hidden primary
  Hidden master
    A primary server that supplies zone transfers without being listed in
    the zone's public NS records. :RFC:`9499#section-6` calls this a
    "hidden master". In a Cascade deployment, a hidden primary can supply
    the unsigned zone; its role is distinct from the :term:`hidden signer`.

  Hidden signer
    A signer placed between the source of an unsigned zone and the public
    authoritative servers that serve the signed result. Cascade uses this
    deployment model and should not receive ordinary public DNS queries.
    See :doc:`before-you-start`.

  Signing software
    Software that creates and maintains DNSSEC signatures for zones, either
    within an authoritative server or as a separate tool.
    See :RFC:`9499#section-10`. Cascade is a standalone signer.

  Zone file
  Master file
    A text representation of DNS resource records, commonly used to store
    a zone. The format is defined in :RFC:`1035#section-5` and discussed
    in :RFC:`9499#section-5`. Cascade can load an unsigned zone from a file
    instead of obtaining it through a :term:`zone transfer`.

  SOA
    The Start of Authority record at the zone apex. It contains the primary
    server name, a contact address, the zone's :term:`serial number`, and
    the REFRESH, RETRY, EXPIRE and MINIMUM fields. These control refresh
    timing, expiry and negative caching; MINIMUM is not a default TTL for
    all records. See :RFC:`1035#section-3.3.13` and :RFC:`2308#section-4`.
    Cascade uses SOA queries and timers to discover upstream changes.

  Serial number
    The version identifier in a zone's SOA record. Servers compare serial
    numbers to determine whether zone data has changed, using the wraparound
    arithmetic defined in :RFC:`1982`. Cascade's ``serial-policy`` controls
    how serial numbers are assigned to its signed output.

  Delegation
    The assignment of a child zone to its authoritative servers through NS
    records in the parent zone. See :RFC:`9499#section-7`. For DNSSEC, a DS
    record in the parent can additionally establish trust in the child's keys.

  Zone cut
    The boundary between a parent zone and a delegated child zone.
    See :RFC:`9499#section-7`. This boundary determines which data belongs
    to each zone and matters when signing delegations and denial-of-existence
    records.

  Owner name
    The domain name to which a resource record belongs, called "Owner" in
    :RFC:`9499#section-5`. Records with the same owner name, class and type
    form an :term:`RRset <Resource Record Set (RRset)>`.

  AXFR
    The DNS protocol for transferring a complete zone, defined in
    :RFC:`5936`. Cascade can use AXFR to receive unsigned zones and provide
    signed zones to downstream servers or review hooks.

  IXFR
    The DNS protocol for transferring changes between versions of a zone,
    defined in :RFC:`1995`. Cascade supports IXFR on both sides of the signing
    pipeline. A server may return a full transfer when the required changes
    are unavailable. See :doc:`zone-transfers`.

  NOTIFY
    A DNS message that tells another server that a zone may have changed,
    prompting it to check for an update. NOTIFY does not carry the updated
    zone itself. See :RFC:`1996`. Cascade can receive upstream notifications
    and notify downstream servers after publication.

  TSIG
    Transaction signatures that authenticate DNS messages using a shared
    secret. TSIG protects message integrity and authenticates the peer; it
    does not encrypt zone data or replace DNSSEC signatures. See :RFC:`8945`.
    Cascade can use TSIG for zone transfers and NOTIFY messages.

  DNSKEY
    A DNS record containing a public key and associated parameters used for
    DNSSEC validation. The corresponding private key produces signatures;
    it is not published in DNS. See :RFC:`4034#section-2`.

  RRSIG
    A DNS record containing a signature over an RRset, together with metadata
    including its algorithm, key tag, :term:`signature inception` and
    :term:`signature expiration`. See :RFC:`4034#section-3`. Cascade creates
    and refreshes these records during signing.

  DS
    A Delegation Signer record that identifies a child's DNSKEY using a
    digest and associated parameters. Published in the parent zone, it links
    the child's keys into the DNSSEC chain of trust.
    See :RFC:`4034#section-5`. Updating the parent DS records is an important
    part of KSK and CSK rollovers.

  CDS
    A Child DS record through which a child zone signals the desired DS
    records to its parent. See :RFC:`7344` and :RFC:`8078`. Cascade can
    publish CDS records, but the parent must support and accept the update
    mechanism for the DS records to change automatically.

  CDNSKEY
    A Child DNSKEY record through which a child zone signals the keys from
    which its parent can derive DS records. See :RFC:`7344` and
    :RFC:`8078`. Like CDS, it depends on the parent's update procedure.

  Key rollover
  Key roll
    The controlled replacement of DNSSEC keys while preserving validation
    of published and cached data. See :RFC:`6781#section-4.1`. Cascade
    coordinates publication, propagation checks and waiting periods through
    its key-roll stages. See :doc:`key-management`.

  Signature inception
    The time from which an RRSIG is valid. See :RFC:`4034#section-3.1.5`.
    Cascade can backdate this time using ``signature-inception-offset`` to
    allow for clock differences between systems.

  Signature expiration
    The time after which an RRSIG is no longer valid. See
    :RFC:`4034#section-3.1.5`. This is distinct from the record's TTL and
    from a key's configured lifetime. Cascade refreshes signatures before
    they expire.

  Incremental signing
    Cascade's process of updating signatures and NSEC/NSEC3 data affected
    by zone changes, refreshing signatures approaching expiry, and spreading
    signature changes for key rollovers over time. It is distinct from IXFR,
    which transfers zone changes between servers. See
    :doc:`incremental-signing`.
