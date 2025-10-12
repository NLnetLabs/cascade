Glossary
========

.. glossary::
  :sorted:

  Resource Record Set (RRSET)
    A set of resource records "with the same label, class and type, but with
    different data" (according to :RFC:`2181#section-5`).  Also written as
    "RRSet" in some documents.  As a clarification, "same label" in this
    definition means "same owner name".  In addition, :RFC:`2181` states that
    "the TTLs of all RRs in an RRSet must be the same".

      Note that RRSIG resource records do not match this definition.
      :RFC:`4035` says:

         An RRset MAY have multiple RRSIG RRs associated with it. Note that
         as RRSIG RRs are closely tied to the RRsets whose signatures they
         contain, RRSIG RRs, unlike all other DNS RR types, do not form
         RRsets.  In particular, the :term:`TTL`` values among RRSIG RRs with
         a common owner name do not follow the RRset rules described in
         :RFC:`2181`.
    
  TTL 
    The maximum "time to live" of a resource record. "A TTL value is an
    unsigned number, with a minimum value of 0, and a maximum value of
    2147483647.  That is, a maximum of 2^31 - 1.  When transmitted, this
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