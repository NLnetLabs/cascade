.. TODO better doc title
.. TODO turn bullet points (most are taken from the backlog) into decent text
   (probably still as a list though)

Limitations
===========

Updating config of an existing instance (aka state.db exists) requires using
``cascade config reload`` (and then a restart to bind the new listeners).

Differences to OpenDNSSEC
-------------------------

.. TODO add ", yet" where applicable?

- No jitter support.
- No IXFR out.
- No delay before automatic key deletion.
- No holding keys for use until a backup flag is set.
- No sharing of keys between zones.
- No passthrough mode.
- No incremental signing.
- No TSIG support.

Improvements
++++++++++++

- HSM not required.
- Rust.
.. TODO
- Observability (in theory).

Limitations
-----------

Cascade is NOT a full primary name server. This means:

- No fully standards conform (DNSSEC) DNS query support, meaning no AA or AD
  flag and ignoring the DO flag.
  - Only use AXFR (and normal queries for the SOA RR) to fetch accurate zone
    data from Cascade.
.. (Optionally with TSIG)

Guide:
- Cascade is NOT a complete authoritative DNS server. It will not reply with
  the AD flag set. Nor can it reply to DNSSEC queries. Instead, Cascade is
  intended to be used as a hidden signer with a proper secondary such as NSD
  serving the signed zones to actual clients.
- Cascade only reads the directory/file path configurations from the config
  file when first initializing the state file. When continuing from an existing
  state file, the paths in the config file are ignored.
- Approval script arguments
