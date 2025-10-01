.. TODO better doc title?

Limitations
===========

Making changes to the config
----------------------------

Only on the first start of Cascade will it read the provided config file and
initialize the state. After that, all changes to the config require
a ``cascade config reload`` to load the changes to the config (and, if you
changed Cascade's listener addresses, a restart to bind the new sockets).

All further restarts of Cascade do not pick up changes to the config, until
you issue the ``cascade config reload`` command.

Differences to OpenDNSSEC
-------------------------

The alpha release of Cascade is missing some of the features provided by
OpenDNSSEC that will be added in a future release:

- No jitter support.
- No IXFR out.
- No delay before automatic key deletion.
- No holding keys for use until a backup flag is set.
- No sharing of keys between zones.
- No passthrough mode.
- No incremental signing.
- No support for sharing keys between zones.
- No TSIG support.
- No inbound XFR/NOTIFY access control.
- Only IP address outbound NOTIFY access control, no prefix support.

Improvements
++++++++++++

- An HSM is not required.
- More suited to containerized usage:
  - Supports stdout/stderr logging as well as syslog.
  - Single daemon per image.
- Rust.
- Observability (Still a Work-In-Progress).
- No XML.
- No database.
- No file based communication between daemons.
- Finer grained control over and insight into key states.

NOT a complete authoritative name server
----------------------------------------

Cascade is NOT a complete authoritative DNS server. It will not reply with the
AA or AD flag set. Nor can it reply to DNSSEC queries. Instead, Cascade is
intended to be used as a hidden signer with a proper secondary such as NSD
serving the signed zones to actual clients.

Other known limitations
-----------------------

- No NOTIFY retry support.
- No NOTIFY "Notify Set" (RFC 1996) discovery.
- HSM algorithm support is limited to RSASHA256 and ECDSAP256SHA256.
- No KMIP batching.