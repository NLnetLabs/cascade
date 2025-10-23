Known Limitations
=================

Cascade is a hidden signer. As such, it is *not* a complete authoritative DNS
server. Cascade will not reply with the AA or AD flag set, nor can it reply
to DNSSEC queries. Instead, Cascade is intended to be used with a proper
secondary serving the signed zones to actual clients.

Expectations for the Alpha Release
----------------------------------

.. tip:: This page details what you can expect from Cascade in its alpha form.
   Our goal is to gather operator feedback. Please :ref:`reach out <reach-out>`
   to us.

- The included functionality should work correctly for simple scenarios with
  correct inputs when running on setups (O/S, HSM) that we have tested on.
- Handling of incorrect inputs, edge cases, more complex scenarios, non-default
  policy settings, and so on *may be incomplete or incorrect*. Please 
  :ref:`report any bugs you find <reach-out>`
- The user experience is a *work-in-progress*. The goal of Cascade is not only
  to be a correctly functioning DNSSEC signer which makes it easy to do the
  right thing and hard to do the wrong thing, it should also be obvious how to
  use it and be clear what the system did, is doing now and will do in the
  future. But we're not there yet, we have more ideas but :ref:`we'd love to
  hear yours too <reach-out>`.

Policy Edits Require Explicit Reload
------------------------------------

Users may expect that edits to policy files will take effect if Cascade is
restarted, however this is not the case. Cascade deliberately does not reload
the policy files until explicitly told to do so via ``cascade policy
reload``.

This design ensures that a restart doesn't suddenly cause unexpected changes
in behaviour, e.g. config file edits that were made but never actually used
and then forgotten about.

Differences to OpenDNSSEC
-------------------------

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

Missing features
++++++++++++++++

The alpha release of Cascade is missing some of the features provided by
OpenDNSSEC that will be added in a future release:

- Jitter support.
- IXFR out.
- File output.
- Delay before automatic key deletion.
- Holding keys for use until a backup flag is set.
- Sharing of keys between zones.
- Passthrough mode.
- Incremental signing.
- TSIG support.
- Inbound XFR/NOTIFY access control.
- Prefix based access control.
- CAA record support.
- Terminology differences, Cascade does not use the term "omnipresent" for
  example.

Other known limitations
-----------------------

- No NOTIFY retry support.
- No NOTIFY "Notify Set" (RFC 1996) discovery.
- No KMIP batching support.
- No DNS UPDATE support.
- HSM algorithm support is limited to RSASHA256 and ECDSAP256SHA256.
- Changing a policy to use an HSM will not affect existing zones.
- Memory usage can be improved.
