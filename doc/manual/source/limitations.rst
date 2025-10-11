Known Limitations
=================

Cascade is a hidden signer. This has implications for :doc:`before-you-start`.


Expectations for the alpha release
----------------------------------

.. tip:: This page details what you can expect from Cascade in its alpha form.
   Our goal is to gather operator feedback. Please :ref:`reach out <reach-out>`
   to us.

- The included functionality should work correctly for simple scenarios with
  correct inputs when running on setups (O/S, HSM) that we have tested on.
- Handling of incorrect inputs, edge cases, more complex scenarios, non-default
  policy settings, and so on *may be incomplete or incorrect*. Please `report
  any bugs you find <https://github.com/NLnetLabs/cascade/issues/new>`_
- The user experience is a *work-in-progress*. The goal of Cascade is not only
  to be a correctly functioning DNSSEC signer which makes it easy to do the
  right thing and hard to do the wrong thing, it should also be obvious how to
  use it and be clear what the system did, is doing now and will do in the
  future. But we're not there yet, we have more ideas but `we'd love to hear
  yours too <https://github.com/NLnetLabs/cascade/issues/new>`_.

Config & Policy Require Explicit Reload
---------------------------------------

Users may expect that edits to the Cascade configuration file or to policy
files will take effect if Cascade is restarted, however this is not the case.

Cascade deliberately does not reload the configuration or policy files until
explicitly told to do so via ``cascade config reload`` and ``cascade policy
reload`` respectively.

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

- No jitter support.
- No IXFR out.
- No file output.
- No delay before automatic key deletion.
- No holding keys for use until a backup flag is set.
- No sharing of keys between zones.
- No passthrough mode.
- No incremental signing.
- No support for sharing keys between zones.
- No TSIG support.
- No inbound XFR/NOTIFY access control.
- No prefix based access control.
- Terminology differences, Cascade does not use the term "omnipresent" for
  example.
- No CAA record support.

Not a complete authoritative nameserver
---------------------------------------

Cascade is *not* a complete authoritative DNS server. It will not reply with
the AA or AD flag set, nor can it reply to DNSSEC queries. Instead, Cascade
is intended to be used as a hidden signer with a proper secondary such as NSD
serving the signed zones to actual clients.

Other known limitations
-----------------------

- No NOTIFY retry support.
- No NOTIFY "Notify Set" (RFC 1996) discovery.
- No KMIP batching support.
- No DNS UPDATE support.
- HSM algorithm support is limited to RSASHA256 and ECDSAP256SHA256.
- Changing a policy to use a HSM will not affect existing zones.
- Memory usage can be improved.
