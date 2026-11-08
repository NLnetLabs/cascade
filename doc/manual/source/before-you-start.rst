Before You Start
================

Cascade is a DNSSEC signer, not an authoritative nameserver. Before installing
it, make sure that its deployment model fits your DNS infrastructure and that
you understand the current limitations of the beta release.

How Cascade Fits into Your DNS Infrastructure
----------------------------------------------

Cascade is designed to run as a *hidden signer* between the source of an
unsigned zone and the authoritative nameservers that publish the signed zone:

#. An upstream primary nameserver transfers an unsigned zone to Cascade, or
   Cascade loads the zone from a local file.
#. Cascade checks the zone, manages its DNSSEC keys, signs it, and optionally
   runs operator-defined :doc:`review hooks <review-hooks>`.
#. Downstream secondary nameservers retrieve the signed zone from Cascade using
   AXFR or IXFR and publish it to DNS clients.

Cascade should run on a system with restricted network and filesystem access.
It must not be exposed as an Internet-facing authoritative nameserver.

.. important:: Cascade implements only the DNS functionality needed for its
   role as a hidden signer. It is not a complete authoritative DNS server and
   does not answer ordinary DNS queries. Place one or more authoritative
   secondary nameservers downstream to serve signed zones to the Internet.

You can use any authoritative nameservers on either side of Cascade that
supports AXFR or IXFR. An example is to use :doc:`NSD can be configured <nsd>`
by NLnet Labs as both the upstream primary and a downstream secondary.

Is Cascade Right for Your Deployment?
-------------------------------------

Cascade is currently aimed primarily at TLD operators and other operators with
a limited number of zones. It is intended to provide continuity and an eventual
migration path for OpenDNSSEC users, while improving performance,
observability, configuration, and control over the signing pipeline.

Cascade is currently in **beta**. Use it for testing and evaluation, and review
the :doc:`known limitations <limitations>` before planning a deployment. In
particular:

- Cascade is not yet intended for clustered operation.
- Its current interfaces are better suited to a limited number of zones than 
  to hosting many small zones.
- Some OpenDNSSEC features and operational edge cases are not yet supported.
- Memory use still has room for improvement.

If these constraints affect your intended deployment, please
:ref:`tell us about your requirements <reach-out>`.

Decisions to Make Before Installation
-------------------------------------

Zone input and publication
~~~~~~~~~~~~~~~~~~~~~~~~~~

Decide how Cascade will receive each unsigned zone and how downstream
nameservers will retrieve the signed result:

- **Input:** a local zone file, or an AXFR/IXFR transfer from an upstream
  primary nameserver.
- **Output:** AXFR/IXFR transfers to downstream secondary nameservers.

Cascade does not currently write signed zones directly to local files. See
:doc:`zone-transfers` for transfer, NOTIFY, access-control, and TSIG options.

Key storage
~~~~~~~~~~~

**An HSM is optional.** Cascade can generate keys, store them in files on 
disk, andsign using software cryptography. If your security policy requires 
an HSM, Cascade supports:

- KMIP-compatible HSMs directly; and
- PKCS#11-compatible HSMs through the separate
  :program:`cascade-hsm-bridge` process.

Separating PKCS#11 support prevents vendor libraries from being loaded into the
main Cascade process. Review the tested devices and integration requirements in
:doc:`hsms`.

Key-roll automation
~~~~~~~~~~~~~~~~~~~

**All key-roll automation stages are enabled by default.** The automated 
reporting and completion stages contact every authoritative nameserver for the 
zone and its parent to determine whether DNSSEC changes have propagated. The 
Cascade host therefore needs network access to each server over IPv4 and, when
a server publishes an AAAA record, IPv6.

If your environment cannot provide that access, disable the ``auto-report`` and
``auto-done`` stages and complete the corresponding key-roll steps manually.
Review the :ref:`key-roll automation controls <automation-control>` before
adding production-like zones.

Pre-publication checks
~~~~~~~~~~~~~~~~~~~~~~

Decide whether zones may proceed directly through the signing pipeline or must
be approved first. Cascade can pause before signing and before publication for
manual approval or for checks performed by your own scripts and tools. See
:doc:`review-hooks`.

Components
----------

A Cascade installation consists of three main programs and, for PKCS#11 HSM
setups, an optional fourth:

#. :program:`cascaded` is the long-running daemon. It receives and loads zone
   data, coordinates key management, signs zones, runs configured review
   steps, and serves signed zones to downstream nameservers.
#. :program:`cascade` is the command-line interface used to configure, inspect,
   and control the daemon.
#. :program:`dnst keyset` manages DNSSEC key state and automated key rolls. The
   :program:`cascaded` daemon invokes it when needed; operators normally do not
   run it directly.
#. :program:`cascade-hsm-bridge` is required only when using an HSM through
   PKCS#11. It is not required for on-disk keys or direct KMIP connections.

Capacity Planning
-----------------

Resource requirements depend on zone size, the number and type of changes,
signing policy, and the amount of work performed in parallel. More CPU cores
allow Cascade to run more operations concurrently, while larger zones require
more memory.

As an indication rather than a sizing guarantee, beta testing has shown memory
use of approximately 30 GiB while signing a 1 GiB zone containing about
25 million input records and producing roughly 10 million additional DNSSEC
records.

Test with representative zones and policies before choosing production-like
hardware. Monitor signing duration, memory use, and queue activity using the
:doc:`status command <man/cascade-status>`, :doc:`health checks
<man/cascade-health>`, and :doc:`metrics`.

Next Steps
----------

When the deployment model and current limitations are suitable for your use
case:

#. :doc:`Install Cascade <installation>` from a package or build it from
   source.
#. Follow the :doc:`quick start <quick-start>` to configure the daemon, create
   a policy, and sign a test zone.
#. Read about :doc:`key management <key-management>` before connecting Cascade
   to parent and downstream nameservers.
