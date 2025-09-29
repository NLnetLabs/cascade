Before You Start
================

Placement
---------

Cascade must *NOT* be run as an Internet facing service as it is only capable
of answering a limited subset of the DNS protocol that a full authoritative
nameserver must support.

Instead, it is what is known as a "hidden signer", taking local zones or zones
received from an upstream primary nameserver, signing those zones and making
the signed results available to downstream, secondary, nameservers which *are*
actually Internet facing.

One possible authoritative server that could be used up and downstream of
Cascade is our NSD product, but any authoritative nameserver product can
be used instead of NSD, assuming that it supports transferring zones via XFR
transfers to and from Cascade.

Intended Audience
-----------------

Cascade is currently targeted for use by TLD operators, but will evolve over
time to cater to other audiences. 

Right now, signing speed is not likely to be a bottle neck for most use
cases, but there are many improvements in the pipeline, especially when using
an HSM. Cascade's memory use is considerable, using about 50GiB of RAM when
signing a ~1GB zone file with about ~25M resource records and adding ~10M
records while signing. Reducing the memory footprint is a priority.

As such, Cascade can currently be used by TLD operators with at most a few
small to medium size zones. As development progresses, it will also support
operators with very large zones or operators with many zones.

Cascade is *NOT* yet intended for operation as a clustered deployment.

As a successor to OpenDNSSEC Cascade is clearly intended to offer continuity
to current users of OpenDNSSEC, but should also be usable by anyone. In particular
while Cascade offers most of the functionality of OpenDNSSEC,
it uses different terminology and has a slightly different architecture in order to offer a superior experience.

Like OpenDNSSEC one can use Cascade with a PKCS#11 compatible HSM, but unlike
OpenDNSSEC using a HSM is not required, on-disk key files may be used instead,
and Cascade will also support KMIP compatible HSMs.

The Moving Parts
----------------

Cascade consists of three, possibly four, pieces:

- The :program:`cascaded` daemon, receiving zone data, signing it, and serving the signed
  result, with support for approval "gates" during the processing pipeline to
  allow you to use your preferred solutions to verify the unsigned and/or
  signed zone before publishing it.

- The cascade command line interface (CLI) for controlling and interacting
  with the cascaded daemon.

- A tool called `dnst keyset` which is somewhat similar to the OpenDNSSEC
  Enforcer but is not a daemon, instead it is invoked as needed by the cascaded
  daemon. In future this may be bundled as an integral part of Cascade but will
  likely still also be supported as an external tool to allow it to be swapped
  out with an alternate version depending on the exact signing policy of the
  operator, especially for scenarios such as multi-signer.

- The _optional_ `kmip2pkcs11` daemon which receives KMIP TCP TLS requests
  and converts them into PKCS#11 operations executed against a loaded PKCS#11
  module. This separation of concerns:
    - permits Cascade to work with KMIP and/or PKCS#11 compatible HSMs in
      exactly the same way from the perspective of the Cascade operator,
    - isolates the Cascade daemon process from untrusted 3rd party PKCS#11 module
      code (avoiding crashes caused by the PKCS#11 code crashing),
    - avoiding the need for the Cascade daemon to have the access rights and
      environment needed to access the HSM,
    - avoiding the confusion caused by PKCS#11 module logging output being
      interleaved with that of the Cascade daemon,
    - offering additional deployment topologies by enabling the HSM access to be
      from a separate process (and even potentially a separate server) to that
      of the Cascade daemon.

Supported Inputs/Outputs
------------------------

Cascade supports:
  - Receiving zone data via AXFR, IXFR or from on-disk files.
  - Publishing data via AXFR (IXFR coming soon, on-disk files while not
    supported directly could be achieved by XFR of the signed zone to an
    on-disk file).

System Requirements
-------------------

Cascade is able to run with fairly limited CPU and memory. Exact figures are
not yet available, but in principle with more CPU cores more operations will
benefit from parallelization, adn with more memory it will be possible to load
and sign larger zones.
