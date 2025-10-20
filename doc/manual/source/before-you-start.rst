Before You Start
================

Placement
---------

Cascade is what is known as a "hidden signer". It is meant to run as a
dedicated server with restricted access that takes local zones or zones
received from an upstream primary nameserver, signs those zones and makes the
results available to downstream, Internet facing *secondary* nameservers. 

.. Warning:: Cascade must *not* be run as an Internet facing service as it is
   designed to answer a limited subset of the DNS protocol that a full
   authoritative nameserver must support.

One possible authoritative server that could be used up and downstream of
Cascade is our authoritative nameserver `NSD <https://nlnetlabs.nl/nsd>`__, but
any authoritative nameserver can be used instead, assuming that it supports
transferring zones via XFR transfers to and from Cascade.

Intended Audience
-----------------

Cascade is currently targeted for use by TLD operators, but will evolve over
time to cater to other audiences. As a successor to OpenDNSSEC, Cascade is
clearly intended to offer continuity and a migration path for current users,
but Cascade will also offer superior performance, flexibility and user
experience.

Cascade does not require the use of a :term:`Hardware security module (HSM)`.
It can make use of on-disk key files, and, if desired, use PKCS#11 and KMIP
compatible HSMs.

The Moving Parts
----------------

Cascade consists of three main components and an optional fourth:

- The :program:`cascaded` daemon for receiving zone data, signing it, and
  serving the signed result. It supports :doc:`review-hooks` during the
  processing pipeline, allowing you to use your preferred solutions to verify
  the unsigned and/or signed zone before publishing it.

- The :program:`cascade` command line interface (CLI) for controlling and
  interacting with the :program:`cascaded` daemon.

- A tool called :program:`dnst keyset`, which is responsible for the key
  management of Cascade. It is invoked as needed by the :program:`cascaded`
  daemon. The reason for having an external key manager is to have the
  flexibility of swapping it out in the future, for example to support
  offline keys or multi-signing. You can read more about this in the
  :doc:`key-management` section.

- The *optional* :program:`kmip2pkcs11` daemon, which is only required when
  using an PKCS#11 compatible HSM. You can read more about this in the
  :doc:`hsms` section.

Supported Inputs/Outputs
------------------------

Cascade supports:
  - Receiving zone data via AXFR or IXFR :term:`zone transfers <Zone
    transfer>`, or from on-disk files.
  - Publishing data via AXFR.

Publishing data via IXFR is coming soon. On-disk files, while not supported
directly, could be achieved by XFR of the signed zone to an on-disk file.

.. important:: Fully automatic key rolls are enabled by default. For this to 
   work, Cascade requires access to all nameservers of the zone and the 
   parent zone. If this is not available, make sure to 
   :ref:`disable automatic key rolls <automation-control>`.

System Requirements
-------------------

Cascade is able to run with fairly limited CPU and memory. Exact figures are
not yet available, but in principle with more CPU cores more operations will
benefit from parallelization, and with more memory it will be possible to load
and sign larger zones.

Right now, signing speed is not likely to be a bottle neck for most use
cases, but there are many speed improvements in the pipeline, especially when
using an HSM. 

.. note:: Cascade's memory use is still considerable with large zones. It 
          uses using about 30GiB of RAM when signing a ~1GB zone file with 
          about ~25M resource records and adding ~10M records while signing.

Cascade can currently be used by operators with at most a few small to medium
size zones. As development progresses, it will also support operators with
very large zones or operators with many zones.

Cascade is *not* yet intended for operation as a clustered deployment.

