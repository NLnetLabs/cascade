Before You Start
================

Placement
---------

Cascade is what is known as a "hidden signer". It is meant to run as a
dedicated server with restricted access that takes local zones or zones
received from an upstream primary nameserver, signs those zones and makes the
results available to downstream, Internet facing *secondary* nameservers.

.. Warning:: Do *not* run Cascade as an Internet facing service, as it is
   designed to answer a limited subset of the DNS protocol that a full
   authoritative nameserver must support.

One possible authoritative server that could be used up and downstream of
Cascade is `NSD <https://nlnetlabs.nl/nsd>`_, but any solution can be used
provided that it supports transferring zones via XFR zone transfers to and
from Cascade.

Intended Audience
-----------------

Cascade is currently targeted for use by TLD operators, but will evolve over
time to cater to other audiences. As a successor to OpenDNSSEC, Cascade is
clearly intended to offer continuity and a migration path for current users,
but Cascade will also offer superior performance, flexibility and user
experience.

.. important:: Cascade does *not* require the use of a Hardware Security
  Module (HSM). It can make use of on-disk key files and, if desired, use
  PKCS#11 and KMIP compatible HSMs.

Components
----------

Cascade consists of three main components and an optional fourth:

1. The :program:`cascaded` daemon for receiving zone data, signing it, and
   serving the signed result. It supports :doc:`review-hooks` during the
   processing pipeline, allowing you to use your preferred solutions to
   automate verification of the unsigned and signed zone, before publishing
   it.

2. The :program:`cascade` command line interface (CLI) for controlling and
   interacting with the :program:`cascaded` daemon.

3. A tool called :program:`dnst keyset`, which is responsible for the
   :doc:`key management <key-management>` of Cascade, including automation of
   key rolls. It is invoked as needed by the :program:`cascaded` daemon.

4. The *optional* :program:`cascade-hsm-bridge` daemon, which is only required
   when using a PKCS#11 compatible :doc:`HSM <hsms>`.

Supported Inputs/Outputs
------------------------

Cascade accepts unsigned zones from local files or through AXFR/IXFR
:term:`zone transfers <Zone transfer>`. Signed zones are published through
AXFR/IXFR. Direct export to a local file is not supported.

System Requirements
-------------------

Exact figures are not yet available, but in principle more CPU cores allow for
more parallel operations and more memory makes it possible to load and sign
larger zones.

To give you some indication, the Cascade beta releases currently use about
30GiB of RAM when signing a 1GiB zone file with about 25 million resource r
ecords and adding roughly 10 million records while signing.

Cascade's design and interface is currently catered towatds operators with
a limited number of zones. As development progresses, it will also support
operators with many (smaller) zones.

Cascade is *not* yet intended for operation as a clustered deployment.
