Key Management
==============

.. note:: The key management strategy is fundamentally different than the
   the implementation in OpenDNSSEC and for example BIND. 
   
   The goal is that key rolls should always go through the same sequence of 
   steps. As much as possible, we strive get all key rolls in a single mold.
   They will always follow the same pattern, while the details of a 
   :term:`KSK <Key signing key (KSK)>` and :term:`ZSK <Zone signing key 
   (ZSK)>` roll will be different.

Implementation
--------------

The key manager is responsible for two things: 

1. For each zone, it maintains and provides key rolls for a set of keys that
   are used to sign. 
2. Signing DNSKEY, CDS, and CDNSKEY :term:`RRsets <Resource Record Set
   (RRset)>`.

Cascade uses an external key manager, which is part of our :program:`dnst` 
toolset. The actual key management is provided by the :subcmd:`keyset` 
subcommand of :program:`dnst`.

The reason for having an external key manager is to have the flexibility to
use different ones. The current key manager requires that keys are online,
either in files or in a :doc:`Hardware Security Module (HSM) <hsms>` and does
not (explicitly) support a multi-signer setup. We envision future key
managers that support offline keys or multi-signing. Finally, a separate key
manager makes it relatively easy for Cascade to support high-availability
setups, though it does not do that at the moment.

Operations
----------

User interaction with the key manager is designed to be done through Cascade.
The key manager manages a set of DNSSEC (:RFC:`9364`) signing keys and
generates a signed DNSKEY RRset. The key manager expects a separate signer,
in this case Cascade, to use the zone signing keys in the key set, sign the
zone and include the DNSKEY RRset (as well as the CDS and CDNSKEY RRsets).
The key manager supports keys stored in files and keys stored in an HSM.

The key manager operates on one zone at a time. For each zone, the key
manager has configuration parameters for key generation (which algorithm to
use, whether to use a :term:`CSK <Combined signing key (CSK)>` or a
:term:`KSK <Key signing key (KSK)>` and :term:`ZSK <Zone signing key (ZSK)>`
pair), parameters for key rolls (whether key rolls are automatic or not), the
lifetimes of keys and signatures, etc. 

Maintaining State
"""""""""""""""""

The key manager maintains a state file for each zone. The state file lists
the keys in the key set, the current key roll state, and has the DNSKEY, CDS,
and CDNSKEY RRsets. key generation (which algorithm to use, whether to use a
CSK and a KSK and a ZSK), parameters for key rolls (whether key rolls are
automatic or not), the lifetimes of keys and signatures, etc.

In addition to the configuration and state files, the key manager maintains
files for keys that are stored in the filesystem.

Updating Keys 
"""""""""""""

The signatures of the DNSKEY, CDS and CDNSKEY RRsets need to updated
periodically. In addition, key roll automation requires periodic invocation
of the key manager to start new key rolls and to make progress on ones that
are currently executing. For this purpose, Cascade invokes the key manager
periodically.

New Zones and Keys 
------------------

When a new zone is added to Cascade, Cascade will invoke the key manager
to create empty key state for the new zone.
When adding a zone it is possible to either let the key manager generate new
keys or import keys from an existing signer.

When the key manager creates new keys, it will start an algorithm roll instead
of using the new keys directly.
The reason for this is that the new zone may be an existing unsigned zone
that now needs to become a DNSSEC signed zone.
The algorithm roll makes sure that the DNSKEY RRset and the zone signatures
have propagated before adding the DS record at the parent.

Key Rolls
---------

The key manager can perform four different types of key rolls:

1. KSK rolls
2. ZSK rolls
3. CSK rolls
4. Algorithm rolls
   
A KSK roll replaces one KSK with a new KSK.
Similarly, a ZSK roll replaces one ZSK with a new ZSK.
A CSK roll also replaces a CSK with a new CSK but the roll also treats a
pair of KSK and ZSK keys as equivalent to a CSK.
So, a CSK roll can also roll from KSK plus ZSK to a new CSK or from a CSK
to new a KSK and ZSK pair.
Note that a roll from KSK plus ZSK to a new KSK plus ZSK pair
is also supported.
Finally, an algorithm roll is similar to a CSK roll, but designed in
a specific way to handle the case where the new key or keys have an algorithm
that is different from one used by the current signing keys.

The KSK and ZSK rolls are completely independent and can run in parallel.
Consistency checks are performed at the start of a key roll.
For example, a KSK key roll cannot start when another KSK roll is in progress or
when a CSK or algorithm roll is in progress.
A KSK roll cannot start either when the current signing key is a CSK or
when the configuration specifies that the new signing key has to be a CSK.
Finally, KSK rolls are also prevented when the algorithm for new keys is
different from the one used by the current key.
Similar limitations apply to the other roll types. Note however that an
algorithm roll can be started even when it is not needed.

Automatic Key Rolls
"""""""""""""""""""

.. important:: Cascade has support for fully automatic key rolls, which is 
   enabled by default. If Cascade is for example running in an isolated 
   network, it will not have access to all nameservers of the zone or the 
   parent zone. In that case it's best to disable automatic key rolls in your 
   :ref:`policy <defining-policy>`.

For automatic key rolls, the key manager will check the propagation of
changes to the DNSKEY RRset, the DS RRset at the parent and the zone's
signatures to all nameservers of the zone or the parent zone. To be able to
do this, the key manager needs network access to those nameservers. If
Cascade is running in an isolated network, then this will fail and it is best
to disable (part of) automatic key rolls in your :ref:`policy
<defining-policy>`. 

To check the signatures in the zone, the key manager will issue an AXFR
request to the primary nameserver listed in the SOA record of the zone. In
the future we plan to make it possible to configure which nameserver should
be used and which TSIG keys should be used for authentication.

The automatic key roll checks have two limitations:

1. They do not work in a multi-signer setup where signers use different keys
   to sign the zone.
2. Propagation cannot be checked in an any-cast setup.The key manager may
   continue with the key roll before all nodes in the any-cast
   cluster have received the new version of the zone.

Future Development
~~~~~~~~~~~~~~~~~~

.. tip:: We explicitly solicit :ref:`your input <reach-out>` on how to 
   improve this feature.

We would like to avoid time-based solutions (because that could mean that
the key roll will continue even if propagation is not complete). 
Solutions we are thinking about are a measurement program at the edge of
the operator's network that reports back to the key manager about the state
of propagation.
For propagation in an any-cast cluster, a system such as RIPE Atlas could be
used to check propagation across the Internet.

Key Roll Steps
""""""""""""""

A key roll consists of six steps:

1. ``start-roll``
2. ``propagation1-complete``
3. ``cache-expired1``
4. ``propagation2-complete``
5. ``cache-expired2``
6. ``roll-done``
   
For each key roll these six steps follow in the same order.
Associated with each step is a (possibly empty) list of actions, which fall 
in three categories:

1. Actions that require updating the zone or the parent zone.
2. Actions that require checking if changes have propagated to all
   nameservers and require reporting of the TTLs of the changed RRset as seen
   at the nameservers.
3. Waiting for changes to propagate to all nameservers but there is no need
   to report the TTL.

Typically, in a list of actions, an action of the first category is paired
with one from the second of third category.
For example, ``UpdateDnskeyRrset`` is paired with either
``ReportDnskeyPropagated`` or ``WaitDnskeyPropagated``.

A key roll starts with the ``start-roll`` step, which creates new keys.
The next step, ``propagation1-complete`` has a TTL argument which is the
maximum of the TTLs of the Report actions.
The ``cache-expired1`` and ``cache-expired2`` have no associated actions.
They simply require waiting for the TTL (in seconds) reported by the
previous ``propagation1-complete`` or ``propagation2-complete``.
The ``propagation2-complete`` step is similar to the ``propagation1-complete`` step.
Finally, the ``roll-done`` step typically has associated Wait actions.
These actions are cleanup actions and are harmless but confusing if they
are skipped.

Control over Automation
"""""""""""""""""""""""

The key manager provides fine grained control over automation.
Automation is configured separately for each of the four roll types.
For each roll type, there are four booleans:

1. ``start``
2. ``report``
3. ``expire``
4. ``done``

When set, the ``start`` boolean directs the key manager to start a key roll
when a relevant key has expired.
A KSK or a ZSK key roll can start automatically if respectively a KSK or a ZSK
has expired.
A CSK roll can start automatically when a CSK has expired but also when a KSK or
ZSK has expired and the new key will be a CSK.
Finally, an algorithm roll can start automatically when the new algorithm is
different from the one used by the existing keys and any key has expired.

The ``report`` flags control the automation of the ``propagation1-complete``
and ``propagation2-complete`` steps.
When enabled, the cron subcommand contacts the nameservers of the zone or
(in the case of ``ReportDsPropagated``, the nameservers of the parent zone)
to check if changes have propagated to all nameservers.
The check obtains the list of nameservers from the apex of the (parent) zone
and collects all IPv4 and IPv6 addresses.
For the ``ReportDnskeyPropagated`` and ``ReportDsPropagated`` actions, each address is
the queried to see if the DNSKEY RRset or DS RRset match
the KSKs.
The ``ReportRrsigPropagated`` action is more complex.
First the entire zone is transferred from the primary nameserver listed in the
SOA record.
Then all relevant signatures are checked if they have the expected key tags.
The maximum TTL in the zone is recorded to be reported.
Finally, all addresses of listed nameservers are checked to see if they
have a SOA serial that is greater than or equal to the one that was checked.

Automation of ``cache-expired1`` and ``cache-expired2`` is enabled by the
``expire`` boolean.
When enabled, the cron subcommand simply checks if enough time has passed
to invoke ``cache-expired1`` or ``cache-expired2``.

Finally the ``done`` boolean enables automation of the ``roll-done`` step.
This automation is very similar to the ``report`` automation.
The only difference is that the Wait actions are automated so propagation
is tracked but no TTL is reported.

Fine grained control of over automation makes it possible to automate
KSK or algorithm without starting them automatically.
You can also let a key roll progress automatically except for doing the ``cache-expired``
steps manually, in order to be able to insert extra manual steps.

The ``report`` and ``done`` automations require that :subcmd:`keyset` has
network access to all nameservers of the zone and all nameservers of the
parent.

Importing Keys
--------------

The key manager supports importing existing keys. Both standalone public keys
as well as public/private key pairs can be imported. A standalone public key
can only be imported from a file whereas public/private key pairs can be
either files or references to keys stored in an HSM. 

.. note:: The public and private key either need to be both files or both 
   stored in an HSM.

There are three basic ways to import existing keys: 

1. A public-key stored in a file
2. A public/private key pair stored in files
3. A public/private key pair stored on an HSM

Public Key in a File
""""""""""""""""""""

A public key can only be imported from a file.
When the key is imported the name of the file is converted to a URL and stored in the key set and
the key will be included in the DNSKEY RRset.
This is useful for certain migrations and to manually implement a
multi-signer DNSSEC signing setup.
Note that automation does not work for this case.

Public/Private Key Pair in Files
""""""""""""""""""""""""""""""""

A public/private key pair can be imported from files.
It is sufficient to give the name of the file that holds the public key if
the filename ends in ``.key`` and the filename of the private key is the
same except that it ends in ``.private``.
If this is not the case then the private key filename must be specified
separately.

Public/Private Key Pair in an HSM
"""""""""""""""""""""""""""""""""

Importing a public/private key stored in an HSM requires specifying the KMIP
server ID, the ID of the public key, the ID of the private key, the
DNSSEC algorithm of the key and the flags (typically 256 for a ZSK and
257 for a KSK).

Ownership
"""""""""

Normally, the key manager assumes ownership of any keys it holds.
This means that when a key is deleted from the key set, the key manager
will also delete the files that hold the public and private keys or delete the
keys from the HSM that was used to create them.

For an imported public/private key pair this is considered too dangerous
because another signer may need the keys.
For this reason keys are imported in so-called ``decoupled`` state.
When a decoupled key is deleted, only the reference to the key is deleted
from the key set, the underlying keys are left untouched.
There is a ``--coupled`` option to tell keyset to take ownership of the key.

