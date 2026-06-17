Catalog Zones
=============

Cascade can manage the set of zones it signs through a :RFC:`9432` *catalog
zone* rather than through individual :doc:`zone <man/cascade-zone>`
configuration. A catalog zone is an ordinary DNS zone whose contents list a
set of *member zones*. Cascade acts as a catalog *consumer*: it transfers a
registered catalog zone from a primary, and automatically adds, signs and
serves the member zones it lists, removing them again when they leave the
catalog.

This is convenient when the set of zones to sign is large or changes
frequently: zones can be added to and removed from Cascade simply by editing
the catalog zone on the primary, with no further interaction with Cascade.

How it works
------------

When you register a catalog with :subcmd:`cascade catalog add`, Cascade:

#. Transfers the catalog zone from the configured primary using AXFR,
   optionally authenticated with a :doc:`TSIG key <man/cascade-tsig>`.
#. Parses the catalog's membership according to :RFC:`9432` (schema
   version 2).
#. Adds any member zones that are not yet managed, and removes any managed
   member zones that are no longer listed.

Each added member zone is configured like any other Cascade zone: it is
transferred from a primary, signed according to a :doc:`policy
<man/cascade-policy>`, and served from the publication server. Cascade
re-transfers and re-reconciles the catalog according to the catalog zone's
SOA ``REFRESH`` timer, and on demand via :subcmd:`cascade catalog reload`.

Selecting a policy and source per member
-----------------------------------------

By default, member zones are transferred from the same primary (and TSIG key)
as the catalog zone, and signed using the catalog's *default policy*.

A member's ``group`` property (RFC 9432) can be used to select different
configuration. For each group you can specify a policy and, optionally, a
different source for that group's member zones:

.. code-block:: text

   cascade catalog add catalog.example. \
       --source 192.0.2.1^my-tsig-key \
       --default-policy default \
       --group production=prod-policy \
       --group staging=staging-policy=192.0.2.2^staging-key

Members whose group has no matching mapping fall back to the default policy
and the catalog's primary.

Example catalog zones
---------------------

The examples below show catalog zones as they would appear in a zonefile on
the primary. The apex ``SOA`` and ``NS`` records are required for the zone
to be valid; :RFC:`9432` recommends using ``invalid.`` as the hostnames in
the apex ``SOA`` and ``NS`` records because the catalog zone is not meant to
be queried like an ordinary zone. Each member is identified by a unique
``<id>`` label; the label itself carries no semantics beyond identifying the
member within the catalog.

Simple catalog
~~~~~~~~~~~~~~

A minimal catalog lists its members with ``PTR`` records at
``<id>.zones.<catalog-apex>`` and declares schema version 2:

.. code-block:: text

   $ORIGIN catalog.example.
   $TTL 3600
   @                SOA  invalid. invalid. ( 2024010100 3600 600 86400 3600 )
   @                NS   invalid.
   version          TXT  "2"
   unique1.zones    PTR  example.com.
   unique2.zones    PTR  example.net.

Register it with Cascade and both members are transferred from the catalog's
primary and signed with the default policy:

.. code-block:: text

   cascade catalog add catalog.example. \
       --source 192.0.2.1 \
       --default-policy default

Catalog with custom signing profiles
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A member's ``group`` property signals that it should be signed with a
particular policy. The catalog zone only carries the group *name*; the
mapping from group name to :doc:`policy <man/cascade-policy>` (and,
optionally, a different primary) is configured in Cascade when the catalog
is registered:

.. code-block:: text

   $ORIGIN catalog.example.
   $TTL 3600
   @                SOA  invalid. invalid. ( 2024010100 3600 600 86400 3600 )
   @                NS   invalid.
   version          TXT  "2"
   prod1.zones      PTR  shop.example.
   group.prod1.zones TXT "production"
   stg1.zones       PTR  shop.staging.example.
   group.stg1.zones TXT "staging"
   misc1.zones      PTR  intranet.example.

The ``production`` and ``staging`` members use the policies named in their
group mappings; ``intranet.example.`` has no ``group`` property and therefore
uses the default policy and the catalog's primary:

.. code-block:: text

   cascade catalog add catalog.example. \
       --source 192.0.2.1^cat-key \
       --default-policy default \
       --group production=prod-policy \
       --group staging=staging-policy=192.0.2.2^staging-key

Records Cascade interprets
~~~~~~~~~~~~~~~~~~~~~~~~~~

Cascade reads the following records from a catalog zone:

* The apex ``SOA`` record (its serial is used to detect catalog changes).
* The apex ``NS`` record (required for the zone to be valid).
* ``version.<catalog-apex>`` ``TXT`` ``"2"`` — the schema version. This
  record is required; any other value causes the catalog to be rejected.
* ``<id>.zones.<catalog-apex>`` ``PTR`` — points to the member zone name.
  Each member must have exactly one such record.
* ``group.<id>.zones.<catalog-apex>`` ``TXT`` — the member's group. This is
  the only optional *member property* that Cascade acts on.

Any other records or member properties are ignored, including other
properties defined by :RFC:`9432` or its predecessors (such as ``coo`` for
change of ownership). A catalog zone that does not declare version ``2`` is
rejected entirely.

Catalog-managed zones
---------------------

Zones added by a catalog are *catalog-managed*: they cannot be removed or
reconfigured manually, only through their catalog. Removing a catalog with
:subcmd:`cascade catalog remove` also removes all of the member zones it
manages.

Producing a downstream catalog
------------------------------

Cascade can also generate a downstream catalog zone that mirrors the members
it manages, so that downstream secondaries can automatically discover and
transfer the signed member zones. Set the ``--produced-catalog`` option when
registering a catalog to enable this.

.. note:: Producing a catalog generates the downstream catalog zone, keeping
          it in step with the consumed catalog. Serving the produced catalog
          over DNS is not yet available.
