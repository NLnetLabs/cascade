Troubleshooting
===============

.. Systemd error: Address already in use... override see quick start
.. Unknown rtype with concrete data ... unsupported rtype in domain

I added a zone with a non-existent file as its source
-----------------------------------------------------

Currently, when adding a zone with a non-existent file as its source, the zone
loader thread will crash. Additionally, Cascade won't be able to start if
configured with a zone source that doesn't exist. In both cases the following
error will be logged:

.. Error:: ERROR cascade::units::zone_loader: [ZL]: Failed to open zone file
   'non-existent': No such file or directory (os error 2)

To fix this until we properly support resolving these situations, you can:

1. Edit the state file of the zone. Its file name is ``<zone-name>.db`` and is
   located in the path configured with the ``zone-state-dir`` config option.

   The state file contains a JSON object containing a source object:
   ``"source": { "zonefile": { "path": "<file-path>" } }``.

   Edit the ``path`` variable to point to the correct file (or a temporary
   dummy, if you plan to remove the zone using the CLI).

2. Remove the zone from Cascade's state.

   After stopping Cascade you can edit the state file and remove the zone from
   the zones array: ``"zones": [ "<zone-name>" ]``.

   Also remove the zone's own state from the zone state directory as
   configured using the ``zone-state-dir`` config option. Its file name is
   ``<zone-name>.db``.

   Finally, remove the keys and their state created for the zone from the
   key's directory as configured using the ``keys-dir`` config option. The
   files associated with the zone are ``<zone-name>.cfg``,
   ``<zone-name>.state``, and all key files starting with ``K<zone-name>``.

Zone with unknown record data
-----------------------------


.. Error:: ERROR cascade::units::zone_loader: [ZL]:
   Failed to parse zone 'example.com': Got 1 errors  .: The record could not
   be parsed: 19:21: unknown record type with concrete data

TODO
