cascade zone
============

Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` zone ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`add` ``[OPTIONS]`` ``--source <SOURCE>`` ``--policy <POLICY>`` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`remove` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`list`

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`reload` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`approve` ``<--unsigned|--signed>``  ``<NAME>`` ``<SERIAL>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`reject` ``<--unsigned|--signed>``  ``<NAME>`` ``<SERIAL>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`override` ``<--unsigned|--signed>`` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`status` ``[--detailed]`` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`reset` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` zone :subcmd:`history` ``<NAME>``

Description
-----------

Manage Cascade's zones.

Global Options
--------------

See :doc:`cascade` for information about global options supported by every CLI
command.

Commands
--------

.. subcmd:: add

   Register a new zone.

.. subcmd:: remove

   Remove a zone.

   .. note:: Once removed downstream servers will no longer be able to fetch
             the zone!

.. subcmd:: list

   List registered zones.

.. subcmd:: reload

   Reload a zone.

.. subcmd:: approve

   Approve a zone being reviewed.

.. subcmd:: reject

   Reject a zone being reviewed.

.. subcmd:: override

   Override a previous rejection of a zone review.

.. subcmd:: status

   Get the status of a single zone.

.. subcmd:: reset

   Reset the pipeline for a zone to get it out of a halted state.

.. subcmd:: history

   Get the history of a single zone.

Options for :subcmd:`zone add`
------------------------------

.. option:: --source <SOURCE>

   The zone source can be the IP address of an upstream nameserver (with
   or without port, defaults to port 53) or the path to a zone file locally
   available to the ``cascaded`` daemon.`

   When specifying an upstream nameserver you may also optionally suffix it
   with ``^<TSIG_KEY_NAME>`` to indicate that the specified RFC 8945 TSIG key
   should be used to sign any SOA, AXFR and IXFR queries that will be sent to
   the upstream source.

   Zones sourced from an upstream nameserver will be automatically updated if
   a new version is detected. This can happen if the upstream nameserver sends
   an RFC 1996 NOTIFY message to Cascade, or if an IXFR or SOA query (if the
   upstream responds with NOTIMP to an IXFR request) sent by Cascade (due to a
   SOA timer expiring) discovers that a newer SOA SERIAL is available, or due
   to an operator issuing a `zone reload` command. For zones that have already
   been retrieved at least once via AXFR, subsequent refreshes will attempt to
   use IXFR and fallback to AXFR if IXFR is not available.

   .. note:: When providing the path to a zone file to load, if :subcmd:`zone
             add` is executed on a different host than where the ``cascaded``
             daemon is running the path must be valid on the **daemon** host.

   .. note:: Note: In order to use a TSIG key you MUST also supply the key to
             Cascade via :subcmd:`tsig add`.

.. option:: --policy <POLICY>

   Policy to use for this zone.

   Note: At present to use a HSM with a zone the HSM must exist and be
   configured in the policy used by the zone when the zone is added. It is not
   possible to change it later in this alpha version of Cascade.

.. option:: --import-public-key <IMPORT_PUBLIC_KEY>

   Import a public key to be included in the DNSKEY RRset.

   This needs to be a file path accessible by the Cascade daemon.

.. option:: --import-ksk-file <IMPORT_KSK_FILE>

   Import a key pair as a KSK.

   The file path needs to be the public key file of the KSK. The private key
   file name is derived from the public key file. Key files are not
   actually copied from the specified paths and must remain accessible
   to the server.

.. option:: --import-zsk-file <IMPORT_ZSK_FILE>

   Import a key pair as a ZSK.

   The file path needs to be the public key file of the ZSK. The private key
   file name is derived from the public key file. Key files are not
   actually copied from the specified paths and must remain accessible
   to the server.

.. option:: --import-csk-file <IMPORT_CSK_FILE>

   Import a key pair as a CSK.

   The file path needs to be the public key file of the CSK. The private key
   file name is derived from the public key file. Key files are not
   actually copied from the specified paths and must remain accessible
   to the server.

.. option:: --import-ksk-kmip <server> <public_id> <private_id> <algorithm> <flags>

   Import a KSK from an HSM.

.. option:: --import-zsk-kmip <server> <public_id> <private_id> <algorithm> <flags>

   Import a ZSK from an HSM.

.. option:: --import-csk-kmip <server> <public_id> <private_id> <algorithm> <flags>

   Import a CSK from an HSM.

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

.. option:: <NAME>

   The name of the zone to add.

Options for :subcmd:`zone remove`
---------------------------------

.. option:: <NAME>

   The name of the zone to remove.

Options for :subcmd:`zone reload`
---------------------------------

.. option:: <NAME>

   The name of the zone to reload.

Options for :subcmd:`zone approve`
----------------------------------

.. option:: <--unsigned|--signed>

   Whether the zone to approve is at the unsigned or signed review stage.

.. option:: <NAME>

   The name of the zone to approve.

.. option:: <SERIAL>

   The serial number of the zone to approve.

Options for :subcmd:`zone reject`
---------------------------------

.. option:: <--unsigned|--signed>

   Whether the zone to reject is at the unsigned or signed review stage.

.. option:: <NAME>

   The name of the zone to reject.

.. option:: <SERIAL>

   The serial number of the zone to reject.

Options for :subcmd:`zone override`
-----------------------------------

.. option:: <--unsigned|--signed>

   Whether the zone to override is at the unsigned or signed review stage.

.. option:: <NAME>

   The name of the zone to override.

Options for :subcmd:`zone status`
---------------------------------

.. _zone-status-detailed:
.. option:: --detailed

   Print detailed information about the zone, including a zone's DNSSEC key
   identifiers in use, as well as the new DNSKEY records during key rolls.

.. option:: <NAME>

   The name of the zone to report the status of.

Options for :subcmd:`zone reset`
---------------------------------

.. option:: <NAME>

   The name of the zone to reset the pipeline of.

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascaded**\ (1)
    :doc:`cascaded`

**cascaded-config.toml**\ (5)
    :doc:`cascaded-config.toml`

**cascaded-policy.toml**\ (5)
    :doc:`cascaded-policy.toml`
