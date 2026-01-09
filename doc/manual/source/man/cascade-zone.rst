cascade zone
============

Synopsis
--------

:program:`cascade zone` ``[OPTIONS]`` ``<COMMAND>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`add` ``[OPTIONS]`` ``--source <SOURCE>`` ``--policy <POLICY>`` ``<NAME>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`remove` ``<NAME>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`list`

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`reload` ``<NAME>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`approve` ``<--unsigned|--signed>``  ``<NAME>`` ``<SERIAL>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`reject` ``<--unsigned|--signed>``  ``<NAME>`` ``<SERIAL>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`status` ``[--detailed]`` ``<NAME>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`history` ``<NAME>``

Description
-----------

Manage Cascade's zones.

Options
-------

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

Commands
--------

.. subcmd:: add

   Register a new zone.

.. subcmd:: remove

   Remove a zone.

.. subcmd:: list

   List registered zones.

.. subcmd:: reload

   Reload a zone.

.. subcmd:: approve

   Approve a zone being reviewed.

.. subcmd:: reject

   Reject a zone being reviewed.

.. subcmd:: status

   Get the status of a single zone.

.. subcmd:: history

   Get the history of a single zone.

Options for :subcmd:`zone add`
------------------------------

.. option:: --source <SOURCE>

   The zone source can be an IP address (with or without port, defaults to port
   53) or a file path.

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

Options for :subcmd:`zone status`
---------------------------------

.. _zone-status-detailed:
.. option:: --detailed

   Print detailed information about the zone, including a zone's DNSSEC key
   identifiers in use, as well as the new DNSKEY records during key rolls.

.. option:: <NAME>

   The name of the zone to report the status of.

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
