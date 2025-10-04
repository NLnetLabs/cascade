cascade zone
============

Synopsis
--------

:program:`cascade zone` ``[OPTIONS]`` ``<COMMAND>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`add` ``[OPTIONS]`` ``--source <SOURCE>`` ``--policy <POLICY>`` ``<NAME>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`remove` ``<NAME>``

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`list`

:program:`cascade zone` ``[OPTIONS]`` :subcmd:`reload` ``<NAME>``

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

   Register a new zone

.. subcmd:: remove

   Remove a zone

.. subcmd:: list

   List registered zones

.. subcmd:: reload

   Reload a zone

.. subcmd:: status

   Get the status of a single zone

.. subcmd:: history

   Get the history of a single zone

Options for :subcmd:`zone add`
------------------------------

.. option:: --source <SOURCE>

   The zone source can be an IP address (with or without port, defaults to port
   53) or a file path

.. option:: --policy <POLICY>

   Policy to use for this zone

.. option:: --import-public-key <IMPORT_PUBLIC_KEY>

   Import a public key to be included in the DNSKEY RRset.

   This needs to be a file path accessible by the Cascade daemon.

.. option:: --import-ksk-file <IMPORT_KSK_FILE>

   Import a key pair as a KSK.

   The file path needs to be the public key file of the KSK. The private key
   file name is derived from the public key file.

.. option:: --import-zsk-file <IMPORT_ZSK_FILE>

   Import a key pair as a ZSK.

   The file path needs to be the public key file of the ZSK. The private key
   file name is derived from the public key file.

.. option:: --import-csk-file <IMPORT_CSK_FILE>

   Import a key pair as a CSK.

   The file path needs to be the public key file of the CSK. The private key
   file name is derived from the public key file.

.. option:: --import-ksk-kmip <server> <public_id> <private_id> <algorithm> <flags>

   Import a KSK from an HSM

.. option:: --import-zsk-kmip <server> <public_id> <private_id> <algorithm> <flags>

   Import a ZSK from an HSM

.. option:: --import-csk-kmip <server> <public_id> <private_id> <algorithm> <flags>

   Import a CSK from an HSM

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).


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
