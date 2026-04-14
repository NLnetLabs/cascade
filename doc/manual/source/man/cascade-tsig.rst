cascade tsig
============

.. versionadded:: 0.1.0-beta1

Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig :subcmd:`add` ``<TSIG_KEY_NAME>`` ``<ALGORITHM>`` ``<SECRET>``

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig :subcmd:`list`

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig :subcmd:`remove` ``<TSIG_KEY_NAME>``

Description
-----------

Manage RFC 8945 TSIG keys for authenticating zone transfers.

.. tip:: Cascade isn't currently able to generate TSIG keys itself.
         One way to generate a TSIG key is to use the `tsig-keygen
         <https://bind9.readthedocs.io/en/latest/manpages.html#tsig-keygen-tsi
         g-key-generation-tool>`_ tool from the ISC BIND project.

Global Options
--------------

See :doc:`cascade` for information about global options supported by every CLI
command.

Commands
--------

.. subcmd:: add

   Register a new TSIG key.

.. subcmd:: list

   List registered TSIG keys and the zones that use them.

.. subcmd:: remove

   Remove a registered TSIG key.

   .. note:: Returns an error if the key does not exist in the TSIG key store
             or if any zone exists that is configured to authenticate with an
			 upstream source using the specified TSIG key.

Arguments for :subcmd:`tsig add`
--------------------------------

.. option:: <TSIG_KEY_NAME>

   The name of the TSIG key to add.

   Alternatively this argument also supports dig syntax for specifying all of
   the TSIG properties at once in colon separated form. The colon separated
   syntax cannot be used in combination with the ``--alg`` and ``--secret``
   options. If ``<ALGORITHM>`` is not specified it defaults to SHA256.

.. option:: <ALGORITHM>

   The TSIG algorithm of the specified TSIG key. Can be one of: hmac-sha1,
   hmac-sha256, hmac-sha384 or hmac-sha512.

.. option:: <SECRET>

   A base64 encoded string defining the actual TSIG key material bytes.

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
