cascade tsig
============

.. versionadded:: 0.1.0-beta1

Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig :subcmd:`add` ``[OPTIONS]``

Description
-----------

Manage RFC 8945 TSIG keys for authenticating zone transfers.

Global Options
--------------

See :doc:`cascade` for information about global options supported by every CLI
command.

Commands
--------

.. subcmd:: add

   Register a new TSIG key.

Options for :subcmd:`tsig add`
------------------------------

.. option:: --name <TSIG_KEY_NAME>
.. option:: --name [<ALGORITHM>]:<TSIG_KEY_NAME>:<SECRET>

   The name of the TSIG key to add.

   Alternatively this argument also supports dig syntax for specifying all of
   the TSIG properties at once in colon separated form. The colon separated
   syntax cannot be used in combination with the ``--alg`` and ``--secret``
   options. If ``<ALGORITHM>`` is not specified it defaults to SHA256.

.. option:: --alg <ALGORITHM>

   The TSIG algorithm of the specified TSIG key. Can be one of: hmac-sha1,
   hmac-sha256, hmac-sha384 or hmac-sha512.

.. option:: --secret <SECRET>

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
