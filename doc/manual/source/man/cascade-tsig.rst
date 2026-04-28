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

Manage :RFC:`8945` (TSIG) keys for authenticating zone transfer (AXFR, IXFR) and
related messages (SOA and NOTIFY).

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

   Add a new TSIG key.

   Incoming DNS messages that are TSIG signed will be rejected if the key used
   to sign the message is not registered with Cascade.

.. subcmd:: list

   List registered TSIG keys.

.. subcmd:: remove

   Remove a TSIG key.

   .. note:: Returns an error if the key does not exist in the TSIG key store,
             or if the key is still referenced by other configuration.

Arguments for :subcmd:`tsig add`
--------------------------------

.. option:: <TSIG_KEY_NAME>
.. option:: [<ALGORITHM>]:<TSIG_KEY_NAME>:<SECRET>

   The name of the TSIG key to add, or a complete TSIG key specification.

   TSIG key names must be valid domain names.

   A complete TSIG key specification consists of an optional algorithm
   (default ``hmac-sha256``), a key name and the secret key material. When a
   complete TSIG key specification is supplied, supplying the ``<ALGORITHM>``
   and ``<SECRET>`` arguments as well will result in an error.

   Secret key material must be the correct length for the specified algorithm
   and must be encoded using the :RFC:`4648` Base64 encoding.

   .. warning:: Secret key material supplied via a command-line argument may
                be visible to other processes running on the same computer as
                the Cascade CLI.

.. option:: <ALGORITHM>

   The TSIG algorithm of the specified TSIG key. Can be one of: ``hmac-sha1``,
   ``hmac-sha256``, ``hmac-sha384`` or ``hmac-sha512``.

.. option:: <SECRET>

   :RFC:`4648` Base64 encoded secret key material. The number of bytes prior
   to encoding must be correct for the specified ``<ALGORITHM>``.

   Can also be a path to a file containing the Base64 encoded secret material.

   .. note:: Secret key material supplied via a command-line argument may be
             visible to other processes running on the same computer as the
             Cascade CLI. Consider supplying a file name instead.

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
