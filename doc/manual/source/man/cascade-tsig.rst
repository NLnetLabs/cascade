cascade tsig
============

.. versionadded:: 0.1.0-beta1

Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` tsig :subcmd:`add` ``<PATH>``

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

.. option:: <PATH>

   Path to the file containing the TSIG key.

   The file format is specified by ``--format``.

   Regardless of the file format the file must contain all the following
   values exactly once.

   The name of the key to add, TSIG key names must be valid domain names.

   The algorithm of the specified TSIG key. Can be one of: ``hmac-sha1``,
   ``hmac-sha256``, ``hmac-sha384`` or ``hmac-sha512``.

   The secret key material must be the correct length for the specified algorithm
   and must be encoded using the :RFC:`4648` Base64 encoding.

.. option:: --format <FORMAT>

   Format used in the TSIG file.

   The **NSD** and **Knot** formats are not parsed with full YAML compliance.

   Possible values:

   - **nsd**:  `NSD TSIG Documentation`_
   - **bind**: `BIND TSIG Documentation`_
   - **knot**: `Knot TSIG Documentation`_

   [default: nsd]

   .. _NSD TSIG Documentation: https://nsd.docs.nlnetlabs.nl/en/latest/running/using-tsig.html
   .. _BIND TSIG Documentation: https://bind9.readthedocs.io/en/stable/reference.html#namedconf-statement-key
   .. _Knot TSIG Documentation: https://www.knot-dns.cz/docs/latest/html/reference.html#key-section

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
