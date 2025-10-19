kmip2pkcs11 Daemon
==================

Synopsis
--------

:program:`kmip2pkcs11` ``[OPTIONS]``

Description
-----------

**kmip2pkcs11** is the Cascade KMIP to PKCS#11 bridge required for Cascade to
access PKCS#11 compatible HSMs, contrary to KMIP HSMs which Cascade supports
natively.

For more information about Cascade, please refer to the Cascade documentation
at https://cascade.docs.nlnetlabs.nl.

Options
-------

.. option:: -c, --config <PATH>

          The configuration file to load. Defaults to
          ``/etc/kmip2pkcs11/config.toml``.

.. option:: --d, --detach

          Detach from terminal; default is to remain in
          foreground
          
.. option:: -V, --version

          Print version.


.. option:: -v, --verbose

          Log more information, twice for even more

.. option:: -q, --quiet

          Log less information, twice for no information

.. option:: --stderr

          Log to stderr

.. option:: --syslog

          Log to syslog

.. option:: --syslog-facility <FACILITY>

          Facility to use for syslog logging. Possible values: :program:`kern`,
          :program:`user`, :program:`mail`, :program:`daemon`, :program:`auth`,
          :program:`syslog`, :program:`lpr`, :program:`news`, :program:`uucp`,
          :program:`cron`, :program:`authpriv`, :program:`ftp`,
          :program:`local0`, :program:`local1`, :program:`local2`,
          :program:`local3`, :program:`local4`, :program:`local5`,
          :program:`local6`, :program:`local7`

.. option:: --logfile <PATH>

          File to log to

.. option:: --working-dir <PATH>

          The working directory of the daemon process

.. option:: --chroot <PATH>

          Root directory for the daemon process

.. option:: --user <UID>

          User for the daemon process

.. option:: --group <GID>

          Group for the daemon process

.. option:: -h, --help

          Print the help text (short summary with ``-h``, long help with
          ``--help``).

Files
-----

/etc/kmip2pkcs11/config.toml
    Default kmip2pkcs11 config file

/var/lib/cascade/kmip/kmip2pkcs11
    Configured PKCS#11 backends

/var/lib/cascade/kmip/credentials.db
    Default credentials for the PKCS#11 HSMs

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

