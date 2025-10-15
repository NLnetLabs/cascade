Cascade Daemon
==============

Synopsis
--------

:program:`cascaded` ``[OPTIONS]``

Description
-----------

**cascaded** is the daemon process of Cascade, a friendly DNSSEC signing
solution.

For more information about Cascade, please refer to the Cascade documentation
at https://cascade.docs.nlnetlabs.nl.

Options
-------

.. option:: --check-config

          Check the configuration and exit.

.. option:: --state <PATH>

          The global state file to use.

.. option:: -c, --config <PATH>

          The configuration file to load. Defaults to
          ``/etc/cascade/config.toml``.

.. option:: --log-level <LEVEL>

          The minimum severity of messages to log [possible values: trace,
          debug, info, warning, error, critical].

          Defaults to ``info``, unless set in the config file.

.. option:: -l, --log <TARGET>

          Where logs should be written to [possible values: stdout, stderr,
          file:<PATH>, syslog].

          .. versionadded:: 0.1.0-alpha2
             Added types `stdout` and `stderr`. Type `file` with values
             `/dev/stdout` and `/dev/stderr` can still be used but may not
             work properly in some cases, e.g. when running under systemd.

.. option:: -d, --daemonize

          Whether Cascade should fork on startup.

.. option:: -h, --help

          Print the help text (short summary with ``-h``, long help with
          ``--help``).

.. option:: -V, --version

          Print version.

Files
-----

/etc/cascade/config.toml
    Default Cascade config file

/etc/cascade/policies
    Default policies directory

/var/lib/cascade/zone-state
    Default zone state directory

/var/lib/cascade/tsig-keys.db
    Default file for stored TSIG keys

/var/lib/cascade/keys
    Default directory for on-disk zone keys

/usr/libexec/cascade/cascade-dnst
    Default (Cascade-specific) dnst binary for use by Cascade

/var/lib/cascade/kmip/credentials.db
    Default file for KMIP credentials

/var/lib/cascade/kmip
    Default directory for KMIP state files

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascaded-config.toml**\ (5)
    :doc:`cascaded-config.toml`

**cascaded-policy.toml**\ (5)
    :doc:`cascaded-policy.toml`
