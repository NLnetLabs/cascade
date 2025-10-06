Cascade CLI
===========

Synopsis
--------

:program:`cascade` ``[OPTIONS]`` ``<COMMAND>``

Description
-----------

**cascade** is the CLI to the :doc:`cascaded`.

Options
-------

.. option:: -s, --server <IP:PORT>

   The cascade server instance to connect to [default: 127.0.0.1:4539].

.. option:: --log-level <LEVEL>

   The minimum severity of messages to log [default: warning] [possible values:
   trace, debug, info, warning, error, critical].

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

.. option:: -V, --version

   Print version.


Commands
--------

.. only:: html or latex or epub

    .. glossary::

        :doc:`cascade-config <cascade-config>`\ (1)

          Manage Cascade's configuration.

        :doc:`cascade-zone <cascade-zone>`\ (1)

          Manage zones.

        :doc:`cascade-policy <cascade-policy>`\ (1)

          Manage policies.

        :doc:`cascade-keyset <cascade-keyset>`\ (1)

          Execute manual key roll or key removal commands.

        :doc:`cascade-hsm <cascade-hsm>`\ (1)

          Manage HSMs.

        :doc:`cascade-template <cascade-template>`\ (1)

          Print example config or policy files.

.. only:: man or text

    **cascade-config**\ (1)
        Manage Cascade's configuration.

    **cascade-zone**\ (1)
        Manage zones.

    **cascade-policy**\ (1)
        Manage policies.

    **cascade-keyset**\ (1)
        Execute manual key roll or key removal commands.

    **cascade-hsm**\ (1)
        Manage HSMs.

    **cascade-template**\ (1)
        Print example config or policy files.

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascaded**\ (1)
    :doc:`cascaded`

**cascaded-config.toml**\ (5)
    :doc:`cascaded-config.toml`

**cascaded-policy.toml**\ (5)
    :doc:`cascaded-policy.toml`
