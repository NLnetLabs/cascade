cascade policy
==============

Synopsis
--------

:program:`cascade policy` ``[OPTIONS]`` ``<COMMAND>``

:program:`cascade policy` ``[OPTIONS]`` :subcmd:`list`

:program:`cascade policy` ``[OPTIONS]`` :subcmd:`show` ``<NAME>``

:program:`cascade policy` ``[OPTIONS]`` :subcmd:`reload`

Description
-----------

Manage Cascade's policies.

Options
-------

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

Commands
--------

.. subcmd:: list

   List registered policies

.. subcmd:: show

   Show the settings contained in a policy

.. subcmd:: reload

   Reload all the policies from the files


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
