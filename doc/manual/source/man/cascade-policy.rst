cascade policy
==============

Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` policy ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` policy :subcmd:`list`

:program:`cascade` ``[GLOBAL OPTIONS]`` policy :subcmd:`show` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` policy :subcmd:`reload`

Description
-----------

Manage Cascade's policies.

Global Options
--------------

See :doc:`cascade` for information about global options supported by every CLI
command.

Commands
--------

.. subcmd:: list

   List registered policies.

.. subcmd:: show

   Show the settings contained in a policy.

.. subcmd:: reload

   Reload all the policies from the files.


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
