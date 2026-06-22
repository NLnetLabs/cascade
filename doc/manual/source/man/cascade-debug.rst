cascade debug
=============

.. versionadded:: 0.1.0-beta1
.. 
Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` debug ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` debug :subcmd:`change-logging` ``[OPTIONS]``

Description
-----------

Debug / troubleshoot Cascade.  The sub-commands here are tools for analyzing
Cascade when lower-level problems occur.  It should be combined with analysis of
Cascade's log files.

Global Options
--------------

See :doc:`cascade` for information about global options supported by every CLI
command.

Commands
--------

.. subcmd:: change-logging

   Change how Cascade logs information.

   The location where logs are written to cannot be changed; but the information
   being logged can be changed.

Options for :subcmd:`debug change-logging`
------------------------------------------

.. option:: -l, --level <LEVEL>

   Change the log level.  Possible values: trace, debug, info, warning, error,
   critical

.. option:: --trace-targets <TARGETS>

   Select internal Cascade modules to selectively log trace-level information
   for.  The names of such modules can be found in the log files.  All other
   modules will continue using the log level.

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
