Troubleshooting
===============

.. Systemd error: Address already in use... override see quick start
.. Unknown rtype with concrete data ... unsupported rtype in domain



Error: Failed to open zone file '<filename>': No such file or directory
-----------------------------------------------------------------------

Server crashed on non-existent zone file source and now won't start anymore:

Option 1: Remove zone from ``state.db``, remove zone's keys/keystate, remove zone's
zone-state.

Option 2: Update zonefile source path in zone-state file
