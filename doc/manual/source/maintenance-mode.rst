Maintenance Mode
================

By default, Cascade will automatically reload and resign the zone when
necessary, but sometimes you might need a bit more control over that process.
That is what "maintenance mode" is for. It blocks any operations on the zone,
allowing the operator to inspect what's going wrong.

Maintenance mode works per zone, allowing you to take control over a particular
zone while the rest of the zones will be updated normally.

.. note::

	Maintenance mode is a work in progress. We plan on allowing triggering certain
	operations manually via the CLI while maintenance mode is enabled in the future.


Toggling Maintenance Mode
-------------------------

Maintenance mode for a zone can be enabled from the CLI with the following
command:

.. code-block:: bash

	cascade zone maintenance enable <zone-name>

It can similarly be disabled with:


.. code-block:: bash

	cascade zone maintenance disabled <zone-name>

You can check whether a zone is in maintenance mode by looking at the ``zone status``
of the zone in question. If it is in maintenance mode, then a warning will be shown
at the bottom:

.. code-block::

	WARNING: This zone is in maintenance mode
	  Cascade will not automatically start new loading and signing operations
	  Run `cascade zone maintenance disable <zone-name>` to resume normal operation
