cascade catalog
===============

Synopsis
--------

:program:`cascade` ``[GLOBAL OPTIONS]`` catalog ``<COMMAND>``

:program:`cascade` ``[GLOBAL OPTIONS]`` catalog :subcmd:`add` ``<NAME>`` ``--source <SOURCE>`` ``--default-policy <POLICY>`` ``[--group <GROUP=POLICY[=SOURCE]>]`` ``[--produced-catalog <NAME>]``

:program:`cascade` ``[GLOBAL OPTIONS]`` catalog :subcmd:`list`

:program:`cascade` ``[GLOBAL OPTIONS]`` catalog :subcmd:`reload` ``<NAME>``

:program:`cascade` ``[GLOBAL OPTIONS]`` catalog :subcmd:`remove` ``<NAME>``

Description
-----------

Manage :RFC:`9432` catalog zones. A catalog zone lists a set of *member
zones*. Cascade transfers a registered catalog zone from a primary, and
automatically adds, signs and serves the member zones it lists, removing them
again when they leave the catalog. This allows zones to be added to and
removed from the signer through the catalog zone rather than through direct
configuration.

Member zones are, by default, transferred from the same primary as the
catalog zone, and signed using the catalog's default policy. A member's
``group`` property (RFC 9432) can be used to select a different policy and a
different source for that member.

Member zones managed by a catalog cannot be added, removed or reconfigured
manually; they are managed entirely through their catalog.

Global Options
--------------

See :doc:`cascade` for information about global options supported by every CLI
command.

Commands
--------

.. subcmd:: add

   Register a catalog zone.

   Cascade immediately begins transferring the catalog zone and reconciling
   its membership.

.. subcmd:: list

   List registered catalogs and the member zones each one currently manages.

.. subcmd:: reload

   Trigger an immediate transfer and reconciliation of a catalog.

.. subcmd:: remove

   Remove a catalog and all of the member zones it manages.

Arguments for :subcmd:`catalog add`
-----------------------------------

.. option:: <NAME>

   The apex name of the catalog zone.

.. option:: --source <SOURCE>

   The primary to transfer the catalog zone from, in the form
   ``<IP>[:<PORT>][^<TSIG_KEY_NAME>]`` (the port defaults to 53). Unless
   overridden per group, member zones are transferred from this same primary.

.. option:: --default-policy <POLICY>

   The policy applied to member zones that have no matching group mapping.

.. option:: --group <GROUP=POLICY[=SOURCE]>

   A per-group override. Member zones whose ``group`` property equals
   ``GROUP`` are signed using ``POLICY`` and, if ``SOURCE`` is given,
   transferred from ``SOURCE`` (in the same form as ``--source``) instead of
   the catalog's primary. May be given more than once.

.. option:: --produced-catalog <NAME>

   The apex name of a catalog zone to produce downstream. When set, Cascade
   generates a catalog zone of this name mirroring the members it manages, so
   that downstream secondaries can automatically transfer the signed member
   zones.

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascade-zone**\ (1)
    :doc:`cascade-zone`

**cascade-tsig**\ (1)
    :doc:`cascade-tsig`
