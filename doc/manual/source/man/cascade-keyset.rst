cascade keyset
==============

Synopsis
--------

.. :program:`cascade keyset` ``[OPTIONS]`` ``<ZONE>`` ``<ROLL TYPE>`` ``<ROLL COMMAND>`` ``[OPTIONS]``

:program:`cascade keyset` ``[OPTIONS]`` ``<ZONE>`` :subcmd:`ksk|zsk|csk|algorithm` ``<ROLL COMMAND>`` ``[OPTIONS]``

.. :program:`cascade keyset` ``[OPTIONS]`` ``<ZONE>`` ``<COMMAND>`` ``[OPTIONS]``

:program:`cascade keyset` ``[OPTIONS]`` ``<ZONE>`` :subcmd:`remove-key` ``[OPTIONS]`` ``<KEY>``

:program:`cascade keyset` ``[OPTIONS]`` ``<ZONE>`` :subcmd:`get` ``[RR]``

Description
-----------

Execute manual key roll or key removal commands.

Options
-------

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

Commands
--------

.. subcmd:: ksk

   Command for KSK rolls.

.. subcmd:: zsk

   Command for ZSK rolls.

.. subcmd:: csk

   Command for CSK rolls.

.. subcmd:: algorithm

   Command for algorithm rolls.

.. subcmd:: remove-key

   Remove a key from the key set.

.. subcmd:: get

   Get the key or keys for a zone as DS, DNSKEY, or CDS RRsets.


Key roll commands for :subcmd:`ksk|zsk|csk|algorithm`
-----------------------------------------------------


.. subcmd:: start-roll

   Start a key roll.

.. subcmd:: propagation1-complete <TTL>

   Inform keyset that the changed RRsets and signatures have propagated.

   TTL is the maximum TTL of the zone.

.. subcmd:: cache-expired1

   Inform keyset that enough time has passed that caches should have expired.

.. subcmd:: propagation2-complete <TTL>

   Inform keyset that the changed RRsets and signatures have propagated.

   TTL is the maximum TTL of the zone.

.. subcmd:: cache-expired2

   Inform keyset that enough time has passed that caches should have expired.

.. subcmd:: roll-done

   Report that the final changes have propagated and the roll is done


Arguments for :subcmd:`keyset remove-key`
-----------------------------------------

.. option:: <KEY>

   The key to remove. This is the key's URI as reported by ``cascade zone
   status``.

Options for :subcmd:`keyset remove-key`
---------------------------------------

.. option:: --force

    Force a key to be removed even if the key is not stale.

.. option:: --continue

    Continue when removing the underlying keys fails.


Arguments for :subcmd:`keyset get`
-----------------------------------------

.. option:: [RR]

   The RRset to print. ``ds``, ``dnskey``, or ``cds``.

   The CDS RRset includes the CDNSKEY RRset and signatures.

   .. note:: The DS and CDS RRset is only available during the appropriate
       step of a key roll. So, if the output is empty, check the zone's key
       roll status to see if it may still be waiting for propagation of e.g.
       the new DNSKEY. If you need the DS RRset even if cascade is still
       waiting for propagation, you can use ``cascade keyset <zone> get
       dnskey | dnst key2ds -n /dev/stdin``.


See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascaded**\ (1)
    :doc:`cascaded`

**cascade-dnst-keyset**\ (1)
    Further documentation of the key roll commands (and more)
