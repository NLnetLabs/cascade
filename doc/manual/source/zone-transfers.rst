Zone Transfers
==============

Cascade is expected to be deployed between a hidden upstream nameserver and
public downstream nameservers. The hidden upstream serves the unsigned zone,
Cascade signs it, and serves the signed zone to downstream nameservers for publication
to consumers.

Communication of changed zone records from upstream to downstream will
be done via the network using the :RFC:`5936` (AXFR) and :RFC:`1995` (IXFR)
protocols.

Authentication of transferring parties can be done using :RFC:`8945` (TSIG)
keys, using a shared secret communicated out of band to the nameservers
sending and receiving the zone records.

Cascade supports timely discovery of zone changes by sending SOA queries to
the upstream nameserver, either in response to an :RFC:`1996` NOTIFY message or
based on the zone's SOA timers.

.. note:: Cascade also supports loading the zone from a file. However, if
          only a small fraction of the records in the zone change from one
          version to the next, loading the entire file every time the zone
          file changes will require more time, CPU and memory compared to
          processing only the differences when using IXFR. Cascade doesn't
          yet support direct writing of signed zones to a file, though a
          signed zone review hook could be used to AXFR the signed zone to
          a file on disk to achieve this.

Using zone transfers with an upstream nameserver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To instruct Cascade to transfer a zone via the network instead of loading
it from a file you must supply an upstream nameserver IP address when
adding the zone. See :program:`cascade` :subcmd:`zone add`, and optionally
a TSIG key to use to authenticate communication.

Cascade will then attempt to fetch the zone. Where possible it will fetch
newer versions of the zone incrementally, as this is more efficient.

Cascade can be instructed to authenticate the upstream nameserver by use of a
TSIG key. The TSIG key to use must be provided to Cascade _before_ adding the
zone. See :program:`cascade` :subcmd:`tsig add`.

Providing zone transfers to a downstream server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, Cascade allows downstream servers to access published zones by
zone transfer, no configuration is needed.

To restrict the downstream nameservers which may request transfer of the
zone use the ``server.outbound.provide-xfr-to`` policy setting.`

To ensure timely update by secondaries, Cascade can be configured to send
:RFC:`1996` NOTIFY messages to specified secondaries. This is done via the
policy setting ``server.outbound.send-notify-to``, optionally specifying an
:RFC:`8945` TSIG key to use to authenticate communication.

.. tip:: Remember to reload the policy file after changing it. See
         :program:`cascade` :subcmd:`policy reload`.

.. tip:: Use :program:`cascade` :subcmd:`tsig add` to add a TSIG key to
         Cascade _before_ reloading policy file changes.

Zone transfers when using automated key rollover
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using automatic key rollover (the default) Cascade will attempt to verify
that certain key properties of the signed zone being served to consumers are
correct.

This verification is done by transferring the zone and inspecting it. By
default transfer is attempted from the nameserver identified by the MNAME
field of the apex SOA record in the zone.

If an alternate nameserver should be queried instead of the MNAME
nameserver, or if a specific port number or TSIG key should be used
to request the transfer, you will also need to configure the Cascade
key manager to fetch the zone correctly. This can be done via the
``key-manager.publication-nameservers`` policy setting.
