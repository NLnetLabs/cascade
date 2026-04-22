Zone Transfers
==============

Cascade is designed to be deployed between a hidden upstream nameserver and
public downstream nameservers. The hidden upstream serves the unsigned zone,
Cascade signs it, and passes it to the downstream nameservers for publication
to consumers.

Communication of changed zone records from upstream to downstream should
be done via the network using the :RFC:`5936` (AXFR) and :RFC:`1995` (IXFR)
protocols.

Securing the transferred data can be done using :RFC:`8945` (TSIG) keys,
using a shared secret communicated out of band to the nameservers sending and
receiving the zone records.

Cascade supports timely discovery of zone changes via :RFC:`1996` (NOTIFY).
If no NOTIFY message is received by Cascade, Cascade will instead discover
new versions of the zone by sending SOA queries periodically to the upstream,
the frequency of which is determined by the timers on the zone's SOA record.

.. note:: Cascade also supports loading the zone from a file. However, if only
          a small fraction of the records in the zone change from one version
          to the next, loading the entire zone every time the zone changes
          will require more time, CPU and memory compared to processing
          only the differences when using IXFR. Additionally, Cascade has no
          built-in support for writing signed zone files to disk, if needed
          this could be done by a signed review hook.

Using zone transfers with an upstream nameserver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To instruct Cascade to transfer a zone via the network instead of loading
it from a file you must supply an upstream nameserver name or address when
adding the zone.

.. code-block:: bash

   $ cascade zone add --source <IP_OR_NAME>[:<PORT>] ...

Cascade will then attempt to fetch the zone from the specified name or IP
address using AXFR. Subsequent fetches will attempt to use IXFR to transfer
only the differences, falling back to AXFR when needed. Subsequent fetches
will be triggered by NOTIFY messages received from the upstream nameserver or
expiry of the SOA REFRESH or RETRY timers.

Securing zone transfers with an upstream nameserver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cascade can be instructed to authenticate the upstream nameserver by use of
a TSIG key. The TSIG key to use must be provided to Cascade _before_ adding
the zone:

.. code-block:: bash

   $ cascade tsig add <TSIG KEY NAME, ALGORITHM AND SECRET BYTES>

When adding a zone the TSIG key name can then be referred to like so:

.. code-block:: bash

   $ cascade zone add --source <IP>[:<PORT>]^<TSIG KEY NAME>

Using zone transfers with a downstream server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Cascade permits zone transfers by default, no configuration is required.

To ensure timely update by secondaries, Cascade can be configured to send
:RFC:`1996` (NOTIFY) messages to specified secondaries. This is done via the
policy setting ``server.outbound.send-notify-to``.

.. note:: The policy file will need to be reloaded via ``cascade policy
          reload`` before adding the zone. Also, when adding the zone you
          will need to pass the `--policy` argument specifying the relevant
          policy to apply to the zone.

.. tip:: If a TSIG key has been added to Cascade via ``cascade tsig add``,
         you can instruct Cascade to authentiate itself to downstreams
         using a specified TSIG key by adding `^<TSIG_KEY_NAME>` to the
         ``server.outbound.send-notify-to`` value.

Controlling automatic key rollover zone transfer settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
