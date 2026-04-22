Integrating with NSD
====================

.. epigraph::

   Name Server Daemon (NSD) by NLnet Labs is an authoritative DNS name server.

   -- https://nsd.docs.nlnetlabs.nl/

Suggested reading
~~~~~~~~~~~~~~~~~

The :ref:`Zone Transfers <zone-transfers.rst>` page explains the general
functionality in Cascade that is referred to below.

Using NSD as a primary to Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use NSD as an upstream name server of Cascade you must add a zone to NSD
that refers to Cascade as a secondary name server. If enabled in NSD, NSD will
send an :RFC:`1996` DNS NOTIFY message to Cascade notifying it when changes to
the zone occur.

The NOTIFY message will trigger Cascade to perform an AXFR transfer to fetch
the full zone content from NSD, or, if already fetched and IXFR is enabled in
NSD, an IXFR transfer will be performed to fetch just the incremental changes
since the last fetch.

If NOTIFY is NOT enabled in NSD, Cascade will monitor NSD for a newer version
of the zone by periodically sending SOA queries according to the number of
seconds defined by the REFRESH field of the zone apex SOA record.

Optionally NSD and Cascade can be configured with the same TSIG key to
authenticate the NOTIFY and XFR messages.

The NSD settings relevant here are:
  - `notify <https://nsd.docs.nlnetlabs.nl/en/latest/manpages/nsd.conf.html#notify>`_
  - `provide-xfr <https://nsd.docs.nlnetlabs.nl/en/latest/manpages/nsd.conf.html#provide>`_

For example the following NSD configuration file fragment adds an
``example.com`` zone to NSD that is to be served as input to a Cascade daemon
running on host 192.168.0.2 listening on the default port 4542:

.. code-block::

   zone:
     name: example.com
	 zonefile: "zonefile.name"
	 notify: 192.168.0.2@4542 NOKEY
	 provide-xfr: 192.168.0.2 NOKEY
	 store-ixfr: yes
 	 create-ixfr: yes

A TSIG key can be used to authenticate the NOTIFY and XFR communications. For
example\:

.. code-block::

  key:
    name: "sec1_key"
    algorithm: hmac-sha256
    secret: "..."

   zone:
     name: example.com
	 zonefile: "zonefile.name"
	 notify: 192.168.0.2@4542 sec1_key
	 provide-xfr: 192.168.0.2 sec1_key
	 store-ixfr: yes
 	 create-ixfr: yes

See https://nsd.docs.nlnetlabs.nl/en/latest/running/using-tsig.html for more
information.

.. tip:: Remember to reload the NSD configuration or restart NSD so that
         changes to the configuration take effect.

Adding the TSIG key to Cascade is done using the ``cascade tsig add`` CLI
command, e.g. like so:

.. code-block:: bash

   $ cascade tsig add --name sec1_key --alg hmac-sha256 --secret "...=="

To use the new TSIG key it must be specified when adding a zone to
Cascade. Assuming that NSD is running on host 192.168.0.1 on port 53,
the following command instructs Cascade to add the ``example.com``
zone sourced from the NSD server using the ``sec1_key`` TSIG key to
authenticate with NSD:

.. code-block:: bash

   $ cascade zone add --source 192.168.0.1^sec1_key --policy default example.com

Using NSD as a secondary to Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO
