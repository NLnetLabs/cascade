Integrating with NSD
====================

.. epigraph::

   Name Server Daemon (NSD) by NLnet Labs is an authoritative DNS name server.

   -- https://nsd.docs.nlnetlabs.nl/

Using NSD as a primary to Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use NSD as an upstream name server of Cascade is done by adding a zone to
NSD that refers to Cascade as a secondary name server to which NSD will
provide XFR (zone transfers), optionally authenticated using a TSIG key.

For example the following NSD configuration file fragment adds an example.com
zone to NSD that is to be served as input to Cascade.

.. code-block::

   zone:
     name: example.com
	 zonefile: "zonefile.name"
	 notify: 127.0.0.1@4542 NOKEY
	 provide-xfr: 127.0.0.1 NOKEY
	 store-ixfr: yes
 	 create-ixfr: yes

A TSIG key can be used to authenticate the NOTIFY and XFR communications. For
example\:

.. code-block::

  key:
    name: "sec1_key"
    algorithm: hmac-md5
    secret: "6KM6qiKfwfEpamEq72HQdA=="

   zone:
     name: example.com
	 zonefile: "zonefile.name"
	 notify: 127.0.0.1@4542 sec1_key
	 provide-xfr: 127.0.0.1 sec1_key
	 store-ixfr: yes
 	 create-ixfr: yes

See https://nsd.docs.nlnetlabs.nl/en/latest/running/using-tsig.html for more
information.

Using NSD as a secondary to Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO
