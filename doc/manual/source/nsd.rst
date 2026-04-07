Integrating with NSD
====================

.. epigraph::

   Name Server Daemon (NSD) by NLnet Labs is an authoritative DNS name server.

   -- https://nsd.docs.nlnetlabs.nl/

Using NSD as a primary to Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use NSD as an upstream name server of Cascade you must add a zone to
NSD that refers to Cascade as a secondary name server so that NSD will send
a NOTIFY message to Cascade when the zone changes and will allow Cascade to
make an XFR request to receive the update zone. Optionally NSD and Cascade
can be configured with the same TSIG key to authenticate the NOTIFY and XFR
messages.

For example the following NSD configuration file fragment adds an example.com
zone to NSD that is to be served as input to a Cascade daemon running on host
192.168.0.2 listening on the default port 4542:

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
    secret: "...=="

   zone:
     name: example.com
	 zonefile: "zonefile.name"
	 notify: 192.168.0.2@4542 sec1_key
	 provide-xfr: 192.168.0.2 sec1_key
	 store-ixfr: yes
 	 create-ixfr: yes

See https://nsd.docs.nlnetlabs.nl/en/latest/running/using-tsig.html for more
information.

Adding the TSIG key to Cascade is done using the ``cascade tsig add`` CLI
command, e.g. like so:

.. code-block:: bash

   $ cascade tsig add --name sec1_key --alg hmac-sha256 --secret "...=="

And then instructing Cascade to use the TSIG key when adding the zone, assuming
that the NSD daemon is running on host 192.168.0.1 on port 53:

.. code-block:: bash

   $ cascade zone add --source 192.168.0.1^sec1_key --policy default example.com

Using NSD as a secondary to Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TODO
