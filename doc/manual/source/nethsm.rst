Integrating with a Nitrokey NetHSM
==================================

.. Note:: The instructions on this page are for a Debian 12 host and assume
   that Cascade has already been installed using our DEB package, and that
   Docker is installed and can run the NetHSM container.

.. Note:: The instructions on this page assume you will be using the NetHSM
   exclusively for the task at hand and for testing. Using the provided
   test image is in no way suggested for production. Please study the
   product documentation to find out how to do so.

.. Note:: Most instructions on this page assume you will be working as a
   normal, i.e. non-``root``, user.

.. epigraph::

   NetHSM is an open hardware security module created and distributed by
   Nitrokey. It's a secure store for cryptographic keys powered by
   open source, which enables people to verify exactly how it works.
   The HSM is accessible through a REST interface, and a PKCS #11 shared object
   interfaces that with Cascade's :program:`kmip2pkcs11`. The software is also
   provided as an OCI image (used here for demonstration purposes) which can be
   used with Docker or Podman for experimentation without having to purchase
   the device proper.

   -- https://www.nitrokey.com/products/nethsm


Launch the NetHSM container
~~~~~~~~~~~~~~~~~~~~~~~~~~~

We launch the container to be removed on exit which means all settings and keys
will be wiped when the container is stopped.

.. code-block:: bash

   $ docker run --rm -ti -p 127.0.0.1:8443:8443 docker.io/nitrokey/nethsm:testing

Install the Prerequisites
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ sudo apt install -y opensc opensc-pkcs11 pipx
   $ pipx install pynitrokey    # for the nitropy utility
   $ pipx ensurepath
   $ source ~/.bashrc
   $ export NETPKCS="/usr/lib/x86_64-linux-gnu/nethsm-pkcs11.so"

We download and install the NetHSM PKCS#11 driver to a somewhat shorter name;
``$NETPKCS`` will help us keep command-lines short in this documentation.

.. code-block:: bash

    $ wget https://github.com/Nitrokey/nethsm-pkcs11/releases/download/v1.7.2/nethsm-pkcs11-v1.7.2-x86_64-linux-glibc.so
    $ sudo install nethsm-pkcs11-v1.7.2-x86_64-linux-glibc.so $NETPKCS

Configure the NetHSM PKCS#11 driver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We then configure the driver, in the file ``/etc/nitrokey/p11nethsm.conf``,
paying attention to the URI, usernames, and passwords.  as per `NetHSM's
PKCS#11 Setup documentation <https://docs.nitrokey.com/nethsm/pkcs11-setup>`_

.. code-block:: text

    enable_set_attribute_value: false
    log_level: Debug
    syslog_facility: "user"

    slots:
      - label: LocalHSM                        # Name your NetHSM however you want
        description: Local HSM (docker)        # Optional description
        operator:
          username: "jj01"
          password: "blab123456"
        administrator:
          username: "admin18"
          password: "secret9999"

        instances:
          - url: "https://127.0.0.1:8443/api/v1"   # URL to reach the server
            max_idle_connections: 10
            danger_insecure_cert: false
        retries:
          count: 3
          delay_seconds: 1
        tcp_keepalive:
          time_seconds: 600
          interval_seconds: 60
          retries: 3
        connections_max_idle_duration: 1800
        timeout_seconds: 10

Provision the HSM
~~~~~~~~~~~~~~~~~

Configure access to the NetHSM, ensuring IP address and port number match those
of the container running the HSM. We show passwords in clear below so as to be
able to demonstrate where they are later used. Please and obviously don't use
these. As we haven't `configured a TLS key and certificate for the device
<https://docs.nitrokey.com/nethsm/administration#tls-certificate>`_ we
disable TLS verification on the connection (not recommended).

.. code-block:: bash

   $ export NETHSM_HOST=127.0.0.1:8443

   $ nitropy nethsm --no-verify-tls provision
   Command line tool to interact with Nitrokey devices 0.11.2
   Unlock passphrase: nlnetlabs001
   Repeat for confirmation:
   Admin passphrase: lecascadeur
   Repeat for confirmation:
   Warning: The unlock passphrase cannot be reset without knowing the current value...
   NetHSM 127.0.0.1:8443 provisioned


Configure NetHSM's TLS certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These steps are optional and probably not worth doing for the ephemeral HSM
test container which will have its data destroyed when it's stopped. You must
then remember to add ``--no-verify-tls`` to all subsequent :program:`nitropy`
commands. However, when running on a productive NetHSM, and since we are
actually talking to an HSM we should endeavour to communicate securely.

Generate a certificate signing request on the NetHSM. (Until our certificate is
added to the NetHSM we must disable TLS certificate verification.)

.. code-block:: bash

   $ nitropy nethsm --no-verify-tls csr \
         --api \
         --country="NL" \
         --state-or-province="North Holland" \
         --locality="Amsterdam" \
         --organization="NLnet Labs" \
         --organizational-unit="Cascade" \
         --common-name="nethsm.example.net" \
         --email-address="info@example.net"
   Command line tool to interact with Nitrokey devices 0.11.2
   [auth] User name for NetHSM 127.0.0.1:8443: admin
   [auth] Password for user admin on NetHSM 127.0.0.1:8443: lecascadeur
   -----BEGIN CERTIFICATE REQUEST-----
   MIIBjDCCATECAQAwgZ4xGzAZBgNVBAMMEm5ldGhzbS5leGFtcGxlLm5ldDELMAkG
   ...
   aRRIYefZ9EB/6NoULVJjTQ==
   -----END CERTIFICATE REQUEST-----

Have the certificate signed by a Certification Authority (CA) and verify the
certificate is what we expect. (Not shown here, but our CA has added SANs for
the IP address(es) of the device.)

.. code-block:: bash

   $ openssl x509 -in nethsm1.crt -noout -subject
   subject= /CN=nethsm.example.net/C=NL/L=Amsterdam/ST=North Holland/O=NLnet Labs/OU=Cascade/emailAddress=info@example.net

Overwrite the device's self-signed certificate with that which we received from
the CA, in PEM format.

.. code-block:: bash

   $ nitropy nethsm --no-verify-tls  set-certificate --api /tmp/nethsm1.crt
   Command line tool to interact with Nitrokey devices 0.11.2
   [auth] User name for NetHSM 127.0.0.1:8443: admin
   [auth] Password for user admin on NetHSM 127.0.0.1:8443: lecascadeur
   Updated the API certificate for NetHSM 127.0.0.1:8443

Verify a connection to the NetHSM can be validated by our CA certificate by
specifying the ``--ca-certs`` option to :program:`nitropy`

.. code-block:: bash

   $ nitropy nethsm --ca-certs ca.crt info
   Command line tool to interact with Nitrokey devices 0.11.2
   Host:    127.0.0.1:8443
   Vendor:  Nitrokey GmbH
   Product: NetHSM

Install our CA certificate on the system. This certificate bundle (store) will
typically be used by programs on our host.

.. code-block:: bash

   $ sudo mkdir /usr/local/share/ca-certificates/nethsm-ca
   $ sudo install -m444 ca.crt /usr/local/share/ca-certificates/nethsm-ca
   $ sudo update-ca-certificates

Sadly Python uses a distinct certificate store, and becasue :program:`nitropy`
is written in Python, we determine which file Python will search for
certificates and add ours to that. (If :program:`nitropy` was install with
:program:`pipx`, the path to :program:`python3` will likely be
``~/.local/pipx/venvs/pynitrokey/bin/python``.)

.. code-block:: bash

   $ python3
   >>> import certifi
   >>> print(certifi.where())
   /etc/ssl/certs/ca-certificates.crt

   $ sudo tee -a /etc/ssl/certs/ca-certificates.crt < ca.crt

We can now access the NetHSM with a verified TLS connection and need neither
disable verification (``--no-verify-tls``) nor always use the ``--ca-certs``
option.

.. code-block:: bash

   $ nitropy nethsm info
   Command line tool to interact with Nitrokey devices 0.11.2
   Host:    127.0.0.1:8443
   Vendor:  Nitrokey GmbH
   Product: NetHSM


Add a dedicated user
~~~~~~~~~~~~~~~~~~~~

We add a dedicated user with which Cascade's :program:`kmip2pkcs11` will
connect to and interact with the NetHSM. (It is possible to have other programs
use the same HSM with distinct usernames.)

.. code-block:: bash

   $ nitropy nethsm add-user \
       --real-name "Jane Jolie" \
       --role Operator \
       --user-id jj01 \
       --passphrase blab123456
    Command line tool to interact with Nitrokey devices 0.11.2
    [auth] User name for NetHSM 127.0.0.1:8443: admin
    [auth] Password for user admin on NetHSM 127.0.0.1:8443: lecascadeur
    User jj01 added to NetHSM 127.0.0.1:8443

Verify NetHSM is accessible and show its slots
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The NetHSM should now be configured and we can attempt to access it via its
PKCS#11 interface. (If logging has been configured for the driver, the following
command will cause logs to be written.)

.. code-block:: bash

   $ pkcs11-tool --module $NETPKCS --show-info
   Cryptoki version 3.1
   Manufacturer     Nitrokey
   Library          Nitrokey NetHsm PKCS#11 library (ver 1.7)
   Using slot 0 with a present token (0x0)

   $ pkcs11-tool --module $NETPKCS --list-slots
   Available slots:
   Slot 0 (0x0): NetHSM
     token label        : LocalHSM
     token manufacturer : Nitrokey GmbH
     token model        : NetHSM
     token flags        : rng, token initialized, PIN initialized
     hardware version   : 0.1
     firmware version   : 3.1
     serial num         : 0000000000
     pin min/max        : 0/0
   Slot 1 (0x1): NetHSM
     token label        : LocalHSM
     token manufacturer : Nitrokey GmbH
     token model        : NetHSM
     token flags        : rng, token initialized, PIN initialized
     hardware version   : 0.1
     firmware version   : 3.1
     serial num         : 0000000000
     pin min/max        : 0/0

List the HSM's mechanisms
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   $ pkcs11-tool --module $NETPKCS --list-mechanisms
   Using slot 0 with a present token (0x0)
   Supported mechanisms:
     AES-CBC, keySize={128,256}, hw, encrypt, decrypt, generate
     RSA-X-509, keySize={1024,8192}, hw, decrypt
     RSA-PKCS, keySize={1024,8192}, hw, decrypt, sign, generate_key_pair
     SHA1-RSA-PKCS, keySize={1024,8192}, hw, decrypt, sign, generate_key_pair
     SHA224-RSA-PKCS, keySize={1024,8192}, hw, decrypt, sign, generate_key_pair
     SHA256-RSA-PKCS, keySize={1024,8192}, hw, decrypt, sign, generate_key_pair
    ...


Configure :program:`kmip2pkcs11`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:program:`kmip2pkcs11` needs to know where to find the NetHSM PKCS#11
module. As PKCS#11 modules are loaded into a host application, any
access to resources needed by the PKCS#11 module must be granted to
the host application.

.. code-block:: bash

   # sed -i -e 's|^lib_path = .\+|lib_path = "/usr/lib/x86_64-linux-gnu/nethsm-pkcs11.so"|' /etc/kmip2pkcs11/config.toml
   # systemctl start kmip2pkcs11

Create a Cascade Policy that uses your HSM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a Cascade policy called ``nethsm`` and set it to use the HSM
called ``kmip2pkcs11`` we configured earlier.

.. code-block:: bash

   # cascade template policy | tee /etc/cascade/policies/nethsm.toml
   # sed -i -e 's|^#hsm-server-id = .\+|hsm-server-id = "kmip2pkcs11"|' /etc/cascade/policies/nethsm.toml

Start the Cascade daemon:

.. code-block:: bash

   # systemctl start cascaded
   # cascade policy reload
   Policies reloaded:
   - nethsm added


Configure a HSM in Cascade called ``kmip2pkcs11`` that will connect to the
locally running :program:`kmip2pkcs11` daemon. The ``username`` is the slot
identifier we found in our NetHSM earlier, and the ``password`` anything --
it isn't actually used here, as the username/password with which we'll connect
to the NetHSM has been configured in ``p11nethsm.conf`` above.

.. code-block:: bash

   # cascade hsm add --insecure --username 0 --password "123456" kmip2pkcs11 127.0.0.1
   Added KMIP server 'kmip2pkcs11 0.1.0-alpha using PKCS#11 token with label LocalHSM in slot NetHSM via library nethsm-pkcs11.so'

Sign a Test Zone with NetHSM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a test zone to load and sign and ensure the Cascade daemon has access to it:

.. code-block:: bash

   # mkdir /etc/cascade/zones
   # cat > /etc/cascade/zones/example.net << EOF
   example.net.    3600    IN      SOA     ns.example.net. username.example.net. 1 86400 7200 2419200 300
   example.net.            IN      NS      ns
   ns                      IN      A       192.0.2.1
   EOF
   # chown -R cascade: /etc/cascade/zones

Add our test zone to Cascade and associate the policy that we created with
the zone:

.. code-block:: bash

   # cascade zone add --source /etc/cascade/zones/example.net --policy nethsm example.net
   Added zone example.net

Check that the zone has been signed, and print out additional information
which includes the identifiers of the signing keys that were used:

.. code-block:: bash

   $ cascade zone status example.net
   Status report for zone 'example.net' using policy 'nethsm'
   ✔ Waited for a new version of the example.net zone
   ✔ Loaded version 3
     Loaded at 2025-11-22T14:42:20+00:00 (1h 11m 36s ago)
     Loaded 196 B and 3 records from the filesystem in 0 seconds
   ✔ Auto approving signing of version 3, no checks enabled in policy.
   ✔ Approval received to sign version 3, signing requested
   ✔ Signed version 3 as version 1763826146
     Signing requested at 2025-11-22T15:42:26+00:00 (11m 30s ago)
     Signing started at 2025-11-22T15:42:26+00:00 (11m 30s ago)
     Signing finished at 2025-11-22T15:42:26+00:00 (11m 30s ago)
     Collected 3 records in 0s, sorted in 0s
     Generated 2 NSEC(3) records in 0s
     Generated 5 signatures in 0s (5 sig/s)
     Inserted signatures in 0s (5 sig/s)
     Took 0s in total, using 2 threads
     Current action: Finished
   ✔ Waited for approval to publish version 1763826146
   ✔ Published version 1763826146
     Published zone available on 127.0.0.1:4543

   $ dig @127.0.0.1 -p 4543 example.net DNSKEY +nocrypto +norec +noedns
   ;; Got answer:
   ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11653
   ;; flags: qr; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

   ;; ANSWER SECTION:
   example.net.		3600	IN	DNSKEY	257 3 13 [key id = 31203]

   ;; Query time: 0 msec
   ;; SERVER: 127.0.0.1#4543(127.0.0.1) (UDP)
   ;; WHEN: Sat Nov 22 16:56:00 CET 2025
   ;; MSG SIZE  rcvd: 131

Inspect the keys directly on the NetHSM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the :program:`nitropy` program installed earlier to list objects on the
NetHSM. We see an object created by Cascade on the device.

.. code-block:: bash

   $ nitropy nethsm -u jj01 -p blab123456 list-keys
   Command line tool to interact with Nitrokey devices 0.11.2
   Keys on NetHSM 127.0.0.1:8443:

   Key ID                                  	Type   	Mechanisms     	Operations	Tags
   ----------------------------------------	-------	---------------	----------	----
   3fccaf83ff24bde4e0d3ee036acad36dec76bd8a	EC_P256	ECDSA_Signature	16


The :program:`pkcs11-tool` can list the objects it sees via the PKCS#11 interface.

.. code-block:: bash

   $ pkcs11-tool --module $NETPKCS --list-objects
   Using slot 0 with a present token (0x0)
   Public Key Object; EC  EC_POINT 256 bits
     EC_POINT:   04410454a0f26046607a1606788bf116ad348125948d7da55dfe581f3c7e8cefb2b57bdce49a5884fad0d86a20b7e3e63f726aefccc08218e9915c0774d7db82e3f27d
     EC_PARAMS:  06082a8648ce3d030107
     label:      3fccaf83ff24bde4e0d3ee036acad36dec76bd8a
     ID:         33666363616638336666323462646534653064336565303336616361643336646563373662643861
     Usage:      none
     Access:     none
   Private Key Object; EC
     label:      3fccaf83ff24bde4e0d3ee036acad36dec76bd8a
     ID:         33666363616638336666323462646534653064336565303336616361643336646563373662643861
     Usage:      sign, derive
     Access:     sensitive, always sensitive, never extractable
     Allowed mechanisms: ECDSA

Key labels
~~~~~~~~~~

In order to determine which key on the NetHSM belongs to a zone, we can use
:program:`cascade` to output detailed information about the zone status.


.. code-block:: bash

   $ cascade zone status example.net --detailed
   Status report for zone 'example.net' using policy 'csk13-hsm'
   ✔ Waited for a new version of the example.net zone
   ✔ Loaded version 3
   ...
    key kmip://kmip2pkcs11/keys/3FCCAF83FF24BDE4E0D3EE036ACAD36DEC76BD8A_pub?algorithm=13&flags=257 does not expire. No validity period is configured for the key type

The lowercased value of `3FCCAF83FF24BDE4E0D3EE036ACAD36DEC76BD8A` is the label of the key as reported by the above tools.

Final notes
~~~~~~~~~~~

It doesn't appear to be possible to determine which key on the NetHSM
corresponds to which zone. Contrary to keys generated on the
:doc:`SmartCard-HSM <smartcard-hsm>`, the key labels are random names. Changing
the value of ``enable_set_attribute_value`` in ``p11nethsm.conf`` doesn't seem
to make a difference.

End.

— Contributed by `Jan-Piet Mens <https://jpmens.net>`_
