Integrating with SoftHSMv2
==========================

.. Note:: The instructions on this page are for an Ubuntu 24.04 host and
   assume that Cascade has already been installed using our DEB package.

.. epigraph::

   SoftHSM is an implementation of a cryptographic store accessible through
   a PKCS #11 interface. You can use it to explore PKCS #11 without having
   a Hardware Security Module. It was originally developed as a part of the
   OpenDNSSEC project. SoftHSM uses Botan or OpenSSL for its cryptographic
   operations.

   -- https://www.softhsm.org/

Install SoftHSMv2 and initialize it:

.. code-block:: bash

   # apt install -y softhsm2
   # softhsm2-util --init-token --label Cascade --pin 1234 --so-pin 1234 --free

Configure :program:`kmip2pkcs11` to use the SoftHSMv2 PKCS#11 module and to
have access to its data files, and start the daemon:

.. code-block:: bash

   # sed -i -e 's|^lib_path = .\+|lib_path = "/usr/lib/softhsm/libsofthsm2.so"|' /etc/kmip2pkcs11/config.toml
   # chown -R kmip2pkcs11: /var/lib/softhsm
   # systemctl start kmip2pkcs11

Create a test zone to load and sign and ensure the Cascade daemon has access to it:

.. code-block:: bash

   # mkdir /etc/cascade/zones
   # cat > /etc/cascade/zones/example.com << EOF
   example.com.    3600    IN      SOA     ns.example.com. username.example.com. 1 86400 7200 2419200 300
   example.com.            IN      NS      ns
   ns                      IN      A       192.0.2.1
   EOF
   # chown -R cascade: /etc/cascade/zones

Create a Cascade policy called ``default`` and set it to use a HSM
called ``kmip2pkcs11``.

.. code-block:: bash

   # cascade template policy | tee /etc/cascade/policies/default.toml
   # sed -i -e 's|^#hsm-server-id = .\+|hsm-server-id = "kmip2pkcs11"|' /etc/cascade/policies/default.toml

Start the Cascade daemon:

.. code-block:: bash

   # systemctl start cascaded

Configure a HSM in Cascade called ``kmip2pkcs11`` that will connect to the
locally running :program:`kmip2pkcs11` daemon:

.. code-block:: bash

   # cascade hsm add --insecure --username Cascade --password 1234 kmip2pkcs11 127.0.0.1
   Added KMIP server 'kmip2pkcs11 0.1.0-rc1 using PKCS#11 token with label Cascade in slot SoftHSM slot ID 0x1948bafd via library libsofthsm2.so'.

Add our test zone and associate the policy that we created with the zone:

.. code-block:: bash

   # cascade zone add --source /etc/cascade/zones/example.com --policy default example.com
   Added zone example.com

Check that the zone has been signed, and print out additional information
which includes the identifiers of the signing keys that were used:

.. code-block:: bash

   # cascade zone status example.com --detailed
   Status report for zone 'example.com' using policy 'default'
   ✔ Waited for a new version of the example.com zone
   ✔ Loaded version 1
     Loaded at 2025-10-01T21:44:13+00:00 (1m 46s ago)
     Loaded 196 B from the filesystem in 0 seconds
   ✔ Auto approving signing of version 1, no checks enabled in policy.
   ✔ Approval received to sign version 1, signing requested
   ✔ Signed version 1 as version 2025100101
     Signed at 2025-10-01T21:44:13+00:00 (1m 45s ago)
     Signed 3 records in 0s
   ✔ Auto approving publication of version 2025100101, no checks enabled in policy.
   ✔ Published version 2025100101
     Published zone available on 127.0.0.1:8053
   DNSSEC keys:
     KSK tagged 16598:
       Reference: kmip://kmip2pkcs11/keys/C9623EAF300AF8E4A3DF6D5F6AD6674B49CCD322_pub?algorithm=13&flags=257
       Actively used for signing
     ZSK tagged 50714:
       Reference: kmip://kmip2pkcs11/keys/3C95A4EC3A1E26BC67EC0336926ADBB212ADB3D8_pub?algorithm=13&flags=256
       Actively used for signing
   ...

Install the ``pkcs11-tool`` program from the ``opensc`` package and use it to query SoftHSMv2 directly:

.. code-block:: bash

   # apt install -y opensc
   # pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --token-label Cascade --so-pin 1234 -O
   Public Key Object; EC  EC_POINT 256 bits
     EC_POINT:   04410489c96a67a451f26b75d0cbf903211d7d892e36c577a707e144a97309f20f47144a4bb1c5b437ac04fc1a2f44251253f69bd6d9d575cbe69b612e1d6fc2bf903d
     EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
     label:      example.com-50714-zsk-pub
     ID:         3c95a4ec3a1e26bc67ec0336926adbb212adb3d8
     Usage:      verify, verifyRecover
     Access:     local
   Public Key Object; EC  EC_POINT 256 bits
     EC_POINT:   0441041517afa18dcf0eb9aec58de3bd54585e152e634ee332c4d73c587e4fb2ebded9432be24cd4ea34f34290ffbd5f27a1ef1cfaa82662e8ebaf236c23896f19dfb2
     EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
     label:      example.com-16598-ksk-pub
     ID:         c9623eaf300af8e4a3df6d5f6ad6674b49ccd322
     Usage:      verify, verifyRecover
     Access:     local

Notice that the key IDs stored in SoftHSMv2 match those reported by Cascade.

End.
