Hardware Security Modules (HSMs)
================================

.. Note:: Cascade does not *require* a :term:`Hardware Security Module (HSM)`
   to operate. While it is common practice to secure cryptographic key 
   material using an HSM, not all operators use an HSM. Cascade is able to 
   use `OpenSSL <https://www.openssl.org>`_ and/or 
   `ring <https://crates.io/crates/ring/>`_ software cryptography to generate
   signing keys and to cryptographically sign DNS :term:`RRset <Resource 
   Record Set (RRset)>` data, storing the generated keys in on-disk files.

An Introduction to HSMs
-----------------------

A Hardware Security Module is typically a tamper proof hardware vault capable
of generating and securely storing cryptographic keys and performing signing
operations using those keys on data provided via an interface and returning
the signed result via the same interface.

HSM Interfaces
~~~~~~~~~~~~~~

In most cases, you interact with an HSM via an interface that is compliant
with the Oasis PKCS#11 (Public-Key Cryptography Standard) specification. Some
HSMs also or alternatively support a newer Oasis specification called KMIP
(Key Management Interoperability Protocol).

KMIP is a data (de)serialization protocol that operates on top of the widely
used TCP and TLS combination of protocols. As such, it requires no additional
software or special configuration to use and poses no direct security or
stability threat to the client process.

This is quite different to PKCS#11, which requires the HSM vendor to provide
a library of code that offers a C language style interface to be used by the
client at runtime by loading the library (a.k.a. module) into its own process
with no knowledge of or control over what that code is going to do.

Cascade and HSMs
----------------

Cascade supports both PKCS#11 and KMIP compatible HSMs. KMIP
is supported natively, while PKCS#11 is supported through our
:program:`cascade-hsm-bridge`.

Cascade is an application written in Rust. Crossing the divide between the
Rust host application and a loaded C library means giving up the stability
and memory safety guarantees offered by Rust. As such, Cascade was designed
to *not* load PKCS#11 modules directly but instead to hand that risk off to a
helper tool: :program:`cascade-hsm-bridge`.

To interact with a HSM over its PKCS#11 interface, Cascade sends KMIP requests
to :program:`cascade-hsm-bridge`, which executes them against a loaded PKCS#11
vendor library.

Supported HSMs
--------------

In principle any HSM supporting PKCS#11 v2.40 or KMIP 1.2 should be supported.
To work with an HSM using its PKCS#11 interface, Cascade requires our
:program:`cascade-hsm-bridge`.

Several HSMs have been tested with Cascade by the community. Testing was limited to normal
usage only, not attempting to deliberately cause problems, and not attempting
to stress or performance test the interface. The tested HSMs are\:

.. csv-table:: Supported HSMs
   :header: Vendor, Model, Type, Interface, Guide
   :widths: auto

   CardContact, SmartCard-HSM, "Smart Card", PKCS#11, :doc:`view <smartcard-hsm>`
   Fortanix, DSM, Cloud, KMIP,
   Nitrokey, NetHSM, "Server, Docker image", PKCS#11, :doc:`view <nethsm>`
   Thales, "Cloud HSM", Cloud, PKCS#11, :doc:`view <thales>`
   Securosys, "Primus HSM, CloudHSM", "Server, Cloud", "KMIP, PKCS#11", `view <https://docs.securosys.com/cascade/overview>`_
   SoftHSM, "SoftHSM v2.6.1", Software, PKCS#11, :doc:`view <softhsm>`
   Yubico, "YubiHSM 2", "USB key", PKCS#11,

.. Note:: Cascade requires TLS 1.3 for connections to the KMIP server, even
   though KMIP 1.2 requires servers to offer support for old versions of the
   TLS protocol with known security vulnerabilities. For this reason, PyKMIP
   is **NOT** supported by Cascade as it only supports older vulnerable TLS
   versions.

Known quirks
~~~~~~~~~~~~

Please be aware of the following quirks that you may run into when integrating
Cascade with the respective HSMs.

* Nitrokey NetHSM:

  * Username and password must be specified in `p11nethsm.conf` for both the
    `operator` and `admin` user. The admin role is needed so that :program:`cascade-hsm-bridge`
    can `generate new key pairs <https://docs.nitrokey.com/nethsm/operation#generate-key>`_.
    See the `Nitrokey documentation <https://docs.nitrokey.com/nethsm/pkcs11-setup#users>`_
    for more information.
  * Does `not support <https://github.com/NLnetLabs/cascade/pull/621#issuecomment-4677960984>`_
    labels (``CKA_LABEL``). As a result, you will not see human-readable labels
    when listing keys with ``pkcs11-tool``.

Configuration with KMIP
-----------------------

This section describes how to integrate an HSM with Cascade via KMIP.

Follow your vendor's instructions to deploy, initialise, and configure the HSM
or the KMIP server. As a result, you should have the following values:

* KMIP server IP or FQDN
* KMIP server port (default: 5696)
* Credentials: Username/password or mTLS (client cert, client key)

Add the KMIP server to Cascade using :doc:`cascade hsm add <man/cascade-hsm>`.
Choose a server ID that helps you identify the HSM, such as ``kmip-hsm-1``.

.. code-block:: bash

   # With username/password
   cascade hsm add --insecure --username <USERNAME> --password <PASSWORD> <SERVER_ID> <IP_HOST_OR_FQDN>

   # With mTLS
   cascade hsm add --client-cert client.crt --client-key client.key --ca-cert server-ca.crt <SERVER_ID> <IP_HOST_OR_FQDN>

Cascade will verify that it can connect and that the target server appears to be a
KMIP compatible HSM.

.. Note:: Cascade does **not** yet verify that the target KMIP server supports
   the :ref:`operations<cascade-hsm-bridge:index:supported operations>` needed
   by  Cascade.

Configuration with PKCS#11
--------------------------

This section describes how to integrate an HSM with Cascade via PKCS#11.

Install the PKCS#11 module
~~~~~~~~~~~~~~~~~~~~~~~~~~

Install the PKCS#11 module for your HSM on the same machine as Cascade.
You may need to edit vendor-specific config files or set certain environment
variables for the :program:`cascade-hsm-bridge` process.
See your vendor's documentation for details.

As a result, you should have the following:

* Path to the PKCS#11 module (example: ``/usr/lib/softhsm/libsofthsm2.so``)
* PKCS#11 Token Label (string) or slot ID (numeric) or slot index (numeric)
* PKCS#11 User PIN

.. Note:: The examples below use the SoftHSM module path. Replace it with the
   path to your HSM's PKCS#11 module.

Ensure that the :program:`cascade-hsm-bridge` user has access to the
the PKCS#11 module and all its resources (config files, environment variables, ...).
For example, for SoftHSM you can chown the ``/var/lib/softhsm`` directory:

.. code-block:: bash

   chown -R cascade-hsm-bridge: /var/lib/softhsm

Test the PKCS#11 connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~

List the available slots. Note the token label and the slot ID.

.. code-block:: bash

   $ sudo -u cascade-hsm-bridge pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots
   Available slots:
   Slot 0 (0x2f5f235f): SoftHSM slot ID 0x2f5f235f
     token label        : cascade-token
     token manufacturer : SoftHSM project
     token model        : SoftHSM v2
     token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
     hardware version   : 2.6
     firmware version   : 2.6
     serial num         : 0bce0b87af5f235f
     pin min/max        : 4/255

In this example, 0 is the slot index, 0x2f5f235f is the slot ID, and
cascade-token is the token label.

List the keys on the token. This command verifies that you can connect to the
HSM via PKCS#11 and can log in.

.. code-block:: bash

   sudo -u cascade-hsm-bridge pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 0x2f5f235f --login --pin 1234 --list-objects

Observe that these commands execute ``pkcs11-tool`` as the ``cascade-hsm-bridge``
user, which :program:`cascade-hsm-bridge` also runs as.

Configure :program:`cascade-hsm-bridge`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you installed Cascade via a DEB or RPM package you should also already have
the :program:`cascade-hsm-bridge` software installed, unless you explicitly
opted not to install it. You can also :doc:`build the software <building>`
from source.

.. seealso:: We provide man pages for both the 
   :doc:`cascade-hsm-bridge daemon<cascade-hsm-bridge:man/cascade-hsm-bridge>` and
   :doc:`configuration file<cascade-hsm-bridge:man/cascade-hsm-bridge-config.toml>`.

When installed via a package the daemon will not be run automatically. This
is because you first need to configure both the PKCS#11 module and :program:`cascade-hsm-bridge`.

Edit the :doc:`cascade-hsm-bridge configuration file<cascade-hsm-bridge:man/cascade-hsm-bridge-config.toml>`
to set the location of your PKCS#11 module. If you installed Cascade via a
package, this file is located at ``/etc/cascade-hsm-bridge/config.toml``.

Set the ``lib_path`` option to tell :program:`cascade-hsm-bridge` where to find
the PKCS#11 module:

.. code-block:: toml

   [pkcs11]
   lib_path = "/usr/lib/softhsm/libsofthsm2.so"

Optionally, generate a proper TLS server certificate for use by :program:`cascade-hsm-bridge`.
Set the :option:`cascade-hsm-bridge:cert_path` and :option:`cascade-hsm-bridge:key_path`
to point the certificate file and accompanying private key.
If you omit these settings, :program:`cascade-hsm-bridge` will generate a
long-lived self-signed TLS server certificate each time it starts.

Then (re)start the service:

.. code-block:: bash

   systemctl restart cascade-hsm-bridge

Check the logs to verify that :program:`cascade-hsm-bridge` starts without errors:

.. code-block:: bash

   journalctl --follow --no-tail -u cascade-hsm-bridge

.. note:: There is currently no way to test that the
   :doc:`cascade-hsm-bridge configuration <man/cascade-hsm-bridge-config.toml>`
   is correct other than trying to use it with Cascade.

If not installed with systemd, start it directly:

.. code-block:: bash

   cascade-hsm-bridge --config /etc/cascade-hsm-bridge/config.toml --daemonize --user <USER> --group <GROUP>

.. tip:: Use the :option:`cascade-hsm-bridge:--user` and
   :option:`cascade-hsm-bridge:--group` arguments to make
   :program:`cascade-hsm-bridge` run as the same user that has access to any
   necessary resources required by PKCS#11 module vendor.

Use :program:`cascade-hsm-bridge` with Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use :program:`cascade-hsm-bridge` with Cascade we must tell it that there
is a HSM running that it can connect to. In the instructions below the PKCS#11
token label and PIN are the values you configured above.

.. code-block:: bash

   cascade hsm add --insecure --username <PKCS#11 token label> --password <PKCS#11 PIN> cascade-hsm-bridge 127.0.0.1

.. Note:: The :option:`--insecure` option must be used if using a self-signed
   TLS certificate, which is the default. 127.0.0.1 should be changed if your
   :program:`cascade-hsm-bridge` instance is running on a different address.

Cascade will verify that it can connect and that the target server appears to be a
KMIP compatible HSM.

.. Note:: Cascade does **not** yet verify that the target KMIP server supports
   the :ref:`operations<cascade-hsm-bridge:index:supported operations>` needed
   by  Cascade. For :program:`cascade-hsm-bridge` this isn't a problem as it
   is designed to work with Cascade.

Using the HSM in a policy
-------------------------

Once you have added the HSM to Cascade, you need to add the HSM to a policy,
so that when zones are added the keys for the zones will be generated using the HSM.

To do this, edit :file:`/etc/cascade/policies/<your_policy>.toml` and set:

.. code-block:: text

   [key-manager.generation]
   hsm-server-id = "cascade-hsm-bridge"

Now when you use ``cascade zone add --policy <your_policy>`` the HSM will be used
for key generation and signing.

See the :doc:`quick start <quick-start>` for details on how to use the policy
to sign a zone.

Inspecting the key state
------------------------

Cascade automatically creates the KSK and ZSK on the HSM.
With :doc:`cascade zone status <man/cascade-zone>` you can inspect the DNSSEC
key status of a zone:

.. code-block:: bash

   $ cascade zone status <ZONE> --detailed
   # ...
   DNSSEC keys:
    KSK tagged 45285:
     Reference: kmip://cascade-hsm-bridge-1/keys/AAA7DA60B816B3B96F6FC0518363FDD8BB74F3B6_pub?algorithm=13&flags=257
     Actively used for signing
    ZSK tagged 44695:
     Reference: kmip://cascade-hsm-bridge-1/keys/ABACB17A39D21DF2012C58D31C71A49CAB2A5A4B_pub?algorithm=13&flags=256
     Actively used for signing

You can inspect your HSM key store to verify this.
The hex string in the ``Reference`` field should be the key ID on the HSM.
Additionally, some HSMs have audit logs that show the key generation and signing operations.

For PKCS#11, you can list keys using ``pkcs11-tool``:

.. code-block:: bash

   $ sudo -u cascade-hsm-bridge pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 0x27378f68 --list-objects --login --pin 1234

   Private Key Object; EC
     label:      rsa.example.com-45285-ksk-pri
     ID:         aaa7da60b816b3b96f6fc0518363fdd8bb74f3b6
     Usage:      sign
     Access:     sensitive, always sensitive, never extractable, local
     Allowed mechanisms: ECDSA,ECDSA-SHA1,ECDSA-SHA224,ECDSA-SHA256,ECDSA-SHA384,ECDSA-SHA512,ECDSA-SHA3-224,ECDSA-SHA3-256,ECDSA-SHA3-384,ECDSA-SHA3-512,ECDH1-DERIVE
   Public Key Object; EC  EC_POINT 256 bits
     EC_POINT:   044104ebfe54f2c4724c48441cc37b43752e179dfa1cd0e68886d3086b1d6255bd4c11bbbc05dcc27cb668a5969eb6fb9d286779e7f44dbb2cb37affff92e854b38afa
     EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
     label:      rsa.example.com-45285-ksk-pub
     ID:         aaa7da60b816b3b96f6fc0518363fdd8bb74f3b6
     Usage:      verify
     Access:     local
   Private Key Object; EC
     label:      rsa.example.com-44695-zsk-pri
     ID:         abacb17a39d21df2012c58d31c71a49cab2a5a4b
     Usage:      sign
     Access:     sensitive, always sensitive, never extractable, local
     Allowed mechanisms: ECDSA,ECDSA-SHA1,ECDSA-SHA224,ECDSA-SHA256,ECDSA-SHA384,ECDSA-SHA512,ECDSA-SHA3-224,ECDSA-SHA3-256,ECDSA-SHA3-384,ECDSA-SHA3-512,ECDH1-DERIVE
   Public Key Object; EC  EC_POINT 256 bits
     EC_POINT:   044104df97078194fa299788c6d2770277913d499e6050da67733bd51b573baf2d4a1ce37f8207c2e3f7052ee268e38e7384d8729986b449f51746d9793efc2e8d8caa
     EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
     label:      rsa.example.com-44695-zsk-pub
     ID:         abacb17a39d21df2012c58d31c71a49cab2a5a4b
     Usage:      verify
     Access:     local
