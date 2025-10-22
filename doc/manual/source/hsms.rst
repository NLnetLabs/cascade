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

A Hardware Security Module is typically a tamper proof hardware vault (though
software variants exist as well) capable of generating and securely storing
cryptographic keys and performing signing operations using those keys on
data provided via an interface and returning the signed result via the same
interface.

HSM Interfaces
~~~~~~~~~~~~~~

Typically HSMs are interacted with programmatically via an interface that
is compliant with the Oasis PKCS#11 (Public-Key Cryptography Standard)
specification. Some HSMs also or alternatively support a newer Oasis
specification called KMIP (Key Management Interoperability Protocol).

KMIP is a data (de)serialization protocol that operates on top of the widely
used TCP and TLS combination of protocols. As such it requires no additional
software or special configuration to use and poses no direct security or
stability threat to the client process.

This is quite different to PKCS#11 which requires the HSM vendor to provide
a library of code that offers a C language style interface to be used by the
client at runtime by loading the library (aka module) into its own process
with no knowledge of or control over what that code is going to do.

Cascade and HSMs
----------------

Cascade supports both PKCS#11 and KMIP compatible HSMs. KMIP is supported
natively, while PKCS#11 is supported through our :program:`kmip2pkcs11` bridge.

As Cascade is a Rust powered application, crossing the divide between the Rust
host application and a loaded C library means giving up the stability and
memory safety guarantees offered by Rust. As such Cascade was designed to
*not* load PKCS#11 modules directly but instead to hand that risk off to a
helper tool: :program:`kmip2pkcs11`.

To interact with a HSM over its PKCS#11 interface, Cascade sends KMIP requests
to :program:`kmip2pkcs11`, which executes them against a loaded PKCS#11 vendor
library.

Supported HSMs
~~~~~~~~~~~~~~

In principle any HSM supporting PKCS#11 v2.40 or KMIP 1.2 should be supported.
To work with an HSM using its PKCS#11 interface, Cascade requires our
:program:`kmip2pkcs11` relay. 

Several HSMs have been tested in limited fashion with Cascade. Limited here
meaning normal usage only, not attempting to deliberately cause problems, and
not attempting to stress or performance test the interface. The tested HSMs
are:

.. table:: Supported HSMs
   :widths: auto

   ================  ============  =========  =================
   HSM               Type          Interface  Integration guide
   ================  ============  =========  =================
   Fortanix DSM      Cloud         KMIP       
   Thales Cloud HSM  Cloud         PKCS#11    :doc:`view <thales>`
   Nitrokey NetHSM   Docker image  PKCS#11    
   YubiHSM 2         USB key       PKCS#11    
   SoftHSM v2.6.1    Software      PKCS#11    :doc:`view <softhsm>`
   SmartCard-HSM     Smart Card    PKCS#11    :doc:`view <smartcard-hsm>`
   ================  ============  =========  =================

.. Note:: Cascade requires TLS 1.3 for connections to the KMIP server, even
   though KMIP 1.2 requires servers to offer support for old versions of the
   TLS protocol with known security vulnerabilities. For this reason Cascade
   **cannot** be used with PyKMIP as this implementation only supports older,
   vulnerable TLS versions.

Setting up kmip2pkcs11
~~~~~~~~~~~~~~~~~~~~~~

If you installed Cascade via a DEB or RPM package you should also already
have the :program:`kmip2pkcs11` software installed, unless you explicitly
opted not to install it. If installing via building from sources the
instructions we provide also describe how to install :program:`kmip2pkcs11`.

Test:
:ref:`kmip2pkcs11 logging <kmip2pkcs11:logging-options>`
:option:`user`, :option:`group`

When installed via a package the daemon will not be run automatically. This is
because you will need to:

- Edit the :file:`/etc/kmip2pkcs11/config.toml` file to tell
  :program:`kmip2pkcs111` where to find the PKCS#11 module to load.
- Depending on your PKCS#11 module you may need to set PKCS#11 vendor
  specific environment variables for the :program:`kmip2pkcs11` process,
  and/or ensure that PKCS#11 vendor specific configuration files and possibly
  also other software are installed and correctly configured.
- Ensure that the :program:`kmip2pkcs11` user has access to the resources
  needed by the PKCS#11 module to be loaded.
- Use the (vendor specific) PKCS#11 module setup process to create a token
  label and PIN that Cascade should use to authenticate with the HSM.
- Optionally generate a proper TLS certificate for use by :program:`kmip2pkcs11`
  and set the :file:`/etc/kmip2pkcs11/config.toml` settings ``cert_path`` and
  ``key_path`` to point the certificate file and accompanying private key. If
  you omit these settings :program:`kmip2pkcs11` will generate a long-lived
  self-signed TLS certificate each time it starts.

.. Note:: There is currently no way to test that the configuration
   of :program:`kmip2pkcs11` is correct other than to try using it with
   Cascade.

When ready, start :program:`kmip2pkcs11` either via systemd (if installed from
a package) or directly:

.. code-block:: bash

   kmip2pkcs11 --config /etc/kmip2pkcs11/config.toml -d --user <USER> --group <GROUP>

.. Tip:: Use the ``--user`` and ``--group`` arguments to make :program:`kmip2pkcs11`
   run as the same user that has access to any necessary resources required by
   PKCS#11 module vendor.

Using kmip2pkcs11 with Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use :program:`kmip2pkcs11` with Cascade we must tell it that there is a HSM
running that it can connect to. In the instructions below the PKCS#11 token label
and PIN are the values you configured above.

.. code-block:: bash

   cascade hsm add --insecure --username <PKCS#11 token label> --password <PKCS#11 PIN> kmip2pkcs11 127.0.0.1

.. Note:: ``--insecure`` must be used if using a self-signed TLS certificate (the
   default) with :program:`kmip2pkcs11`. 127.0.0.1 should be changed if your
   :program:`kmip2pkcs11` instance is running on a different address.

Cascade will verify that it can connect and that the target server appears to be a
KMIP compatible HSM.

.. Note:: Cascade does **not** yet verify that the target KMIP server supports
   the features needed by Cascade. For :program:`kmip2pkcs11` this isn't a problem
   as it is designed to work with Cascade.

Next we need to add the HSM to a policy so that when zones are added the keys for the
zones will be generated using the HSM.

To do this, edit :file:`/etc/cascade/policies/<your_policy>.toml` and set:

.. code-block:: text

   [key-manager.generation]
   hsm-server-id = "kmip2pkcs11"

Now when you use ``cascade zone add --policy <your_policy>`` the HSM will be used
for key generation and signing.
