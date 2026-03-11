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
~~~~~~~~~~~~~~

In principle any HSM supporting PKCS#11 v2.40 or KMIP 1.2 should be supported.
To work with an HSM using its PKCS#11 interface, Cascade requires our
:program:`cascade-hsm-bridge`.

Several HSMs have been tested with Cascade. Our testing was limited to normal
usage only, not attempting to deliberately cause problems, and not attempting
to stress or performance test the interface. The tested HSMs are:

.. table:: Supported HSMs
   :widths: auto

   =====================  ============  =========  =================
   HSM                    Type          Interface  Integration guide
   =====================  ============  =========  =================
   Fortanix DSM           Cloud         KMIP       
   Thales Cloud HSM       Cloud         PKCS#11    :doc:`view <thales>`
   Nitrokey NetHSM [1]_   Docker image  PKCS#11    :doc:`view <nethsm>`
   YubiHSM 2              USB key       PKCS#11    
   SoftHSM v2.6.1         Software      PKCS#11    :doc:`view <softhsm>`
   SmartCard-HSM          Smart Card    PKCS#11    :doc:`view <smartcard-hsm>`
   =====================  ============  =========  =================

.. [1] Works with v1.7.2 of their PKCS#11 module. v2.0.0 and above are
   NOT currently supported due to a `known bug in cascade-hsm-bridge
   <https://github.com/NLnetLabs/cascade-hsm-bridge/issues/14>`_.

.. Note:: Cascade requires TLS 1.3 for connections to the KMIP server, even
   though KMIP 1.2 requires servers to offer support for old versions of the
   TLS protocol with known security vulnerabilities. For this reason, PyKMIP
   is **NOT** supported by Cascade as it only supports older vulnerable TLS
   versions.

Setting up cascade-hsm-bridge
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you installed Cascade via a DEB or RPM package you should also already have
the :program:`cascade-hsm-bridge` software installed, unless you explicitly
opted not to install it. You can also :doc:`build the software <building>`
from source.

.. seealso:: We provide man pages for both the 
   :doc:`cascade-hsm-bridge daemon<cascade-hsm-bridge:man/cascade-hsm-bridge>` and
   :doc:`configuration file<cascade-hsm-bridge:man/cascade-hsm-bridge-config.toml>`.

When installed via a package the daemon will not be run automatically. This
is because you will need to:

- Edit the :doc:`cascade-hsm-bridge configuration
  file<cascade-hsm-bridge:man/cascade-hsm-bridge-config.toml>` to set the
  location of your PKCS#11 module.
- Depending on your PKCS#11 module, you may need to set vendor specific
  environment variables for the :program:`cascade-hsm-bridge` process.  You
  may also need to ensure that vendor specific configuration files and
  possibly other software is installed and correctly configured.
- Ensure that the :program:`cascade-hsm-bridge` user has access to the
  resources needed by the PKCS#11 module to be loaded.
- Use the (vendor specific) PKCS#11 module setup process to create a token
  label and PIN that Cascade should use to authenticate with the HSM.
- Optionally, generate a proper TLS certificate
  for use by :program:`cascade-hsm-bridge` and
  set the :option:`cascade-hsm-bridge:cert_path`
  and :option:`cascade-hsm-bridge:key_path` in
  :file:`/etc/cascade-hsm-bridge/config.toml` to point the certificate
  file and accompanying private key. If you omit these settings,
  :program:`cascade-hsm-bridge` will generate a long-lived self-signed TLS
  certificate each time it starts.

.. note:: There is currently no way to test that the  :doc:`cascade-hsm-bridge
   configuration<man/cascade-hsm-bridge-config.toml>` is correct other than
   trying to use it with Cascade.

When ready, start :program:`cascade-hsm-bridge` either via systemd (if
installed from a package) or directly:

.. code-block:: bash

   cascade-hsm-bridge --config /etc/cascade-hsm-bridge/config.toml -d --user <USER> --group <GROUP>

.. tip:: Use the :option:`cascade-hsm-bridge:--user` and
   :option:`cascade-hsm-bridge:--group` arguments to make
   :program:`cascade-hsm-bridge` run as the same user that has access to any
   necessary resources required by PKCS#11 module vendor.

Using cascade-hsm-bridge with Cascade
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

Next, we need to add the HSM to a policy so that when zones are added the keys for the
zones will be generated using the HSM.

To do this, edit :file:`/etc/cascade/policies/<your_policy>.toml` and set:

.. code-block:: text

   [key-manager.generation]
   hsm-server-id = "cascade-hsm-bridge"

Now when you use ``cascade zone add --policy <your_policy>`` the HSM will be used
for key generation and signing.
