cascade hsm
===========

Synopsis
--------

:program:`cascade hsm` ``[OPTIONS]`` ``<COMMAND>``

:program:`cascade hsm` ``[OPTIONS]`` :subcmd:`add` ``<SERVER_ID>`` ``<IP_HOST_OR_FQDN>``

:program:`cascade hsm` ``[OPTIONS]`` :subcmd:`show` ``<SERVER_ID>``

:program:`cascade hsm` ``[OPTIONS]`` :subcmd:`list`

Description
-----------

Manage HSM's.

Options
-------

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

Commands
--------

.. subcmd:: add

   Add a KMIP server to use for key generation & signing

.. subcmd:: show

   Get the details of an existing KMIP server

.. subcmd:: list

   List all configured KMIP servers

Arguments for :subcmd:`hsm show`
--------------------------------

.. option:: <SERVER_ID>

   The identifier of the KMIP server to show information about


:subcmd:`hsm add`
-----------------

Add a KMIP server to use for key generation & signing.

If this is the first KMIP server to be configured it will be set as the default
KMIP server which will be used to generate new keys instead of using
Ring/OpenSSL based key generation.

If this is NOT the first KMIP server to be configured, the default KMIP server
will be left as-is, either unset or set to an existing KMIP server.

Arguments for :subcmd:`hsm add`
-------------------------------

.. option:: <SERVER_ID>

      An identifier to refer to the KMIP server by.

      This identifier is used in KMIP key URLs. The identifier serves several
      purposes:

      1. To make it easy at a glance to recognize which KMIP server a given key
      was created on, by allowing operators to assign a meaningful name to the
      server instead of whatever identity strings the server associates with
      itself or by using hostnames or IP addresses as identifiers.

      2. To refer to additional configuration elsewhere to avoid including
      sensitive and/or verbose KMIP server credential or TLS client
      certificate/key authentication data in the URL, and which would be
      repeated in every key created on the same server.

      3. To allow the actual location of the server and/or its access
      credentials to be rotated without affecting the key URLs, e.g. if
      a server is assigned a new IP address or if access credentials change.

      The downside of this is that consumers of the key URL must also possess
      the additional configuration settings and be able to fetch them based on
      the same server identifier.

.. option:: <IP_HOST_OR_FQDN>

      The hostname or IP address of the KMIP server

Options for :subcmd:`hsm add`
-----------------------------

.. option:: -h, --help

   Print the help text (short summary with ``-h``, long help with ``--help``).

Server:
+++++++

.. option:: --port <PORT>

          TCP port to connect to the KMIP server on

          [default: 5696]

Client Credentials:
+++++++++++++++++++

.. option:: --username <USERNAME>

          Optional username to authenticate to the KMIP server as.

.. option:: --password <PASSWORD>

          Optional password to authenticate to the KMIP server with.

Client Certificate Authentication:
++++++++++++++++++++++++++++++++++

.. option:: --client-cert <CLIENT_CERT_PATH>

          Optional path to a TLS certificate to authenticate to the KMIP server
          with. The file will be read and sent to the server

.. option:: --client-key <CLIENT_KEY_PATH>

          Optional path to a private key for client certificate authentication.
          THe file will be read and sent to the server.

          The private key is needed to be able to prove to the KMIP server that
          you are the owner of the provided TLS client certificate.

Server Certificate Verification:
++++++++++++++++++++++++++++++++

.. option:: --insecure

          Whether to accept the KMIP server TLS certificate without
          verifying it.

          Set to false if using a self-signed TLS certificate, e.g. in a test
          environment.

.. option:: --server-cert <SERVER_CERT_PATH>

          Optional path to a TLS PEM certificate for the server

.. option:: --ca-cert <CA_CERT_PATH>

          Optional path to a TLS PEM certificate for a Certificate Authority

Client Limits:
++++++++++++++

.. option:: --connect-timeout <CONNECT_TIMEOUT>

          TCP connect timeout

          [default: 3s]

.. option:: --read-timeout <READ_TIMEOUT>

          TCP response read timeout

          [default: 30s]

.. option:: --write-timeout <WRITE_TIMEOUT>

          TCP request write timeout

          [default: 3s]

.. option:: --max-response-bytes <MAX_RESPONSE_BYTES>

          Maximum KMIP response size to accept (in bytes)

          [default: 8192]

Key Labels:
+++++++++++

.. option:: --key-label-prefix <KEY_LABEL_PREFIX>

          Optional user supplied key label prefix.

          Can be used to denote the s/w that created the key, and/or to
          indicate which installation/environment it belongs to, e.g. dev,
          test, prod, etc.

.. option:: --key-label-max-bytes <KEY_LABEL_MAX_BYTES>

          Maximum label length (in bytes) permitted by the HSM

          [default: 32]

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascaded**\ (1)
    :doc:`cascaded`

**kmip2pkcs11**\ (1)
    KMIP to PKCS#11 relay documentation
