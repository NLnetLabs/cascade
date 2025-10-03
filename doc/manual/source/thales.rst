Integrating with Thales Cloud HSM
=================================

.. Note::

   The instructions on this page are for use with the `Thales Data
   Protection on Demand <https://thales.eu.market.dpondemand.io/signup/>`_
   (DPoD) service.

   **Warning:** DPoD is **NOT** free. An initial free trial is available but
   thereafter it is a paid service.

.. Note::

   The PKCS#11 specific part of the instructions below should be similar for
   any modern Thales HSM service. The instructions are based around the Thales
   guide for using a `Docker container to Access a Luna Cloud HSM Service
   <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_in
   stall/linux_minimal_client_access_dpod.htm>`_.

.. Tip::

   Docker is NOT required to use Cascade. This example uses Docker because the
   Thales documentation describes how using Docker one can easily get PKCS#11
   connectivity to a Thales Luna Cloud HSM working.

   Hwoever, when running :program:`kmip2pkcs11` as a systemd service, i.e. not
   in a Docker container as this page describes, be aware that you will need
   to use the ``systemctl edit kmip2pkcs11`` command to set some extra systemd
   settings that the Thales Luna Cloud HSM PKCS#11 module needs.

   .. code-block:: text

      [Service]
      WorkingDirectory=/usr/local/dpodclient/libs/64
      Environment="ChrystokiConfigurationPath=/usr/local/dpodclient"
      MemoryDenyWriteExecute=no

Acquire the PKCS#11 Module
~~~~~~~~~~~~~~~~~~~~~~~~~~

The first step to using a Thales HSM with Cascade, assuming that the HSM
itself is already provisioned, is to acquire the Thales PKCS#11 module that
contains the code needed to connect to a Thales Luna Cloud HSM.

.. Note::

   Thales HSMs are commercial products and Thales do not make their software
   developer kit, of which the PKCS#11 module is part, publically available.
   One version of it is however available via the free trial of the Thales
   Data Protection on Demand service which we will demonstrate here.

1. Login to the Thales DPoD portal. This step assumes you already have an
   account.

2. Via the Service tab add a Luna Cloud HSM service to your account.

3. Enter a name for your service.

4. (optional) Tick the "Remove FIPS restrictions" box. For our test we left
   the "Remove FIPS restrictions" box unticked.

5. Click the name of your new Luna Cloud HSM service on the Service tab.

6. Click the "New Service Client" button.

7. Give your service client a name when asked.

8. Click the "Create Service Client" button.

9. Click the "Download Client" button that appears.

This will download a ZIP archive called "setup-<YOUR_CLIENT_NAME>.zip.

Inside the zip are the files needed to connect to the Luna Cloud HSM using a
PKCS#11 client like :program:`kmip2pkcs11`, including client certificates to
authenticate, a PKCS#11 module configuration file called ``Chrystoki.conf```,
and a TAR archive containing the PKCS#11 module ``libs/64/libCryptoki2.so``.

Testing the PKCS#11 Module
~~~~~~~~~~~~~~~~~~~~~~~~~~

By this point you should in principle have everything needed to connect
:program:`kmip2pkcs11` or any other PKCS#11 client to the Luna Cloud HSM.

However, there are a lot of files in the downloaded service client
ZIP and you'll need to work out which ones you need and how to use them.

Thales provide a guide for using a `Docker
container to Access a Luna Cloud HSM Service
<https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_in
stall/linux_minimal_client_access_dpod.htm>`_. We use that guide here to
demonstrate that Cascade works with the Thales Luna Cloud HSM.

.. Tip::

   The following Thales documentation pages are particularly relevant in the
   next steps:

     - `Create a Docker Container to Access a Luna Cloud HSM Service <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_install/linux_minimal_client_access_dpod.htm>`_
     - `Initializing an Application Partition <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/initialize_par.htm>`_
     - `Partition Roles <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/partition_roles/partition_roles.htm>`_
     - `Initializing the Crypto Officer Role <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/partition_roles/init_co_cu.htm#InitCO>`_

Follow the steps below to confirm that you can connect via PKCS#11 to your DPoD
Luna Cloud HSM instance.

10. Build a Docker image as described at `Create a Docker Container to Access
    a Luna Cloud HSM Service <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_install/linux_minimal_client_access_dpod.htm>`_.

.. Note::

   Replace ``FROM ubuntu:20.04`` in the Docker instructions with ``FROM ubuntu:22.04``.`

   When following the instructions to build the Docker image, replace
   references to ``setup-myclient.zip`` with **YOUR** service client ZIP that
   you downloaded in step 9 above.

11. Assuming that you have built your Docker image according to the Thales
    instructions using your downloaded service client ZIP, run a container
    based on the image and use the Thales ``lunacm`` command to setup access
    to your Luna Cloud HSM:

    .. Note::

       The docker command below has an additional ``--publish`` argument that
       is not present in the Thales documentation. This is needed to expose
       the :program:`kmi2pkcs11` listen port outside the container so that you
       can connect to it from Cascade running on the host or inside another
       container.

    .. code-block:: bash
    
       $ docker run -it \
           --name luna \
           --publish 5696:5696 \
           --entrypoint=./bin/64/lunacm \
           myimage
       lunacm:> role login -name po
       lunacm:> role init -name co
       lunacm:> role login -name co
       lunacm:> role changepw -name co

12. To test our settings before we use :program:`kmip2pkcs11` we can use
    the opensc ``pkcs11-tool`` program *from another shell terminal*:

    .. code-block:: bash
   
       $ docker exec -it luna /bin/bash
       # apt update
       # apt install -y opensc
       # pkcs11-tool --module ./libs/64/libCryptoki2.so -I
       Cryptoki version 2.20
       Manufacturer     SafeNet
       Library          Chrystoki                       (ver 10.9)
       Using slot 3 with a present token (0x3)

   # pkcs11-tool --module ./libs/64/libCryptoki2.so --login -O
   Using slot 3 with a present token (0x3)
   Logging in to "MyPartition".
   Please enter User PIN: <THE PASSWORD YOU CHOSE ABOVE>

Now that that works we can install :program:`kmip2pkcs11`.

Installing and Configuring :program:`kmip2pkcs11`
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

13. Continuing from the same /bin/bash session inside the Docker container,
    follow the :doc:`installation` steps to install :program:`kmip2pkcs11`
    for Ubuntu 24.04, the base image used by our DPoD Docker container.

    .. Note::

       The installation instructions use ``sudo`` but this does not usually
       exist inside a Docker container as typically one executes commands as
       ``root``. Either remove ``sudo`` from any commands you copy-paste, or
       execute ``alias sudo=`` before copy-pasting commands that use ``sudo``.
       This will ensure that the commands work as intended.

14. Next edit the :program:`kmip2pkcs11` configuration file to point it to
    the Thales Luna Cloud HSM PKCS#11 module:

    .. code-block:: bash

       $ sed -i -e 's|^lib_path =.\+|lib_path = "/usr/local/dpodclient/libs/64/libCryptoki2.so"|' /etc/kmip2pkcs11/config.toml

15. Now run :program:`kmip2pkcs11` and send its logs to a file so that for
    this test we can easily see the content of the logs. Normally in a Docker
    container one would send logs to stdout and then view them using the
    ``docker logs`` command:

    .. code-block:: bash

       $ kmip2pkcs11 -c /etc/kmip2pkcs11/config.toml -d --logfile /tmp/kmip2pkcs11.log
       $ cat /tmp/kmip2pkcs11.log
       [2025-10-03T20:48:37] [INFO] Loading and initializing PKCS#11 library /usr/local/dpodclient/libs/64/libCryptoki2.so
       [2025-10-03T20:48:37] [INFO] Loaded SafeNet PKCS#11 library v10.9 supporting Cryptoki v2.20: Chrystoki
       [2025-10-03T20:48:37] [WARN] Generating self-signed server identity certificate
       [2025-10-03T20:48:37] [INFO] Listening on 127.0.0.1:5696`

Here we can see that the PKCS#11 module has been loaded correctly.

Next you need to get Cascade running and add :program:`kmip2pkcs11` as the HSM
that it will use.

You can learn how to do that on the :doc:`hsms` page.

.. Note::

   Skip down to the *"Using kmip2pkcs11 with Cascade"* section as we have
   already setup :program:`kmip2pkcs11` on 127.0.0.1 port 5659 as expected
   by that page, but in a Docker container that contains the necessary Thales
   Luna Cloud HSM PKCS#11 module and related files.
