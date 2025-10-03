Integrating with Thales Cloud HSM
=================================

.. Note:: The instructions on this page are for use with the `Thales Data
   Protection on Demand <https://thales.eu.market.dpondemand.io/signup/>`_
   service. A free trial is available but thereafter it is a paid service. The
   PKCS#11 specific part of the instructions below should be similar for
   any modern Thales HSM service. The instructions are based around the Thales
   guide for using a `Docker container to Access a Luna Cloud HSM Service
   <https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_in
   stall/linux_minimal_client_access_dpod.htm>`_ but Cascade will work
   equally well without Docker, it just needs the Thales PKCS#11 module and a
   correctly configured Thales HSM to communicate with.

The first step to using a Thales HSM with Cascade, assuming that the HSM
itself is already provisioned, is to acquire the Thales PKCS#11 software.

Thales HSMs are commercial products and Thales do not make their software
developer kit, of which the PKCS#11 module is part, publically available.
One version of it is however available via the free trial of the Thales
Data Protection on Demand service which we will demonstrate here.

1. Login to the Thales DPoD portal and via the Service tab add a Luna Cloud
   HSM service to your account. Enter a name for your service. For our test
   we left the "Remove FIPS restrictions" box unticked and named our service
   "Luna HSM with FIPS restrictions".

2. Click the name of your new Luna Cloud HSM service on the Service tab and
   click the "New Service Client" button. Give your service client a name.
   For our test we named our service client "kmip2pkcs11" as we expected the
   Cascade :program:`kmip2pkcs11` tool to be the client that connects to the
   Luna Cloud HSM. Client the "Create Service Client" button.

3. Click the "Download Client" button that appears. This will download a ZIP
   archive called "setup-<YOUR_CLIENT_NAME>.zip. Inside the zip are the key
   files needed to connect to the Luna Cloud HSM using a PKCS#11 client like
   :program:`kmip2pkcs11` including client certificates to authenticate, a
   PKCS#11 module configuration file called ``Chrystoki.conf```, and a TAR
   archive containing the PKCS#11 module ``libs/64/libCryptoki2.so``.

Now, at this point you should in principle have everything needed to connect
:program:`kmip2pkcs11` or any other PKCS#11 client to the Luna Cloud HSM.

However, there are a lot of files in the downloaded service client
ZIP and one easy way to use them properly is to follow the Thales
guide for using a `Docker container to Access a Luna Cloud HSM Service
<https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_in
stall/linux_minimal_client_access_dpod.htm>`_.

First, the following Thales documentation pages are particularly relevant
in the next steps:

  - https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_install/linux_minimal_client_access_dpod.htm
  - https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/initialize_par.htm
  - https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/partition_roles/partition_roles.htm
  - https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/partition_roles/init_co_cu.htm#InitCO

Assuming that you have built your Docker image according to the Thales
instructions using your downloaded service client ZIP, proceed as follows
for one way to setup the Luna Cloud HSM for use with Cascade:

.. code-block:: bash

   $ docker run -it --name luna --entrypoint=./bin/64/lunacm myimage
   lunacm:> role login -name po
   lunacm:> role init -name co
   lunacm:> role login -name co
   lunacm:> role changepw -name co

To test our settings before we use :program:`kmip2pkcs11` we can use
the opensc ``pkcs11-tool`` program from another terminal:

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

Now that that works we can configure :program:`kmip2pkcs11`.

TO DO
