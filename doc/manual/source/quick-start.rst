Quick Start
============

After :doc:`installing <installation>` Cascade you need to configure its
listening addresses before you can start using it.

Configuration the listen addresses
----------------------------------

Cascade only listens on localhost, by default. To make your signed zones
available, you need to add your public IP addresses to Cascade's listen
addresses.

.. tabs::

   .. group-tab:: Using systemd

        On a system with systemd, you need to override the
        ``cascaded.socket``, as Cascade will only listen on localhost, by
        default. To add your own listeners, use the following command:

        .. code-block:: bash

           sudo systemctl edit cascaded.socket

        and insert the following config:

        .. code-block:: text

           [Socket]
           ListenDatagram=<your-ip>:53
           ListenStream=<your-ip>:53

        if you wish to disable the listen address for localhost, you'll need
        to replace the top line with the following (adding ``ListenStream=``
        resets all previously defined ``ListenStream`` and ``ListenDatagram``
        settings):

        .. code-block:: text

           [Socket]
           #ListenStream=
           # ... the other ListenDatagram/ListenStream settings

        After editing the ``cascaded.socket`` file, you need to issue this
        command to instruct systemd to pick up the changes:

        .. code-block:: bash

            sudo systemctl daemon-reload

        Then you can start Cascade with:

        .. code-block:: bash

            sudo systemctl start cascaded

        Or, if Cascade is already running, restart with:

        .. code-block:: bash

            sudo systemctl restart cascaded

   .. group-tab:: Without systemd

        When using Cascade without systemd, you need to configure the listen
        address in Cascade's ``config.toml`` in the ``[servers]`` section:

        .. code-block:: text

            [server]
            servers = ["127.0.0.1:53", "<your-ip>:53"]

        Then you can start Cascade with (replace the config and state path
        with your appropriate values):

        .. code-block:: bash

            sudo cascade --config /etc/cascade/config.toml --state /var/lib/cascade/state.db

Adding an unsigned zone to sign
-------------------------------

After configuring Cascade, you can begin adding zones. Cascade supports zones
sourced from a local file or fetched from another name server using XFR.

However, before adding a zone you need to create a zone policy to use for the
zone (you can choose your own name instead of ``default``):

.. code-block:: bash

   cascade template policy | sudo tee /etc/cascade/policies/default.toml

Then, to add a zone use:

.. code-block:: bash

   cascade zone add --source <file-path|ip-address> --policy default <zone-name>

Now, your zone will be picked up by Cascade, keys prepared, and the signing
process started. You can view the unsigned zone by querying the zone loader
using AXFR (by default, on ``localhost:8051``) and after successful signing,
query the publication server using AXFR on ``localhost:8053`` (or your above
configured listen address).
