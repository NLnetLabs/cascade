Quick Start
============

After :doc:`installing <installation>` Cascade you can immediately start using
it, unless you need to adjust the addresses it listens on or need to modify
the settings relating to daemonization.

Configuring the listen addresses
----------------------------------

Cascade only listens on localhost, by default. To make your signed zones
available to your public primaries, you need to add the required IP addresses
to Cascade's listen addresses.

.. tabs::

   .. group-tab:: Using systemd

        On systems using systemd the ``cascaded.socket`` unit is used to bind
        to listen addresses on behalf of Cascade. By default, the provided
        listen address is ``localhost:53``. If you wish to change the
        addresses bound, you will need to override the ``cascaded.socket``
        unit. One way to do this is to use the ``systemctl edit`` command like
        so:

        .. code-block:: bash

           sudo systemctl edit cascaded.socket

        and insert the following config:

        .. code-block:: text

           [Socket]
           # Uncomment the next line if you wish to disable listening on localhost.
           #ListenStream=
           ListenDatagram=<your-ip>:53
           ListenStream=<your-ip>:53

        Then notify systemd of the changes and (re)start Cascade:

        .. code-block:: bash

            sudo systemctl daemon-reload
            sudo systemctl restart cascaded

   .. group-tab:: Without systemd

        When using Cascade without systemd, you need to configure the listen
        address in Cascade's ``config.toml`` in the ``[servers]`` section:

        .. code-block:: text

            [server]
            servers = ["<your-ip>:53"]

        Then you can start Cascade with (replace the config and state path
        with your appropriate values, and if your config uses privileged ports
        or the daemonization identity feature run the command as root):

        .. code-block:: bash

            cascade --config /etc/cascade/config.toml --state /var/lib/cascade/state.db


Signing your first zone
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
using AXFR (by default, on ``localhost:8051``) and, after successful signing,
query the publication server using AXFR on ``localhost:53`` (or your above
configured listen address).
