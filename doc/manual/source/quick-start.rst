Quick Start
============

After :doc:`installing <installation>` Cascade you can immediately start using
it, unless you need to adjust the addresses it listens on or need to modify
the settings relating to daemonization.

Configuring Cascade
---------------------

By default, Cascade only listens on the localhost address. If you want Cascade to listen
on other addresses too, you need to configure them.

The ``/etc/cascade/config.toml`` file controls listen addresses, which filesystem paths Cascade uses, daemonizatioan settings (running in the background, running aa a different user, and log settings.

If using systemd to run Cascade some of these settings should be ignored and systemd features used instead.

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

Zones take a lot of their settings from policy.

Policies allow easy re-use of settings across multiple zones and control things like whether or not zones should be reviewed and how, what DNSSEC settings should be used to sign the zone, and more.

Adding a policy is done by creating a file. To make it easy to get started we provide a default policy template so we'll use that to create a policy for our zone to use.

The name of the policy is taken from the filename. The directory to save the policy file to is determined by the ``policy-dir`` setting as configured in ``/etc/cascade/config.toml``. The filename can be any valid filename and will be used as the name of the policy.

In the example below the `sudo tee` command is needed because the default policy directory is not writable by the current user.

.. code-block:: bash

   cascade template policy | sudo tee /etc/cascade/policies/default.toml
   cascade policy reload

Then, to add a zone use:

.. code-block:: bash

   cascade zone add --source <file-path|ip-address> --policy default <zone-name>

Now, your zone will be picked up by Cascade, keys prepared, and the signing
process started. You can view the unsigned zone by querying the zone loader
using AXFR (by default, on ``localhost:8051``) and, after successful signing,
query the publication server using AXFR on ``localhost:53`` (or your above
configured listen address).
