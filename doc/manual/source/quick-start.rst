Quick Start
============

After :doc:`installing <installation>` Cascade you can immediately start using
it, unless you need to adjust the addresses it listens on or need to modify
the settings relating to daemonization.

.. important:: Fully automatic key rolls are enabled by default. For this to 
   work, Cascade requires access to all nameservers of the zone and the 
   parent zone. If this is not available, make sure to 
   :ref:`disable automatic key rolls <automation-control>`.

.. _cascade-config:

Configuring Cascade
-------------------

By default, Cascade only listens on the localhost address. If you want Cascade
to listen on other addresses too, you need to configure them.

The :file:`/etc/cascade/config.toml` file controls listen addresses, which
filesystem paths Cascade uses, daemonization settings (running in the
background, running as a different user), and log settings.

If using systemd to run Cascade some of these settings should be ignored and
systemd features used instead.

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

            cascaded --config /etc/cascade/config.toml --state /var/lib/cascade/state.db

.. _defining-policy:

Defining Policy
---------------

After configuring Cascade, you can begin adding zones. Cascade supports zones
sourced from a local file or fetched from another nameserver using XFR 
:term:`zone transfers <Zone transfer>`.

.. Note:: The current version of Cascade does not yet support TSIG 
   authenticated XFR nor can it pass through a signed zone intact. Any DNSSEC
   records will be stripped from the zone before signing. We expect to add 
   support for these features soon.

Zones take a lot of their settings from policy. Policies allow easy re-use of
settings across multiple zones and control things like whether or not zones
should be reviewed and how, what DNSSEC settings should be used to sign the
zone, and more.

Adding a policy is done by creating a file. To make it easy to get started we
provide a default policy template so we'll use that to create a policy for our
zone to use.

The name of the policy is taken from the file name. The directory to save the
policy file to is determined by the :option:`policy-dir` setting as
configured in :file:`/etc/cascade/config.toml`. 

In the example below, the :command:`sudo tee` command is needed because the
default policy directory is not writable by the current user.

.. Tip::

   Cascade needs to running before you proceed further. See 
   :ref:`Configuring Cascade <cascade-config>` above on how to configure 
   and start Cascade.

.. code-block:: bash

   cascade template policy | sudo tee /etc/cascade/policies/default.toml
   cascade policy reload

Signing Your First Zone
-----------------------

Adding a zone will trigger Cascade to load, sign and publish it. If you have
configured :doc:`review-hooks`, they will be executed and may intentionally
prevent your zone reaching publication.

To add a zone use:

.. code-block:: bash

   cascade zone add --source <file-path|ip-address> --policy default <zone-name>

Cascade will now generate signing keys for the zone and attempt to load and
sign it.

Checking the Result
-------------------

You can view the status of a zone with:

.. code-block:: bash

   cascade zone status <zone-name>

For example:

.. code-block:: text

    Status report for zone 'example.com' using policy 'default'
    ✔ Waited for a new version of the example.com zone
    ✔ Loaded version 1
      Loaded at 2025-09-30T12:00:05+00:00 (2s ago)
      Loaded 596 B from the filesystem in 0 seconds
    ✔ Auto approving signing of version 1, no checks enabled in policy.
    ✔ Approval received to sign version 1, signing requested
    ✔ Signed version 1 as version 2025093001
      Signed at 2025-09-30T12:00:06+00:00 (1s ago)
      Signed 3 records in 0s
    ✔ Auto approving publication of version 2025093001, no checks enabled in policy.
    ✔ Published version 2025093001
      Published zone available on 127.0.0.1:4543

From the above you can see that the signed zone can be retrieved from
``127.0.0.1:4543`` using a DNS client, e.g.:

.. code-block:: bash

    dig @127.0.0.1 -p 4543 AXFR example.com

If you have the BIND `dnssec-verify
<https://bind9.readthedocs.io/en/latest/manpages.html#std-iscman-dnssec-verify>`_
tool installed, you can check that the zone is correctly DNSSEC signed:

.. code-block:: bash

   $ dig @127.0.0.1 -p 4543 example.com AXFR | dnssec-verify -o example.com /dev/stdin
   Loading zone 'example.com' from file '/dev/stdin'

   Verifying the zone using the following algorithms:
   - ECDSAP256SHA256
   Zone fully signed:
   Algorithm: ECDSAP256SHA256: KSKs: 1 active, 0 stand-by, 0 revoked
                               ZSKs: 1 active, 0 stand-by, 0 revoked

Next Steps
----------

- Establishing the chain of trust to the parent.
- :doc:`Automating pre-publication checks <review-hooks>`.
- :doc:`Using a Hardware Security Module <hsms>`.
- Migrating an existing DNSSEC signed zone.
- `Getting support <https://nlnetlabs.nl/services/contracts/>`_.
