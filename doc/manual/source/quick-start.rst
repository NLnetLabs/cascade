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

If using systemd to run Cascade, some of these settings should be ignored and
systemd features should be used instead.

.. tabs::

   .. group-tab:: Using systemd

        .. note::

           For a full explanation of systemd settings please consult the
           `systemd documentation <https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html>`_.

        When using Cascade with systemd some settings must be configured
        using the Cascade configuration file and others must be configured 
        via systemd.

        Systemd has built-in support for deamon features such as dropping
        privileges (see ``User=`` and ``Group=``), binding to privileged
        ports (port numbers below 1024) and forking the process to run in
        the background.

        To support binding to privileged ports without requiring elevated
        privileges Cascade supports the systemd `socket activation feature <https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html#>`_.
        To use this you will need to create a ``socket`` unit. An example
        ``cascade.socket`` unit might look as follows:

        .. code-block::

          [Unit]
          Description=Cascade Sockets
          
          [Socket]
          # To prevent listening on localhost replace 127.0.0.1:53 with a
          # blank value, e.g.
          # ListenStream=
          ListenDatagram=127.0.0.1:53
          ListenDatagram=[::1]:53
          ListenStream=127.0.0.1:53
          ListenStream=[::1]:53
          Accept=no
          
          [Install]
          WantedBy=sockets.target

        You may also need to add the following ``Requires`` line to the
        Cascade unit file:

        .. code-block::

           [Unit]
           Requires=cascade.socket

        To start Cascade use the following command: (you may need elevated
        privileges to run this command, e.g. run it as ``root`` or use a
        command such as ``sudo``)

        .. code-block::

           systemctl start cascade

   .. group-tab:: Without systemd

        When using Cascade without systemd, all configuration is done via the
        Cascade configuration file.

        To configure to listen on specific interfaces or ports see the ``servers``
        setting in the ``[server]`` section of Cascade's ``config.toml``:

        .. code-block:: text

            [server]
            servers = ["<your-ip>:<your-port>"]

        Then you can start Cascade with the following command. Replace the
        config and state path with values suitable for your system.

        .. note::
        
           If you configure Cascade to listen on a privileged port (port
           numbers below 1024) or use the daemonization ``identity`` feature,
           you will need to run the command with sufficient privileges, e.g.
           by running it as ``root`` or via a command such as ``sudo``.

        .. code-block:: bash

            cascaded --config /etc/cascade/config.toml --state /var/lib/cascade/state.db

Interacting with Cascade
------------------------

Cascade consists of two parts: the :program:`cascaded` daemon which runs
continuously, receiving, signing and publishing zone records, and the
:program:`cascade` CLI (command-line interface) tool which can be used to
inspect and control Cascade.

Using the CLI we can see that on first start Cascade has no policies and
no zones:

.. code-block:: bash

   $ cascade status
   Signing queue:
     The signing queue is currently empty.

   $ cascade policy list

   $ cascade zone list

.. Note:: The program:`cascade` CLI connects via HTTPS to the
   :program:`cascaded` daemon. By default it connects to 127.0.0.1:4539.
   You can override this by passing ``--server <IP>:<PORT>`` or by defining
   an environment variable ``CASCADE_DAEMON="<IP>:<PORT>"`` to connect to a
   Cascade daemon running on another machine or port.

The :program:`cascade` CLI is the primary means of interacting with the
:program:`cascaded` daemon.

For monitoring purposes Cascade supports `Prometheus <https://prometheus.io/>`_
which when combined with other tools such as `Grafana <https://grafana.com/grafana/>`_
and `Alertmanager <https://prometheus.io/docs/alerting/latest/alertmanager/>`_
enable visual insight into the behaviour of Cascade and early warning of
unexpected situations.

Additionally, while normally not needed, the CLI and the daemon produce logs
which can be inspected and if needed can be made more verbose. The CLI logs
to the terminal while the daemon typically logs to syslog or to a file. Both
the CLI and the daemon take a ``--log-level`` argument which can be used to
adjust the verbosity of the produced log output. It is also possible to use
the CLI to adjust the verbosity of an already running daemon, for example:

.. code-block:: bash

   $ cascade debug change-logging --level debug
   Changed log-level to: debug

.. _defining-policy:

Defining Policy
---------------

After configuring Cascade, you can begin adding zones. Cascade supports zones
sourced from a local file or fetched from another nameserver using XFR 
:term:`zone transfers <Zone transfer>`.

Zones take a lot of their settings from policy. Policies allow easy re-use of
settings across multiple zones and control things like whether or not zones
should be reviewed and how, what DNSSEC settings should be used to sign the
zone, and more.

Adding a policy is done by creating a file. To make it easy to get started we
provide a default policy template so we'll use that to create a policy for
our zone to use. The name of the policy is taken from the file name. The
directory to save the policy file to is determined by the
:option:`policy-dir` setting as configured in
:file:`/etc/cascade/config.toml`. 

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

    zone:   example.com
    policy: default
    source: /path/to/zonefile/example.txt

    review
      loaded: off
      signed: off

    last published
      loaded serial: 2001062501
      signed serial: 2026050600
      timestamp:     2026-06-02T12:53:10.158779414Z
      size:          10 records

    status: idle

    Published zone available at 127.0.0.1:4542

From the above you can see that the signed zone can be retrieved from
``127.0.0.1:4542`` using a DNS client, e.g.:

.. code-block:: bash

    dig @127.0.0.1 -p 4542 AXFR example.com

If you have the BIND `dnssec-verify
<https://bind9.readthedocs.io/en/latest/manpages.html#std-iscman-dnssec-verify>`_
tool installed, you can check that the zone is correctly DNSSEC signed:

.. code-block:: bash

   $ dig @127.0.0.1 -p 4542 example.com AXFR | dnssec-verify -o example.com /dev/stdin
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
