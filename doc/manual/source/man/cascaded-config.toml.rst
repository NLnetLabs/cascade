Configuration File Format
=========================

Cascade uses the TOML format for its configuration file. A template can be
generated using ``cascade template config``. The provided values to the options
below are the default values and are serving as a hint to the option's format.

Example
-------

.. code-block:: text

    version = "v1"
    policy-dir = "/etc/cascade/policies"
    zone-state-dir = "/var/lib/cascade/zone-state"
    tsig-store-path = "/var/lib/cascade/tsig-keys.db"
    kmip-credentials-store-path = "/var/lib/cascade/kmip/credentials.db"
    keys-dir = "/var/lib/cascade/keys"
    kmip-server-state-dir = "/var/lib/cascade/kmip"
    dnst-binary-path = "/usr/libexec/cascade/cascade-dnst"

    [daemon]
    log-level = "info"
    log-target = { type = "stdout" }
    daemonize = false

    [remote-control]
    servers = ["127.0.0.1:4539", "[::1]:4539"]

    [loader]
    notify-listeners = ["127.0.0.1:4540", "[::1]:4540"]

    [loader.review]
    servers = ["127.0.0.1:4541", "[::1]:4541"]

    [signer]
    [signer.review]
    servers = ["127.0.0.1:4542", "[::1]:4542"]

    [key-manager]

    [server]
    servers = ["127.0.0.1:4543", "[::1]:4543"]

Options
-------

Global Options
++++++++++++++

.. option:: version = "v1"

   The configuration file version. (REQUIRED)

   This is the only required option.  All other settings, and their defaults,
   are associated with this version number.  More versions may be added in the
   future and Cascade may drop support for older versions over time.

   - ``v1``: This format.

.. option:: policy-dir = "/etc/cascade/policies"

   The directory storing zone policies.

   Zone policies are user-managed files configuring groups of zones.  You can
   modify them as you like, then ask Cascade to reload them with ``cascade
   policy reload``.

.. option:: zone-state-dir = "/var/lib/cascade/zone-state"

   The directory storing per-zone state files.

   Cascade maintains an internal state file for every known zone here.  These
   files should not be modified manually, but they can be backed up and
   restored in the event of filesystem corruption.

.. option:: tsig-store-path = "/var/lib/cascade/tsig-keys.db"

   The file storing TSIG key secrets.

   This is an internal state file containing sensitive cryptographic material.
   It should not be modified manually, but it can be backed up and restored in
   the event of filesystem corruption.  Carefully consider its security.

   Note: This setting is not used at present as the alpha version of Cascade
   does not yet support TSIG keys.

.. option:: kmip-credentials-store-path = "/var/lib/cascade/kmip/credentials.db"

   The file storing KMIP credentials.

   This is an internal state file containing sensitive KMIP server login
   credentials. It should not be modified manually, but it can be backed up
   and restored in the event of filesystem corruption.  Carefully consider
   its security.

.. option:: keys-dir = "/var/lib/cascade/keys"

   The directory storing rollover states and on-disk DNSSEC keys.

   For every zone, the state of its DNSSEC keys (which keys are used, on-going
   rollovers, etc.) are stored here.  If on-disk keys are used to sign zones,
   they are stored also here.

   The organization of this directory (file names and file formats) constitutes
   internal implementation details.  It should not be modified manually, but it
   can be backed up and restored in the event of filesystem corruption.
   Carefully consider its security.

.. option:: kmip-server-state-dir = "/var/lib/cascade/kmip"

   The directory containing KMIP server state.

   Information about known KMIP servers is stored in this directory.

   The organization of this directory (file names and file formats) constitutes
   internal implementation details.  It should not be modified manually, but it
   can be backed up and restored in the event of filesystem corruption.

.. option:: dnst-binary-path = "/usr/libexec/cascade/cascade-dnst"

   The path to the dnst binary Cascade should use.

   Cascade relies on a Cascade specific verison of the (not yet officially
   released) ``dnst`` program (<https://github.com/NLnetLabs/dnst>) in order
   to perform DNSSEC key management.  You can specify an absolute path here, or
   just ``dnst`` if it is in $PATH.



Settings relevant to any daemon program.
++++++++++++++++++++++++++++++++++++++++

The ``[daemon]`` section.

.. option:: log-level = "info"

   The minimum severity of the messages logged by the daemon.

   Messages at or above the specified severity level will be logged.  The
   following levels are defined:

   - ``trace``: A function or variable was interacted with, for debugging.
   - ``debug``: Something occurred that may be relevant to debugging.
   - ``info``: Things are proceeding as expected.
   - ``warning``: Something does not appear to be correct.
   - ``error``: Something went wrong (but Cascade can recover).
   - ``critical``: Something went wrong and Cascade can't function at all.

.. option:: log-target = { type = "stdout" }
.. option:: log-target = { type = "stderr" }
.. option:: log-target = { type = "syslog" }
.. option:: log-target = { type = "file", path = "cascaded.log" }

   The location the daemon writes logs to.

   - type ``file``: Logs are appended line-by-line to the specified file path.

     If it is a terminal, ANSI escape codes may be used to style the output.

   - type ``stdout``: Logs are written to stdout. (The default)

     If it is a terminal, ANSI escape codes may be used to style the output.

   - type ``stderr``: Logs are written to stderr.

     If it is a terminal, ANSI escape codes may be used to style the output.

   - type ``syslog``: Logs are written to the UNIX syslog.

     This option is only supported on UNIX systems.

.. option:: daemonize = false

   Whether to apply internal daemonization.

   'Daemonization' involves several steps:

   - Forking the process to disconnect it from the terminal
   - Tracking the new process' PID (by storing it in a file)
   - Binding privileged ports (below 1024) as configured
   - Dropping administrator privileges

   These features may be provided by an external system service manager, such
   as systemd.  If no such service manager is being used, Cascade can provide
   such features itself, by setting this option to ``true``.  This will also
   enable the ``pid-file`` and ``identity`` settings (although they remain
   optional).

.. TODO: Link to a dedicated systemd / daemonization guide for Cascade.

.. option:: pid-file = "/var/run/cascade.pid"

   The path to a PID file to maintain, if any.

   If specified, Cascade will maintain a PID file at this location; it will be
   a simple plain-text file containing the PID number of the daemon process.
   This option is only supported if ``daemonize`` is true.

.. option:: identity = "cascade:cascade"

   An identity (user and group) to assume after startup.

   Cascade will assume the specified identity after initialization.  Note that
   this will fail if Cascade is started without administrator privileges.  This
   option is only supported if ``daemonize`` is ``true``.

   The identity can be specified as ``<user>:<group>`` or just ``<user>``; in the
   latter case, the identically named group will be used.  Numeric IDs are not
   supported; only names can be used.

   .. NOTE:: When using systemd, you should rely on its 'User=' and 'Group='
       options instead.  See <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User=>.


How Cascade is controlled.
++++++++++++++++++++++++++

The ``[remote-control]`` section.

.. option:: servers = ["127.0.0.1:4539", "[::1]:4539"]

   Where to serve Cascade's HTTP API.

   The HTTP API can be used to monitor and control Cascade.  The addresses
   refer to TCP sockets that will be listened on for HTTP requests.  At the
   moment, security mechanisms like TLS are not supported.

   These sockets may be bound by systemd and passed into Cascade.  If systemd
   does not provide them, Cascade will bind them itself (and will do so before
   dropping privileges, if that is enabled).


How zones are loaded.
+++++++++++++++++++++

The ``[loader]`` section.

.. option:: notify-listeners = ["127.0.0.1:4540", "[::1]:4540"]

   Where to listen for zone change notifications.

   A DNS server will be bound to these addresses.  If a DNS NOTIFY message for
   a known zone is received there, the zone will be reloaded appropriately.

   Unless explicitly specified (e.g. ``udp://localhost:4540``), each address will
   be served over UDP and TCP.  An empty array will disable listening entirely.

   These sockets may be bound by systemd and passed into Cascade.  If systemd
   does not provide them, Cascade will bind them itself (and will do so before
   dropping privileges, if that is enabled).


How loaded zones are reviewed.
++++++++++++++++++++++++++++++

The ``[loader.review]`` section.

.. option:: servers = ["127.0.0.1:4541", "[::1]:4541"]

   Where to serve loaded zones for review.

   A DNS server will be bound to these addresses, and will serve the contents
   of all loaded zones.  This can be used to verify the consistency of these
   zones.

   Unless explicitly specified (e.g. ``udp://localhost:4541``), each address will
   be served over UDP and TCP.  An empty array will disable serving entirely.

   These sockets may be bound by systemd and passed into Cascade.  If systemd
   does not provide them, Cascade will bind them itself (and will do so before
   dropping privileges, if that is enabled).


How zones are signed.
+++++++++++++++++++++

The ``[signer]`` section. (This only includes the ``[signer.review]`` section
below, for now).

How signed zones are reviewed.
++++++++++++++++++++++++++++++

The ``[signer.review]`` section.

.. option:: servers = ["127.0.0.1:4542", "[::1]:4542"]

   Where to serve signed zones for review.

   A DNS server will be bound to these addresses, and will serve the contents
   of all signed (but not necessarily published) zones.  This can be used to
   check the correctness of the signer.

   Unless explicitly specified (e.g. ``udp://localhost:4542``), each address will
   be served over UDP and TCP.  An empty array will disable serving entirely.

   These sockets may be bound by systemd and passed into Cascade.  If systemd
   does not provide them, Cascade will bind them itself (and will do so before
   dropping privileges, if that is enabled).


DNSSEC key management.
++++++++++++++++++++++

The ``[key-manager]`` section. (Currently without options)


How zones are published.
++++++++++++++++++++++++

The ``[server]`` section.

.. option:: servers = ["127.0.0.1:4543", "[::1]:4543"]

   Where to serve published zones.

   A DNS server will be bound to these addresses, and will serve the contents
   of all published zones.  This is the final output from Cascade.

   Unless explicitly specified (e.g. ``udp://localhost:4543``), each address will
   be served over UDP and TCP.  At least one address must be specified.

   These sockets may be bound by systemd and passed into Cascade.  If systemd
   does not provide them, Cascade will bind them itself (and will do so before
   dropping privileges, if that is enabled).


Files
-----

/etc/cascade/config.toml
    Default Cascade config file

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascaded**\ (1)
    :doc:`cascaded`
