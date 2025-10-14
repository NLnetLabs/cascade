Policy File Format
==================

A policy is a collection of settings that apply to a group of zones known to
Cascade.  Policy controls how Cascade operates on those zones, e.g. how they
are signed. This page describes all possible settings and their defaults. You
can generate a template with these default values using ``cascade template
policy``.

Policy files are managed by the user, and are stored at a configurable path
(by default, ``/etc/cascade/policies``).  You can add, modify, and remove
policy files, then update Cascade with ``cascade policy reload``.  Note that:

- Cascade maintains an internal copy of all policies, and will use this until
  ``cascade policy reload`` is used.  If reloading fails, Cascade will continue
  to use its existing internal copy.  It won't reload policies if it restarts.

- Policies cannot be removed if they are attached to zones; those zones need
  to be deleted or shifted to a different policy first.  If you remove a used
  policy and reload policies in Cascade, it will fail and continue to use its
  internal copy of the policy.

- Only policy files stored in the configured policy directory and having a
  ``.toml`` extension will be loaded by Cascade.`

.. note::

   In the current alpha release, changes to some policy options (e.g. review
   hook) also require a server restart in addition to running ``cascade policy
   reload`` to take effect.

Example
-------

.. code-block:: text

    version = "v1"

    [loader]
    [loader.review]
    required = false

    [key-manager]
    ksk.validity = "31536000"
    zsk.validity = "2592000"
    csk.validity = "31536000"
    ksk.auto-start = true
    zsk.auto-start = true
    csk.auto-start = true
    algorithm.auto-start = true
    ksk.auto-report = true
    zsk.auto-report = true
    csk.auto-report = true
    algorithm.auto-report = true
    ksk.auto-expire = true
    zsk.auto-expire = true
    csk.auto-expire = true
    algorithm.auto-expire = true
    ksk.auto-done = true
    zsk.auto-done = true
    csk.auto-done = true
    algorithm.auto-done = true
    ds-algorithm = "SHA256"
    auto-remove = true

    [key-manager.records]
    ttl = 3600
    dnskey.signature-inception-offset = 86400
    cds.signature-inception-offset = 86400
    dnskey.signature-lifetime = 1209600
    cds.signature-lifetime = 1209600
    dnskey.signature-remain-time = 604800
    cds.signature-remain-time = 604800

    [key-manager.generation]
    use-csk = false
    algorithm = "ECDSAP256SHA256"

    [signer]
    serial-policy = "date-counter"
    signature-inception-offset = 86400
    signature-lifetime = 1209600
    signature-remain-time = 604800

    [signer.denial]
    type = "nsec"

    [signer.review]
    required = false

    [server.outbound]
    send-notify-to = []


Options
-------

Global Options
++++++++++++++

.. option:: version = "v1"

   The policy file version. (REQUIRED)

   This is the only required option.  All other settings, and their defaults,
   are associated with this version number.  More versions may be added in the
   future and Cascade may drop support for older versions over time.

   - ``v1``: This format.


How zones are loaded.
+++++++++++++++++++++

The ``[loader]`` section.


.. _policy-loaded-review:

How loaded zones are reviewed.
++++++++++++++++++++++++++++++

The ``[loader.review]`` section.

Review offers an opportunity to perform external checks on the zone contents
loaded by Cascade.

.. option:: required = false

   Whether review is required.

   If this is ``true``, a loaded version of a zone will not be signed or
   published until it is approved.  If it is ``false``, loaded zones will be
   signed immediately.  At the moment, the review hook will only be run if this
   is set to true.

.. option:: cmd-hook = ""

   A hook for reviewing a loaded zone. This is a path to an executable.

   This command string will be executed in the user's shell when a new version
   of a zone is loaded.  At the moment, it will only be run if ``required`` is
   true.

   It will receive the following information via environment variables:

   - ``CASCADE_ZONE``: The name of the zone, formatted without a trailing dot.
   - ``CASCADE_SERIAL``: The serial number of the zone (decimal integer).
   - ``CASCADE_SERVER``: The combined address and port where Cascade is serving
       the zone for review, formatted as ``<ip-addr>:<port>``.
   - ``CASCADE_SERVER_IP``: Just the address of the above server.
   - ``CASCADE_SERVER_PORT``: Just the port of the above server.
   
   The command will be called from an unspecified directory, and it must be
   accessible to Cascade (i.e. after it has dropped privileges). Its exit code
   will determine whether the zone is approved or not.


DNSSEC key management.
++++++++++++++++++++++

The ``[key-manager]`` section.

.. option:: ksk.validity = "31536000"
.. option:: zsk.validity = "2592000"
.. option:: csk.validity = "31536000"

   How long keys are considered valid for.

   If a key has been used for longer than this time, it is considered expired,
   and (if enabled) it will automatically be rolled over to a new key.  Even if
   automatic rollovers are not enabled, the key will be reported as expired.
   This is a soft condition -- DNSSEC does not have a concept of key expiry,
   and it will not break DNSSEC validation, but it is usually important to the
   security of the zone.

   Independent validity times are set for KSKs, ZSKs, and CSKs.  An integer
   value will be interpreted as seconds; ``forever`` means keys never expire.

.. option:: ksk.auto-start = true
.. option:: zsk.auto-start = true
.. option:: csk.auto-start = true
.. option:: algorithm.auto-start = true

   Whether to automatically start key rollovers.

   If this is enabled, Cascade will automatically start rolling over keys when
   they expire (as per ``validity``).  When using this setting, ``validity`` must
   not be set to ``forever``.

   The first step in a rollover will be to generate new keys to replace old
   ones. By disabling this setting, the user can manually control how new keys
   are generated, and when rollovers happen.

.. option:: ksk.auto-report = true
.. option:: zsk.auto-report = true
.. option:: csk.auto-report = true
.. option:: algorithm.auto-report = true

   Whether to automatically check for record propagation.

   If this is enabled, Cascade will automatically contact public DNS servers to
   detect when new records (e.g. DNSKEY) are visible globally.  It is necessary
   to wait until some records are visible globally to progress key rollovers.  If
   this is disabled, the user will have to inform Cascade when these conditions
   are reached manually.

   For this setting to work, Cascade must have network access to the zone's
   public nameservers and the parent zone's public nameservers.

.. option:: ksk.auto-expire = true
.. option:: zsk.auto-expire = true
.. option:: csk.auto-expire = true
.. option:: algorithm.auto-expire = true

   Whether to automatically wait for cache expiry.

   If this is enabled, Cascade will automatically progress through key rollover
   steps that need to wait for downstream users' DNS caches to expire.  It will
   estimate the right amount of time to wait based on record TTLs.

.. option:: ksk.auto-done = true
.. option:: zsk.auto-done = true
.. option:: csk.auto-done = true
.. option:: algorithm.auto-done = true

   Whether to automatically check for rollover completion.

   Like ``auto-report``, if this setting is enabled, Cascade will automatically
   contact public DNS servers to detect when new records are visible globally.
   ``auto-done`` specifically affects automatic checks for the last step of key
   rollovers, and is independent from ``auto-report``.

   For this setting to work, Cascade must have network access to the zone's
   public nameservers and the parent zone's public nameservers.

.. option:: ds-algorithm = "SHA-256"

   The hash algorithm used by the parent zones' DS records.

   Supported options:

   - ``SHA-256``: SHA-256.
   - ``SHA-384``: SHA-384.

.. option:: auto-remove = true

   Whether to automatically remove expired keys.

   If this is set, expired keys will be removed automatically (by deleting the
   files for on-disk keys or removing it from the HSM).


The management of DNS records by the key manager.
+++++++++++++++++++++++++++++++++++++++++++++++++

The ``[key-manager.records]`` section.

The key manager generates and signs several records (DNSKEY and CDS).  This
section controls its behaviour towards them.

.. option:: ttl = 3600

   The TTL for the generated records.

.. option:: dnskey.signature-inception-offset = 86400
.. option:: cds.signature-inception-offset = 86400

   The offset for generated signature inceptions.

   Record signatures have a fixed inception time, from when they are considered
   valid.  An imprecise computer clock could cause signatures to be considered
   invalid, because their inception point appears to be some time in the future.
   To prevent such cases, this setting allows the inception time to be offset
   into the past.

   Independent offsets can be set for each type of record.  An integer value is
   intepreted as seconds; inception times will be calculated as ``now - offset``
   at the time of signing.

.. option:: dnskey.signature-lifetime = 1209600
.. option:: cds.signature-lifetime = 1209600

   The lifetime of generated signatures.

   Record signatures have a fixed lifetime, after which they are considered
   invalid.  To keep the zone valid, the signatures should be regenerated before
   they expire; see ``signature-remain-time`` to control regeneration time.

   Independent lifetimes can be set for each type of record.  An integer value is
   interpreted as seconds.

.. option:: dnskey.signature-remain-time = 604800
.. option:: cds.signature-remain-time = 604800

   The amount of time remaining before expiry when signatures will be
   regenerated.

   In order to prevent a zone's signatures from appearing invalid, they
   have to be regenerated before they expire.  That hard limit is set by
   ``signature-lifetime`` above.  This setting controls how long before expiry
   signatures will be regenerated; it must be less than the ``signature-lifetime``
   setting.

   Independent waiting times can be set for each type of record.  An integer
   value is interpreted as seconds.

How keys are generated.
+++++++++++++++++++++++

The ``[key-manager.generation]`` section.

.. option:: hsm-server-id = ""

   The HSM server to use.

   If this is set, the named HSM server (which must be configured via ``cascade
   hsm add``) will be used for generating new DNSSEC keys.

   See https://cascade.docs.nlnetlabs.nl/en/latest/hsms.html for more
   information.

.. option:: use-csk = false

   Whether to generate CSKs, instead of separate ZSKs and KSKs.

   A CSK (Combined Signing Key) takes the role of both ZSK and KSK for a zone,
   unlike the standard practice of using separate keys for ZSK and KSK.  This
   setting does not affect how DNSSEC validation is performed, only procedures
   for key rollovers.

   If this is enabled, Cascade will generate CSKs for the associated zones.

.. option:: algorithm = "ECDSAP256SHA256"

   The cryptographic algorithm (and parameters) for generated keys.

   DNSSEC supports various cryptographic algorithms for signatures; one must be
   selected, and for some algorithms, additional parameters are also necessary.
   The same algorithm and parameters will be applied to the ZSK and KSK.

   - ``RSASHA256[:<bits>]``, algorithm 8, with a public key size of
     ``<bits>`` (default 2048) bits.
   - ``RSASHA512[:<bits>]``, algorithm 10, with a public key size of
     ``<bits>`` (default 2048) bits.
   - ``ECDSAP256SHA256``, algorithm 13.
   - ``ECDSAP384SHA384``, algorithm 14.
   - ``ED25519``, algorithm 15.
   - ``ED448``, algorithm 16.

   There are additional algorithms, but many are now considered insecure, and
   it is recommended or mandated to avoid them.  In addition, RSA keys smaller
   than 2048 bits are not recommended.

   .. NOTE:: At the moment, only RSASHA256 and ECDSAP256SHA256 work with HSMs.
       Other algorithms cannot be used with HSMs, and will cause generation
       failures.


How zones are signed.
+++++++++++++++++++++

The ``[signer]`` section.

Note that certain records (e.g. DNSKEY and CDS records at the apex of the
zone) are signed by the key manager, rather than the zone signer; see the
``[key-manager.records]`` section for configuring the signing of those records.

.. option:: serial-policy = "date-counter"

   How SOA serial numbers are generated for signed zones.

   Supported options:

   - ``keep``: use the same serial number as the unsigned zone.
   - ``counter``: increment the serial number every time.
   - ``unix-time``: use the current Unix time, in seconds.
   - ``date-counter``: format the number as ``<YYYY><MM><DD><xx>`` in decimal.
     ``<xx>`` is a simple counter to allow up to 100 versions per day.

.. option:: signature-inception-offset = 86400

   The offset for generated signature inceptions.

   Record signatures have a fixed inception time, from when they are considered
   valid.  An imprecise computer clock could cause signatures to be considered
   invalid, because their inception point appears to be some time in the
   future. To prevent such cases, this setting allows the inception time to be
   offset into the past.

   An integer value is interpreted as seconds; inception times will be
   calculated as ``now - offset`` at the time of signing.

.. option:: signature-lifetime = 1209600

   The lifetime of generated signatures.

   Record signatures have a fixed lifetime, after which they are considered
   invalid.  To keep the zone valid, the signatures should be regenerated before
   they expire; see ``signature-remain-time`` to control regeneration time.

   An integer value is interpreted as seconds.

.. option:: signature-remain-time = 604800

   The amount of time remaining before expiry when signatures will be
   regenerated.

   In order to prevent a zone's signatures from appearing invalid, they
   have to be regenerated before they expire.  That hard limit is set by
   ``signature-lifetime`` above.  This setting controls how long before expiry
   signatures will be regenerated; it must be less than the ``signature-lifetime``
   setting.

   An integer value is interpreted as seconds.

How denial-of-existence records are generated.
++++++++++++++++++++++++++++++++++++++++++++++

The ``[signer.denial]`` section.

.. option:: type = "nsec"

   The type of denial-of-existence records to generate.

   Supported options:
   - ``nsec``: Use NSEC records (RFC 4034).
   - ``nsec3``: Use NSEC3 records (RFC 5155).

.. option:: opt-out = false

   (Only set when using NSEC3)

   Whether to skip NSEC3 records for unsigned delegations.

   This enables the NSEC3 Opt-Out flag, and skips delegations to unsigned zones
   when generating NSEC3 records.  This affects the security of the zone, so be
   careful if you wish to enable it.

.. _policy-signed-review:

How signed zones are reviewed.
++++++++++++++++++++++++++++++

The ``[signer.review]`` section.

.. option:: [signer.review]

   How signed zones are reviewed.

.. option:: required = false

   Whether review is required.

   If this is ``true``, a signed version of a zone will not be published until it
   is approved.  If it is ``false``, signed zones will be published immediately.
   At the moment, the review hook will only be run if this is set to true.

.. option:: cmd-hook = ""

   A hook for reviewing a signed zone. This is a path to an executable.

   This command string will be executed in the user's shell when a new version of
   a zone is signed.  At the moment, it will only be run if ``required`` is true.

   It will receive the following information via environment variables:

   - ``CASCADE_ZONE``: The name of the zone, formatted without a trailing dot.
   - ``CASCADE_SERIAL``: The serial number of the signed zone (decimal integer).
   - ``CASCADE_SERVER``: The combined address and port where Cascade is serving
       the zone for review, formatted as ``<ip-addr>:<port>``.
   - ``CASCADE_SERVER_IP``: Just the address of the above server.
   - ``CASCADE_SERVER_PORT``: Just the port of the above server.

   The command will be called from an unspecified directory, and it must be
   accessible to Cascade (i.e. after it has dropped privileges). Its exit code
   will determine whether the zone is approved or not.


How published zones are served.
+++++++++++++++++++++++++++++++

The ``[server.outbound]`` section.

.. option:: send-notify-to = []

   The set of nameservers to which NOTIFY messages should be sent.

   If empty, no NOTIFY messages will be sent.

   A collection of ``IP:[port]``, defaulting to port 53 when not specified, e.g.:
   ``send-notify-to = ["[::1]:53"]``


Files
-----

/etc/cascade/config.toml
    Default Cascade config file

/etc/cascade/policies
    Default policies directory

See Also
--------

https://cascade.docs.nlnetlabs.nl
    Cascade online documentation

**cascade**\ (1)
    :doc:`cascade`

**cascaded**\ (1)
    :doc:`cascaded`

**cascaded-config.toml**\ (5)
    :doc:`cascaded-config.toml`
