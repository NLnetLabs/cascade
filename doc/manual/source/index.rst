Cascade
=======

.. only:: html

   |lastupdated| |discourse| |mastodon|

   .. |lastupdated| image:: https://img.shields.io/github/last-commit/NLnetLabs/cascade?path=%2Fdoc%2Fmanual&label=last%20updated&color=orange
      :alt: Last docs update
      :target: https://github.com/NLnetLabs/cascade/commits/main/doc/manual/source

   .. |discourse| image:: https://img.shields.io/badge/Discourse-NLnet_Labs-orange?logo=Discourse
      :alt: Discourse
      :target: https://community.nlnetlabs.nl/c/cascade/10

   .. |mastodon| image:: https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social
      :alt: Mastodon
      :target: https://social.nlnetlabs.nl/@nlnetlabs

Cascade is a friendly, standalone :doc:`DNSSEC <intro>` signing solution
from NLnet Labs. It automates key management and :term:`zone` signing while keeping
operators informed and in control.

Cascade is currently in **beta**. It is ready for testing and evaluation,
but you should review the current :doc:`limitations` before using it. We
welcome :ref:`feedback about your experience <reach-out>` as we continue to
improve its functionality, performance, and operator experience.

.. tip:: New to Cascade? Start with :doc:`before-you-start`, then follow the
         :doc:`quick-start` to sign your first zone. To see what changed in
         beta1, read `"Cascade: Start your engines!"
         <https://blog.nlnetlabs.nl/cascade-beta1-release/>`_. Changes in
         subsequent versions are listed in the `release notes
         <https://github.com/NLnetLabs/cascade/releases/>`_.

Why Cascade?
------------

Simple deployment
   The Cascade pipeline runs as a single binary and does not require separate
   database software. Install a :doc:`binary package <installation>` or
   :doc:`build Cascade from source <building>`, then run it in any way that
   works for your infrastructure.

Safe automation
   Cascade provides sensible defaults based on industry best practices while
   giving you detailed control over :doc:`key management <key-management>`
   and the DNSSEC signing process.

Flexible key storage
   Keep keys on disk or use a :doc:`Hardware Security Module <hsms>`. Cascade
   supports several :term:`HSM <Hardware security module (HSM)>` integrations, so you can choose the setup that fits
   your operational and security requirements.

Observable signing
   Cascade is designed to communicate what it is doing. Its status, health,
   and metrics interfaces help you monitor operation, while
   :doc:`review-hooks` let you verify unsigned and :term:`signed zones <Signed zone>` with your own
   tooling before publication.

Standards-based integration
   Integrate Cascade into an existing DNS environment using
   :doc:`zone-transfers` and the available nameserver integrations.

Open source and professionally supported
   Cascade is open-source software developed by NLnet Labs. `Professional
   support and consultancy services
   <https://www.nlnetlabs.nl/services/contracts/>`_ are available with a
   service-level agreement.

Where to start
--------------

- Read :doc:`intro` for an introduction to DNSSEC and Cascade.
- Review :doc:`before-you-start` and the current :doc:`limitations`.
- Follow the :doc:`installation` and :doc:`quick-start` guides.
- Learn how Cascade handles :doc:`key-management` and
  :doc:`incremental-signing`.
- Connect an :doc:`HSM <hsms>` or configure a :doc:`nameserver integration
  <nsd>` when you are ready to build a production-style setup.
- Use the :doc:`faq`, command-line manual pages, and configuration-file
  references when operating or troubleshooting Cascade.

.. _reach-out:

Feedback
--------

Operator feedback is especially valuable during the beta. Please tell us
about missing functionality, unclear documentation, unexpected behavior,
performance, memory usage, and your overall experience. Details such as your
operating system, HSM, and the size and number of zones in your setup help us
understand your results.

You can reach us by:

- starting a discussion on the `NLnet Labs Community Forum
  <https://community.nlnetlabs.nl/c/cascade/10/>`_;
- creating a `GitHub issue
  <https://github.com/NLnetLabs/cascade/issues/>`_;
- joining the `NLnet Labs DNS
  <https://chat.dns-oarc.net/community/channels/ldns>`_ channel on the
  `DNS OARC Mattermost server
  <https://www.dns-oarc.net/oarc/services/chat>`_;
- mentioning us on `Mastodon
  <https://social.nlnetlabs.nl/@nlnetlabs/>`_; or
- sending the Cascade team an `email <mailto:cascade@nlnetlabs.nl>`_.

The Community Forum is the best place to discuss operational experiences,
share ideas, and request features. Positive reports are welcome too.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   intro
   before-you-start
   architecture
   installation
   building
   quick-start

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Core
   :name: toc-core

   key-management
   incremental-signing
   hsms
   review-hooks
   zone-transfers
   maintenance-mode
   metrics

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Guides
   :name: toc-guides

.. cascade-for-opendnssec-users

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Nameserver Integrations
   :name: toc-nameserver-integrations

   nsd

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: HSM Integrations
   :name: toc-hsm-integrations

   softhsm
   thales
   smartcard-hsm
   nethsm
.. fortanix
   nitrokey
   yubihsm


.. Commented out until these pages are written
.. .. toctree::
..    :maxdepth: 2
..    :hidden:
..    :caption: Advanced
..    :name: toc-advanced

..    migration
..    offline-ksk

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Reference
   :name: toc-reference

   faq
   limitations
   glossary

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Manual Pages
   :name: toc-manual-pages

   man/cascade
   man/cascaded
   man/cascaded-config.toml
   man/cascaded-policy.toml
   man/cascade-debug
   man/cascade-health
   man/cascade-hsm
   man/cascade-info
   man/cascade-keyset
   man/cascade-policy
   man/cascade-status
   man/cascade-template
   man/cascade-tsig
   man/cascade-zone
   cascade-hsm-bridge Daemon <https://cascade.docs.nlnetlabs.nl/projects/cascade-hsm-bridge/en/latest/man/cascade-hsm-bridge.html>
   cascade-hsm-bridge Configuration File Format <https://cascade.docs.nlnetlabs.nl/projects/cascade-hsm-bridge/en/latest/man/cascade-hsm-bridge-config.toml.html>

.. ^ need to work around lack of intersphinx links in toctree by creating a hyperlink
