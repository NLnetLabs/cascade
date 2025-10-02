Cascade
=======

A friendly DNSSEC signing solution written in Rust, a programming
language designed for performance and memory safety.

Flexibility
   Run Cascade the way that you want: from a package or a Docker image,
   on-premise or in the cloud, with keys on disk or an HSM of your
   choice.

Sensible defaults
   Get started easily with default settings based on industry 
   best practices. 

Controllability
   Cascade gives you tight control over the DNSSEC signing process and
   offers validation hooks at each stage of the process. 

Observability
   With Cascade you cut out the guesswork. You will know what the
   pipeline is doing and why, and what you can expect to happen next.

Open-source with professional support services
   NLnet Labs offers `professional support and consultancy services
   <https://www.nlnetlabs.nl/services/contracts/>`_ with a service-level
   agreement. Cascade is liberally licensed under the `BSD 3-Clause license
   <https://github.com/NLnetLabs/cascade/blob/main/LICENSE>`_.

Cascade is ONLY a DNSSEC signing solution and not a complete primary name
server. To read what that entails, read the :doc:`before you start
<before-you-start>` section.

   .. only:: html

      |mastodon|

      .. |mastodon| image:: https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social
         :alt: Mastodon
         :target: https://social.nlnetlabs.nl/@nlnetlabs

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

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

   cli
   hsms
   review-hooks

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Guides
   :name: toc-guides

   importing-keys
   cascade-for-opendnssec-users

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Integrations
   :name: toc-integrations

   fortanix
   nitrokey
   softhsm
   thales
   yubihsm
   

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Advanced
   :name: toc-advanced

   migration
   offline-ksk

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Reference
   :name: toc-reference

   limitations
