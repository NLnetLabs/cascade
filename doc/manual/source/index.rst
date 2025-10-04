Cascade
=======

A friendly `DNSSEC <https://www.rfc-editor.org/rfc/rfc9364>`_ signing solution written in Rust, a programming language
designed for performance and memory safety.

Cascade has the following design goals:

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

We would love for you to :doc:`get to know Cascade
<before-you-start>`.

.. _reach-out:

.. tip:: Cascade is currently in its first *alpha version*, with documented :doc:`limitations`. Our goal is to gather operator feedback. Don't be shy and reach out. In particular:

     - If these documentation pages don't answer your question,
       `tell us what we missed <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - Performance and memory usage are expected to improve but if
       you think it won't meet your needs `tell us about your use case
       <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - Not all intended functionality has been implemented at this
       point. If a feature that you need is missing `please let us know
       <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - We are actively working to shape the user experience to operator needs.
       We have a lot more ideas for improvement and `we'd love to hear yours
       too <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - Do tell us about your positive experiences. Use social media (#cascade)
       or `create an issue <https://github.com/NLnetLabs/cascade/issues/new>`_.
       We particularly appreciate hearing O/S, HSM and size/number of zones you
       worked with.

   If GitHub isn't your thing you can also `contact us by email <mailto://cascade@nlnetlabs.nl>`_.

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
.. cascade-for-opendnssec-users

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Integrations
   :name: toc-integrations

   softhsm
   thales
.. fortanix
   nitrokey
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

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Manual Pages
   :name: toc-manual-pages

   man/cascade
   man/cascaded
   man/cascaded-config.toml
   man/cascaded-policy.toml
   man/cascade-config
   man/cascade-hsm
   man/cascade-keyset
   man/cascade-policy
   man/cascade-template
   man/cascade-zone
