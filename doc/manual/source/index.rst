Cascade
=======

.. admonition:: Alpha version

   Cascade is currently in its first alpha version. What can you expect from
   Cascade in its alpha form:

     - If these documentation pages don't answer your question,
       `tell us what we missed <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - The included functionality *should work* correctly for simple scenarios
       with correct inputs when running on setups (O/S, HSM) that we have
       tested on.
     - Handling of incorrect inputs, edge cases, more complex
       scenarios, non-default policy settings, and so on *may be
       incomplete or incorrect*. Please `report any bugs you find
       <https://github.com/NLnetLabs/cascade/issues/new>`_
     - The user experience is a *work-in-progress*. The goal of Cascade
       is not only to be a correctly functioning DNSSEC signer which
       makes it easy to do the right thing and hard to do the wrong
       thing, it should also be obvious how to use it and be clear what
       the system did, is doing now and will do in the future. But we're
       not there yet, we have more ideas but `we'd love to hear yours too
       <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - Not all intended functionality has been implemented at this
       point. If a feature that you need is missing `please let us know
       <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - Performance and memory usage are expected to improve but if
       you think it won't meet your needs `tell us about your use case
       <https://github.com/NLnetLabs/cascade/issues/new>`_. *We run
       Cascade ourselves* at cascade.nlnetlabs.nl but it hasn't been
       running for very long so there may be issues when left running
       for a longer time. If that happens `we want to know about it
       <https://github.com/NLnetLabs/cascade/issues/new>`_.
     - If it works for you post on social media with hashtag #cascade or `post
       an issue <https://github.com/NLnetLabs/cascade/issues/new>`_ telling us
       which O/S, HSM and size/number of zones it worked for.
     - Help us out with more data and more platforms. We test with various
       data sources and with the operating systems and HSMs available to
       us. If you can give us more data to test with, help with building and
       testing on more platforms, have an HSM you can let us use (especially
       hardware we can use for performance testing) please `contact us 
       <mailto://cascade@nlnetlabs.nl>`_.

   If GitHub isn't your thing you can also
   `contact us by email <mailto://cascade@nlnetlabs.nl>`_.

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
