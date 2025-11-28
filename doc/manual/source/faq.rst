Frequently Asked Questions
==========================

.. contents::
   :local:

..
  Frequently asked questions should be questions that actually got asked.
  Formulate them as a question and an answer.
  Consider that the answer is best as a reference to another place in the documentation.


Design and Architecture
-----------------------

Why did you build this project in Rust?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Because Cascade is written in the Rust programming language, it is
significantly less likely to crash or suffer from memory safety issues. Rust
also makes it easier to leverage the higher core count of modern computers
through "`fearless concurrency
<https://doc.rust-lang.org/book/ch16-00-concurrency.html>`_".

.. seealso::

   `Rust Programming Language website <https://rust-lang.org>`_
      An overview of Rust's feature set.


Do I need separate database software to run Cascade?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No, the Cascade pipeline runs as a single binary and no additional database
software is required. Cascade stores its state in on-disk files in JSON
format, by default at various locations under a single parent directory. As
such, state is human-readable and easily backed up.

.. seealso::

   :doc:`architecture`
      An overview of Cascade's design.

Do I need to use a HSM to run Cascade?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No, Cascade does not require a Hardware Security Module (HSM) to operate.
While it is common practice to secure cryptographic key material using an HSM,
not all operators use an HSM. Cascade is able to use OpenSSL and/or ring
software cryptography to generate signing keys and to cryptographically sign
DNS RRset data, storing the generated keys in on-disk files.

Why is the default policy KSK/ZSK and not CSK?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Key rolls should be automatic and frequent.
Frequent key rolls help to ensure that key rolls are normal operational
practice and not an exception.
Key rolls should be automated as much as possible to avoid mistakes.
Unfortuantely, the standard for updating DS records (CDS, RFC 8078) is not
widely implemented so in many cases a KSK roll has to have a manual component.

These factors favor the KSK/ZSK split because it makes frequent ZSK rolls
possible and KSK rolls can limited to something reasonable.

Finally KSK and ZSK key rolls are less complex than CSK rolls.
Some people use a CSK and never roll the key.
That avoids the key roll complexity but leads to a lack opf operational
practice when a situation arises that a key roll is needed.

Why are the default key lifetimes the way they are?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ZSK roll requires re-signing the entire zone.
For bigger zones, this should not be done too often to keep the overhead of the key roll low.
Once a month seems an nice compromise.

A KSK roll requires updating the DS RRset in the parent zone.
For this reason a KSK once a year is a good compromise.


.. seealso::

   :doc:`hsms`
      Hardware Security Modules (HSMs).

Installing ang Building
-----------------------

Can I build Cascade with LibreSSL?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No, OpenSSL 3.x is required as these versions fully support Edwards-curve
Digital Security Algorithm (EdDSA) keys and signatures using the Ed448 curve
(DNSSEC algorithm 16). By contrast, LibreSSL `does not yet have support
<https://github.com/libressl/portable/issues/552>`_ for Ed448. 

Ed448 was standardized for use with DNSSEC in February 2017 (:RFC:`8080`) and
has been a RECOMMENDED algorithm since June 2019 (:RFC:`8624`). 

.. seealso::

   :ref:`Install OpenSSL <building:openssl>`
      Installing OpenSSL on common distributions, such as Debian, Ubuntu and
      Red Hat Enterprise Linux. 
