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

.. seealso::

   :doc:`hsms`
      Hardware Security Modules (HSMs).

Installing ang Building
-----------------------

Can I build Cascade with LibreSSL?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

No, OpenSSL 3.x is required as these versions fully support Edwards-curve
Digital Security Algorithm (EdDSA) keys and signatures using the Ed448 curve
(DNSSEC algorithm 16). In contrast, LibreSSL `does not yet have support
<https://github.com/libressl/portable/issues/552>`_ for Ed448. 

Ed448 was standardized for use with DNSSEC in February 2017 (:RFC:`8080`) and
has been a RECOMMENDED algorithm since June 2019 (:RFC:`8624`). 

.. seealso::

   :ref:`building:openssl`
      Installing OpenSSL on common distributions, such as Debian, Ubuntu and
      Red Hat Enterprise Linux. 