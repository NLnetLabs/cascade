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

Cascade is written in the Rust programming language, making it significantly
less likely to crash or suffer from memory safety issues. When needed, Rust
makes it easier to leverage the higher core count of modern computers through
"`fearless concurrency
<https://doc.rust-lang.org/book/ch16-00-concurrency.html>`_".

.. seealso::

   `Rust Programming Language website <https://rust-lang.org>`_
      An overview of Rust's feature set.


Do I need separate database software to run Cascade?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Cascade pipeline runs as a single binary and no additional database
software is required. 

Cascade stores its state in on-disk files in JSON format, by default at
various locations under a single parent directory. As such, state is
human-readable and easily backed up.

.. seealso::

   :doc:`architecture`
      An overview of Cascade's design.