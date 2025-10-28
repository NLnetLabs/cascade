Building From Source
====================

There are three things you need to build Cascade: a C toolchain, OpenSSL, and
Rust. You can run Cascade on any operating system and CPU architecture
where you can fulfil these requirements.

Dependencies
------------

To get started, you need a C toolchain and OpenSSL because the cryptographic
primitives used by Cascade require it. You also need Rust, because that's the
programming language that Cascade has been written in. Additionally, you need
a few tools used by Cascade. However, they are installed together with
Cascade in the steps below.

C Toolchain
"""""""""""

Some of the libraries Cascade depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum set of
packages to build from C sources. For example, this command will install
everything you need on Debian/Ubuntu:

.. code-block:: bash

  apt install build-essential

If you are unsure, try to run :command:`cc` on a command line. If there is a
complaint about missing input files, you are probably good to go.

OpenSSL
"""""""

Your system will likely have a package manager that will allow you to install
OpenSSL in a few easy steps. For Cascade, you will need
:command:`libssl-dev`, sometimes called :command:`openssl-dev`. On
Debian-like Linux distributions, this should be as simple as running:

.. code-block:: bash

    apt install libssl-dev openssl pkg-config

Rust
""""

The Rust compiler runs on, and compiles to, a great number of platforms,
though not all of them are equally supported. The official `Rust Platform
Support`_ page provides an overview of the various support levels.

While some system distributions include Rust as system packages, Cascade
relies on a relatively new version of Rust, currently |rustversion| or newer.
We therefore suggest using the canonical Rust installation via a tool called
:program:`rustup`.

Assuming you already have :program:`curl` installed, you can install
:program:`rustup` and Rust by simply entering:

.. code-block:: bash

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

During installation :program:`rustup` will attempt to configure the ``PATH``.
Modifications to ``PATH`` may not take effect until the console is restarted,
or the user is logged out, or it may not succeed at all. If, after
installation, running :command:`rustc --version` in the console fails, this
is the most likely reason.

Building
--------

In Rust, a library or executable program such as Cascade is called a *crate*.
Crates are published on `crates.io <https://crates.io/>`_, the Rust package
registry. Cargo is the Rust package manager. It is a tool that allows Rust
packages to declare their various dependencies and ensure that you’ll always
get a repeatable build. 

Cargo fetches and builds Cascade’s dependencies into an executable binary
for your platform. By default, you install from crates.io, but you can for
example also install from a specific Git URL, as explained below.

Installing the latest Cascade (and :program:`dnst`, a runtime dependency) is
as simple as running:

.. Installing the latest Cascade (and dnst, a runtime dependency) release from
.. crates.io is as simple as running:

.. Commented out until released
.. .. code-block:: text

  cargo install --locked cascade dnst

.. code-block:: bash

  cargo install --locked --git https://github.com/nlnetlabs/cascade
  cargo install --locked --branch keyset --git https://github.com/nlnetlabs/dnst

The command will build Cascade and install it in the same directory that
Cargo itself lives in, likely ``$HOME/.cargo/bin``. Ensure this directory is
in your PATH so you can run Cascade immediately.

If you want to use a PKCS#11 compatible Hardware Security Module (HSM) with 
Cascade, also install the KMIP to PKCS#11 relay with:

.. Commented out until released
.. .. code-block:: text

  cargo install --locked kmip2pkcs11

.. code-block:: bash

  cargo install --locked --git https://github.com/nlnetlabs/kmip2pkcs11

Finally, before running Cascade you will need to create a few directories and
Cascade's config file. Create the directory where you want to store the config
(let's say ``./cascade`` for this example), and generate an example
config file:

.. code-block:: bash

  mkdir ./cascade
  cascade template config > ./cascade/config.toml

Then update the :file:`config.toml` to use the appropriate paths.

Updating
""""""""

.. tip::

   Read the :ref:`general updating instructions <updating>` first.

If you want to update to the latest version of Cascade, it’s recommended
to update Rust itself as well, using:

.. code-block:: bash

    rustup update

Use the ``--force`` option to overwrite an existing version with the latest
Cascade release:

.. code-block:: text

    cargo install --locked --force --git https://github.com/nlnetlabs/cascade
    cargo install --locked --force --branch keyset --git https://github.com/nlnetlabs/dnst
..  cargo install --locked --force cascade dnst

Also for the KMIP to PKCS#11 relay if you are using it:

.. code-block:: bash

    cargo install --locked --force --git https://github.com/nlnetlabs/kmip2pkcs11
..  cargo install --locked --force kmip2pkcs11

Installing Specific Versions
""""""""""""""""""""""""""""

If you want to install a specific version of Cascade using Cargo, explicitly
use the ``--version`` option. If needed, use the ``--force`` option to
overwrite an existing version:
        
.. code-block:: bash

    cargo install --locked --force --git https://github.com/nlnetlabs/cascade --tag 0.1.0-alpha3
..  cargo install --locked --force cascade --version 0.1.0-alpha

Make sure to install a compatible version of :program:`dnst`.

All new features of Cascade are built on a branch and merged via a `pull
request <https://github.com/NLnetLabs/Cascade/pulls>`_, allowing you to
easily try them out using Cargo. If you want to try a specific branch from
the repository you can use the ``--git`` and ``--branch`` options:

.. code-block:: bash

    cargo install --git https://github.com/NLnetLabs/cascade.git --branch main
    
.. Seealso:: For more installation options refer to the `Cargo book
             <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.

