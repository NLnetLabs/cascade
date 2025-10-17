Building From Source
====================

There are two things you need to build Cascade: a C toolchain and Rust. You
can run Cascade on any operating system and CPU architecture where you can
fulfil these requirements.

Dependencies
------------

To get started, you need a C toolchain because the cryptographic primitives
used by Cascade require it. You also need Rust because that’s the programming
language that Cascade has been written in.

Additionally, you need a few tools used by Cascade. However, they are
installed together with Cascade in the steps below.

C Toolchain
"""""""""""

Some of the libraries Cascade depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum set of
packages to build from C sources. For example, this command will install
everything you need on Debian/Ubuntu:

.. code-block:: text

  apt install build-essential

If you are unsure, try to run :command:`cc` on a command line. If there is a
complaint about missing input files, you are probably good to go.

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

.. code-block:: text

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

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

Installing the latest Cascade (and dnst, a runtime dependency) is as simple as
running:

.. Installing the latest Cascade (and dnst, a runtime dependency) release from
.. crates.io is as simple as running:

.. Commented out until released
.. .. code-block:: text

  cargo install --locked cascade dnst

.. code-block:: text

  cargo install --locked --git https://github.com/nlnetlabs/cascade
  cargo install --locked --branch keyset --git https://github.com/nlnetlabs/dnst

The command will build Cascade and install it in the same directory that
Cargo itself lives in, likely ``$HOME/.cargo/bin``. Ensure this directory is
in your PATH so you can run Cascade immediately.

If you want to use a PKCS#11-based HSM with your Cascade instance, also
install the KMIP to PKCS#11 relay with:

.. Commented out until released
.. .. code-block:: text

  cargo install --locked kmip2pkcs11

.. code-block:: text

  cargo install --locked --git https://github.com/nlnetlabs/kmip2pkcs11

Finally, before running Cascade you will need to create a few directories and
Cascade's config file. Create the directory where you want to store the config
(let's say ``./cascade`` for this example), and generate an example
config file:

.. code-block:: text

  mkdir ./cascade
  cascade template config > ./cascade/config.toml

Then update the ``config.toml`` to use the appropriate paths.

Updating
""""""""

.. danger::

   In its current alpha version form Cascade does not yet support upgrading
   and will likely report errors if a newer version is started without first
   deleting the state and policy files created by an older version.
 
   Before upgrading do the following: *(if you modified any of the filesystem
   locations specified in your Cascade config file, use the updated paths
   instead of the default paths shown in these instructions)*
 
   .. code-block:: bash
 
      sudo pkill cascaded
      sudo rm -R /var/lib/cascade
      sudo rm -R /etc/cascade/policies

If you want to update to the latest version of Cascade, it’s recommended
to update Rust itself as well, using:

.. code-block:: text

    rustup update

Use the ``--force`` option to overwrite an existing version with the latest
Cascade release:

.. code-block:: text

    cargo install --locked --force --git https://github.com/nlnetlabs/cascade
    cargo install --locked --force --branch keyset --git https://github.com/nlnetlabs/dnst
..  cargo install --locked --force cascade dnst

Also for the KMIP to PKCS#11 relay if you are using it:

.. code-block:: text

    cargo install --locked --force --git https://github.com/nlnetlabs/kmip2pkcs11
..  cargo install --locked --force kmip2pkcs11

Installing Specific Versions
""""""""""""""""""""""""""""

If you want to install a specific version of
Cascade using Cargo, explicitly use the ``--version`` option. If needed,
use the ``--force`` option to overwrite an existing version:
        
.. code-block:: text

    cargo install --locked --force --git https://github.com/nlnetlabs/cascade --tag 0.1.0-alpha
..  cargo install --locked --force cascade --version 0.1.0-alpha

Make sure to install a compatible version of ``dnst``.

All new features of Cascade are built on a branch and merged via a `pull
request <https://github.com/NLnetLabs/Cascade/pulls>`_, allowing you to
easily try them out using Cargo. If you want to try a specific branch from
the repository you can use the ``--git`` and ``--branch`` options:

.. code-block:: text

    cargo install --git https://github.com/NLnetLabs/cascade.git --branch main
    
.. Seealso:: For more installation options refer to the `Cargo book
             <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.

Statically Linked Cascade
-------------------------

While Rust binaries are mostly statically linked, they depend on
:program:`libc` which, as least as :program:`glibc` that is standard on Linux
systems, is somewhat difficult to link statically. This is why Cascade
binaries are actually dynamically linked on :program:`glibc` systems and can
only be transferred between systems with the same :program:`glibc` versions.

However, Rust can build binaries based on the alternative implementation
named :program:`musl`, allowing you to statically link them. Building such
binaries is easy with :program:`rustup`. You need to install :program:`musl`
and the correct :program:`musl` target such as ``x86_64-unknown-linux-musl``
for x86\_64 Linux systems. Then you can just build Cascade for that
target.

On a Debian (and presumably Ubuntu) system, enter the following:

.. code-block:: bash

   sudo apt-get install musl-tools
   rustup target add x86_64-unknown-linux-musl
   cargo build --target=x86_64-unknown-linux-musl --release

Platform Specific Instructions
------------------------------

For some platforms, :program:`rustup` cannot provide binary releases to
install directly. The `Rust Platform Support`_ page lists
several platforms where official binary releases are not available, but Rust
is still guaranteed to build. For these platforms, automated tests are not
run so it’s not guaranteed to produce a working build, but they often work to
quite a good degree.

.. _Rust Platform Support:  https://doc.rust-lang.org/nightly/rustc/platform-support.html

OpenBSD
"""""""

On OpenBSD, `patches
<https://github.com/openbsd/ports/tree/master/lang/rust/patches>`_ are
required to get Rust running correctly, but these are well maintained and
offer the latest version of Rust quite quickly.

Rust can be installed on OpenBSD by running:

.. code-block:: bash

   pkg_add rust
