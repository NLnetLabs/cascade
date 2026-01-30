FROM ubuntu:latest

USER root

SHELL [ "/bin/bash", "--login", "-e", "-o", "pipefail", "-c" ]

# We are using multiple "RUN" steps to make good use of caching of the
# container build steps. It makes building the container image faster when
# only changing things in the later steps.

RUN <<EOF
  # Install packages
  export DEBIAN_FRONTEND=noninteractive
  apt-get update

  # For rustup (for common Actions scripts)
  apt-get install -y build-essential curl

  # Node.js (for common Actions scripts)
  apt-get install -y nodejs

  # DNS
  apt-get install -y bind9 bind9-dnsutils nsd unbound

  # OpenSSL (used by Cascade)
  apt-get install -y pkg-config libssl-dev

  apt-get install -y file
EOF

RUN <<EOF
  # Install Rust
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
EOF

ARG MSRV

RUN <<EOF
  # Also install other rust toolchains
  rustup toolchain install nightly $MSRV
  rustup default stable
EOF

RUN <<EOF
  # Install dnst
  cargo install --debug --git https://github.com/nlnetlabs/dnst --branch keyset --root /root/cargo-debug --locked --bin=dnst
  cargo install --git https://github.com/nlnetlabs/dnst --branch keyset --root /root/cargo-release --locked --bin=dnst
EOF

# Make sure this stays at the end of the Dockerfile to make best use of image step caching
# COPY --exclude=target --exclude=.git --exclude=.github --exclude=act-wrapper --exclude=doc . /cascade/
# Only copy the build relevant files into the container (this ensures that the
# container is only re-built when cascade build relevant files have changed)
COPY etc/ /cascade/etc/
COPY Cargo.toml Cargo.lock /cascade/
COPY src/ /cascade/src/

RUN <<EOF
  cd /cascade/

  ls -lha

  # Build Cascade
  cargo build
  cargo build --release

  # Save built binaries
  cp -v -t /root/cargo-release/bin/ target/release/{cascade,cascaded}
  cp -v -t /root/cargo-debug/bin/ target/debug/{cascade,cascaded}
  # Default to debug builds. If a test requires the release build it needs to override the symlinks or update its PATH
  ln -st /usr/local/bin/ /root/cargo-debug/bin/*

  # Delete the repository to reduce the size of the image (and act will copy
  # the repository into the container anyway)
  cd /
  rm -rf /cascade
EOF
