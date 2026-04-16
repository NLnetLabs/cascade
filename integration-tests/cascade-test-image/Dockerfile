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

  # For rustup and dnst
  apt-get install -y build-essential curl ca-certificates curl gnupg lsb-release

  # Fetch NLnet Labs package key
  curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | \
    gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

  # Setup the nlnetlabs proposed package repo
  printf "deb [arch=%s signed-by=%s] %s\n" \
    "$(dpkg --print-architecture)" \
    "/usr/share/keyrings/nlnetlabs-archive-keyring.gpg" \
    "https://packages.nlnetlabs.nl/linux/ubuntu $(lsb_release -cs)-proposed main" | \
      tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

  # Node.js (for common Actions scripts)
  apt-get install -y nodejs

  # DNS
  apt-get install -y bind9 bind9-dnsutils nsd unbound

  # OpenSSL (used by Cascade)
  apt-get install -y pkg-config libssl-dev

  apt-get install -y file
EOF

# Provide the dnst version as a variable to make it easy to update the docker
# image used by the act-wrapper to a new version of dnst. Otherwise, users will
# have to manually invalidate the cached version of the RUN step below as the
# RUN step content wouldn't change.
ARG DNST_VERSION=0.2.0~alpha1-1noble
ARG DNST_VERSION_CARGO=v0.2.0-alpha1

RUN <<EOF
  # Install dnst
  export DEBIAN_FRONTEND=noninteractive

  apt-get update
  apt-get install -y dnst=$DNST_VERSION
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
  # Create links to dnst and cascade binaries (debug by default)
  ln -sft /usr/local/bin/ /root/cargo-debug/bin/{dnst,cascade,cascaded}
EOF

RUN <<EOF
  # Install the debug build of dnst.
  cargo install --debug --git https://github.com/nlnetlabs/dnst --tag $DNST_VERSION_CARGO --root /root/cargo-debug --locked --bin=dnst dnst
  # Link the installed dnst installed by apt to the cargo-release directory so
  # that we don't have to modify the build profile selection action.
  mkdir -p /root/cargo-release/bin
  ln -sf -T /usr/bin/dnst /root/cargo-release/bin/dnst
EOF

# Copy source files into container in case we need to build from source
COPY etc/ /cascade/etc/
COPY Cargo.toml Cargo.lock build.rs /cascade/
COPY src/ /cascade/src/
COPY crates/ /cascade/crates/

# Copy built the cascade binaries into the container
# Make sure this stays at the end of the Dockerfile to make best use of image step caching
COPY target/release/cascaded target/release/cascade /root/cargo-release/bin/
COPY target/debug/cascaded target/debug/cascade /root/cargo-debug/bin/

ARG REBUILD_INSIDE=false

RUN <<EOF
  if [[ "$REBUILD_INSIDE" == true ]]; then
    cd /cascade/

    # Build Cascade
    cargo build
    cargo build --release

    # Save built binaries
    cp -v -t /root/cargo-release/bin/ target/release/{cascade,cascaded}
    cp -v -t /root/cargo-debug/bin/ target/debug/{cascade,cascaded}

    # Delete the repository to reduce the size of the image (and act will copy
    # the repository into the container anyway)
    cd /
    rm -rf /cascade
  fi
EOF
