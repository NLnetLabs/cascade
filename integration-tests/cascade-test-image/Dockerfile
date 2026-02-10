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
  # Create links to dnst and cascade binaries (debug by default)
  ln -sft /usr/local/bin/ /root/cargo-debug/bin/{dnst,cascade,cascaded}
EOF

RUN <<EOF
  # Install dnst
  cargo install --debug --git https://github.com/nlnetlabs/dnst --branch keyset --root /root/cargo-debug --locked --bin=dnst
  cargo install --git https://github.com/nlnetlabs/dnst --branch keyset --root /root/cargo-release --locked --bin=dnst
EOF

# Copy built the cascade binaries into the container
# Make sure this stays at the end of the Dockerfile to make best use of image step caching
COPY target/release/cascaded target/release/cascade /root/cargo-release/bin/
COPY target/debug/cascaded target/debug/cascade /root/cargo-debug/bin/

# Copy source files into container in case we need to build from source
COPY etc/ /cascade/etc/
COPY Cargo.toml Cargo.lock /cascade/
COPY src/ /cascade/src/
COPY crates/ /cascade/crates/

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
