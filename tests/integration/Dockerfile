# Steps are carefully organized to maximize caching.
# Build flow: `base` -> { `dnst`, `cascade-hsm-bridge` } -> `final`

# --- Stage `base`

FROM ubuntu:latest AS base
USER root
SHELL ["/bin/bash", "--login", "-e", "-o", "pipefail", "-c"]

# NOTE: This step does not invalidate the cache. A cached execution will be used
# most of the time, which means the installed packages might be slightly old. We
# don't strictly require the latest version of anything, so this is fine.
#
# We might not always need every package here; but we install all of them so
# they can be part of the same cached layer.
RUN <<EOF
  export DEBIAN_FRONTEND=noninteractive

  # The runner desn't have an `apt` index, fetch one.
  apt-get update

  packages=(
    # Basics
    file
    # Rust
    cargo
    # DNS
    bind9 bind9-dnsutils nsd unbound ldnsutils
    # OpenSSL (used by Cascade if building inside the image)
    pkg-config libssl-dev
    # PKCS#11
    libsofthsm2 opensc
  )

  # Install everything in one go so that `apt` can parallelize downloads.
  apt-get install -y "${packages[@]}"

  # Initialize SoftHSMv2.
  # 
  # This is more efficient than doing it in a separate layer.
  softhsm2-util --init-token --label Cascade --pin 1234 --so-pin 1234 --free
EOF

# TODO: Do we need a specific Rust version?

# --- Stage `dnst`

FROM base AS dnst
USER root
SHELL ["/bin/bash", "--login", "-e", "-o", "pipefail", "-c"]

ADD --keep-git-dir=false \
  https://github.com/NLnetLabs/dnst.git#0d0f564e66b131d3f0eee22b04cc136fab2e1f1a \
  /src

RUN <<EOF
  cd /src
  cargo build --profile=dev
  cp target/debug/dnst -t /
EOF

# --- Stage `cascade-hsm-bridge`

FROM base AS cascade-hsm-bridge
USER root
SHELL ["/bin/bash", "--login", "-e", "-o", "pipefail", "-c"]

ADD --keep-git-dir=false \
  https://github.com/NLnetLabs/cascade-hsm-bridge.git#3960ba4e03276bcda3500a06d9cfb4110f9ac47b \
  /src

RUN <<EOF
  cd /src
  cargo build --profile=dev
  cp target/debug/cascade-hsm-bridge -t /
EOF

# --- Stage `final`

FROM base AS final
USER root
SHELL ["/bin/bash", "--login", "-e", "-o", "pipefail", "-c"]
# HACK: Allow the container to be started and run indefinitely.
ENTRYPOINT ["sleep", "inf"]

COPY --from=dnst /dnst /test/bin/
COPY --from=cascade-hsm-bridge /cascade-hsm-bridge /test/bin/
COPY --link . /test
