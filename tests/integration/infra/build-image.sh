#!/bin/sh
#
# Manually build the Docker image for integration tests. Normally, the
# integration test suite will automatically build the image, in exactly the
# same way (see `image.rs`).

set -eu -o pipefail
cd "$(dirname "$0")/../../.."

# `tests/integration/Dockerfile` -> `./Dockerfile`
# `tests/integration/data` -> `./`
tar --create \
  --transform='s#tests/integration/#./#' tests/integration/Dockerfile \
  --directory=$PWD/tests/integration/data . \
  | docker buildx build - -t nlnetlabs/cascade-tests-runner
