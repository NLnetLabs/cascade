#!/usr/bin/env bash
# We expect to receive from the environment:
# - CASCADE_ZONE
# - CASCADE_SERIAL
# - CASCADE_TOKEN
# - CASCADE_SERVER
set -euo pipefail -x

echo "Hook invoked with $*"

