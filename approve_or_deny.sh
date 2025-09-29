#!/usr/bin/env bash
# We expect to receive from the environment:
# - CASCADE_ZONE
# - CASCADE_SERIAL
# - CASCADE_TOKEN
# - CASCADE_SERVER
# - CASCADE_CONTROL
set -euo pipefail -x

echo "Hook invoked with $*"

wget -qO- "http://$CASCADE_CONTROL/approve/${CASCADE_TOKEN}?zone=${CASCADE_ZONE}&serial=${CASCADE_SERIAL}"
