#!/usr/bin/env bash
# We expect to receive from the environment:
# - CASCADE_ZONE
# - CASCADE_SERIAL
# - CASCADE_SERVER
# - CASCADE_SERVER_IP
# - CASCADE_SERVER_PORT

set -euo pipefail -x

echo "Hook invoked with $*"

dig +noall +onesoa +answer "@$CASCADE_SERVER_IP" -p "$CASCADE_SERVER_PORT" "${CASCADE_ZONE}" AXFR | dnssec-verify -o "${CASCADE_ZONE}" /dev/stdin /tmp/keys/
