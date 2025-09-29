#!/usr/bin/env bash
# We expect to receive from the environment:
# - CASCADE_ZONE
# - CASCADE_SERIAL
# - CASCADE_TOKEN
# - CASCADE_SERVER
# - CASCADE_UNSIGNED_SERVER
# - CASCADE_CONTROL

set -euo pipefail -x

echo "Hook invoked with $*"

SERVER_IP=${CASCADE_SERVER%:*}
SERVER_IP_DIG="${SERVER_IP//[\[\]]/}" # remove brackets from IPv6
SERVER_PORT=${CASCADE_SERVER##*:} # Using double '##' in case its an IPv6

dig +noall +onesoa +answer "@$SERVER_IP_DIG" -p "$SERVER_PORT" "${CASCADE_ZONE}" AXFR | dnssec-verify -o "${CASCADE_ZONE}" /dev/stdin /tmp/keys/ || {
    wget -qO- "http://$CASCADE_CONTROL/reject/${CASCADE_TOKEN}?zone=${CASCADE_ZONE}&serial=${CASCADE_SERIAL}"
    exit 0
}

wget -qO- "http://$CASCADE_CONTROL/approve/${CASCADE_TOKEN}?zone=${CASCADE_ZONE}&serial=${CASCADE_SERIAL}"
