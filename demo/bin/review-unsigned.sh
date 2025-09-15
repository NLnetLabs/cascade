#!/bin/sh

set -euo pipefail

server="${CASCADE_SERVER%:*}"
port="${CASCADE_SERVER#*:}"

test -n "$(dig -p $port @$server +short $CASCADE_ZONE A)"
test -n "$(dig -p $port @$server +short $CASCADE_ZONE AAAA)"

test -z "$(dig -p $port @$server +short $CASCADE_ZONE NSEC)"
test -z "$(dig -p $port @$server +short $CASCADE_ZONE RRSIG)"
