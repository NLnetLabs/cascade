#!/bin/sh

set -euo pipefail

server="${CASCADE_SERVER%:*}"
port="${CASCADE_SERVER#*:}"

test -n "$(dig -p $port @$server +short $CASCADE_ZONE A)"
test -n "$(dig -p $port @$server +short $CASCADE_ZONE AAAA)"

test -n "$(dig -p $port @$server +short $CASCADE_ZONE NSEC)"
test -n "$(dig -p $port @$server +short $CASCADE_ZONE RRSIG)"
