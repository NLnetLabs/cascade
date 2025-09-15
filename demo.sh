#!/bin/sh

set -euxo pipefail

# total_time=0
# function sleep() {
#   total_time=$(($total_time + $1))
#   /usr/bin/sleep 2
# }

sleep 5

tree; sleep 15

cat nsd/example.com.zone; sleep 10

cat kmip2pkcs11/config.toml; sleep 15

cat cascade/config.toml; sleep 25

tail nsd/log; tail kmip2pkcs11/log; sleep 10

pushd cascade
cascaded --state state.db --config config.toml &
popd
sleep 20

cascade --help; sleep 5

cascade zone list; sleep 5

cascade hsm add --insecure --username Cascade --password 1234 --port 5696 kmip2pkcs11 127.0.0.1; sleep 10

cascade policy reload; sleep 5
cat cascade/policies/example.toml; sleep 20

cat bin/review-unsigned.sh; sleep 30

cat bin/review-signed.sh; sleep 10

cascade zone add --help; sleep 15

cascade zone add --source 127.0.0.1:8055 --policy example example.com; sleep 5

cascade zone list; sleep 5

cascade zone status example.com; sleep 10

cascade zone enable example.com; sleep 5

cascade zone status example.com; sleep 40

cat <<EOF >nsd/example.com.zone
example.com. SOA ns.example.com. admin.example.com. 42 28800 7200 604800 240
             NS  ns.example.com.
             A   127.0.0.2
EOF
kill -HUP $(cat nsd/pid)
sleep 10

cascade zone status example.com; sleep 10

cascade zone resume example.com
cascade zone status example.com
sleep 10

cascade zone status --detailed example.com; sleep 30
