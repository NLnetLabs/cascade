#!/bin/sh

set -euxo pipefail

# Wipe data from a previous run
killed=0
for pidfile in local/nsd/pid local/kmip2pkcs11/pid local/cascade/pid; do
  if test -f $pidfile; then
      kill "$(cat $pidfile)" && killed=1 || true
  fi
done
[[ $killed -ne 0 ]] && sleep 1
rm -rf /var/lib/softhsm/tokens
rm -rf local

# Set up a clean working directory
mkdir local
cd local
mkdir /var/lib/softhsm/tokens

# Build and copy over all binaries
mkdir bin
for dir in cascade dnst kmip2pkcs11; do
    pushd "$HOME/code/NLnetLabs/$dir" >/dev/null
    cargo build --message-format json --release
    popd >/dev/null
done | jq -r '.executable|strings' | xargs cp -t bin --update=none-fail
export PATH="$PWD/bin:$PATH"

### Configure everything #######################################################

mkdir nsd kmip2pkcs11 cascade
mkdir cascade/{policies,zone-state,kmip-server-state}

# Configure NSD (esp. for unprivileged use)
cat <<EOF >nsd/nsd.conf
server:
  zonelistfile: ./zonelist
  logfile: ./log
  pidfile: ./pid
  xfrdir: .
  xfrdfile: ./xfrd.state
  ip-address: 127.0.0.1
  cookie-secret: E8D3BD81DA2B1B63DBC9CBE85B8FD36F
  zonesdir: .
  port: 8055

remote-control:
  control-enable: yes
  control-interface: $PWD/nsd/control.ctl
  server-key-file: ./server.key
  server-cert-file: ./server.pem
  control-key-file: ./control.key
  control-cert-file: ./control.pem

zone:
  name: example.com
  zonefile: ./example.com.zone
  notify: 127.0.0.1@8013 NOKEY
  provide-xfr: 127.0.0.1 NOKEY
  store-ixfr: yes
  create-ixfr: yes
EOF

# Generate TLS certificates
nsd-control-setup -d .
mv nsd_control.key nsd/control.key
mv nsd_control.pem nsd/control.pem
mv nsd_server.key nsd/server.key
mv nsd_server.pem nsd/server.pem

# Write the initial version of the zone
cat <<EOF >nsd/example.com.zone
example.com. SOA ns.example.com. admin.example.com. 41 28800 7200 604800 240
             NS  ns.example.com.
EOF

# Configure 'kmip2pkcs11'.
cat <<EOF >kmip2pkcs11/config.toml
lib_path = "/usr/lib64/softhsm/libsofthsm2.so"

log_target = "file"
log_file = "./log"
log_level = "info"

addr = "127.0.0.1"
port = 5696
EOF

# Configure Cascade
cat <<EOF >cascade/config.toml
version = "v1"

policy-dir = "./policies"
zone-state-dir = "./zone-state"
tsig-store-path = "./tsig-keys.db"
keys-dir = "./keys"
dnst-binary-path = "dnst"
kmip-credentials-store-path = "./kmip-creds"
kmip-server-state-dir = "./kmip-server-state"

[daemon]
log-level = "trace"
log-target = { type = "file", path = "./log" }
daemonize = false

[loader]
review.servers = ["127.0.0.1:8011"]

[signer]
review.servers = ["127.0.0.1:8012"]

[server]
servers = ["127.0.0.1:8013"]
EOF

cat <<EOF >bin/review-unsigned.sh
#!/bin/sh

function pass() {
  curl "http://\$CASCADE_CONTROL/approve/\$CASCADE_TOKEN?zone=\$CASCADE_ZONE&serial=\$CASCADE_SERIAL"
}

function fail() {
  curl "http://\$CASCADE_CONTROL/reject/\$CASCADE_TOKEN?zone=\$CASCADE_ZONE&serial=\$CASCADE_SERIAL"
  exit 1
}

server=\${CASCADE_SERVER%:*}
port=\${CASCADE_SERVER#*:}

test -n "\$(dig -p \$port @\$server +short \$CASCADE_ZONE A)" || fail
test -n "\$(dig -p \$port @\$server +short \$CASCADE_ZONE RRSIG)" && fail
pass
EOF
chmod +x bin/review-unsigned.sh

cat <<EOF >bin/review-signed.sh
#!/bin/sh

function pass() {
  curl "http://\$CASCADE_CONTROL/approve/\$CASCADE_TOKEN?zone=\$CASCADE_ZONE&serial=\$CASCADE_SERIAL"
}

function fail() {
  curl "http://\$CASCADE_CONTROL/reject/\$CASCADE_TOKEN?zone=\$CASCADE_ZONE&serial=\$CASCADE_SERIAL"
  exit 1
}

server=\${CASCADE_SERVER%:*}
port=\${CASCADE_SERVER#*:}

test -n "\$(dig -p \$port @\$server +short \$CASCADE_ZONE A)" || fail
test -n "\$(dig -p \$port @\$server +short \$CASCADE_ZONE RRSIG)" || fail
test -n "\$(dig -p \$port @\$server +short \$CASCADE_ZONE DNSKEY)" || fail
pass
EOF
chmod +x bin/review-signed.sh

cat <<EOF >cascade/policies/example.toml
version = "v1"

[loader.review]
required = true
cmd-hook = "review-unsigned.sh"

[key-manager.generation]
hsm-server-id = "kmip2pkcs11"

[signer.review]
required = true
cmd-hook = "review-signed.sh"
EOF

### Launch all the support daemons #############################################

# Start NSD
pushd nsd
nsd -c nsd.conf -u $USER
popd

# Add an HSM token.
softhsm2-util --init-token --label Cascade --pin 1234 --so-pin 1234 --free

# Launch 'kmip2pkcs11'.
pushd kmip2pkcs11
kmip2pkcs11 --config config.toml &
echo $! >pid
disown
popd

### Begin the recording ########################################################

exec asciinema rec -c ../demo.sh
