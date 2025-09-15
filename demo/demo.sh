# Sane environment.
set -euxo pipefail
cd /srv/cascade

# Stop Cascade if it is already running.
sudo systemctl stop cascaded
sudo systemctl stop kmip2pkcs11-cascaded

# Copy over all static files.
cp -r $HOME/cascade/demo/* ./

# Build and copy over all binaries.
for dir in cascade dnst kmip2pkcs11; do
  pushd "$HOME/$dir" >/dev/null
  cargo build --message-format json --release
  popd >/dev/null
done | jq -r '.executable|strings' | xargs cp -t /srv/cascade/bin
export PATH="/srv/cascade/bin:${PATH}"

# Correct ownership.
sudo chown -R cascade:cascade /srv/cascade
sudo chmod -R g+w /srv/cascade

# Wipe all existing Cascade state.
rm -rf cascade/{keys,kmip,zone-state,state.db}

set +x

function run() {
  while true; do
    echo "---------------------------------"
    echo "> $@"
    read -p "(y, n, s, q): " answer
    case "$answer" in
      y|""):
        eval "$@"
        echo "... exited with status $?"
        break
        ;;
      n):
        break
        continue
        ;;
      s):
        bash || true
        continue
        ;;
      q):
        exit 0
        ;;
      *):
        continue
        ;;
    esac
  done
}

# Show the current state.
run tree

# Start Cascade.
run "sudo systemctl start cascaded; sudo systemctl start kmip2pkcs11-cascaded"

# Check the logs.
run sudo systemctl status cascaded
run tail cascade/log

# Check on SoftHSM keys.
run SOFTHSM2_CONF=/srv/cascade/softhsm/softhsm2.conf softhsm2-util --show-slots

# Check 'kmip2pkcs11'.
run cat kmip2pkcs11/config.toml

# Add SoftHSM via 'kmip2pkcs11'.
run cascade hsm add \
  --username \"Cascade token 1\" --password \"verysecurepin\" \
  --insecure --port 1060 softhsm 127.0.0.1

# Show 'cascade.nlnetlabs.nl'.
run cat cascade/zones/cascade.nlnetlabs.nl.zone

# Show the 'hsm' policy.
run cat cascade/policies/cascade.toml

# Add the zone.
run cascade zone add --policy cascade \
  --source /srv/cascade/cascade/zones/cascade.nlnetlabs.nl.zone \
  --import-ksk-kmip softhsm 1B938AF32D4CD4AD7EFC4532F54828FBC38B5781_pub 1B938AF32D4CD4AD7EFC4532F54828FBC38B5781_priv 13 257 \
  --import-zsk-kmip softhsm 2AF59DCEEBEF088702837E66613F875F5026D5A9_pub 2AF59DCEEBEF088702837E66613F875F5026D5A9_priv 13 256 \
  cascade.nlnetlabs.nl 

# Watch Cascade do stuff.
run tail cascade/log

# Check on the zone.
run cascade zone list
run cascade zone status cascade.nlnetlabs.nl

# Oh no!  We have a problem!
# Restore the missing AAAA record.
run vim cascade/zones/cascade.nlnetlabs.nl.zone

# Carry on.
run cascade zone reload cascade.nlnetlabs.nl
run cascade zone status cascade.nlnetlabs.nl

run cascade zone status --detailed cascade.nlnetlabs.nl

echo "---------------------------------"
echo "That's the main demo!"
echo
exec bash
