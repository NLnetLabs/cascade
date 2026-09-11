#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install|post-upgrade)
    echo -e "\nCASCADE VERSION:"
    cascade --version

    echo -e "\nCASCADED VERSION:"
    cascaded --version

    echo -e "\nDNST VERSION:"
    dnst --version

    echo -e "\nCASCADED CONF:"
    cat /etc/cascade/config.toml

    echo -e "\nCASCADE SERVICE STATUS:"
    systemctl status cascade || true

    echo -e "\nCASCADE MAN PAGE (first 20 lines only):"
    man -P cat cascade | head -n 20 || true

    echo -e "\nCASCADED MAN PAGE (first 20 lines only):"
    man -P cat cascaded | head -n 20 || true

    echo -e "\nCASCADE SERVICE SHOULD BE STOPPED BY DEFAULT:"
    if systemctl is-active cascade; then
      echo "Systemd 'cascade' service is unexpectedly active"
      exit 1
    fi

    echo -e "\nTEST SYSTEMD SERVICE STARTUP:"
    systemctl start cascade

    # Give it time to start
    sleep 3s

    # Dump the status
    systemctl status cascade

    # Check that the service is active
    systemctl is-active cascade
    ;;
esac
