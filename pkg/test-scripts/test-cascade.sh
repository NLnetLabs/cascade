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
    /usr/libexec/cascade/cascade-dnst --version

    echo -e "\nCASCADED CONF:"
    cat /etc/cascade/config.toml

    echo -e "\nCASCADED SERVICE STATUS:"
    systemctl status cascaded || true

    echo -e "\nCASCADE MAN PAGE (first 20 lines only):"
    man -P cat cascade | head -n 20 || true

    echo -e "\nCASCADED MAN PAGE (first 20 lines only):"
    man -P cat cascaded | head -n 20 || true

    echo -e "\nCASCADED SERVICE SHOULD BE STOPPED BY DEFAULT:"
    if systemctl is-active cascaded; then
      echo "Systemd 'cascaded' service is unexpectedly active"
      exit 1
    fi

    echo -e "\nTEST SYSTEMD SERVICE STARTUP:"
    systemctl start cascaded

    # Give it time to start
    sleep 3s

    # Dump the status
    systemctl status cascaded

    # Check that the service is active
    systemctl is-active cascaded
    ;;
esac
