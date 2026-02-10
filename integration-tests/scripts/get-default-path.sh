#!/usr/bin/env bash

# Exit on any error
set -e
# Error on accessing an unset variable
set -u

###
# Help message
###

usage() {
  cat <<EOF >&2
Usage: ${0} <item>

Output the default path for something as configured using the
setup-and-start-cascade action.

By default, paths are configured releative to the GITHUB_WORKSPACE environment
variable, which is therefore used by this script.


Arguments:
  item            One of:
                    - config.toml
                    - state.db
                    - policy-dir
                    - zone-state-dir
                    - tsig-store-path
                    - tsig-store-path
                    - kmip-credentials-store-path
                    - kmip-server-state-dir
                    - keys-dir
                    - dnst-binary-path
                    - log-target

Options:
  -h, --help    Print this help text
EOF
}

if [[ "${1-}" =~ ^(-h|--help|)$ ]]; then
  usage
  exit
fi

item=${1-}

source "$(dirname "$0")/common.sh"

get-cascade-config-option "$GITHUB_WORKSPACE/cascade-dir" "$item"
