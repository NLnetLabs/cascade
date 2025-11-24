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
Usage: ${0} [path]

'sed' the cascade config to have all options point to subdirectories of
a single directory—The path argument, or if not provided, the current working
directory, by default.

'dnst' is configured to be in '\${GITHUB_WORKSPACE}/target/dnst/bin/dnst'.


Arguments:
  path          The base directory to put all cascade config into. If <path>
                  is a relative path, it is converted to an absolute one.

Options:
  -h, --help    Print this help text
EOF
}

if [[ "${1-}" =~ ^-h|--help$ ]]; then
  usage
  exit
fi

# From `cascade template config | grep -E '^[^#].*/'`
# policy-dir = "/etc/cascade/policies"
# zone-state-dir = "/var/lib/cascade/zone-state"
# tsig-store-path = "/var/lib/cascade/tsig-keys.db"
# kmip-credentials-store-path = "/var/lib/cascade/kmip/credentials.db"
# keys-dir = "/var/lib/cascade/keys"
# kmip-server-state-dir = "/var/lib/cascade/kmip"
# dnst-binary-path = "/usr/libexec/cascade/cascade-dnst"

# The base dir must be an absolute path
if [[ -n "${1-}" ]]; then
  # A very naive check, but sufficient for our use case
  if [[ "$1" == /* ]]; then
    _base_dir=$1
  else
    _base_dir=$(realpath -- "$1")
  fi
else
  _base_dir=$PWD
fi

sed -e "s_^policy-dir.*_policy-dir = \"${_base_dir}/policies\"_" \
  -e "s_^zone-state-dir.*_zone-state-dir = \"${_base_dir}/zone-state\"_" \
  -e "s_^tsig-store-path.*_tsig-store-path = \"${_base_dir}/tsig-keys.db\"_" \
  -e "s_^kmip-credentials-store-path.*_kmip-credentials-store-path = \"${_base_dir}/kmip/credentials.db\"_" \
  -e "s_^kmip-server-state-dir.*_kmip-server-state-dir = \"${_base_dir}/kmip\"_" \
  -e "s_^keys-dir.*_keys-dir = \"${_base_dir}/keys\"_" \
  -e "s_^dnst-binary-path.*_dnst-binary-path = \"${GITHUB_WORKSPACE}/target/dnst/bin/dnst\"_"
