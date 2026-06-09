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
Usage: ${0} <path> <log-level>

'sed' the cascade config to have all options point to subdirectories of
a single directory—The path argument, or if not provided, the current working
directory, by default.

'dnst' is used from the PATH environment variable.


Arguments:
  path            The base directory to put all cascade config into. If <path>
                    is a relative path, it is converted to an absolute one.

  log-level       The level of logging the Cascade should output. One of:
                    error, warning, info, debug, trace

Options:
  -h, --help    Print this help text
EOF
}

if [[ "${1-}" =~ ^-h|--help$ ]]; then
  usage
  exit
fi

_path=${1-$PWD}
_log_level=${2-debug}

# The base dir must be an absolute path
# A very naive check, but sufficient for our use case
if [[ "${_path}" == /* ]]; then
  _base_dir=${_path}
else
  _base_dir=$(realpath -- "${_path}")
fi

source "$(dirname "$0")/common.sh"

sed -e "s_^policy-dir.*_policy-dir = \"$(get-cascade-config-option "${_base_dir}" "policy-dir")\"_" \
  -e "s_^zone-state-dir.*_zone-state-dir = \"$(get-cascade-config-option "${_base_dir}" "zone-state-dir")\"_" \
  -e "s_^tsig-store-path.*_tsig-store-path = \"$(get-cascade-config-option "${_base_dir}" "tsig-store-path")\"_" \
  -e "s_^kmip-credentials-store-path.*_kmip-credentials-store-path = \"$(get-cascade-config-option "${_base_dir}" "kmip-credentials-store-path")\"_" \
  -e "s_^kmip-server-state-dir.*_kmip-server-state-dir = \"$(get-cascade-config-option "${_base_dir}" "kmip-server-state-dir")\"_" \
  -e "s_^keys-dir.*_keys-dir = \"$(get-cascade-config-option "${_base_dir}" "keys-dir")\"_" \
  -e "s_^dnst-binary-path.*_dnst-binary-path = \"$(get-cascade-config-option "${_base_dir}" "dnst-binary-path")\"_" \
  -e "s_^log-level.*_log-level = \"${_log_level}\"_" \
  -e "s_^log-target.*_log-target = { type = \"file\", path = \"$(get-cascade-config-option "${_base_dir}" "log-target")\" }_"
