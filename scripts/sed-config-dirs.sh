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
Usage: ${0} <build-profile> [path]

'sed' the cascade config to have all options point to subdirectories of
a single directory—The path argument, or if not provided, the current working
directory, by default.

'dnst' is configured to be in '\${GITHUB_WORKSPACE}/target/dnst/<build-profile>/bin/dnst'.


Arguments:
  build-profile   The build profile for the test (debug or release).
  path            The base directory to put all cascade config into. If <path>
                    is a relative path, it is converted to an absolute one.

Options:
  -h, --help    Print this help text
EOF
}

if [[ "${1-}" =~ ^-h|--help$ ]]; then
  usage
  exit
fi

_build_profile=${1-}
_path=${2-}

if ! [[ "${_build_profile}" =~ ^debug|release$ ]]; then
  echo "Build profile argument MUST be either debug or release." >&2
  usage
  exit 1
fi

# The base dir must be an absolute path
if [[ -n "${_path}" ]]; then
  # A very naive check, but sufficient for our use case
  if [[ "${_path}" == /* ]]; then
    _base_dir=${_path}
  else
    _base_dir=$(realpath -- "${_path}")
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
  -e "s_^dnst-binary-path.*_dnst-binary-path = \"${GITHUB_WORKSPACE}/target/dnst/${_build_profile}/bin/dnst\"_" \
  -e 's_^log-level.*_log-level = "debug"_' \
  -e "s_^log-target.*_log-target = { type = \"file\", path = \"${_base_dir}/cascade.log\" }_"
