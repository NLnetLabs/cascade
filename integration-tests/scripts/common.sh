#!/usr/bin/env bash

function get-cascade-config-option() {
  local _base_dir=${1%/}
  case "$2" in
    config.toml)
      echo "${_base_dir}/config.toml"
      ;;
    state.db)
      echo "${_base_dir}/state.db"
      ;;
    policy-dir)
      echo "${_base_dir}/policies"
      ;;
    zone-state-dir)
      echo "${_base_dir}/zone-state"
      ;;
    tsig-store-path)
      echo "${_base_dir}/tsig-keys.db"
      ;;
    kmip-credentials-store-path)
      echo "${_base_dir}/kmip/credentials.db"
      ;;
    kmip-server-state-dir)
      echo "${_base_dir}/kmip"
      ;;
    keys-dir)
      echo "${_base_dir}/keys"
      ;;
    dnst-binary-path)
      echo "dnst"
      ;;
    log-target)
      echo "${_base_dir}/cascade.log"
      ;;
    *)
      return 1
      ;;
  esac
}
