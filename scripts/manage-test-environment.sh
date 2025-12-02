#!/usr/bin/env bash

# Log every action taken or command run
# set -x
# Exit the script if any command errors
set -e
# Return an error for a pipeline if any command of the pipeline fails and not
# only the last one
set -o pipefail
# Error on accessing unset variables or parameters
set -u

## Globals
_scriptname=$0
_ignore_no_ubuntu=false
_nameserver_base_dir=$PWD/nameservers
_cascade_port=4543
_bind_port=1053
_nsd_port=1054
_nsd_primary_port=1055

###
# Help message
###

usage() {
  cat <<EOF >&2
Usage: ${_scriptname} [OPTIONS] <action>

Setup, start, and stop the nameservers and resolvers needed to test Cascade with full automation.

Setup installs the required software and creates necessary configuration.
Start starts the nameservers/resolver and overwrites resolv.conf to use Unbound.
Stop restores the original resolv.conf file and stops the nameservers/resolver.

Requires to run on an Ubuntu system.

Arguments:
  action:
    - setup:            Setup the test environment incl. installing the software
    - start:            Start the background services (NSD, Unbound, etc.)
    - stop:             Stop the background services based on the PID file created by start
    - setup-and-start:  Both setup and start in one

    - list-ports:       List the ports configured for the different services
    - generate-configuration:       Only generate the directories and configuration files
    - test:             Check the service's statuses (xxx-control status and dig test SOA)
    - control:          Run a control command (see usage below)

Options:
      --ignore-no-ubuntu    Disable the ckeck if this script is run on an Ubuntu system
  -h, --help                Print this help text

Usage: ${_scriptname} [OPTIONS] control <bind|unbound|nsd-primary|nsd-secondary> <args...>
  The args are the usual arguments for nsd-control, unbound-control, or rndc respectively.
EOF
}

# echo to stderr
log-error() {
  echo "$@" >&2
}

###
# Helper functions for checking parsed arguments
###

check-empty() {
  if [[ -z "$2" ]]; then
    log-error "Missing $1 '$3' ${4-}"
    usage
    exit 1
  fi
}

check-empty-opt() { check-empty option "$@"; }
check-empty-arg() { check-empty argument "$@"; }

######################
## Argument parsing ##
######################

# Assigning to a variable first to exit on getopt failure (through set -e)
PARSED_ARGS=$(getopt -n "$0" -o "hp:" -l "help,ignore-no-ubuntu" -- "$@")
eval set -- "$PARSED_ARGS"

while [[ -n "$1" ]]; do
  case "$1" in
    -h|--help)
      usage && exit
      ;;
    --ignore-no-ubuntu)
      _ignore_no_ubuntu=true
      shift 1
      ;;
    --)
      shift 1
      break
      ;;
    *) log-error "Unknown option: $1" && usage && exit 1
  esac
done

if [[ "${1-}" != "control" && "$#" -gt 1 ]]; then
	log-error "Too many arguments"
	usage
	exit 1
fi

# with set -u (nounset), using "$1" if it's not set errors, therefore, use "${1-}"
check-empty-arg "${1-}" "action"
_action="$1"

if [[ "${_ignore_no_ubuntu}" != "true" ]] && ! grep -q "ID=ubuntu" /etc/os-release; then
  log-error "You are not on Ubuntu."
  log-error "This script requires a ubuntu system (but might work on other debian derivatives)."
  log-error "You can ignore this check by passing the --ignore-no-ubuntu option."
fi

###############
## Functions ##
###############

# # join_by <delimiter> <items...>
# function join_by() {
#   local delim=$1 first=$2
#   if shift 2; then
#     printf %s "$first" "${@/#/$delim}"
#   fi
# }

# # background-cmd <pid-var-name> <cmd> <args...>
# # execute a command in the background and assign its PID to the provided
# # variable name
# function background-cmd() {
#   declare -n pid_var_reference=$1
#   shift
#   "$@" &
#   # shellcheck disable=2034 # disable warning about assigned but never read
#   pid_var_reference=$!
# }
# # Example for background-cmd
# background-cmd blub sleep 5
# # disable warning about variable read but never assigned as it
# # is assigned by background-cmd
# # shellcheck disable=2154
# echo "blub=$blub"

# generate-configuration will create the nameserver base directory, the
# necessary subdirectories, and the configuration files
function generate-configuration() {
  local base_dir=${_nameserver_base_dir}

  mkdir -p "${base_dir}"/{bind,nsd/zones,nsd-primary/zones}

tee "${base_dir}/bind.conf" <<EOF
options {
  // Set bind's working directory
  directory "${base_dir}/bind";
  pid-file "${base_dir}/bind.pid";

  listen-on-v6 { none; };
  listen-on port ${_bind_port} { 127.0.0.1; };

  allow-recursion { none; };
  allow-transfer { 127.0.0.0/8; };
  recursion false;
};

// Disable IPv6 lookups altogether
server ::/0 {
  bogus true;
};

// Setup parent zone
zone "test" IN {
  type master;
  file "test.zone";
  journal "test.zone.jnl";
  allow-query { 127.0.0.0/8; };
  allow-transfer { 127.0.0.0/8; };
  allow-update { 127.0.0.0/8; };
};

key "rndc-key" {
  algorithm hmac-sha256;
  secret "4SXolSodx0SzFKwUyfBmcLjZ5WxJGsQQpDB+p3JXxFg=";
};

controls {
  inet 127.0.0.1 port 1953 allow { 127.0.0.1; } keys { "rndc-key"; };
};
EOF

tee "${base_dir}/bind/rndc.conf" <<EOF
key "rndc-key" {
  algorithm hmac-sha256;
  secret "4SXolSodx0SzFKwUyfBmcLjZ5WxJGsQQpDB+p3JXxFg=";
};

options {
  default-key "rndc-key";
  default-server 127.0.0.1;
  default-port 1953;
};
EOF

tee "${base_dir}/bind/test.zone" <<'EOF'
$TTL 5 ; use a very short TTL for sped up keyset rolls
test.   IN SOA ns1.test. mail.test. (
                      1          ; serial
                     60          ; refresh (60 seconds)
                     60          ; retry (60 seconds)
                   3600          ; expire (1 hour)
                      5          ; minimum (5 seconds)
                    )
@           NS  test.
@           NS  ns1.test.
@           A   127.0.0.1
ns1.test.   A   127.0.0.1

example.test.       NS  example.test.
example.test.       NS  ns1.example.test.
example.test.       A   127.0.0.1
ns1.example.test.   A   127.0.0.1
EOF

tee "${base_dir}/unbound.conf" <<EOF
server:
  num-threads: 4
  do-daemonize: yes
  pidfile: "${base_dir}/unbound.pid"
  logfile: "${base_dir}/unbound.log"

  do-not-query-localhost: no
  domain-insecure: test
  local-zone: test nodefault

stub-zone:
  name: "test"
  stub-host: test
  stub-addr: 127.0.0.1@${_bind_port}

stub-zone:
  name: "example.test"
  stub-host: example.test
  stub-addr: 127.0.0.1@${_nsd_port}

python:
dynlib:
remote-control:
  control-enable: yes
  control-interface: "/tmp/unbound.ctl"

forward-zone:
  name: "."
  forward-addr: 9.9.9.9
  forward-addr: 149.112.112.112
  forward-addr: 1.1.1.1
  forward-addr: 1.0.0.1
EOF

tee "${base_dir}/nsd.conf" <<EOF
server:
  ip-address: 127.0.0.1@${_nsd_port}
  verbosity: 5
  username: "" # disable privilege "drop" to user "nsd"
  debug-mode: no
  pidfile: "${base_dir}/nsd.pid"
  logfile: "${base_dir}/nsd.log"
  # NSD 4.3.9 option
  database: ""

  zonesdir: "${base_dir}/nsd/zones"
  zonelistfile: "${base_dir}/nsd/zone.list"
  xfrdfile: "${base_dir}/nsd/ixfr.state"
  refuse-any: yes

# Syntax error in NSD 4.3.9 as installed from Ubuntu 22.04 package
#verify:

remote-control:
  control-enable: yes
  control-interface: "${base_dir}/nsd/nsd.sock"

pattern:
  name: secondary
  zonefile: "%s.secondary-zone"
  allow-notify: 127.0.0.1 NOKEY
  # Until Cascade supports IXFR we always use AXFR
  request-xfr: AXFR 127.0.0.1@${_cascade_port} NOKEY
  provide-xfr: 127.0.0.1 NOKEY

zone:
  name: example.test
  include-pattern: secondary
EOF

tee "${base_dir}/nsd-primary.conf" <<EOF
server:
  ip-address: 127.0.0.1@${_nsd_primary_port}
  verbosity: 5
  username: "" # disable privilege "drop" to user "nsd"
  debug-mode: no
  pidfile: "${base_dir}/nsd-primary.pid"
  logfile: "${base_dir}/nsd-primary.log"
  # NSD 4.3.9 option
  database: ""

  zonesdir: "${base_dir}/nsd-primary/zones"
  zonelistfile: "${base_dir}/nsd-primary/zone.list"
  xfrdfile: "${base_dir}/nsd-primary/ixfr.state"
  refuse-any: yes

# Syntax error in NSD 4.3.9 as installed from Ubuntu 22.04 package
#verify:

remote-control:
  control-enable: yes
  control-interface: "${base_dir}/nsd-primary/nsd.sock"

pattern:
  name: primary
  zonefile: "%s.primary-zone"
  allow-notify: 127.0.0.1 NOKEY
  provide-xfr: 127.0.0.1 NOKEY

zone:
  name: example.test
  include-pattern: primary
EOF

tee "${base_dir}/nsd-primary/zones/example.test.primary-zone" <<'EOF'
$TTL 5 ; use a very short TTL for sped up keyset rolls
example.test.   IN SOA ns1.example.test. mail.example.test. (
                      1          ; serial
                     60          ; refresh (60 seconds)
                     60          ; retry (60 seconds)
                   3600          ; expire (1 hour)
                      5          ; minimum (5 seconds)
                    )
@           NS  example.test.
@           NS  ns1.example.test.
@           A   127.0.0.1
ns1         A   127.0.0.1

www         A   169.254.1.1
mail        MX  10 example.test.
text        TXT "Hello World!"
EOF


}

function setup-services() {
  sudo apt update
  sudo apt install bind9 nsd unbound

  generate-configuration
}

function restore-resolv.conf() {
  # We cannot replace the file /etc/resolv.conf itself, only the content,
  # because it is a bind-mount by Docker.
  sudo cp "${_nameserver_base_dir}/resolv.conf.bak" /etc/resolv.conf
  sudo rm "${_nameserver_base_dir}/resolv.conf.bak"
}

function backup-and-replace-resolv.conf() {
  # cp -a to preserve links
  sudo cp /etc/resolv.conf "${_nameserver_base_dir}/resolv.conf.bak"
  sudo tee /etc/resolv.conf <<EOF
nameserver 127.0.0.1
options edns0 trust-ad
EOF
}

function start-services() {
  (
    # Change into the bind directory because named always creates a named.run
    # logfile in the working directory. -L only changes the logging from syslog
    # to a logfile.
    cd "${_nameserver_base_dir}/bind"
    named -c "${_nameserver_base_dir}/bind.conf" -d 1 -L "${_nameserver_base_dir}/bind.log"
  )
  nsd -c "${_nameserver_base_dir}/nsd.conf"
  nsd -c "${_nameserver_base_dir}/nsd-primary.conf"
  sudo unbound -c "${_nameserver_base_dir}/unbound.conf"
  backup-and-replace-resolv.conf
}

function stop-services() {
  restore-resolv.conf
  rndc -c "${_nameserver_base_dir}/bind/rndc.conf" stop
  nsd-control -c "${_nameserver_base_dir}/nsd.conf" stop
  nsd-control -c "${_nameserver_base_dir}/nsd-primary.conf" stop
  sudo unbound-control -c "${_nameserver_base_dir}/unbound.conf" stop
}

function test-services() {
  (
    set +e # don't exit on error
    log-error ">> BIND9 status:"
    rndc -c "${_nameserver_base_dir}/bind/rndc.conf" status
    log-error
    log-error ">> NSD (secondary) status:"
    nsd-control -c "${_nameserver_base_dir}/nsd.conf" status
    log-error
    log-error ">> NSD (primary) status:"
    nsd-control -c "${_nameserver_base_dir}/nsd-primary.conf" status
    log-error
    log-error ">> NSD (primary) zonestatus example.test:"
    nsd-control -c "${_nameserver_base_dir}/nsd-primary.conf" zonestatus example.test
    log-error
    log-error ">> Unbound status:"
    sudo unbound-control -c "${_nameserver_base_dir}/unbound.conf" status
    log-error
    log-error ">> dig test SOA:"
    dig test SOA
    log-error
    log-error ">> dig @127.0.0.1 -p 1055 example.test AXFR:"
    dig @127.0.0.1 -p 1055 example.test AXFR
  )
}

function bind-control-cmd() {
  rndc -c "${_nameserver_base_dir}/bind/rndc.conf" "$@"
}

function nsd-secondary-control-cmd() {
  nsd-control -c "${_nameserver_base_dir}/nsd.conf" stop
}

function nsd-primary-control-cmd() {
  nsd-control -c "${_nameserver_base_dir}/nsd-primary.conf" stop
}

function unbound-control-cmd() {
  sudo unbound-control -c "${_nameserver_base_dir}/unbound.conf" "$@"
}

function run-control-cmd() {
  if [[ -z "$*" ]]; then
    log-error "Missing control arguments"
    usage
    exit 1
  elif ! [[ "$1" =~ ^bind|unbound|nsd-primary|nsd-secondary$ ]]; then
    log-error "Wrong control command"
    usage
    exit 1
  fi

  local variant=$1
  shift

  # Call the appropriate control-cmd function from above with the rest of the
  # arguments
  "${variant}-control-cmd" "$@"
}

function list-ports() {
  cat <<EOF
NSD_PORT=${_nsd_port}
NSD_PRIMARY_PORT=${_nsd_primary_port}
BIND_PORT=${_bind_port}
CASCADE_PORT=${_cascade_port}
EOF
}

############
### MAIN ###
############

case "${_action}" in
  start)
    start-services
    ;;
  setup)
    setup-services
    ;;
  setup-and-start)
    setup-services
    start-services
    ;;
  stop)
    stop-services
    ;;
  generate-configuration)
    generate-configuration
    ;;
  test)
    test-services
    ;;
  list-ports)
    list-ports
    ;;
  control)
    shift
    run-control-cmd "$@"
    ;;
  *)
    log-error "Unknown action: ${_action}" && usage && exit 1
esac

# vim: set ts=2 et sw=2:
