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
Usage: ${0} <test-name> <description> [<PR>]

This script generates the harness for a new test and adds it to the workflow.

Arguments:
  test-name       The job name for the workflow file.
  description     A name/short description of the test.
  PR              The PR (number) that introduced this test.

Options:
  -h, --help    Print this help text
EOF
}

if [[ "${1-}" =~ ^(-h|--help|)$ ]]; then
  usage
  exit
fi

job="${1-}"
description="${2-}"
pr="${3-}"

git_root=$(git rev-parse --show-toplevel)
workflow_file="${git_root}/.github/workflows/system-tests.yml"
tests_dir="${git_root}/.github/actions/tests/"
tests_template="${git_root}/.github/actions/tests/test-template"



if [[ -n "$pr" ]]; then
  echo "  # Added for https://github.com/NLnetLabs/cascade/pull/$pr" >> "$workflow_file"
fi

tee -a "${workflow_file}" >/dev/null <<EOF
  ${job}:
    name: $description
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable]
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/tests/${job}
EOF

cp -r "${tests_template}" "${tests_dir}/${job}"
sed -i "s%<NAME>%${description}%; s%<DESCRIPTION>%${description}%g" "${tests_dir}/${job}/action.yml"
