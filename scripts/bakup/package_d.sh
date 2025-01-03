#!/usr/bin/env bash

set -e
set -u
set -o pipefail
set -x  # Enable debugging

ROOTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOTDIR

# shellcheck source=SCRIPTDIR/.util/tools.sh
source "${ROOTDIR}/scripts/.util/tools.sh"

# shellcheck source=SCRIPTDIR/.util/print.sh
source "${ROOTDIR}/scripts/.util/print.sh"

function main() {
  local stack version cached output
  stack="any"
  cached="false"
  output="${ROOTDIR}/build/nr-buildpack.zip"

  while [[ "${#}" != 0 ]]; do
    case "${1}" in
      --stack)
        stack="${2}"
        shift 2
        ;;

      --version)
        version="${2}"
        shift 2
        ;;

      --cached)
        cached="true"
        shift 1
        ;;

      --output)
        output="${2}"
        shift 2
        ;;

      --help|-h)
        shift 1
        usage
        exit 0
        ;;

      "")
        # skip if the argument is empty
        shift 1
        ;;

      *)
        util::print::error "unknown argument \"${1}\""
        exit 1  # Exit with error status for unknown arguments
        ;;
    esac
  done

  if [[ -z "${version:-}" ]]; then
    usage
    echo
    util::print::error "--version is required"
    exit 1  # Exit with error status if --version is missing
  fi

  package::buildpack "${version}" "${cached}" "${stack}" "${output}"
}

function usage() {
  cat <<-USAGE
package.sh --version <version> [OPTIONS]
Packages the buildpack into a .zip file.
OPTIONS
  --help               -h            prints the command usage
  --version <version>  -v <version>  specifies the version number to use when packaging the buildpack
  --cached                           cache the buildpack dependencies (default: true)
USAGE
}

function package::buildpack() {
  local version cached stack output
  version="${1}"
  cached="${2}"
  stack="${3}"
  output="${4}"

  mkdir -p "$(dirname "${output}")"

  # Unset GOBIN before cross-compiling
  original_gobin=$GOBIN
  unset GOBIN

  util::tools::buildpack-packager::install --directory "${ROOTDIR}/.bin"

  # Restore GOBIN after installation
  export GOBIN=$original_gobin

  echo "Building buildpack (version: ${version}, stack: ${stack}, cached: ${cached}, output: ${output})"

  local stack_flag
  stack_flag="--any-stack"
  if [[ "${stack}" != "any" ]]; then
    stack_flag="--stack=${stack}"
  fi

  local file
  file="$(
    buildpack-packager build \
      "--version=${version}" \
      "--cached=${cached}" \
      "${stack_flag}" \
    | xargs -n1 | grep -e '\.zip$'
  )"

  mv "${file}" "${output}"
}

main "${@:-}"

