#!/usr/bin/env bash

set -e
set -u
set -o pipefail

ROOTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOTDIR

# shellcheck source=SCRIPTDIR/.util/tools.sh
source "${ROOTDIR}/scripts/.util/tools.sh"

# shellcheck source=SCRIPTDIR/.util/print.sh
source "${ROOTDIR}/scripts/.util/print.sh"

function main() {
  local version cached
  cached="false"
  version=$(get_version)

  while [[ "${#}" != 0 ]]; do
    case "${1}" in
      --cached)
        cached="true"
        shift 1
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
    esac
  done

  if [[ -z "${version:-}" ]]; then
    usage
    echo
    util::print::error "VERSION file is required"
  fi

  # Define the filename suffix based on the cached flag
  local cached_suffix
  if [[ "${cached}" == "true" ]]; then
    cached_suffix="cached"
  else
    cached_suffix=""
  fi

  # Package buildpack for cflinuxfs4
  package::buildpack "${version}" "${cached}" "cflinuxfs4" "${ROOTDIR}/build/newrelic_nginx_buildpack-${cached_suffix}-cflinuxfs4-v${version}.zip"

  # Package buildpack for cflinuxfs3
  package::buildpack "${version}" "${cached}" "cflinuxfs3" "${ROOTDIR}/build/newrelic_nginx_buildpack-${cached_suffix}-cflinuxfs3-v${version}.zip"
}

function get_version() {
  local version_file="${ROOTDIR}/VERSION"
  if [[ -f "${version_file}" ]]; then
    cat "${version_file}"
  else
    util::print::error "VERSION file not found"
    exit 1
  fi
}

function usage() {
  cat <<-USAGE
package.sh [OPTIONS]
Packages the buildpack into a .zip file.
OPTIONS
  --help               -h            prints the command usage
  --cached                           cache the buildpack dependencies (default: false)
USAGE
}

function package::buildpack() {
  local version cached stack output
  version="${1}"
  cached="${2}"
  stack="${3}"
  output="${4}"

  mkdir -p "$(dirname "${output}")"

  util::tools::buildpack-packager::install --directory "${ROOTDIR}/.bin"

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


