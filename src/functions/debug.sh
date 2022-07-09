#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

debug_report() {
  echo "***** Checksec debug *****"
  failed=false
  id
  uname -a

  echo "checksec version: ${SCRIPT_MAJOR}.${SCRIPT_MINOR}.${SCRIPT_REVISION} -- ${SCRIPT_VERSION}"

  if [[ -f /etc/os-release ]]; then
    # freedesktop.org and systemd
    # shellcheck disable=SC1091
    source /etc/os-release
    # shellcheck disable=SC2153
    OS=${NAME}
    VER=${VERSION_ID}
  elif type lsb_release > /dev/null 2>&1; then
    # linuxbase.org
    OS=$(lsb_release -si)
    VER=$(lsb_release -sr)
  elif [[ -f /etc/lsb-release ]]; then
    # For some versions of Debian/Ubuntu without lsb_release command
    # shellcheck disable=SC1091
    source /etc/lsb-release
    OS=${DISTRIB_ID}
    VER=${DISTRIB_RELEASE}
  elif [[ -f /etc/debian_version ]]; then
    # Older Debian/Ubuntu/etc.
    OS=Debian
    VER=$(cat /etc/debian_version)
  elif [[ -f /etc/SuSe-release ]]; then
    # Older SuSE/etc.
    OS=$(cat /etc/SuSe-release)
    VER=$(uname -r)
  elif [[ -f /etc/redhat-release ]]; then
    # Older Red Hat, CentOS, etc.
    OS=$(cat /etc/redhat-release)
    VER=$(uname -r)
  else
    # Fall back to uname, e.g. "Linux <version>", also works for BSD, etc.
    OS=$(uname -s)
    VER=$(uname -r)
  fi

  echo "OS=${OS}"
  echo "VER=${VER}"

  for command in cat awk sysctl sed uname objdump mktemp openssl grep stat file find head ps readlink basename id which wget curl readelf eu-readelf; do
    path="$(command -v ${command})"
    if [[ -e "${path}" ]]; then
      ls -l "${path}"
      if [[ -L "${path}" ]]; then
        absolutepath=$(readlink -f "${path}")
        ls -l "${absolutepath}"
        file "${absolutepath}"
      else
        file "${path}"
      fi
    else
      echo "*** can not find command ${command}"
      failed=true
    fi
  done

  if [[ ${failed} ]]; then
    exit 1
  fi
}
