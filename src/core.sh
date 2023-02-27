#!/usr/bin/env bash
# shellcheck disable=SC2154,SC2034
# these top lines are moved during build

# set global lang to C
export LC_ALL="C"

# version
SCRIPT_VERSION=2022052701
SCRIPT_MAJOR=2
SCRIPT_MINOR=6
SCRIPT_REVISION=0

# global vars
debug=false
verbose=false
format="cli"
SCRIPT_NAME="checksec"
SCRIPT_URL="https://github.com/slimm609/checksec.sh/raw/master/${SCRIPT_NAME}"
SIG_URL="https://github.com/slimm609/checksec.sh/raw/master/$(basename ${SCRIPT_NAME} .sh).sig"

pkg_release=false
commandsmissing=false
OPT=0
extended_checks=false
# FORTIFY_SOURCE vars
FS_end=_chk
FS_cnt_total=0
FS_cnt_checked=0
FS_cnt_unchecked=0

# check if directory exists
dir_exists() {
  if [[ -d "${1}" ]]; then
    return 0
  else
    return 1
  fi
}

# check user privileges
root_privs() {
  if [[ $(id -u) -eq 0 ]]; then
    return 0
  else
    return 1
  fi
}

# check for required files and deps first
# check if command exists
command_exists() {
  type "${1}" > /dev/null 2>&1
}

for command in cat awk sed sysctl objdump uname mktemp openssl grep stat file find sort head ps readlink basename id which xargs ldd; do
  if ! (command_exists ${command}); then
    echo >&2 -e "\e[31mWARNING: '${command}' not found! It's required for most checks.\e[0m"
    commandsmissing=true
  fi
done

if [[ ${commandsmissing} == true ]]; then
  echo >&2 -e "\n\e[31mWARNING: Not all necessary commands found. Some tests might not work!\e[0m\n"
  sleep 2
fi

# search for libc
# shall be called before using variable FS_libc
search_libc() {
  if [[ -z ${FS_libc} ]]; then
    # if a specific search path is given, use it
    if [[ -n "${LIBC_FILE}" ]]; then
      if [[ -f "${LIBC_FILE}" ]]; then
        FS_libc=${LIBC_FILE}
      elif [[ -d "${LIBC_FILE}" ]]; then
        LIBC_SEARCH_PATH=${LIBC_FILE}
      fi
    # otherwise use ldd to get the libc location
    elif [[ -f $(ldd "$(command -v grep)" 2> /dev/null | grep 'libc\.so' | cut -d' ' -f3) ]]; then
      FS_libc=$(ldd "$(command -v grep)" 2> /dev/null | grep 'libc\.so' | cut -d' ' -f3)
    fi

    # if a search path was given or ldd failed we need to search for libc
    if [[ -z ${FS_libc} ]]; then
      # if a search path was specified, look for libc in LIBC_SEARCH_PATH
      if [[ -n "${LIBC_SEARCH_PATH}" ]]; then
        FS_libc=$(find "${LIBC_SEARCH_PATH}" \( -name "libc.so.6" -o -name "libc.so.7" -o -name "libc.so" \) -print -quit 2> /dev/null)
      # if ldd failed, then as a last resort search for libc in "/lib/", "/lib64/" and "/"
      else
        FS_libc=$(find /lib/ /lib64/ / \( -name "libc.so.6" -o -name "libc.so.7" -o -name "libc.so" \) -print -quit 2> /dev/null)
      fi
    fi

    #FS_libc is used across multiple functions
    if [[ -e ${FS_libc} ]]; then
      export FS_libc
    else
      printf "\033[31mError: libc not found.\033[m\n\n"
      exit 1
    fi
  fi
}

for command in readelf eu-readelf greadelf; do
  if (command_exists ${command}); then
    readelf="${command} -W"
    break
  fi
done

if [[ -z ${readelf} ]]; then
  echo -e "\n\e[31mERROR: readelf is a required tool for almost all tests. Aborting...\e[0m\n"
  exit
fi

sysarch=$(uname -m)
if [[ "${sysarch}" == "x86_64" ]]; then
  arch="64"
elif [[ "${sysarch}" == "i?86" ]]; then
  arch="32"
elif [[ "${sysarch}" =~ "arm" ]]; then
  arch="arm"
elif [[ "${sysarch}" =~ "aarch64" ]]; then
  arch="aarch64"
fi
