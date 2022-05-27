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
FS_libc=0

PATH=${PATH}:/sbin/:/usr/sbin/

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
  if [[ $(/usr/bin/id -u) -eq 0 ]]; then
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

for command in cat awk sed sysctl uname mktemp openssl grep stat file find sort head ps readlink basename id which xargs; do
  if ! (command_exists ${command}); then
    echo >&2 -e "\e[31mWARNING: '${command}' not found! It's required for most checks.\e[0m"
    commandsmissing=true
  fi
done

if [[ ${commandsmissing} == true ]]; then
  echo >&2 -e "\n\e[31mWARNING: Not all necessary commands found. Some tests might not work!\e[0m\n"
  sleep 2
fi

if (command_exists readelf); then
  readelf="readelf -W"
elif (command_exists eu-readelf); then
  readelf="eu-readelf -W"
elif (command_exists greadelf); then
  readelf="greadelf -W"
else
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
