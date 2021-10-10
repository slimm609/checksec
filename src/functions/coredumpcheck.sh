#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

#Check core dumps restricted?
coredumpcheck() {
  coreValue=$(grep -Exic "hard[[:blank:]]+core[[:blank:]]+0" /etc/security/limits.conf)
  coreValueDefault=$(grep -Exic "\*[[:blank:]]+hard[[:blank:]]+core[[:blank:]]+0" /etc/security/limits.conf)
  dumpableValue=$(sysctl -b -e fs.suid_dumpable)
  if { [[ "${coreValue}" == 1 ]] || [[ "${coreValueDefault}" == 1 ]]; } && { [[ "${dumpableValue}" == 0 ]] || [[ "${dumpableValue}" == 2 ]]; }; then
    echo_message '\033[32mRestricted\033[m\n\n' '' '' ''
  else
    echo_message '\033[31mNot Restricted\033[m\n\n' '' '' ''
  fi
}
