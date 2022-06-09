#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

#Check core dumps restricted?
coredumpcheck() {
  if [[ -f /etc/security/limits.conf ]]; then
    coreValue=$(grep -Exic "hard[[:blank:]]+core[[:blank:]]+0" /etc/security/limits.conf)
    coreValueDefault=$(grep -Exic "\*[[:blank:]]+hard[[:blank:]]+core[[:blank:]]+0" /etc/security/limits.conf)
  else
    coreValue=0
    coreValueDefault=0
  fi
  dumpableValue=$(sysctl -n fs.suid_dumpable)
  if { [[ "${coreValue}" == 1 ]] || [[ "${coreValueDefault}" == 1 ]]; } && { [[ "${dumpableValue}" == 0 ]] || [[ "${dumpableValue}" == 2 ]]; }; then
    echo_message '\033[32mRestricted\033[m\n\n' '' '' ''
  else
    echo_message '\033[31mNot Restricted\033[m\n\n' '' '' ''
  fi
}
