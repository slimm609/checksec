#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# check cpu nx flag
nxcheck() {
  if grep -qFw 'nx' /proc/cpuinfo; then
    echo_message '\033[32mYes\033[m\n\n' '' '' ''
  else
    echo_message '\033[31mNo\033[m\n\n' '' '' ''
  fi
}
