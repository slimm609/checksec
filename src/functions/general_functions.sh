#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

echo_message() {
  if [[ ${format} == "csv" ]]; then
    echo -n -e "$2"
  elif [[ ${format} == "xml" ]]; then
    echo -n -e "$3"
  elif [[ ${format} == "json" ]]; then
    echo -n -e "$4"
  else #default to cli
    echo -n -e "${1}"
  fi
}

# check if input is numeric
isNumeric() {
  echo "$@" | grep -q -v "[^0-9]"
}

# check if input is a string
isString() {
  echo "$@" | grep -q -v "[^ A-Z_a-z]"
}
