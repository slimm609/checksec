#!/usr/bin/env bash
# shellcheck disable=SC2154,SC2034
# these top lines are moved during build

# format
format() {
  list="cli csv xml json"
  if [[ -n "${output_format}" ]]; then
    if [[ ! ${list} =~ ${output_format} ]]; then
      printf "\033[31mError: Please provide a valid format {cli, csv, xml, json}.\033[m\n\n"
      exit 1
    fi
  fi
  if [[ "${output_format}" == "xml" ]]; then
    echo '<?xml version="1.0" encoding="UTF-8"?>'
  fi
  format="${output_format}"
}
