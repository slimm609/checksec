#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# check mapped libraries
libcheck() {
  IFS=" " read -r -a libs <<< "$(awk '{ print $6 }' "/proc/${1}/maps" | grep '/' | sort -u | xargs file | grep ELF | awk '{ print $1 }' | sed 's/:/ /')"
  echo_message "\n* Loaded libraries (file information, # of mapped files: ${#libs[@]}):\n\n" "" "" "\"libs\": {"

  for ((element = 0; element < ${#libs[@]}; element++)); do
    echo_message "  ${libs[$element]}:\n" "${libs[$element]}," "" ""
    echo_message "    " "" "    " ""
    filecheck "${libs[$element]}"
    if [[ ${element} == $((${#libs[@]} - 1)) ]]; then
      echo_message "\n\n" "\n" " filename='${libs[$element]}' />\n" ""
    else
      echo_message "\n\n" "\n" " filename='${libs[$element]}' />\n" "},"
    fi
  done
}
