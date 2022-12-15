#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

chk_fortify_file() {
  # if first char of pathname is '~' replace it with '${HOME}'
  if [[ "${CHK_FORTIFY_FILE:0:1}" = '~' ]]; then
    CHK_FORTIFY_FILE=${HOME}/${CHK_FORTIFY_FILE:1}
  fi

  if [[ -z "${CHK_FORTIFY_FILE}" ]]; then
    printf "\033[31mError: Please provide a valid file.\033[m\n\n"
    exit 1
  fi
  # does the file exist?
  if [[ ! -f "${CHK_FORTIFY_FILE}" ]]; then
    printf "\033[31mError: The file '%s' does not exist.\033[m\n\n" "${CHK_FORTIFY_FILE}"
    exit 1
  fi
  # read permissions?
  if [[ ! -r "${CHK_FORTIFY_FILE}" ]]; then
    printf "\033[31mError: No read permissions for '%s' (run as root).\033[m\n\n" "${CHK_FORTIFY_FILE}"
    exit 1
  fi
  # ELF executable?
  out=$(file "$(readlink -f "${CHK_FORTIFY_FILE}")")
  if [[ ! ${out} =~ ELF ]]; then
    printf "\033[31mError: Not an ELF file: "
    file "${CHK_FORTIFY_FILE}"
    printf "\033[m\n"
    exit 1
  fi

  search_libc

  FS_chk_func_libc=()
  FS_functions=()
  while IFS='' read -r line; do FS_chk_func_libc+=("$line"); done < <(${readelf} -s "${FS_libc}" 2> /dev/null | grep _chk@@ | awk '{ print $8 }' | cut -c 3- | sed -e 's/_chk@.*//')
  while IFS='' read -r line; do FS_functions+=("$line"); done < <(${readelf} -s "${CHK_FORTIFY_FILE}" 2> /dev/null | awk '{ print $8 }' | sed 's/_*//' | sed -e 's/@.*//')
  echo_message "" "" "<fortify-test name='${CHK_FORTIFY_FILE}' " "{ \"fortify-test\": { \"name\":\"${CHK_FORTIFY_FILE}\" "
  FS_libc_check
  FS_binary_check
  FS_comparison
  FS_summary
  echo_message "" "" "</fortify-test>\n" "} }"
}

chk_fortify_proc() {
  if [[ -z "${CHK_FORTIFY_PROC}" ]]; then
    printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
    exit 1
  fi
  if ! (isNumeric "${CHK_FORTIFY_PROC}"); then
    printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
    exit 1
  fi
  cd /proc || exit
  N=${CHK_FORTIFY_PROC}
  if [[ -d "${N}" ]]; then
    # read permissions?
    if [[ ! -r "${N}/exe" ]]; then
      if ! (root_privs); then
        printf "\033[31mNo read permissions for '/proc/%s/exe' (run as root).\033[m\n\n" "${N}"
        exit 1
      fi
      if [[ ! "$(readlink "${N}/exe")" ]]; then
        printf "\033[31mPermission denied. Requested process ID belongs to a kernel thread.\033[m\n\n"
        exit 1
      fi
      exit 1
    fi
    name=$(head -1 "${N}/status" | cut -b 7-)
    echo_message "* Process name (PID)                         : ${name} (${N})\n" "" "" ""

    search_libc

    FS_chk_func_libc=()
    FS_functions=()
    while IFS='' read -r line; do FS_chk_func_libc+=("$line"); done < <(${readelf} -s "${FS_libc}" 2> /dev/null | grep _chk@@ | awk '{ print $8 }' | cut -c 3- | sed -e 's/_chk@.*//')
    while IFS='' read -r line; do FS_functions+=("$line"); done < <(${readelf} -s "${CHK_FORTIFY_PROC}/exe" 2> /dev/null | awk '{ print $8 }' | sed 's/_*//' | sed -e 's/@.*//')
    echo_message "" "" "<fortify-test name='${name}' pid='${N}' " "{ \"fortify-test\": { \"name\":\"${name}\", \"pid\":\"${N}\" "
    FS_libc_check
    FS_binary_check
    FS_comparison
    FS_summary
    echo_message "" "" "</fortify-test>\n" "} }"
  fi
}
