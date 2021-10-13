#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

chk_dir() {
  if [[ -z "${CHK_DIR}" ]]; then
    printf "\033[31mError: Please provide a valid directory.\033[m\n\n"
    exit 1
  fi
  # follow symlink
  if [[ -L "${CHK_DIR}" ]]; then
    CHK_DIR=$(readlink -f "${CHK_DIR}")
  fi
  # remove trailing slashes
  tempdir=$(echo "${CHK_DIR}" | sed -e "s/\/*$//")
  if [[ ! -d "${tempdir}" ]]; then
    printf "\033[31mError: The directory '%s' does not exist.\033[m\n\n" "${tempdir}"
    exit 1
  fi
  if ${extended_checks}; then
    echo_message "RELRO           STACK CANARY      NX            PIE             SELFRANDO             Clang CFI            SafeStack            RPATH      RUNPATH    Symbols      \tFORTIFY\tFortified\tFortifiable   Filename\n" '' "<dir name='$tempdir'>\n" "{ \"dir\": { \"name\":\"$tempdir\" }"
  else
    echo_message "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH    Symbols      \tFORTIFY\tFortified\tFortifiable   Filename\n" '' "<dir name='$tempdir'>\n" "{ \"dir\": { \"name\":\"$tempdir\" }"
  fi
  fdircount=0
  fdirtotal=0

  while read -r N; do
    if [[ "${N}" != "[A-Za-z1-0]*" ]]; then
      out=$(file "$(readlink -f "${N}")")
      if [[ ${out} =~ ELF ]]; then
        ((fdirtotal++))
      fi
    fi
  done < <(find "${tempdir}" -type f 2> /dev/null)
  if [[ $fdirtotal -gt 0 ]]; then
    echo_message "" "" "" ","
  fi
  while read -r N; do
    if [[ "${N}" != "[A-Za-z1-0]*" ]]; then
      # read permissions?
      if [[ ! -r "${N}" ]]; then
        printf "\033[31mError: No read permissions for '%s' (run as root).\033[m\n" ", ${N}"
      else
        # ELF executable?
        out=$(file "$(readlink -f "${N}")")
        if [[ ! ${out} =~ ELF ]]; then
          if [[ "${verbose}" = "true" ]]; then
            echo_message "\033[34m*** Not an ELF file: ${tempdir}/" "" "" ""
            file "${N}"
            echo_message "\033[m" "" "" ""
          fi
        else
          ((fdircount++))
          echo_message "" "" "    " ""
          filecheck "${N}"
          if [[ "$(find "${N}" \( -perm -004000 -o -perm -002000 \) -type f -print)" ]]; then
            echo_message "\033[37;41m${N}\033[m\n" ",${N}\n" " filename='${N}' />\n" ", \"filename\":\"${N}\"}"
          else
            echo_message "${N}\n" ",${N}\n" " filename='${N}' />\n" ", \"filename\":\"${N}\"}"
          fi
          if [[ "${fdircount}" == "${fdirtotal}" ]]; then
            echo_message "" "" "" ""
          else
            echo_message "" "" "" ","
          fi
        fi
      fi
    fi
  done < <(find "${tempdir}" -type f 2> /dev/null)
  echo_message "" "" "</dir>\n" "}"
}
