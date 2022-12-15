#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

chk_file() {
  if [[ -z "${CHK_FILE}" ]]; then
    printf "\033[31mError: Please provide a valid file.\033[m\n\n"
    exit 1
  fi

  # does the file exist?
  if [[ ! -e "${CHK_FILE}" ]]; then
    printf "\033[31mError: The file '%s' does not exist.\033[m\n\n" "${CHK_FILE}"
    exit 1
  fi

  # read permissions?
  if [[ ! -r "${CHK_FILE}" ]]; then
    printf "\033[31mError: No read permissions for '%s' (run as root).\033[m\n\n" "${CHK_FILE}"
    exit 1
  fi

  # ELF executable?
  out=$(file "$(readlink -f "${CHK_FILE}")")
  if [[ ! ${out} =~ ELF ]]; then
    printf "\033[31mError: Not an ELF file: "
    file "${CHK_FILE}"
    printf "\033[m\n"
    exit 1
  fi
  if ${extended_checks}; then
    echo_message "RELRO           STACK CANARY      NX            PIE             SELFRANDO             Clang CFI            SafeStack            RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE\n" '' '' '{'
  else
    echo_message "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE\n" '' '' '{'
  fi
  filecheck "${CHK_FILE}"
  if [[ "$(find "${CHK_FILE}" \( -perm -004000 -o -perm -002000 \) -type f -print)" ]]; then
    echo_message "\033[37;41m${CHK_FILE}\033[m\n" ",${CHK_FILE}\n" " filename='${CHK_FILE}'/>\n" " } }"
  else
    echo_message "${CHK_FILE}\n" ",${CHK_FILE}\n" " filename='${CHK_FILE}'/>\n" " } }"
  fi
}

chk_file_list() {

  if ${extended_checks}; then
    echo_message "RELRO           STACK CANARY      NX            PIE             SELFRANDO             Clang CFI            SafeStack            RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE\n" '' '' '{\n'
  else
    echo_message "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH\tSymbols\t\tFORTIFY\tFortified\tFortifiable\tFILE\n" '' '' '{\n'
  fi

  LAST_LINE_NUMBER=$(wc -l < "${CHK_FILE_LIST}")
  CURRENT_LINE_NUMBER=0
  while IFS="" read -r p || [[ -n "${p}" ]]; do
    CHK_FILE="${p}"
    CURRENT_LINE_NUMBER=$((CURRENT_LINE_NUMBER + 1))

    if [[ -z "${CHK_FILE}" ]]; then
      printf "\033[31mError: Please provide a valid file.\033[m\n\n"
      exit 1
    fi

    # does the file exist?
    if [[ ! -e "${CHK_FILE}" ]]; then
      printf "\033[31mError: The file '%s' does not exist.\033[m\n\n" "${CHK_FILE}"
      exit 1
    fi

    # read permissions?
    if [[ ! -r "${CHK_FILE}" ]]; then
      printf "\033[31mError: No read permissions for '%s' (run as root).\033[m\n\n" "${CHK_FILE}"
      exit 1
    fi

    # ELF executable?
    out=$(file "$(readlink -f "${CHK_FILE}")")
    if [[ ! ${out} =~ ELF ]]; then
      printf "\033[31mError: Not an ELF file: "
      file "${CHK_FILE}"
      printf "\033[m\n"
      exit 1
    fi
    filecheck "${CHK_FILE}"
    if [[ "$(find "${CHK_FILE}" \( -perm -004000 -o -perm -002000 \) -type f -print)" ]]; then
      echo_message "\033[37;41m${CHK_FILE}\033[m\n" ",${CHK_FILE}\n" " filename='${CHK_FILE}'/>\n" " } }"
    else
      LINE_ENDING=" },\n"
      if [[ $CURRENT_LINE_NUMBER -eq $LAST_LINE_NUMBER ]]; then
        LINE_ENDING=" }\n"
      fi
      echo_message "${CHK_FILE}\n" ",${CHK_FILE}\n" " filename='${CHK_FILE}'/>\n" "${LINE_ENDING}"
    fi

  done < "${CHK_FILE_LIST}"

  echo_message '' '' '' ' }\n'
}
