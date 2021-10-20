#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

chk_proc_all() {
  cd /proc || exit
  echo_message "* System-wide ASLR" "" "" ""
  aslrcheck
  echo_message "* Does the CPU support NX: " "" "<procs>" ""
  nxcheck
  echo_message "* Core-Dumps access to all users: " "" "" ""
  coredumpcheck
  if ${extended_checks}; then
    echo_message "         COMMAND    PID RELRO           STACK CANARY            Clang CFI            SafeStack            SECCOMP          NX/PaX        PIE                     SELFRANDO             FORTIFY\n" "" "" '{'
  else
    echo_message "         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY\n" "" "" '{'
  fi
  lastpid=0
  currpid=0
  for N in [1-9]*; do
    if [[ "${N}" != "$$" ]] && readlink -q "${N}"/exe > /dev/null; then
      ((lastpid++))
    fi
  done
  for N in [1-9]*; do
    if [[ "${N}" != "$$" ]] && readlink -q "${N}"/exe > /dev/null; then
      ((currpid++))
      name=$(head -1 "${N}"/status | cut -b 7-)
      if [[ $format == "cli" ]]; then
        printf "%16s" "${name}"
        printf "%7d " "${N}"
      else
        echo_message "" "${N}," " <proc pid='${N}'" " \"${N}\": { "
        echo_message "" "${name}," " name='${name}'" "\"name\":\"${name}\","
      fi
      proccheck "${N}"
      if [[ "${lastpid}" == "${currpid}" ]]; then
        echo_message "\n" "\n" "</proc>\n" ""
      else
        echo_message "\n" "\n" "</proc>\n" ","
      fi
    fi
  done
  echo_message "" "" "</procs>" " }\n"
  if [[ ! -e /usr/bin/id ]]; then
    echo_message "\n\033[33mNote: If you are running 'checksec.sh' as an unprivileged user, you\n" "" "" ""
    echo_message "      will not see all processes. Please run the script as root.\033[m\n\n" "" "" "\n"
  else
    if ! (root_privs); then
      echo_message "\n\033[33mNote: You are running 'checksec.sh' as an unprivileged user.\n" "" "" ""
      echo_message "      Too see all processes, please run the script as root.\033[m\n\n" "" "" "\n"
    fi
  fi
}

chk_proc() {
  if [[ -z "${CHK_PROC}" ]]; then
    printf "\033[31mError: Please provide a valid process name.\033[m\n\n"
    exit 1
  fi
  cd /proc || exit
  if (isString "${CHK_PROC}"); then
    IFS=" " read -r -a fpids <<< "$(pgrep -d ' ' "${CHK_PROC}")"
  elif (isNumeric "${CHK_PROC}"); then
    fpids=("${CHK_PROC}")
  else
    printf "\033[31mError: Please provide a valid process name or pid.\033[m\n\n"
    exit 1
  fi

  if [[ ${#fpids} -eq 0 ]]; then
    printf "\033[31mError: No process with the given name or pid found.\033[m\n\n"
    exit 1
  fi
  echo_message "* System-wide ASLR" '' '' ''
  aslrcheck
  echo_message "* Does the CPU support NX: " '' '' ''
  nxcheck
  if ${extended_checks}; then
    echo_message "         COMMAND    PID RELRO           STACK CANARY            Clang CFI            SafeStack            SECCOMP          NX/PaX        PIE                     SELFRANDO             FORTIFY\n" "" "" '{'
  else
    echo_message "         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY\n" "" "" '{'
  fi
  pos=$((${#fpids[*]} - 1))
  last=${fpids[$pos]}
  for N in "${fpids[@]}"; do
    if [[ -d "${N}" ]]; then
      name=$(head -1 "${N}"/status | cut -b 7-)
      if [[ $format == "cli" ]]; then
        printf "%16s" "${name}"
        printf "%7d " "${N}"
      else
        echo_message "" "${N}," "<proc pid='${N}'" " \"${N}\": {"
        echo_message "" "${name}," " name='${name}'" "\"name\":\"${name}\","
      fi
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
      proccheck "${N}"
      if [[ "${N}" == "$last" ]]; then
        echo_message "\n" "\n" "</proc>\n" ""
      else
        echo_message "\n" "\n" "</proc>\n" ","
      fi
    fi
  done
  echo_message "\n" "\n" "\n" "}\n"
}

chk_proc_libs() {
  if [[ -z "${CHK_PROC_LIBS}" ]]; then
    printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
    exit 1
  fi
  if ! (isNumeric "${CHK_PROC_LIBS}"); then
    printf "\033[31mError: Please provide a valid process ID.\033[m\n\n"
    exit 1
  fi
  cd /proc || exit
  echo_message "* System-wide ASLR" '' '' ''
  aslrcheck
  echo_message "* Does the CPU support NX: " '' '' ''
  nxcheck
  echo_message "* Process information:\n\n" "" "" ""
  if ${extended_checks}; then
    echo_message "         COMMAND    PID RELRO           STACK CANARY            Clang CFI            SafeStack            SECCOMP        NX/PaX        PIE                     Fortify Source\n" '' '' ''
  else
    echo_message "         COMMAND    PID RELRO           STACK CANARY            SECCOMP        NX/PaX        PIE                     Fortify Source\n" '' '' ''
  fi
  N=${CHK_PROC_LIBS}
  if [[ -d "${N}" ]]; then
    name=$(head -1 "${N}/status" | cut -b 7-)
    if [[ "${format}" == "cli" ]]; then
      printf "%16s" "${name}"
      printf "%7d " "${N}"
    else
      echo_message "" "${name}," "<proc name='${name}'" "{ \"proc\": { \"name\":\"${name}\", "
      echo_message "" "${N}," " pid='${N}'" "\"pid\":\"${N}\","
    fi
    # read permissions?
    if [[ ! -r "${N}/exe" ]]; then
      if ! (root_privs); then
        printf "\033[31mNo read permissions for '/proc/%s/exe' (run as root).\033[m\n\n" "${N}"
        exit 1
      fi
      if [[ ! "$(readlink "${N}"/exe)" ]]; then
        printf "\033[31mPermission denied. Requested process ID belongs to a kernel thread.\033[m\n\n"
        exit 1
      fi
      exit 1
    fi
    proccheck "${N}"
    echo_message "\n\n\n" "\n" "\n" ","
    if ${extended_checks}; then
      echo_message "    RELRO           STACK CANARY   Clang CFI            SafeStack            NX/PaX        PIE            Clang CFI            SafeStack            RPath       RunPath   Fortify Fortified   Fortifiable\n" '' '' ''
    else
      echo_message "    RELRO           STACK CANARY   NX/PaX        PIE            RPath       RunPath   Fortify Fortified   Fortifiable\n" '' '' ''
    fi
    libcheck "${N}"
    echo_message "\n" "\n" "</proc>\n" "} } }"
  fi
}
