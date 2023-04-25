#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# check process(es)
proccheck() {
  # check for RELRO support
  if ${readelf} -l "${1}/exe" 2> /dev/null | grep -q 'Program Headers'; then
    if ${readelf} -l "${1}/exe" 2> /dev/null | grep -q 'GNU_RELRO'; then
      if ${readelf} -d "${1}/exe" 2> /dev/null | grep -q 'BIND_NOW' || ! ${readelf} -l "${1}/exe" 2> /dev/null | grep -q '\.got\.plt'; then
        echo_message '\033[32mFull RELRO   \033[m   ' 'Full RELRO,' ' relro="full"' '"relro":"full",'
      else
        echo_message '\033[33mPartial RELRO\033[m   ' 'Partial RELRO,' ' relro="partial"' '"relro":"partial",'
      fi
    else
      echo_message '\033[31mNo RELRO     \033[m   ' 'No RELRO,' ' relro="no"' '"relro":"no",'
    fi
  else
    echo -n -e '\033[31mPermission denied (please run as root)\033[m\n'
    exit 1
  fi

  # check for stack canary support
  if ${readelf} -W -s "${1}/exe" 2> /dev/null | grep -q 'Symbol table'; then
    if ${readelf} -W -s "${1}/exe" 2> /dev/null | grep " UND " | grep -Eq '__stack_chk_fail|__stack_chk_guard|__intel_security_cookie'; then
      echo_message '\033[32mCanary found         \033[m   ' 'Canary found,' ' canary="yes"' '"canary":"yes",'
    else
      echo_message '\033[31mNo canary found      \033[m   ' 'No Canary found,' ' canary="no"' '"canary":"no",'
    fi
  else
    if [[ "${1}" == "1" ]]; then
      echo_message '\033[33mPermission denied    \033[m   ' 'Permission denied,' ' canary="Permission denied"' '"canary":"Permission denied",'
    else
      echo_message '\033[33mNo symbol table found \033[m  ' 'No symbol table found,' ' canary="No symbol table found"' '"canary":"No symbol table found",'
    fi
  fi

  if ${extended_checks}; then
    # check if compiled with Clang CFI
    $debug && echo -e "\n***function proccheck->clangcfi"
    #if $readelf -s "$1" 2>/dev/null | grep -Eq '\.cfi'; then
    read -r -a cfifunc <<< "$($readelf -s "$1/exe" 2> /dev/null | grep '\.cfi' | awk '{ print $8 }')"
    func=${cfifunc/.cfi/}
    # TODO: fix this check properly, need more clang CFI files to be able to test properly
    # shellcheck disable=SC2128
    if [ -n "$cfifunc" ] && $readelf -s "$1/exe" 2> /dev/null | grep -q "$func$"; then
      echo_message '\033[32mClang CFI found   \033[m   ' 'with CFI,' ' clangcfi="yes"' '"clangcfi":"yes",'
    else
      echo_message '\033[31mNo Clang CFI found\033[m   ' 'without CFI,' ' clangcfi="no"' '"clangcfi":"no",'
    fi

    # check if compiled with Clang SafeStack
    $debug && echo -e "\n***function proccheck->safestack"
    if $readelf -s "$1/exe" 2> /dev/null | grep -Eq '__safestack_init'; then
      echo_message '\033[32mSafeStack found   \033[m   ' 'with SafeStack,' ' safestack="yes"' '"safestack":"yes",'
    else
      echo_message '\033[31mNo SafeStack found\033[m   ' 'without SafeStack,' ' safestack="no"' '"safestack":"no",'
    fi
  fi

  # check for Seccomp mode
  seccomp=$(grep 'Seccomp:' "${1}/status" 2> /dev/null | cut -b10)
  if [[ "${seccomp}" == "1" ]]; then
    echo_message '\033[32mSeccomp strict\033[m   ' 'Seccomp strict,' ' seccomp="strict"' '"seccomp":"strict",'
  elif [[ "${seccomp}" == "2" ]]; then
    echo_message '\033[32mSeccomp-bpf   \033[m   ' 'Seccomp-bpf,' ' seccomp="bpf"' '"seccomp":"bpf",'
  else
    echo_message '\033[31mNo Seccomp    \033[m   ' 'No Seccomp,' ' seccomp="no"' '"seccomp":"no",'
  fi

  # first check for PaX support
  # shellcheck disable=SC2126
  if [[ $(grep -c 'PaX:' "${1}/status" 2> /dev/null) -gt 0 ]]; then
    pageexec=$(grep 'PaX:' "${1}/status" 2> /dev/null | cut -b6)
    segmexec=$(grep 'PaX:' "${1}/status" 2> /dev/null | cut -b10)
    mprotect=$(grep 'PaX:' "${1}/status" 2> /dev/null | cut -b8)
    randmmap=$(grep 'PaX:' "${1}/status" 2> /dev/null | cut -b9)
    if [[ "${pageexec}" = "P" || "${segmexec}" = "S" ]] && [[ "${mprotect}" = "M" && "${randmmap}" = "R" ]]; then
      echo_message '\033[32mPaX enabled\033[m   ' 'Pax enabled,' ' pax="yes"' '"pax":"yes",'
    elif [[ "${pageexec}" = "p" && "${segmexec}" = "s" && "${randmmap}" = "R" ]]; then
      echo_message '\033[33mPaX ASLR only\033[m ' 'Pax ASLR only,' ' pax="aslr_only"' '"pax":"aslr_only",'
    elif [[ "${pageexec}" = "P" || "${segmexec}" = "S" ]] && [[ "${mprotect}" = "m" && "${randmmap}" = "R" ]]; then
      echo_message '\033[33mPaX mprot off \033[m' 'Pax mprot off,' ' pax="mprot_off"' '"pax":"mprot_off",'
    elif [[ "${pageexec}" = "P" || "${segmexec}" = "S" ]] && [[ "${mprotect}" = "M" && "${randmmap}" = "r" ]]; then
      echo_message '\033[33mPaX ASLR off\033[m  ' 'Pax ASLR off,' ' pax="aslr_off"' '"pax":"aslr_off",'
    elif [[ "${pageexec}" = "P" || "${segmexec}" = "S" ]] && [[ "${mprotect}" = "m" && "${randmmap}" = "r" ]]; then
      echo_message '\033[33mPaX NX only\033[m   ' 'Pax NX only,' ' pax="nx_only"' '"pax":"nx_only",'
    else
      echo_message '\033[31mPaX disabled\033[m  ' 'Pax disabled,' ' pax="no"' '"pax":"no",'
    fi
    # fallback check for NX support
  elif [[ $(${s_readelf} -l "${1}/exe" 2> /dev/null | grep -A 1 'GNU_STACK' | sed 'N;s/\n//g' | grep -Eo "0x[0-9a-f]{16}" | grep -v 0x0000000000000000 | wc -l) -gt 0 ]]; then
    echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"' '"nx":"no",'
  else
    echo_message '\033[32mNX enabled \033[m   ' 'NX enabled,' ' pax="yes"' '"nx":"yes",'
  fi

  # check for PIE support
  if ${readelf} -h "${1}/exe" 2> /dev/null | grep -q 'Type:[[:space:]]*EXEC'; then
    echo_message '\033[31mNo PIE               \033[m   ' 'No PIE,' ' pie="no"' '"pie":"no",'
  elif ${readelf} -h "${1}/exe" 2> /dev/null | grep -q 'Type:[[:space:]]*DYN'; then
    if ${readelf} -d "${1}/exe" 2> /dev/null | grep -q 'DEBUG'; then
      echo_message '\033[32mPIE enabled          \033[m   ' 'PIE enabled,' ' pie="yes"' '"pie":"yes",'
    else
      echo_message '\033[33mDynamic Shared Object\033[m   ' 'Dynamic Shared Object,' ' pie="dso"' '"pie":"dso",'
    fi
  else
    echo_message '\033[33mNot an ELF file      \033[m   ' 'Not an ELF file,' ' pie="not_elf"' '"pie":"not_elf",'
  fi

  if ${extended_checks}; then
    # check for selfrando support
    if ${readelf} -S "${1}/exe" 2> /dev/null | grep -c 'txtrp' | grep -q '1'; then
      echo_message '\033[32mSelfrando enabled    \033[m   '
    else
      echo_message '\033[31mNo Selfrando         \033[m   '
    fi
  fi

  #check for forifty source support
  Proc_FS_functions="$(${readelf} -s "${1}/exe" 2> /dev/null | awk '{ print $8 }' | sed 's/_*//' | sed -e 's/@.*//')"
  if grep -q '_chk$' <<< "$Proc_FS_functions"; then
    echo_message '\033[32mYes\033[m' 'Yes' " fortify_source='yes'>" '"fortify_source":"yes" }'
  else
    echo_message "\033[31mNo\033[m" "No" " fortify_source='no'>" '"fortify_source":"no" }'
  fi
}
