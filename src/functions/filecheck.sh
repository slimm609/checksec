#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# check file(s)
filecheck() {
  # check for RELRO support
  if [[ $(${readelf} -l "${1}") =~ "no program headers" ]]; then
    echo_message '\033[31mN/A          \033[m   ' 'N/A,' '<file relro="n/a"' " \"${1}\": { \"relro\":\"n/a\","
  elif ${readelf} -l "${1}" 2> /dev/null | grep -q 'GNU_RELRO'; then
    if ${readelf} -d "${1}" 2> /dev/null | grep -q 'BIND_NOW' || ! ${readelf} -l "${1}" 2> /dev/null | grep -q '\.got\.plt'; then
      echo_message '\033[32mFull RELRO   \033[m   ' 'Full RELRO,' '<file relro="full"' " \"${1}\": { \"relro\":\"full\","
    else
      echo_message '\033[33mPartial RELRO\033[m   ' 'Partial RELRO,' '<file relro="partial"' " \"${1}\": { \"relro\":\"partial\","
    fi
  else
    echo_message '\033[31mNo RELRO     \033[m   ' 'No RELRO,' '<file relro="no"' " \"${1}\": { \"relro\":\"no\","
  fi

  # check for stack canary support
  if ${readelf} -s "${1}" 2> /dev/null | grep " UND " | grep -Eq '__stack_chk_fail|__stack_chk_guard|__intel_security_cookie'; then
    echo_message '\033[32mCanary found   \033[m   ' 'Canary found,' ' canary="yes"' '"canary":"yes",'
  else
    echo_message '\033[31mNo canary found\033[m   ' 'No Canary found,' ' canary="no"' '"canary":"no",'
  fi

  # check for NX support
  # shellcheck disable=SC2126
  if [[ $(${readelf} -l "${1}") =~ "no program headers" ]]; then
    echo_message '\033[31mN/A        \033[m   ' 'N/A,' ' nx="n/a"' '"nx":"n/a",'
  elif ${readelf} -l "${1}" 2> /dev/null | grep -q 'GNU_STACK'; then
    if [[ $(${s_readelf} -l "${1}" 2> /dev/null | grep -A 1 'GNU_STACK' | sed 'N;s/\n//g' | grep -Eo "0x[0-9a-f]{16}" | grep -v 0x0000000000000000 | wc -l) -gt 0 ]]; then
      echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"' '"nx":"no",'
    else
      echo_message '\033[32mNX enabled \033[m   ' 'NX enabled,' ' nx="yes"' '"nx":"yes",'
    fi
  else
    echo_message '\033[31mNX disabled\033[m   ' 'NX disabled,' ' nx="no"' '"nx":"no",'
  fi

  # check for PIE support
  if ${readelf} -h "${1}" 2> /dev/null | grep -q 'Type:[[:space:]]*EXEC'; then
    echo_message '\033[31mNo PIE       \033[m   ' 'No PIE,' ' pie="no"' '"pie":"no",'
  elif ${readelf} -h "${1}" 2> /dev/null | grep -q 'Type:[[:space:]]*DYN'; then
    if ${readelf} -d "${1}" 2> /dev/null | grep -q 'DEBUG'; then
      echo_message '\033[32mPIE enabled  \033[m   ' 'PIE enabled,' ' pie="yes"' '"pie":"yes",'
    else
      echo_message '\033[33mDSO          \033[m   ' 'DSO,' ' pie="dso"' '"pie":"dso",'
    fi
  elif ${readelf} -h "${1}" 2> /dev/null | grep -q 'Type:[[:space:]]*REL'; then
    echo_message '\033[33mREL          \033[m   ' 'REL,' ' pie="rel"' '"pie":"rel",'
  else
    echo_message '\033[33mNot an ELF file\033[m   ' 'Not an ELF file,' ' pie="not_elf"' '"pie":"not_elf",'
  fi

  if ${extended_checks}; then
    # check for selfrando support
    if ${readelf} -S "${1}" 2> /dev/null | grep -c 'txtrp' | grep -q '1'; then
      echo_message '\033[32mSelfrando enabled  \033[m   '
    else
      echo_message '\033[31mNo Selfrando       \033[m   '
    fi
  fi

  if ${extended_checks}; then
    # check if compiled with Clang CFI
    #if $readelf -s "$1" 2>/dev/null | grep -Eq '\.cfi'; then
    read -r cfifunc <<< "$($readelf -s "${1}" 2> /dev/null | grep '\.cfi' | awk '{ print $8 }')"
    func=${cfifunc/.cfi/}
    if [ -n "$cfifunc" ] && $readelf -s "$1" 2> /dev/null | grep -q "$func$"; then
      echo_message '\033[32mClang CFI found   \033[m   ' 'with CFI,' ' clangcfi="yes"' '"clangcfi":"yes",'
    else
      echo_message '\033[31mNo Clang CFI found\033[m   ' 'without CFI,' ' clangcfi="no"' '"clangcfi":"no",'
    fi

    # check if compiled with Clang SafeStack
    if $readelf -s "$1" 2> /dev/null | grep -Eq '__safestack_init'; then
      echo_message '\033[32mSafeStack found   \033[m   ' 'with SafeStack,' ' safestack="yes"' '"safestack":"yes",'
    else
      echo_message '\033[31mNo SafeStack found\033[m   ' 'without SafeStack,' ' safestack="no"' '"safestack":"no",'
    fi
  fi

  # check for rpath / run path
  # search for a line that matches RPATH and extract the colon-separated path list within brackets
  # example input: "0x000000000000000f (RPATH) Library rpath: [/lib/systemd:/lib/apparmor]"
  if [[ $(${readelf} -d "${1}") =~ "no dynamic section" ]]; then
    echo_message '\033[32mN/A      \033[m  ' 'N/A,' ' rpath="n/a"' '"rpath":"n/a",'
  else
    IFS=: read -r -a rpath_array <<< "$(${readelf} -d "${1}" 2> /dev/null | awk -F'[][]' '/RPATH/ {print $2}')"
    if [[ "${#rpath_array[@]}" -gt 0 ]]; then
      if xargs stat -c %A <<< "${rpath_array[*]}" 2> /dev/null | grep -q 'rw'; then
        echo_message '\033[31mRW-RPATH \033[m  ' 'RPATH,' ' rpath="yes"' '"rpath":"yes",'
      else
        echo_message '\033[31mRPATH   \033[m  ' 'RPATH,' ' rpath="yes"' '"rpath":"yes",'
      fi
    else
      echo_message '\033[32mNo RPATH \033[m  ' 'No RPATH,' ' rpath="no"' '"rpath":"no",'
    fi
  fi

  # search for a line that matches RUNPATH and extract the colon-separated path list within brackets
  if [[ $(${readelf} -d "${1}") =~ "no dynamic section" ]]; then
    echo_message '\033[32mN/A        \033[m  ' 'N/A,' ' runpath="n/a"' '"runpath":"n/a",'
  else
    IFS=: read -r -a runpath_array <<< "$(${readelf} -d "${1}" 2> /dev/null | awk -F'[][]' '/RUNPATH/ {print $2}')"
    if [[ "${#runpath_array[@]}" -gt 0 ]]; then
      if xargs stat -c %A <<< "${runpath_array[*]}" 2> /dev/null | grep -q 'rw'; then
        echo_message '\033[31mRW-RUNPATH \033[m  ' 'RUNPATH,' ' runpath="yes"' '"runpath":"yes",'
      else
        echo_message '\033[31mRUNPATH   \033[m  ' 'RUNPATH,' ' runpath="yes"' '"runpath":"yes",'
      fi
    else
      echo_message '\033[32mNo RUNPATH \033[m  ' 'No RUNPATH,' ' runpath="no"' '"runpath":"no",'
    fi
  fi

  # check for stripped symbols in the binary
  IFS=" " read -r -a SYM_cnt <<< "$(${readelf} --symbols "${1}" 2> /dev/null | grep '\.symtab' | cut -d' ' -f5 | cut -d: -f1)"
  if ${readelf} --symbols "${1}" 2> /dev/null | grep -q '\.symtab'; then
    echo_message "\033[31m${SYM_cnt[0]} Symbols\t\033[m  " 'Symbols,' ' symbols="yes"' '"symbols":"yes",'
  else
    echo_message '\033[32mNo Symbols\t\033[m  ' 'No Symbols,' ' symbols="no"' '"symbols":"no",'
  fi

  search_libc

  FS_filechk_func_libc="$(${readelf} -s "${FS_libc}" 2> /dev/null | sed -ne 's/.*__\(.*_chk\)@@.*/\1/p')"
  FS_func_libc="${FS_filechk_func_libc//_chk/}"
  FS_func="$(${readelf} --dyn-syms "${1}" 2> /dev/null | awk '{ print $8 }' | sed -e 's/_*//' -e 's/@.*//' -e '/^$/d')"
  FS_cnt_checked=$(grep -cFxf <(sort <<< "${FS_filechk_func_libc}") <(sort <<< "${FS_func}"))
  FS_cnt_unchecked=$(grep -cFxf <(sort <<< "${FS_func_libc}") <(sort <<< "${FS_func}"))
  FS_cnt_total=$((FS_cnt_unchecked + FS_cnt_checked))

  if grep -q '_chk$' <<< "$FS_func"; then
    echo_message '\033[32mYes\033[m' 'Yes,' ' fortify_source="yes" ' '"fortify_source":"yes",'
  else
    echo_message "\033[31mNo\033[m" "No," ' fortify_source="no" ' '"fortify_source":"no",'
  fi
  echo_message "\t${FS_cnt_checked}\t" "${FS_cnt_checked}", "fortified=\"${FS_cnt_checked}\" " "\"fortified\":\"${FS_cnt_checked}\","
  echo_message "\t${FS_cnt_total}\t\t" "${FS_cnt_total}" "fortify-able=\"${FS_cnt_total}\"" "\"fortify-able\":\"${FS_cnt_total}\""
}
