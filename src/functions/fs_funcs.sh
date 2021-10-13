#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# --- FORTIFY_SOURCE subfunctions (start) ---
# is FORTIFY_SOURCE supported by libc?
FS_libc_check() {
  echo_message "* FORTIFY_SOURCE support available (libc)    : " "" ""

  if [[ "${#FS_chk_func_libc[@]}" != "0" ]]; then
    echo_message "\033[32mYes\033[m\n" "Yes," " libc_fortify_source='yes' " ', "libc_fortify_source":"yes"'
  else
    echo_message "\033[31mNo\033[m\n" "No," " libc_fortify_source='no' " ', "libc_fortify_source":"no"'
    exit 1
  fi
}

# was the binary compiled with FORTIFY_SOURCE?
FS_binary_check() {
  echo_message "* Binary compiled with FORTIFY_SOURCE support: " "" "" ""

  for ((FS_elem_functions = 0; FS_elem_functions < ${#FS_functions[@]}; FS_elem_functions++)); do
    if [[ ${FS_functions[$FS_elem_functions]} =~ _chk$ ]]; then
      echo_message "\033[32mYes\033[m\n" "Yes\n" " binary_compiled_with_fortify='yes'>\n" ', "binary_compiled_with_fortify":"yes"'
      return
    fi
  done
  echo_message "\033[31mNo\033[m\n" "No\n" " binary_compiled_with_fortify='no'>\n" ', "binary_compiled_with_fortify":"no"'
}

FS_comparison() {
  echo_message "\n" "" ""
  echo_message " ------ EXECUTABLE-FILE ------- . -------- LIBC --------\n" "" "" ""
  echo_message " Fortifiable library functions | Checked function names\n" "" "" ""
  echo_message " -------------------------------------------------------\n" "" "" ""

  for ((FS_elem_libc = 0; FS_elem_libc < ${#FS_chk_func_libc[@]}; FS_elem_libc++)); do
    for ((FS_elem_functions = 0; FS_elem_functions < ${#FS_functions[@]}; FS_elem_functions++)); do
      FS_tmp_func=${FS_functions[$FS_elem_functions]}
      FS_tmp_libc=${FS_chk_func_libc[$FS_elem_libc]}

      if [[ ${FS_tmp_func} =~ ^${FS_tmp_libc}$ ]]; then
        if [[ ${format} == "cli" ]]; then
          printf " \033[31m%-30s\033[m | __%s%s\n" "${FS_tmp_func}" "${FS_tmp_libc}" "${FS_end}"
        else
          if [[ $FS_elem_functions == 0 ]]; then
            echo_message "" "${FS_tmp_func},${FS_tmp_libc},yes\n" "    <function name='${FS_tmp_func}' libc='${FS_tmp_libc}' fortifiable='yes' />\n" ", \"function\": { \"name\":\"${FS_tmp_func}\", \"libc\":\"${FS_tmp_libc}\", \"fortifiable\":\"yes\" }"
          elif [[ $FS_elem_functions == $((${#FS_functions[@]} - 1)) ]]; then
            echo_message "" "${FS_tmp_func},${FS_tmp_libc},yes\n" "    <function name='${FS_tmp_func}' libc='${FS_tmp_libc}' fortifiable='yes' />\n" ", \"function\": { \"name\":\"${FS_tmp_func}\", \"libc\":\"${FS_tmp_libc}\", \"fortifiable\":\"yes\" }"
          else
            echo_message "" "${FS_tmp_func},${FS_tmp_libc},yes\n" "    <function name='${FS_tmp_func}' libc='${FS_tmp_libc}' fortifiable='yes' />\n" ", \"function\": { \"name\":\"${FS_tmp_func}\", \"libc\":\"${FS_tmp_libc}\", \"fortifiable\":\"yes\" }"
          fi
        fi
        ((FS_cnt_total++))
        ((FS_cnt_unchecked++))
      elif [[ ${FS_tmp_func} =~ ^${FS_tmp_libc}(_chk)$ ]]; then
        if [[ ${format} == "cli" ]]; then
          printf " \033[32m%-30s\033[m | __%s%s\n" "${FS_tmp_func}" "${FS_tmp_libc}" "${FS_end}"
        else
          if [[ $FS_elem_functions == 0 ]]; then
            echo_message "" "${FS_tmp_func},${FS_tmp_libc},no\n" "    <function name='${FS_tmp_func}' libc='${FS_tmp_libc}' fortifiable='no' />\n" ", \"function\": { \"name\":\"${FS_tmp_func}\", \"libc\":\"${FS_tmp_libc}\", \"fortifiable\":\"no\" }"
          elif [[ $FS_elem_functions == $((${#FS_functions[@]} - 1)) ]]; then
            echo_message "" "${FS_tmp_func},${FS_tmp_libc},no\n" "    <function name='${FS_tmp_func}' libc='${FS_tmp_libc}' fortifiable='no' />\n" ", \"function\": { \"name\":\"${FS_tmp_func}\", \"libc\":\"${FS_tmp_libc}\", \"fortifiable\":\"no\" }"
          else
            echo_message "" "${FS_tmp_func},${FS_tmp_libc},no\n" "    <function name='${FS_tmp_func}' libc='${FS_tmp_libc}' fortifiable='no' />\n" ", \"function\": { \"name\":\"${FS_tmp_func}\", \"libc\":\"${FS_tmp_libc}\", \"fortifiable\":\"no\" }"
          fi
        fi
        ((FS_cnt_total++))
        ((FS_cnt_checked++))
      fi

    done
  done
}

FS_summary() {
  echo_message "\n" "" "\n" ""
  echo_message "SUMMARY:\n\n" "" "" ""
  echo_message "* Number of checked functions in libc                : ${#FS_chk_func_libc[@]}\n" "${#FS_chk_func_libc[@]}," "    <stats nb_libc_func='${#FS_chk_func_libc[@]}'" ", \"stats\": { \"nb_libc_func\":\"${#FS_chk_func_libc[@]}\""
  echo_message "* Total number of library functions in the executable: ${#FS_functions[@]}\n" "${#FS_functions[@]}," " nb_total_func='${#FS_functions[@]}'" ", \"nb_total_func\":\"${#FS_functions[@]}\""
  echo_message "* Number of Fortifiable functions in the executable : ${FS_cnt_total}\n" "${FS_cnt_total}," " nb_fortifiable_func='${FS_cnt_total}'" ", \"nb_fortifiable_func\":\"${FS_cnt_total}\""
  echo_message "* Number of checked functions in the executable      : \033[32m${FS_cnt_checked}\033[m\n" "${FS_cnt_checked}," " nb_checked_func='${FS_cnt_checked}'" ", \"nb_checked_func\":\"${FS_cnt_checked}\""
  echo_message "* Number of unchecked functions in the executable    : \033[31m${FS_cnt_unchecked}\033[m\n" "${FS_cnt_unchecked}" " nb_unchecked_func='${FS_cnt_unchecked}' />" ", \"nb_unchecked_func\":\"${FS_cnt_unchecked}\" } "
  echo_message "\n" "\n" "\n" ""
}
