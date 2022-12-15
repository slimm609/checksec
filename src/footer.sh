#!/usr/bin/env bash
# shellcheck disable=SC2154,SC2034
# these top lines are moved during build

# run help if nothing is passed
if [[ $# -lt 1 ]]; then
  help
  exit 1
fi

optspec=":h-:"
while getopts "${optspec}" optchar; do
  case "${optchar}" in
    -)
      case "${OPTARG}" in
        version)
          version
          exit 0
          ;;
        debug)
          debug=true
          ;;
        trace)
          export BASH_XTRACEFD=5
          export PS4='(${BASH_SOURCE##*/}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
          set -x
          ;;
        help)
          help
          exit 0
          ;;
        debug_report)
          debug_report
          exit 0
          ;;
        update | upgrade)
          # shellcheck disable=SC2119
          upgrade
          exit 0
          ;;
        format=* | output=*)
          output_format=${OPTARG#*=}
          format
          ;;
        verbose)
          verbose=true
          ;;
        extended)
          extended_checks=true
          ;;
        dir=*)
          CHK_DIR=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_dir"
          ;;
        file=*)
          CHK_FILE=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_file"
          ;;
        listfile=*)
          CHK_FILE_LIST=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_file_list"
          ;;
        libcfile=*)
          LIBC_FILE=${OPTARG#*=}
          echo LIBC_FILE="${LIBC_FILE}"
          ;;
        proc-all)
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_proc_all"
          ;;
        proc=*)
          CHK_PROC=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_proc"
          ;;
        proc-libs=*)
          CHK_PROC_LIBS=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_proc_libs"
          ;;
        fortify-file=*)
          CHK_FORTIFY_FILE=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_fortify_file"
          ;;
        fortify-proc=*)
          CHK_FORTIFY_PROC=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_fortify_proc"
          ;;
        kernel=*)
          CHK_KERNEL=${OPTARG#*=}
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_kernel"
          ;;
        kernel)
          OPT=$((OPT + 1))
          CHK_FUNCTION="chk_kernel"
          ;;
        *)
          printf "\033[31mError: Unknown option %s.\033[m\n\n" "${OPTARG}"
          exit 1
          ;;
      esac
      ;;
    *)
      help
      exit 0
      ;;
  esac
done

if [[ "${OPT}" == 0 ]]; then
  printf "\033[31mError: No option selected. Please select an option.\033[m\n\n"
  exit 1
elif [[ "${OPT}" != 1 ]]; then
  printf "\033[31mError: To many options selected. Please select one at a time.\033[m\n\n"
  exit 1
fi

for variable in CHK_DIR CHK_FILE CHK_FORTIFY_FILE CHK_FORTIFY_PROC CHK_PROC CHK_PROC_LIBS; do
  if [[ -n ${!variable+x} ]]; then
    if [[ -z "${!variable}" ]]; then
      printf "\033[31mError: Option Required.\033[m\n\n"
      help
      exit 1
    fi
  fi
done

# call the function
${CHK_FUNCTION}
