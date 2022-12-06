#!/usr/bin/env bash
set -ou pipefail
if [[ -f /bin/bash ]]; then
  test_file="/bin/bash"
elif [[ -f /bin/sh ]]; then
  test_file="/bin/sh"
elif [[ -f /bin/ls ]]; then
  test_file="/bin/ls"
else
  echo "could not find valid file to test"
  exit 255
fi

DIR=$(
  cd "$(dirname "$0")"
  pwd
)
PARENT=$(
  cd "$(dirname "$0")/.."
  pwd
)

jsonlint=$(command -v jsonlint || command -v jsonlint-py)
#check json for proc-all
echo "starting proc-all check - json"
"${PARENT}"/checksec --format=json --proc-all > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "proc-all json validation failed"
  exit 1
fi

#check json for proc-all
echo "starting extended proc-all check - json"
"${PARENT}/checksec" --format=json --proc-all --extended > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "proc-all json validation failed"
  exit 1
fi

#check json for kernel
echo "starting kernel check - json"
"${PARENT}/checksec" --format=json --kernel > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "kernel json validation failed"
  exit 1
fi

echo "starting custom kernel check for file kernel.config - json"
"${PARENT}/checksec" --format=json --kernel=kernel.config > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "custom kernel json validation failed"
  exit 1
fi

while read -r file; do
  #check json against custom kernel config to trigger all checks
  echo "starting custom kernel check for file ${file} - json"
  "${PARENT}/checksec" --format=json --kernel="${file}" > "${DIR}/output.json"
  "${jsonlint}" "${DIR}/output.json" > /dev/null
  RET=$?
  jq . < "${DIR}/output.json" &> /dev/null
  JQRET=$?
  if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
    cat "${DIR}/output.json"
    echo "custom kernel json validation failed"
    exit 1
  fi
done < <(find "${PARENT}"/kernel_configs/configs/ -type f -iname "config-*")

#check json for file
echo "starting file check - json"
"${PARENT}/checksec" --format=json --file="${test_file}" > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "file json validation failed"
  exit 1
fi

#check json for listfile
echo "starting listfile check - json"
"${PARENT}/checksec" --format=json --listfile=<(printf "%b" "${test_file}\n${test_file}") > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "listfile json validation failed"
  exit 1
fi

#check json for file extended
echo "starting extended file check - json"
"${PARENT}/checksec" --format=json --extended --file="${test_file}" > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "file json validation failed"
  exit 1
fi

#check json for fortify file
echo "starting fortify-file check - json"
"${PARENT}/checksec" --format=json --fortify-file="${test_file}" > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "fortify-file json validation failed"
  exit 1
fi

#check json for fortify file
echo "starting extended fortify-file check - json"
"${PARENT}/checksec" --format=json --fortify-file="${test_file}" --extended > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "fortify-file json validation failed"
  exit 1
fi

#check json for fortify proc
echo "starting fortify-proc check - json"
"${PARENT}/checksec" --format=json --fortify-proc=1 > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "fortify-file json validation failed"
  exit 1
fi

#check json for fortify proc
echo "starting extended fortify-proc check - json"
"${PARENT}/checksec" --format=json --fortify-proc=1 --extended > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "fortify-file json validation failed"
  exit 1
fi

#check json for dir
echo "starting dir check - json"
"${PARENT}"/checksec --format=json --dir=/sbin > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "dir json validation failed"
  exit 1
fi

echo "All json validation tests passed jsonlint"
rm -f "${DIR}/output.json"
