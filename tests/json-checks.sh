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

DIR=$(cd "$(dirname "$0")" && pwd)
PARENT=$(cd "$(dirname "$0")/.." && pwd)

jsonlint=$(command -v jsonlint || command -v jsonlint-py)

# procAll
echo "starting procAll check - json"
"${PARENT}/checksec" -o json procAll > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "procAll json validation failed"
  exit 1
fi

# kernel: only run with explicit config files
echo "starting custom kernel check for file kernel.config - json"
"${PARENT}/checksec" -o json kernel kernel.config > "${DIR}/output.json"
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
  echo "starting custom kernel check for file ${file} - json"
  "${PARENT}/checksec" -o json kernel "${file}" > "${DIR}/output.json"
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

# file
echo "starting file check - json"
"${PARENT}/checksec" -o json file "${test_file}" > "${DIR}/output.json"
"${jsonlint}" "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "file json validation failed"
  exit 1
fi

# fortify-file
echo "starting fortify-file check - json"
"${PARENT}/checksec" -o json fortifyFile "${test_file}" > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "fortify-file json validation failed"
  exit 1
fi

# fortify-proc using a controlled test process
echo "starting fortify-proc check - json"
test_bin="${DIR}/binaries/output/all"
"${test_bin}" > /dev/null &
pid=$!
sleep 1
"${PARENT}/checksec" -o json fortifyProc "${pid}" > "${DIR}/output.json"
"${jsonlint}" --allow duplicate-keys "${DIR}/output.json" > /dev/null
RET=$?
jq . < "${DIR}/output.json" &> /dev/null
JQRET=$?
if [[ ${RET} != 0 ]] || [[ ${JQRET} != 0 ]]; then
  cat "${DIR}/output.json"
  echo "fortify-proc json validation failed"
  kill -9 "${pid}" > /dev/null 2>&1 || true
  exit 1
fi
kill -9 "${pid}" > /dev/null 2>&1 || true

# dir
echo "starting dir check - json"
"${PARENT}/checksec" -o json dir /sbin > "${DIR}/output.json"
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
