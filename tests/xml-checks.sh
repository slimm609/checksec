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

#check xml for proc-all
echo "starting proc-all check - xml"
"${PARENT}"/checksec --format=xml --proc-all > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "proc-all xml validation failed"
  exit 1
fi

#check xml for proc-all
echo "starting extended proc-all check - xml"
"${PARENT}"/checksec --format=xml --proc-all --extended > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "proc-all xml validation failed"
  exit 1
fi

#check xml for kernel
echo "starting kernel check - xml"
"${PARENT}"/checksec --format=xml --kernel > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "kernel xml validation failed"
  exit 1
fi

echo "starting custom kernel check for file kernel.config - json"
"${PARENT}"/checksec --format=xml --kernel=kernel.config > "${DIR}"/output.xml
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "custom kernel json validation failed"
  exit 1
fi

while read -r file; do
  #check xml against custom kernel config to trigger all checks
  echo "starting custom kernel check for file ${file} - xml"
  "${PARENT}"/checksec --format=xml --kernel="${file}" > "${DIR}/output.xml"
  xmllint --noout "${DIR}/output.xml"
  RET=$?
  if [ ${RET} != 0 ]; then
    cat "${DIR}/output.xml"
    echo "custom kernel xml validation failed"
    exit 1
  fi
done < <(find "${PARENT}"/kernel_configs/configs/ -type f -iname "config-*")

#check xml for file
echo "starting file check - xml"
"${PARENT}"/checksec --format=xml --file="${test_file}" > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "file xml validation failed"
  exit 1
fi

#check xml for file
echo "starting extended file check - xml"
"${PARENT}"/checksec --format=xml --file="${test_file}" --extended > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "file xml validation failed"
  exit 1
fi

#check xml for fortify file
echo "starting fortify-file check - xml"
"${PARENT}"/checksec --format=xml --fortify-file="${test_file}" > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "fortify-file xml validation failed"
  exit 1
fi

#check xml for fortify file
echo "starting extended fortify-file check - xml"
"${PARENT}"/checksec --format=xml --fortify-file="${test_file}" --extended > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "fortify-file xml validation failed"
  exit 1
fi

#check xml for fortify proc
echo "starting fortify-proc check - xml"
"${PARENT}"/checksec --format=xml --fortify-proc=1 > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "fortify-proc xml validation failed"
  exit 1
fi

#check xml for fortify proc
echo "starting extended fortify-proc check - xml"
"${PARENT}"/checksec --format=xml --fortify-proc=1 --extended > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "fortify-proc xml validation failed"
  exit 1
fi

#check xml for dir
echo "starting dir check - xml"
"${PARENT}"/checksec --format=xml --dir=/sbin > "${DIR}/output.xml"
xmllint --noout "${DIR}/output.xml"
RET=$?
if [ ${RET} != 0 ]; then
  cat "${DIR}/output.xml"
  echo "dir xml validation failed"
  exit 1
fi

echo "All XML validation tests passed xmllint"
rm -f "${DIR}/output.xml"
