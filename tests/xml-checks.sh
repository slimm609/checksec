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

# Helper to wrap XML output with a single root element for valid XML
wrap_and_validate() {
  local cmd=("$@")
  local body="${DIR}/output_body.xml"
  local out="${DIR}/output.xml"
  rm -f "$body" "$out"
  "${cmd[@]}" > "$body"
  local ret=$?
  if [[ $ret -ne 0 ]]; then
    echo "command failed: ${cmd[*]}"
    exit 1
  fi
  if [[ ! -s "$body" ]]; then
    echo "empty XML body from: ${cmd[*]}"
    exit 1
  fi
  {
    echo "<root>"
    cat "$body"
    echo "</root>"
  } > "$out"
  xmllint --noout "$out"
}

# procAll
echo "starting procAll check - xml"
wrap_and_validate "${PARENT}/checksec" -o xml procAll || {
  cat "${DIR}/output.xml"
  echo "procAll xml validation failed"
  exit 1
}

# kernel: only run with explicit config files (container may not have system config)
echo "starting custom kernel check for file kernel.config - xml"
wrap_and_validate "${PARENT}/checksec" -o xml kernel kernel.config || {
  cat "${DIR}/output.xml"
  echo "custom kernel xml validation failed"
  exit 1
}

while read -r file; do
  echo "starting custom kernel check for file ${file} - xml"
  wrap_and_validate "${PARENT}/checksec" -o xml kernel "${file}" || {
    cat "${DIR}/output.xml"
    echo "custom kernel xml validation failed"
    exit 1
  }
done < <(find "${PARENT}"/kernel_configs/configs/ -type f -iname "config-*")

# file
echo "starting file check - xml"
wrap_and_validate "${PARENT}/checksec" -o xml file "${test_file}" || {
  cat "${DIR}/output.xml"
  echo "file xml validation failed"
  exit 1
}

# fortify-file
echo "starting fortify-file check - xml"
wrap_and_validate "${PARENT}/checksec" -o xml fortifyFile "${test_file}" || {
  cat "${DIR}/output.xml"
  echo "fortify-file xml validation failed"
  exit 1
}

# fortify-proc using a controlled test process
echo "starting fortify-proc check - xml"
test_bin="${DIR}/binaries/output/all"
"${test_bin}" > /dev/null &
pid=$!
sleep 1
wrap_and_validate "${PARENT}/checksec" -o xml fortifyProc "${pid}" || {
  cat "${DIR}/output.xml"
  echo "fortify-proc xml validation failed"
  kill -9 "${pid}" > /dev/null 2>&1 || true
  exit 1
}
kill -9 "${pid}" > /dev/null 2>&1 || true

# dir
echo "starting dir check - xml"
wrap_and_validate "${PARENT}/checksec" -o xml dir /sbin || {
  cat "${DIR}/output.xml"
  echo "dir xml validation failed"
  exit 1
}

echo "All XML validation tests passed xmllint"
rm -f "${DIR}/output.xml"
