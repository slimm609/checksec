#!/usr/bin/env bash

set -euo pipefail

DIR=$(
  cd "$(dirname "$0")" || exit
  pwd
)
PARENT=$(
  cd "$(dirname "$0")/.." || exit
  pwd
)

(
  cd "${DIR}/binaries/" || exit
  ./build_binaries.sh
)

for bin in all all32 all_cl all_cl32 \
  dso.so dso32.so dso_cl.so dso_cl32.so \
  none none32 none_cl none_cl32 \
  partial partial32 partial_cl partial_cl32 \
  rel.o rel32.o rel_cl.o rel_cl32.o \
  rpath rpath32 rpath_cl rpath_cl32 \
  runpath runpath32 runpath_cl runpath_cl32 \
  nolibc nolibc_cl nolibc32 nolibc_cl32 \
  fszero fszero_cl fszero32 fszero_cl32; do
  if [[ ! -f "${DIR}/binaries/output/${bin}" ]]; then
    echo "Could not find test file output/${bin}. Run build_binaries.sh in the binaries folder to generate it."
    exit 255
  fi
done

# Helpers to parse JSON even if warnings are printed before the array
json_out() {
  "${PARENT}/checksec" -o json "$@" 2> /dev/null | awk 'found{print} /^\[/ {found=1; print}'
}
json_file_field() {
  local f="$1"
  shift
  local key="$1"
  shift
  json_out file "${f}" | jq -r "(.[0].checks.${key})"
}
json_proc_field() {
  local pid="$1"
  shift
  local key="$1"
  shift
  json_out proc "${pid}" | jq -r "(.[0].checks.${key})"
}

#============================================
# file checks
#============================================

echo "Starting RELRO check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" relro) == "Full RELRO" ]]
done
for bin in partial partial32 partial_cl partial_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" relro) == "Partial RELRO" ]]
done
for bin in none none32 none_cl none_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" relro) == "No RELRO" ]]
done
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" relro) == "N/A" ]]
done
echo "RELRO validation tests passed"

echo "Starting Stack Canary check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" canary) == "Canary found" ]]
done
for bin in none none32 none_cl none_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" canary) == "No Canary found" ]]
done
echo "Stack Canary validation tests passed"

echo "Starting NX check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" nx) == "NX enabled" ]]
done
for bin in none none32 none_cl none_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" nx) == "NX disabled" ]]
done
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" nx) == "N/A" ]]
done
echo "NX validation tests passed"

echo "Starting PIE check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" pie) == "PIE enabled" ]]
done
for bin in none none32 none_cl none_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" pie) == "No PIE" ]]
done
for bin in dso.so dso32.so dso_cl.so dso_cl32.so; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" pie) == "DSO" ]]
done
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" pie) == "REL" ]]
done
echo "PIE validation tests passed"

echo "Starting RPATH check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" rpath) == "No RPATH" ]]
done
for bin in rpath rpath32 rpath_cl rpath_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" rpath) == "RPATH" ]]
done
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" rpath) == "N/A" ]]
done
echo "RPATH validation tests passed"

echo "Starting RUNPATH check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" runpath) == "No RUNPATH" ]]
done
for bin in runpath runpath32 runpath_cl runpath_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" runpath) == "RUNPATH" ]]
done
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" runpath) == "N/A" ]]
done
echo "RUNPATH validation tests passed"

echo "Starting Symbols check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" symbols) == "No Symbols" ]]
done
for bin in none none32 none_cl none_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" symbols) == "Symbols" ]]
done
echo "Symbols validation tests passed"

echo "Starting Fortify check"
for bin in all all32 all_cl all_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" fortify_source) == "Yes" ]]
done
for bin in none none32 none_cl none_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" fortify_source) == "No" ]]
done
for bin in nolibc nolibc_cl nolibc32 nolibc_cl32 fszero fszero_cl fszero32 fszero_cl32; do
  [[ $(json_file_field "${DIR}/binaries/output/${bin}" fortify_source) == "N/A" ]]
done
echo "Fortify validation tests passed"

#============================================
# process checks (use PIDs)
#============================================

start_and_check() {
  local bin_name="$1"
  shift
  local field="$1"
  shift
  local expect="$1"
  shift
  "${DIR}/binaries/output/${bin_name}" > /dev/null &
  local pid=$!
  sleep 1
  local got
  got=$(json_proc_field "${pid}" "${field}")
  kill -9 "${pid}" > /dev/null 2>&1 || true
  if [[ "${got}" != "${expect}" ]]; then
    echo "Process ${bin_name}: expected ${field}='${expect}', got '${got}'"
    exit 1
  fi
}

echo "Starting RELRO process check"
for bin in all all32 all_cl all_cl32; do start_and_check "${bin}" relro "Full RELRO"; done
for bin in partial partial32 partial_cl partial_cl32; do start_and_check "${bin}" relro "Partial RELRO"; done
for bin in none none32 none_cl none_cl32; do start_and_check "${bin}" relro "No RELRO"; done
echo "RELRO process validation tests passed"

echo "Starting Stack Canary process check"
for bin in all all32 all_cl all_cl32; do start_and_check "${bin}" canary "Canary found"; done
for bin in none none32 none_cl none_cl32; do start-and-check "${bin}" canary "No Canary found"; done
echo "Stack Canary process validation tests passed"

echo "Starting NX process check"
for bin in all all32 all_cl all_cl32; do start_and_check "${bin}" nx "NX enabled"; done
for bin in none none32 none_cl none_cl32; do start_and_check "${bin}" nx "NX disabled"; done
echo "NX process validation tests passed"

echo "Starting PIE process check"
for bin in all all32 all_cl all_cl32; do start_and_check "${bin}" pie "PIE enabled"; done
for bin in none none32 none_cl none_cl32; do start_and_check "${bin}" pie "No PIE"; done
echo "PIE process validation tests passed"

echo "Starting Fortify process check"
for bin in all all32 all_cl all_cl32; do start_and_check "${bin}" fortify_source "Yes"; done
for bin in none none32 none_cl none_cl32; do start_and_check "${bin}" fortify_source "No"; done
for bin in nolibc nolibc_cl nolibc32 nolibc_cl32 fszero fszero_cl fszero32 fszero_cl32; do start_and_check "${bin}" fortify_source "N/A"; done
echo "Fortify process validation tests passed"

#============================================
# Mach-O file checks (committed fixtures)
#============================================
MACHO="${DIR}/binaries/output/macho"
for bin in exec_arm64 nopie_x86_64 nocanary_arm64 dylib.dylib hardened_arm64 debuggable_arm64 unsigned_arm64 stripped_arm64 lazy_arm64 dyldenv_arm64; do
  if [[ ! -f "${MACHO}/${bin}" ]]; then
    echo "Could not find Mach-O fixture ${bin}. Run tests/binaries/build_macho_fixtures.sh on macOS."
    exit 255
  fi
done

echo "Starting Mach-O PIE check"
[[ $(json_file_field "${MACHO}/exec_arm64" pie.value) == "PIE Enabled" ]]
[[ $(json_file_field "${MACHO}/nopie_x86_64" pie.value) == "PIE Disabled" ]]
[[ $(json_file_field "${MACHO}/dylib.dylib" pie.value) == "DSO" ]]
echo "Starting Mach-O canary check"
[[ $(json_file_field "${MACHO}/exec_arm64" canary.value) == "Canary Found" ]]
[[ $(json_file_field "${MACHO}/nocanary_arm64" canary.value) == "No Canary Found" ]]
echo "Starting Mach-O signature checks"
[[ $(json_file_field "${MACHO}/exec_arm64" signature.value) == "Linker-signed" ]]
[[ $(json_file_field "${MACHO}/unsigned_arm64" signature.value) == "Unsigned" ]]
[[ $(json_file_field "${MACHO}/hardened_arm64" hardened_runtime.value) == "Enabled" ]]
[[ $(json_file_field "${MACHO}/debuggable_arm64" entitlements.status) == "red" ]]
echo "Starting Mach-O symbols / fixups / dyld_env checks"
[[ $(json_file_field "${MACHO}/stripped_arm64" symbols.value) == "No Symbols" ]]
[[ $(json_file_field "${MACHO}/lazy_arm64" fixups.value) == "Lazy binding" ]]
[[ $(json_file_field "${MACHO}/exec_arm64" fixups.value) == "Chained fixups" ]]
[[ $(json_file_field "${MACHO}/dyldenv_arm64" dyld_env.status) == "red" ]]
echo "Starting fat Mach-O row count check"
[[ $(json_out file "${MACHO}/fat" | jq 'length') == "2" ]]
[[ $(json_out file "${MACHO}/fat" | jq -r '.[0].format') == "macho" ]]
echo "Mach-O validation tests passed"

echo "Done."
echo "All hardening validation tests passed"
