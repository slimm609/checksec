#!/usr/bin/env bash

DIR=$(
  cd "$(dirname "$0")"
  pwd
)
PARENT=$(
  cd "$(dirname "$0")/.."
  pwd
)

(
  cd "${DIR}/binaries/"
  ./build_binaries.sh
)

for bin in all all32 all_cl all_cl32 \
  cfi cfi32 sstack sstack32 \
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

#============================================
# file checks
#============================================

echo "Starting RELRO check"
# Full RELRO
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f1) != "Full RELRO" ]]; then
    echo "Full RELRO validation failed on \"${bin}\""
    exit 1
  fi
done
# Partial RELRO
for bin in partial partial32 partial_cl partial_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f1) != "Partial RELRO" ]]; then
    echo "Partial RELRO validation failed on \"${bin}\""
    exit 1
  fi
done
# No RELRO
for bin in none none32 none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f1) != "No RELRO" ]]; then
    echo "No RELRO validation failed on \"${bin}\""
    exit 1
  fi
done
# N/A
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f1) != "N/A" ]]; then
    echo "N/A RELRO validation failed on \"${bin}\""
    exit 1
  fi
done
echo "RELRO validation tests passed"

#============================================

echo "Starting Stack Canary check"
# Canary found
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f2) != "Canary found" ]]; then
    echo "Stack Canary validation failed on \"${bin}\""
    exit 1
  fi
done
# No Canary found
for bin in none none32 none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f2) != "No Canary found" ]]; then
    echo "No Stack Canary validation failed on \"${bin}\""
    exit 1
  fi
done
echo "Stack Canary validation tests passed"

#============================================

echo "Starting NX check"
# NX enabled
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f3) != "NX enabled" ]]; then
    echo "NX enabled validation failed on \"${bin}\""
    exit 1
  fi
done
# NX disabled
for bin in none none32 none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f3) != "NX disabled" ]]; then
    echo "NX disabled validation failed on \"${bin}\""
    exit 1
  fi
done
# N/A
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f3) != "N/A" ]]; then
    echo "N/A NX validation failed on \"${bin}\""
    exit 1
  fi
done
echo "NX validation tests passed"

#============================================

echo "Starting PIE check"
# PIE enabled
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f4) != "PIE enabled" ]]; then
    echo "PIE enabled validation failed on \"${bin}\""
    exit 1
  fi
done
# No PIE
for bin in none none32 none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f4) != "No PIE" ]]; then
    echo "No PIE validation failed on \"${bin}\""
    exit 1
  fi
done
# DSO
for bin in dso.so dso32.so dso_cl.so dso_cl32.so; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f4) != "DSO" ]]; then
    echo "PIE DSO validation failed on \"${bin}\""
    exit 1
  fi
done
# REL
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f4) != "REL" ]]; then
    echo "PIE REL validation failed on \"${bin}\""
    exit 1
  fi
done
echo "PIE validation tests passed"

#============================================

echo "Starting CFI check"
# with CFI
for bin in cfi cfi32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --extended --format=csv | cut -d, -f5) != "with CFI" ]]; then
    echo "CFI validation failed on \"${bin}\""
    exit 1
  fi
done
# without CFI
for bin in none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --extended --format=csv | cut -d, -f5) != "without CFI" ]]; then
    echo "No CFI validation failed on \"${bin}\""
    exit 1
  fi
done
echo "CFI validation tests passed"

#============================================

echo "Starting SafeStack check"
# with SafeStack
for bin in sstack sstack32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --extended --format=csv | cut -d, -f6) != "with SafeStack" ]]; then
    echo "SafeStack validation failed on \"${bin}\""
    exit 1
  fi
done
# without SafeStack
for bin in none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --extended --format=csv | cut -d, -f6) != "without SafeStack" ]]; then
    echo "No SafeStack validation failed on \"${bin}\""
    exit 1
  fi
done
echo "SafeStack validation tests passed"

#============================================

echo "Starting RUNPATH check"
# No RPATH
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f5) != "No RPATH" ]]; then
    echo "No RPATH validation failed on \"${bin}\""
    exit 1
  fi
done
# RPATH
for bin in rpath rpath32 rpath_cl rpath_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f5) != "RPATH" ]]; then
    echo "RPATH validation failed on \"${bin}\""
    exit 1
  fi
done
# N/A
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f5) != "N/A" ]]; then
    echo "N/A RPATH validation failed on \"${bin}\""
    exit 1
  fi
done
echo "RPATH validation tests passed"

#============================================

echo "Starting RUNPATH check"
# No RUNPATH
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f6) != "No RUNPATH" ]]; then
    echo "No RUNPATH validation failed on \"${bin}\""
    exit 1
  fi
done
# RUNPATH
for bin in runpath runpath32 runpath_cl runpath_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f6) != "RUNPATH" ]]; then
    echo "RUNPATH validation failed on \"${bin}\""
    exit 1
  fi
done
# N/A
for bin in rel.o rel32.o rel_cl.o rel_cl32.o; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f6) != "N/A" ]]; then
    echo "N/A RUNPATH validation failed on \"${bin}\""
    exit 1
  fi
done
echo "RUNPATH validation tests passed"

#============================================

echo "Starting Symbols check"
# No Symbols
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f7) != "No Symbols" ]]; then
    echo "No Symbols validation failed on \"${bin}\""
    exit 1
  fi
done
# Symbols
for bin in none none32 none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f7) != "Symbols" ]]; then
    echo "Symbols validation failed on \"${bin}\""
    exit 1
  fi
done
echo "Symbols validation tests passed"

#============================================

echo "Starting Fortify check"
# Yes
for bin in all all32 all_cl all_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f8) != "Yes" ]]; then
    echo "Fortify validation failed on \"${bin}\""
    exit 1
  fi
done
# No
for bin in none none32 none_cl none_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f8) != "No" ]]; then
    echo "No Fortify validation failed on \"${bin}\""
    exit 1
  fi
done
# N/A
for bin in nolibc nolibc_cl nolibc32 nolibc_cl32 fszero fszero_cl fszero32 fszero_cl32; do
  if [[ $("${PARENT}"/checksec --file="${DIR}/binaries/output/${bin}" --format=csv | cut -d, -f8) != "N/A" ]]; then
    echo "No Fortify validation failed on \"${bin}\": $("${PARENT}"/checksec --file="${DIR}/binaries/${bin}" --format=csv | cut -d, -f8)"
    exit 1
  fi
done
echo "Fortify validation tests passed"

#============================================
# process checks
#============================================

echo "Starting RELRO process check"
# Full RELRO
for bin in all all32 all_cl all_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f3) != "Full RELRO" ]]; then
    echo "Full RELRO process validation failed on \"${bin}\""
    exit 1
  fi
done
# Partial RELRO
for bin in partial partial32 partial_cl partial_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f3) != "Partial RELRO" ]]; then
    echo "Partial RELRO process validation failed on \"${bin}\""
    exit 1
  fi
done
# No RELRO
for bin in none none32 none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f3) != "No RELRO" ]]; then
    echo "No RELRO process validation failed on \"${bin}\""
    exit 1
  fi
done
sleep 2
echo "RELRO process validation tests passed"

#============================================

echo "Starting Stack Canary process check"
# Canary found
for bin in all all32 all_cl all_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f4) != "Canary found" ]]; then
    echo "Stack Canary process validation failed on \"${bin}\""
    exit 1
  fi
done
# No Canary found
for bin in none none32 none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f4) != "No Canary found" ]]; then
    echo "No Stack Canary process validation failed on \"${bin}\""
    exit 1
  fi
done
sleep 2
echo "Stack Canary process validation tests passed"

#============================================

echo "Starting CFI process check"
# with CFI
for bin in cfi cfi32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --extended --format=csv | cut -d, -f5) != "with CFI" ]]; then
    echo "CFI process validation failed on \"${bin}\""
    exit 1
  fi
done
# without CFI
for bin in none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --extended --format=csv | cut -d, -f5) != "without CFI" ]]; then
    echo "No CFI process validation failed on \"${bin}\""
    exit 1
  fi
done
sleep 2
echo "CFI process validation tests passed"

#============================================

echo "Starting SafeStack process check"
# with SafeStack (omit 32-bit SafeStack because the binary does not work)
bin=sstack
"${DIR}"/binaries/output/${bin} > /dev/null &
if [[ $("${PARENT}"/checksec --proc=${bin} --extended --format=csv | cut -d, -f6) != "with SafeStack" ]]; then
  echo "SafeStack process validation failed on \"${bin}\""
  exit 1
fi
# without SafeStack
for bin in none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --extended --format=csv | cut -d, -f6) != "without SafeStack" ]]; then
    echo "No SafeStack process validation failed on \"${bin}\""
    exit 1
  fi
done
sleep 2
echo "SafeStack process validation tests passed"

#============================================

echo "Starting NX process check"
# NX enabled
for bin in all all32 all_cl all_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f6) != "NX enabled" ]]; then
    echo "NX enabled process validation failed on \"${bin}\""
    exit 1
  fi
done
# NX disabled
for bin in none none32 none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f6) != "NX disabled" ]]; then
    echo "NX disabled process validation failed on \"${bin}\""
    exit 1
  fi
done
sleep 2
echo "NX process validation tests passed"

#============================================

echo "Starting PIE process check"
# PIE enabled
for bin in all all32 all_cl all_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f7) != "PIE enabled" ]]; then
    echo "PIE enabled process validation failed on \"${bin}\""
    exit 1
  fi
done
# No PIE
for bin in none none32 none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f7) != "No PIE" ]]; then
    echo "No PIE process validation failed on \"${bin}\""
    exit 1
  fi
done
sleep 2
echo "PIE process validation tests passed"

#============================================

echo "Starting Fortify process check"
# Yes
for bin in all all32 all_cl all_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f8) != "Yes" ]]; then
    echo "Fortify process validation failed on \"${bin}\""
    exit 1
  fi
done
# No
for bin in none none32 none_cl none_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f8) != "No" ]]; then
    echo "No Fortify process validation failed on \"${bin}\""
    exit 1
  fi
done
# N/A
for bin in nolibc nolibc_cl nolibc32 nolibc_cl32 fszero fszero_cl fszero32 fszero_cl32; do
  "${DIR}"/binaries/output/${bin} > /dev/null &
  if [[ $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f8) != "N/A" ]]; then
    echo "No Fortify process validation failed on \"${bin}\": $("${PARENT}"/checksec --proc=${bin} --format=csv | cut -d, -f8)"
    exit 1
  fi
done
echo "Fortify process validation tests passed"
echo "Done."
echo "All hardening validation tests passed"
