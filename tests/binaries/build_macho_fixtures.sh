#!/usr/bin/env bash
# Build the committed Mach-O fixtures. Runs on a macOS host with Apple clang,
# lipo, codesign and strip. CI does not run this; it reads the committed files.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build_macho_fixtures.sh must run on macOS (needs Apple clang, lipo, codesign)" >&2
  exit 1
fi

cd "$(dirname "$0")"
OUT=output/macho
mkdir -p "${OUT}"
SRC=test.c

clang -w -o "${OUT}/exec_arm64" "${SRC}"
clang -w -arch x86_64 -o "${OUT}/exec_x86_64" "${SRC}"
clang -w -arch x86_64 -Wl,-no_pie -o "${OUT}/nopie_x86_64" "${SRC}"
clang -w -fno-stack-protector -o "${OUT}/nocanary_arm64" "${SRC}"
lipo -create "${OUT}/exec_arm64" "${OUT}/exec_x86_64" -output "${OUT}/fat"
clang -w -shared -o "${OUT}/dylib.dylib" "${SRC}"
clang -w -c -o "${OUT}/obj.o" "${SRC}"
clang -w -Wl,-rpath,@executable_path/../Frameworks -Wl,-rpath,/usr/lib -Wl,-rpath,lib \
  -o "${OUT}/rpath_arm64" "${SRC}"
clang -w -Wl,-no_fixup_chains -o "${OUT}/lazy_arm64" "${SRC}"
clang -w -Wl,-dyld_env,DYLD_INSERT_LIBRARIES=/tmp/x.dylib -o "${OUT}/dyldenv_arm64" "${SRC}"
clang -w -Wl,-sectcreate,__RESTRICT,__restrict,/dev/null -o "${OUT}/restrict_arm64" "${SRC}"
clang -w -mmacosx-version-min=13.0 -o "${OUT}/minos13_arm64" "${SRC}"
clang -w -fsanitize=address -o "${OUT}/asan_arm64" "${SRC}"
clang -w -fobjc-arc -framework Foundation -o "${OUT}/arc_arm64" arc.m
clang -w -fno-objc-arc -framework Foundation -o "${OUT}/noarc_arm64" arc.m

cp "${OUT}/exec_arm64" "${OUT}/adhoc_arm64"
codesign -f -s - "${OUT}/adhoc_arm64"
cp "${OUT}/exec_arm64" "${OUT}/hardened_arm64"
codesign -f -s - --options runtime "${OUT}/hardened_arm64"
cp "${OUT}/exec_arm64" "${OUT}/debuggable_arm64"
codesign -f -s - --entitlements entitlements-debug.plist "${OUT}/debuggable_arm64"
cp "${OUT}/exec_arm64" "${OUT}/unsigned_arm64"
codesign --remove-signature "${OUT}/unsigned_arm64"
# Left unsigned: strip invalidates the linker signature and ad-hoc re-signing fails strict validation.
strip -o "${OUT}/stripped_arm64" "${OUT}/exec_arm64"

# asan links a copy of the runtime dylib next to the binary on some SDKs; the
# fixture only needs the import names, so drop any sidecar.
rm -f "${OUT}"/libclang_rt.asan_osx_dynamic.dylib

echo "Mach-O fixtures written to ${OUT}:"
ls -1 "${OUT}"
