#!/bin/bash
set -x

export PATH=$PATH:/zig/
mkdir -p output

# All hardening features on (except for CFI and SafeStack)
gcc -o output/all test.c -w -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
# Partial RELRO
gcc -o output/partial test.c -w -D_FORTIFY_SOURCE=1 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
# RPATH
gcc -o output/rpath test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
# RUNPATH
gcc -o output/runpath test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
# no hardening features
gcc -o output/none test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
# REL (PIE)
gcc -c test.c -o output/rel.o
# DSO (PIE)
gcc -shared -fPIC -o output/dso.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s
# CFI and SafeStack
clang -o output/cfi test.c -w -flto -fsanitize=cfi -fvisibility=default
clang -o output/sstack test.c -w -fsanitize=safe-stack
# clang instead of gcc
clang -o output/all_cl test.c -w -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
clang -o output/partial_cl test.c -w -D_FORTIFY_SOURCE=1 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
clang -o output/rpath_cl test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
clang -o output/runpath_cl test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
clang -o output/none_cl test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
clang -c test.c -o output/rel_cl.o
clang -shared -fPIC -o output/dso_cl.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s

# 32-bit use zig for cross compile
# zig cc --target=x86-linux-gnu
gcc -m32 -o output/all32 test.c -w -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
gcc -m32 -o output/partial32 test.c -w -D_FORTIFY_SOURCE=1 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
gcc -m32 -o output/rpath32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
gcc -m32 -o output/runpath32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
gcc -m32 -o output/none32 test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
gcc -m32 -c test.c -o output/rel32.o
gcc -m32 -shared -fPIC -o output/dso32.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s

clang -m32 -o output/cfi32 test.c -w -flto -fsanitize=cfi -fvisibility=default
clang -m32 -o output/sstack32 test.c -w -fsanitize=safe-stack
clang -m32 -o output/all_cl32 test.c -w -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
clang -m32 -o output/partial_cl32 test.c -w -D_FORTIFY_SOURCE=1 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
clang -m32 -o output/rpath_cl32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
clang -m32 -o output/runpath_cl32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
clang -m32 -o output/none_cl32 test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
clang -m32 -c test.c -o output/rel_cl32.o
clang -m32 -shared -fPIC -o output/dso_cl32.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s

# Fortify source (NASM assembler installation is required)
nasm -f elf64 -o nolibc.o nolibc.asm
nasm -f elf32 -o nolibc32.o nolibc32.asm
gcc -o output/nolibc nolibc.o -w -nostdlib -no-pie -s
clang -o output/nolibc_cl nolibc.o -w -nostdlib -no-pie -s
gcc -m32 -o output/nolibc32 nolibc32.o -w -nostdlib -no-pie -s
clang -m32 -o output/nolibc_cl32 nolibc32.o -w -nostdlib -no-pie -s

gcc -o output/fszero fszero.c -w -D_FORTIFY_SOURCE=0 -O2 -s
clang -o output/fszero_cl fszero.c -w -D_FORTIFY_SOURCE=0 -O2 -s
gcc -m32 -o output/fszero32 fszero.c -w -D_FORTIFY_SOURCE=0 -O2 -s
clang -m32 -o output/fszero_cl32 fszero.c -w -D_FORTIFY_SOURCE=0 -O2 -s
