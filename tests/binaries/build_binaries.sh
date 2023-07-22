#!/bin/bash

# All hardening features on (except for CFI and SafeStack)
gcc -o all test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
# Partial RELRO
gcc -o partial test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
# RPATH
gcc -o rpath test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
# RUNPATH
gcc -o runpath test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
# no hardening features
gcc -o none test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
# REL (PIE)
gcc -c test.c -o rel.o
# DSO (PIE)
gcc -shared -fPIC -o dso.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s
# CFI and SafeStack
clang -o cfi test.c -w -flto -fsanitize=cfi -fvisibility=default
clang -o sstack test.c -w -fsanitize=safe-stack
# clang instead of gcc
clang -o all_cl test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
clang -o partial_cl test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
clang -o rpath_cl test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
clang -o runpath_cl test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
clang -o none_cl test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
clang -c test.c -o rel_cl.o
clang -shared -fPIC -o dso_cl.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s

# 32-bit (you might need 'sudo apt install gcc-multilib')
gcc -m32 -o all32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
gcc -m32 -o partial32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
gcc -m32 -o rpath32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
gcc -m32 -o runpath32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
gcc -m32 -o none32 test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
gcc -m32 -c test.c -o rel32.o
gcc -m32 -shared -fPIC -o dso32.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s
clang -m32 -o cfi32 test.c -w -flto -fsanitize=cfi -fvisibility=default
clang -m32 -o sstack32 test.c -w -fsanitize=safe-stack
clang -m32 -o all_cl32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s
clang -m32 -o partial_cl32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z lazy -z noexecstack -s
clang -m32 -o rpath_cl32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--disable-new-dtags
clang -m32 -o runpath_cl32 test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fpie -O2 -z relro -z now -z noexecstack -pie -s -Wl,-rpath,./ -Wl,--enable-new-dtags
clang -m32 -o none_cl32 test.c -w -D_FORTIFY_SOURCE=0 -fno-stack-protector -no-pie -O2 -z norelro -z lazy -z execstack
clang -m32 -c test.c -o rel_cl32.o
clang -m32 -shared -fPIC -o dso_cl32.so test.c -w -D_FORTIFY_SOURCE=2 -fstack-protector-strong -O2 -z relro -z now -z noexecstack -s
