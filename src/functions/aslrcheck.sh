#!/usr/bin/env bash
# shellcheck disable=SC2154
# these top lines are moved during build

# check for system-wide ASLR support
aslrcheck() {
  # PaX ASLR support
  if ! (grep -q 'Name:' /proc/1/status 2> /dev/null); then
    echo_message '\033[33m insufficient privileges for PaX ASLR checks\033[m\n' '' '' ''
    echo_message '  Fallback to standard Linux ASLR check' '' '' ''
  fi

  if grep -q 'PaX:' /proc/1/status 2> /dev/null; then
    if grep -q 'PaX:' /proc/1/status 2> /dev/null | grep -q 'R'; then
      echo_message '\033[32mPaX ASLR enabled\033[m\n\n' '' '' ''
    else
      echo_message '\033[31mPaX ASLR disabled\033[m\n\n' '' '' ''
    fi
  else
    # standard Linux 'kernel.randomize_va_space' ASLR support
    # (see the kernel file 'Documentation/sysctl/kernel.txt' for a detailed description)
    echo_message " (kernel.randomize_va_space): " '' '' ''
    if sysctl -a 2> /dev/null | grep -q 'kernel\.randomize_va_space = 1'; then
      echo_message '\033[33mPartial (Setting: 1)\033[m\n\n' '' '' ''
      echo_message "  Description - Make the addresses of mmap base, stack and VDSO page randomized.\n" '' '' ''
      echo_message "  This, among other things, implies that shared libraries will be loaded to \n" '' '' ''
      echo_message "  random addresses. Also for PIE-linked binaries, the location of code start\n" '' '' ''
      echo_message "  is randomized. Heap addresses are *not* randomized.\n\n" '' '' ''
    elif sysctl -a 2> /dev/null | grep -q 'kernel\.randomize_va_space = 2'; then
      echo_message '\033[32mFull (Setting: 2)\033[m\n\n' '' '' ''
      echo_message "  Description - Make the addresses of mmap base, heap, stack and VDSO page randomized.\n" '' '' ''
      echo_message "  This, among other things, implies that shared libraries will be loaded to random \n" '' '' ''
      echo_message "  addresses. Also for PIE-linked binaries, the location of code start is randomized.\n\n" '' '' ''
    elif sysctl -a 2> /dev/null | grep -q 'kernel\.randomize_va_space = 0'; then
      echo_message '\033[31mNone (Setting: 0)\033[m\n' '' '' ''
    else
      echo_message '\033[31mNot supported\033[m\n' '' '' ''
    fi
    echo_message "  See the kernel file 'Documentation/sysctl/kernel.txt' for more details.\n\n" '' '' ''
  fi
}
